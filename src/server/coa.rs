//! Dynamic-Authorization originator: send CoA-Request and
//! Disconnect-Request to a NAS and wait for the ACK/NAK reply
//! (RFC 5176).
//!
//! # Role reversal
//!
//! In `CoA` / Disconnect the AAA server is the *client*: it builds a
//! request, sends it to the NAS's `CoA` listener (UDP/3799 by default),
//! and waits for the NAS to reply with `CoA-ACK` / `CoA-NAK` (or
//! `Disconnect-ACK` / `Disconnect-NAK`). The reply travels back to
//! the source IP+port of the request, so a single bound UDP socket
//! suffices for both halves.
//!
//! # Crypto
//!
//! Every originated request carries:
//!
//! * an Authenticator field equal to
//!   `MD5(packet-with-zeroed-auth || secret)` (RFC 5176 §2.3, same
//!   formula as Accounting-Request);
//! * a `Message-Authenticator` attribute (RFC 3579 §3.2) keyed on
//!   the shared secret, computed over the final packet bytes with
//!   the M-A slot zeroed and the Authenticator field set to the
//!   value above. RFC 5176 §3.1 / §3.2 require it on both request
//!   and reply.
//!
//! Inbound replies are validated the same way: Response Authenticator
//! (`MD5(reply-with-request-auth || secret)`) plus a present and
//! valid `Message-Authenticator`. Anything else is a silent drop
//! per RFC 5176 §3.5.
//!
//! # Identifier allocation
//!
//! The Identifier byte is owned per `target_addr`. We use a
//! `(target → next-id)` counter and skip values still in flight to a
//! given target. With a 1-byte field there is a hard ceiling of 256
//! concurrent in-flight requests per target;
//! [`CoaConfig::max_in_flight_per_target`] caps it well below that
//! by default.
//!
//! # Retry / backoff
//!
//! RFC 5080 §2.2.1 ("Retransmission Behaviour") describes the
//! retransmit pattern. We re-send the same packet bytes (same
//! Identifier, same Authenticator) on each retry; the NAS's dedup
//! cache will fold the duplicate.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio::time::timeout;

use crate::codec::header::{Code, Header, MAX_PACKET_LEN};
use crate::codec::message_authenticator::Verification;
use crate::codec::{authenticator, message_authenticator, CodecError, PacketBuffer};

/// Which dynamic-authorization request the NAS sent us (RFC 5176).
///
/// Decoded from the packet code by
/// [`crate::server::Request::coa_action`]; dispatch on this in your
/// handler instead of integer-comparing
/// [`crate::server::Request::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoaAction {
    /// `CoA-Request` (code 43, RFC 5176 §2.1). Reply with `CoA-ACK`
    /// on success or `CoA-NAK` carrying an [`ErrorCause`].
    Coa,
    /// `Disconnect-Request` (code 40, RFC 5176 §2.2). Reply with
    /// `Disconnect-ACK` on success or `Disconnect-NAK` carrying an
    /// [`ErrorCause`].
    Disconnect,
}

impl CoaAction {
    /// Wire code emitted on a successful reply (`CoA-ACK` /
    /// `Disconnect-ACK`).
    #[must_use]
    pub fn ack_code(self) -> Code {
        match self {
            Self::Coa => Code::COA_ACK,
            Self::Disconnect => Code::DISCONNECT_ACK,
        }
    }

    /// Wire code emitted on a rejection (`CoA-NAK` /
    /// `Disconnect-NAK`).
    #[must_use]
    pub fn nak_code(self) -> Code {
        match self {
            Self::Coa => Code::COA_NAK,
            Self::Disconnect => Code::DISCONNECT_NAK,
        }
    }

    /// Decode from the inbound packet code. Returns `None` for any
    /// code that is not a CoA-Request or Disconnect-Request.
    #[must_use]
    pub fn from_code(code: Code) -> Option<Self> {
        match code {
            Code::COA_REQUEST => Some(Self::Coa),
            Code::DISCONNECT_REQUEST => Some(Self::Disconnect),
            _ => None,
        }
    }
}

/// `Error-Cause` (attribute 101) values a NAK reply may carry to
/// tell the originator why it was rejected (RFC 5176 §3.5 — values
/// inherited from RFC 3576 §5.18 plus 5176-specific additions).
///
/// Wire encoding is a 4-byte big-endian unsigned integer; conversion
/// is via [`ErrorCause::from_u32`] / [`ErrorCause::to_u32`]. Codes not
/// enumerated here round-trip as [`ErrorCause::Other`] so the type
/// stays total over the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCause {
    /// 201 — Residual Session Context Removed.
    ResidualSessionContextRemoved,
    /// 202 — Invalid EAP Packet (Ignored).
    InvalidEapPacket,
    /// 401 — Unsupported Attribute.
    UnsupportedAttribute,
    /// 402 — Missing Attribute.
    MissingAttribute,
    /// 403 — NAS Identification Mismatch.
    NasIdentificationMismatch,
    /// 404 — Invalid Request.
    InvalidRequest,
    /// 405 — Unsupported Service.
    UnsupportedService,
    /// 406 — Unsupported Extension.
    UnsupportedExtension,
    /// 407 — Invalid Attribute Value.
    InvalidAttributeValue,
    /// 501 — Administratively Prohibited.
    AdministrativelyProhibited,
    /// 502 — Request Not Routable (Proxy).
    RequestNotRoutable,
    /// 503 — Session Context Not Found.
    SessionContextNotFound,
    /// 504 — Session Context Not Removable.
    SessionContextNotRemovable,
    /// 505 — Other Proxy Processing Error.
    OtherProxyProcessingError,
    /// 506 — Resources Unavailable.
    ResourcesUnavailable,
    /// 507 — Request Initiated.
    RequestInitiated,
    /// 508 — Multiple Session Selection Unsupported.
    MultipleSessionSelectionUnsupported,
    /// Any code not enumerated above; preserved for forward
    /// compatibility with future RFC additions or vendor extensions.
    Other(u32),
}

impl ErrorCause {
    /// Decode from the on-wire integer.
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        match v {
            201 => Self::ResidualSessionContextRemoved,
            202 => Self::InvalidEapPacket,
            401 => Self::UnsupportedAttribute,
            402 => Self::MissingAttribute,
            403 => Self::NasIdentificationMismatch,
            404 => Self::InvalidRequest,
            405 => Self::UnsupportedService,
            406 => Self::UnsupportedExtension,
            407 => Self::InvalidAttributeValue,
            501 => Self::AdministrativelyProhibited,
            502 => Self::RequestNotRoutable,
            503 => Self::SessionContextNotFound,
            504 => Self::SessionContextNotRemovable,
            505 => Self::OtherProxyProcessingError,
            506 => Self::ResourcesUnavailable,
            507 => Self::RequestInitiated,
            508 => Self::MultipleSessionSelectionUnsupported,
            other => Self::Other(other),
        }
    }

    /// Encode to the on-wire integer.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::ResidualSessionContextRemoved => 201,
            Self::InvalidEapPacket => 202,
            Self::UnsupportedAttribute => 401,
            Self::MissingAttribute => 402,
            Self::NasIdentificationMismatch => 403,
            Self::InvalidRequest => 404,
            Self::UnsupportedService => 405,
            Self::UnsupportedExtension => 406,
            Self::InvalidAttributeValue => 407,
            Self::AdministrativelyProhibited => 501,
            Self::RequestNotRoutable => 502,
            Self::SessionContextNotFound => 503,
            Self::SessionContextNotRemovable => 504,
            Self::OtherProxyProcessingError => 505,
            Self::ResourcesUnavailable => 506,
            Self::RequestInitiated => 507,
            Self::MultipleSessionSelectionUnsupported => 508,
            Self::Other(v) => v,
        }
    }
}

/// Tunables for [`CoaOriginator`]. All fields have sensible defaults
/// derived from RFC 5080 §2.2.1; override per deployment.
#[derive(Debug, Clone, Copy)]
pub struct CoaConfig {
    /// Time to wait for the first ACK/NAK before retransmitting.
    /// Default 1 second.
    pub initial_timeout: Duration,
    /// Maximum number of retransmissions (excluding the original
    /// send). Default 2 → up to 3 transmissions total.
    pub max_retries: u8,
    /// Multiplier applied to the per-attempt timeout after each
    /// retransmission. Default 2 → 1s, 2s, 4s.
    pub backoff_multiplier: u32,
    /// Cap on the number of concurrent in-flight requests *per
    /// target NAS*. Hard-limited by the 1-byte Identifier field
    /// (256), but operators usually want much less than that.
    /// Default 16.
    pub max_in_flight_per_target: usize,
}

impl Default for CoaConfig {
    fn default() -> Self {
        Self {
            initial_timeout: Duration::from_secs(1),
            max_retries: 2,
            backoff_multiplier: 2,
            max_in_flight_per_target: 16,
        }
    }
}

/// Outcome of an originated CoA-Request or Disconnect-Request.
#[derive(Debug)]
pub enum CoaOutcome {
    /// NAS accepted the request (`CoA-ACK` / `Disconnect-ACK`).
    Ack {
        /// Owned attribute bytes from the reply. Iterate via
        /// [`crate::codec::attributes::iter`].
        attributes: Vec<u8>,
    },
    /// NAS rejected the request (`CoA-NAK` / `Disconnect-NAK`). The
    /// reply attributes typically include an `Error-Cause`
    /// (attribute 101, RFC 5176 §3.5) explaining the rejection.
    Nak {
        /// Owned attribute bytes from the reply.
        attributes: Vec<u8>,
    },
}

/// Errors surfaced by the originator.
#[derive(Debug)]
pub enum CoaError {
    /// I/O error talking to the socket. Terminal — typically means
    /// the underlying transport is gone.
    Io(io::Error),
    /// The supplied `build` closure produced a malformed packet.
    Codec(CodecError),
    /// All retries elapsed without a reply from the NAS.
    Timeout,
    /// Too many requests already in flight to this target — back off
    /// or raise [`CoaConfig::max_in_flight_per_target`].
    InFlightLimit,
    /// Every Identifier in `0..=255` is already in flight to this
    /// target. Should not be reachable while
    /// [`CoaConfig::max_in_flight_per_target`] is the default 16.
    IdentifierExhausted,
    /// The NAS replied with a code we did not expect (anything other
    /// than the matching ACK/NAK pair).
    UnexpectedReplyCode(Code),
    /// The Response Authenticator on the reply did not verify.
    AuthenticatorMismatch,
    /// The reply omitted `Message-Authenticator` or it failed to
    /// verify. RFC 5176 §3.2 / §3.5 require silent discard; we
    /// surface it so the caller can log.
    MessageAuthenticatorInvalid,
    /// The originator was dropped while a request was in flight.
    Cancelled,
}

impl std::fmt::Display for CoaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoaError::Io(e) => write!(f, "i/o: {e}"),
            CoaError::Codec(e) => write!(f, "codec: {e}"),
            CoaError::Timeout => write!(f, "no reply within retry budget"),
            CoaError::InFlightLimit => write!(f, "per-target in-flight limit reached"),
            CoaError::IdentifierExhausted => write!(
                f,
                "every RADIUS Identifier value is in flight to this target",
            ),
            CoaError::UnexpectedReplyCode(c) => write!(f, "unexpected reply code {}", c.0),
            CoaError::AuthenticatorMismatch => {
                write!(f, "reply Response Authenticator failed")
            }
            CoaError::MessageAuthenticatorInvalid => {
                write!(f, "reply Message-Authenticator missing or invalid")
            }
            CoaError::Cancelled => write!(f, "originator dropped before reply arrived"),
        }
    }
}

impl std::error::Error for CoaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoaError::Io(e) => Some(e),
            CoaError::Codec(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CoaError {
    fn from(e: io::Error) -> Self {
        CoaError::Io(e)
    }
}

impl From<CodecError> for CoaError {
    fn from(e: CodecError) -> Self {
        CoaError::Codec(e)
    }
}

/// Reply payload as delivered by the reader task to a waiter. Carries
/// the full datagram so the validator can run the Response
/// Authenticator + M-A checks against the bytes the NAS actually sent.
struct RawReply {
    datagram: Vec<u8>,
}

/// One in-flight slot. Dropping the `Sender` (originator shutdown)
/// gives the waiter `CoaError::Cancelled`.
struct Inflight {
    reply_tx: oneshot::Sender<RawReply>,
}

/// Per-target state. Identifier allocation and the in-flight registry
/// live here; the rate-limit semaphore is kept separately so it can
/// be cloned cheaply per send.
#[derive(Default)]
struct TargetState {
    inflight: HashMap<u8, Inflight>,
    next_identifier: u8,
}

impl TargetState {
    /// Walk the Identifier space starting at `next_identifier`,
    /// returning the first value not currently in flight. `None` if
    /// every value is taken.
    fn find_free_identifier(&mut self) -> Option<u8> {
        for step in 0..=u8::MAX {
            let candidate = self.next_identifier.wrapping_add(step);
            if !self.inflight.contains_key(&candidate) {
                self.next_identifier = candidate.wrapping_add(1);
                return Some(candidate);
            }
        }
        None
    }
}

/// `CoA` / Disconnect originator over UDP.
///
/// One instance owns one bound UDP socket and a background reader
/// task. Share via [`Arc`] across the application.
pub struct CoaOriginator {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<HashMap<SocketAddr, TargetState>>>,
    semaphores: Arc<Mutex<HashMap<SocketAddr, Arc<Semaphore>>>>,
    config: CoaConfig,
    reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for CoaOriginator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoaOriginator")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CoaOriginator {
    /// Bind a fresh UDP socket on `local_addr` and start the reader
    /// task. Use `0.0.0.0:0` (or `[::]:0`) to let the OS pick the
    /// ephemeral port — typical for an originator.
    ///
    /// # Errors
    ///
    /// Forwards any I/O error from [`UdpSocket::bind`].
    pub async fn bind(local_addr: SocketAddr, config: CoaConfig) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        debug!(event = "coa_bind", local = %socket.local_addr()?);
        let state: Arc<Mutex<HashMap<SocketAddr, TargetState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let reader = tokio::spawn(reader_loop(Arc::clone(&socket), Arc::clone(&state)));
        Ok(Self {
            socket,
            state,
            semaphores: Arc::new(Mutex::new(HashMap::new())),
            config,
            reader,
        })
    }

    /// Local address the reader is listening on (the port the NAS
    /// will see as the source of every request, and where it must
    /// send the ACK/NAK).
    ///
    /// # Errors
    ///
    /// Forwards [`UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send a `CoA-Request` to `target` and await `CoA-ACK` or
    /// `CoA-NAK`.
    ///
    /// `secret` is the shared secret with the NAS. `build` is invoked
    /// with a fresh [`PacketBuffer`] that already has the header and
    /// a zeroed `Message-Authenticator` placeholder in place; append
    /// CoA-specific attributes (User-Name / Acct-Session-Id /
    /// dynamic VLAN / etc.) and return.
    ///
    /// # Errors
    ///
    /// See [`CoaError`].
    pub async fn send_coa<F>(
        &self,
        target: SocketAddr,
        secret: &[u8],
        build: F,
    ) -> Result<CoaOutcome, CoaError>
    where
        F: FnOnce(&mut PacketBuffer) -> Result<(), CodecError>,
    {
        self.send_request(target, secret, Code::COA_REQUEST, build)
            .await
    }

    /// Send a `Disconnect-Request` to `target` and await
    /// `Disconnect-ACK` or `Disconnect-NAK`. Same shape as
    /// [`send_coa`](Self::send_coa).
    ///
    /// # Errors
    ///
    /// See [`CoaError`].
    pub async fn send_disconnect<F>(
        &self,
        target: SocketAddr,
        secret: &[u8],
        build: F,
    ) -> Result<CoaOutcome, CoaError>
    where
        F: FnOnce(&mut PacketBuffer) -> Result<(), CodecError>,
    {
        self.send_request(target, secret, Code::DISCONNECT_REQUEST, build)
            .await
    }

    #[allow(clippy::used_underscore_binding)]
    async fn send_request<F>(
        &self,
        target: SocketAddr,
        secret: &[u8],
        code: Code,
        build: F,
    ) -> Result<CoaOutcome, CoaError>
    where
        F: FnOnce(&mut PacketBuffer) -> Result<(), CodecError>,
    {
        // ---- per-target rate limit ---------------------------------
        let sem = self.semaphore_for(target).await;
        let _permit = sem
            .try_acquire_owned()
            .map_err(|_| CoaError::InFlightLimit)?;

        // ---- build packet body (M-A slot reserved up front) --------
        let mut buf = PacketBuffer::new(code, 0);
        let ma_offset = message_authenticator::append_zeroed_slot(&mut buf)?;
        build(&mut buf)?;

        // ---- allocate Identifier + register in-flight slot --------
        let (identifier, reply_rx, request_authenticator) = {
            let mut all = self.state.lock().await;
            let slot = all.entry(target).or_default();
            let identifier = slot
                .find_free_identifier()
                .ok_or(CoaError::IdentifierExhausted)?;
            buf.set_identifier(identifier);

            // Order matters: for Accounting/CoA/Disconnect requests
            // the Authenticator is `MD5(packet-with-zeroed-auth ||
            // secret)`, so it depends on the M-A bytes already being
            // in place. The M-A in turn must be computed with the
            // Authenticator field treated as zero (chicken-and-egg
            // resolved by RFC 5176 §3.1 / RFC 2866 §3 convention):
            //   1. Patch length, leave auth = 0, compute M-A with
            //      a zero substitute, patch M-A.
            //   2. Compute the zeroed-request authenticator over the
            //      packet with M-A populated and auth still 0; set
            //      the Authenticator field.
            buf.patch_length();
            let tag = message_authenticator::compute(buf.as_bytes(), &[0u8; 16], secret);
            message_authenticator::patch(&mut buf, ma_offset, &tag);
            let auth = authenticator::compute_zeroed_request(buf.as_bytes(), secret);
            buf.set_authenticator(auth);

            let (reply_tx, reply_rx) = oneshot::channel();
            slot.inflight.insert(identifier, Inflight { reply_tx });
            (identifier, reply_rx, auth)
        };

        // ---- send + retry loop ------------------------------------
        let bytes = buf.as_bytes().to_vec();
        debug!(
            event = "coa_send",
            %target,
            code = code.0,
            id = identifier,
            len = bytes.len(),
        );
        count!("radius_tokio.coa_requests_sent", "code" => code.0.to_string());
        let outcome = send_and_await(&self.socket, target, &bytes, reply_rx, &self.config).await;

        // ---- always reclaim the slot ------------------------------
        {
            let mut all = self.state.lock().await;
            if let Some(slot) = all.get_mut(&target) {
                slot.inflight.remove(&identifier);
            }
        }

        #[cfg(feature = "metrics")]
        if let Err(e) = &outcome {
            count!(
                "radius_tokio.coa_outcomes",
                "outcome" => if matches!(e, CoaError::Timeout) { "timeout" } else { "error" }
            );
        }
        let raw = outcome?;
        let result = validate_and_classify(code, &raw.datagram, &request_authenticator, secret);
        #[allow(clippy::match_same_arms)]
        // arms differ in obs calls; identical only when both features are off
        match &result {
            Ok(CoaOutcome::Ack { .. }) => {
                debug!(event = "coa_ack", %target, code = code.0, id = identifier);
                count!("radius_tokio.coa_outcomes", "outcome" => "ack");
            }
            Ok(CoaOutcome::Nak { .. }) => {
                debug!(event = "coa_nak", %target, code = code.0, id = identifier);
                count!("radius_tokio.coa_outcomes", "outcome" => "nak");
            }
            Err(_e) => {
                debug!(event = "coa_error", %target, code = code.0, id = identifier, error = %_e);
                count!("radius_tokio.coa_outcomes", "outcome" => "error");
            }
        }
        result
    }

    async fn semaphore_for(&self, target: SocketAddr) -> Arc<Semaphore> {
        let mut map = self.semaphores.lock().await;
        Arc::clone(
            map.entry(target)
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_in_flight_per_target))),
        )
    }
}

impl Drop for CoaOriginator {
    fn drop(&mut self) {
        // Stop the reader task. Inflight oneshot senders are dropped
        // with it, so any waiter sees `CoaError::Cancelled`.
        self.reader.abort();
    }
}

/// Background task: read every datagram off `socket`, decode the
/// header, look up the matching in-flight slot by `(src, identifier)`,
/// and hand the *full datagram bytes* to the waiter via its `oneshot`.
///
/// Anything we cannot match (unknown identifier, malformed header,
/// reply for a slot whose waiter has already given up) is silently
/// dropped — the NAS will retransmit if it cares.
async fn reader_loop(socket: Arc<UdpSocket>, state: Arc<Mutex<HashMap<SocketAddr, TargetState>>>) {
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        let Ok((len, src)) = socket.recv_from(&mut buf).await else {
            // Socket closed; reader exits.
            return;
        };
        let datagram = &buf[..len];
        let Ok((header, _)) = Header::parse(datagram) else {
            continue;
        };
        let inflight = {
            let mut all = state.lock().await;
            all.get_mut(&src)
                .and_then(|t| t.inflight.remove(&header.identifier))
        };
        let Some(slot) = inflight else { continue };
        let _ = slot.reply_tx.send(RawReply {
            datagram: datagram.to_vec(),
        });
    }
}

/// Send the packet and wait for either the oneshot or the timeout,
/// retransmitting up to `config.max_retries` times.
async fn send_and_await(
    socket: &UdpSocket,
    target: SocketAddr,
    bytes: &[u8],
    mut reply_rx: oneshot::Receiver<RawReply>,
    config: &CoaConfig,
) -> Result<RawReply, CoaError> {
    let mut wait = config.initial_timeout;
    let attempts = config.max_retries.saturating_add(1);
    for attempt in 0..attempts {
        socket.send_to(bytes, target).await?;
        if attempt > 0 {
            debug!(event = "coa_retransmit", %target, attempt, len = bytes.len());
        }
        match timeout(wait, &mut reply_rx).await {
            Ok(Ok(reply)) => return Ok(reply),
            Ok(Err(_)) => return Err(CoaError::Cancelled),
            Err(_) => {
                if attempt + 1 < attempts {
                    wait = wait.saturating_mul(config.backoff_multiplier.max(1));
                }
            }
        }
    }
    debug!(event = "coa_timeout", %target, attempts);
    Err(CoaError::Timeout)
}

/// Validate the inbound reply (code + Response Authenticator + M-A)
/// and turn it into a [`CoaOutcome`].
fn validate_and_classify(
    request_code: Code,
    datagram: &[u8],
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> Result<CoaOutcome, CoaError> {
    let (ack_code, nak_code) = match request_code {
        Code::COA_REQUEST => (Code::COA_ACK, Code::COA_NAK),
        Code::DISCONNECT_REQUEST => (Code::DISCONNECT_ACK, Code::DISCONNECT_NAK),
        // Originator only emits the two request codes above.
        other => return Err(CoaError::UnexpectedReplyCode(other)),
    };

    let (header, attrs) = Header::parse(datagram).map_err(|_| CoaError::AuthenticatorMismatch)?;

    if header.code != ack_code && header.code != nak_code {
        return Err(CoaError::UnexpectedReplyCode(header.code));
    }

    if !authenticator::verify_response(datagram, request_authenticator, secret) {
        return Err(CoaError::AuthenticatorMismatch);
    }

    match message_authenticator::verify(datagram, request_authenticator, secret) {
        Verification::Valid => {}
        // RFC 5176 §3.5 makes M-A mandatory on replies; treat absent
        // and invalid identically.
        Verification::Absent | Verification::Invalid => {
            return Err(CoaError::MessageAuthenticatorInvalid);
        }
    }

    Ok(if header.code == ack_code {
        CoaOutcome::Ack {
            attributes: attrs.to_vec(),
        }
    } else {
        CoaOutcome::Nak {
            attributes: attrs.to_vec(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn coa_action_round_trips_codes() {
        assert_eq!(
            CoaAction::from_code(Code::COA_REQUEST),
            Some(CoaAction::Coa)
        );
        assert_eq!(
            CoaAction::from_code(Code::DISCONNECT_REQUEST),
            Some(CoaAction::Disconnect),
        );
        assert_eq!(CoaAction::from_code(Code::ACCESS_REQUEST), None);
        assert_eq!(CoaAction::Coa.ack_code(), Code::COA_ACK);
        assert_eq!(CoaAction::Coa.nak_code(), Code::COA_NAK);
        assert_eq!(CoaAction::Disconnect.ack_code(), Code::DISCONNECT_ACK);
        assert_eq!(CoaAction::Disconnect.nak_code(), Code::DISCONNECT_NAK);
    }

    #[test]
    fn error_cause_round_trips_all_named_values() {
        // Every enumerated cause must round-trip through u32; this
        // is the safety net for a hand-maintained match table.
        let named = [
            ErrorCause::ResidualSessionContextRemoved,
            ErrorCause::InvalidEapPacket,
            ErrorCause::UnsupportedAttribute,
            ErrorCause::MissingAttribute,
            ErrorCause::NasIdentificationMismatch,
            ErrorCause::InvalidRequest,
            ErrorCause::UnsupportedService,
            ErrorCause::UnsupportedExtension,
            ErrorCause::InvalidAttributeValue,
            ErrorCause::AdministrativelyProhibited,
            ErrorCause::RequestNotRoutable,
            ErrorCause::SessionContextNotFound,
            ErrorCause::SessionContextNotRemovable,
            ErrorCause::OtherProxyProcessingError,
            ErrorCause::ResourcesUnavailable,
            ErrorCause::RequestInitiated,
            ErrorCause::MultipleSessionSelectionUnsupported,
        ];
        for cause in named {
            assert_eq!(ErrorCause::from_u32(cause.to_u32()), cause);
        }
    }

    #[test]
    fn error_cause_preserves_unknown_codes() {
        let unknown = ErrorCause::from_u32(9_999);
        assert_eq!(unknown, ErrorCause::Other(9_999));
        assert_eq!(unknown.to_u32(), 9_999);
    }

    #[test]
    fn config_default_values() {
        let cfg = CoaConfig::default();
        assert_eq!(cfg.initial_timeout, Duration::from_secs(1));
        assert_eq!(cfg.max_retries, 2);
        assert_eq!(cfg.backoff_multiplier, 2);
        assert_eq!(cfg.max_in_flight_per_target, 16);
    }

    #[test]
    fn error_display_covers_every_variant() {
        let cases: &[(CoaError, &str)] = &[
            (CoaError::Timeout, "no reply within retry budget"),
            (
                CoaError::InFlightLimit,
                "per-target in-flight limit reached",
            ),
            (
                CoaError::IdentifierExhausted,
                "every RADIUS Identifier value is in flight to this target",
            ),
            (
                CoaError::AuthenticatorMismatch,
                "reply Response Authenticator failed",
            ),
            (
                CoaError::MessageAuthenticatorInvalid,
                "reply Message-Authenticator missing or invalid",
            ),
            (
                CoaError::Cancelled,
                "originator dropped before reply arrived",
            ),
        ];
        for (err, want) in cases {
            assert_eq!(err.to_string(), *want);
        }
        assert_eq!(
            CoaError::UnexpectedReplyCode(Code::ACCESS_REJECT).to_string(),
            "unexpected reply code 3",
        );
        let io_err = io::Error::other("boom");
        assert!(CoaError::Io(io_err).to_string().starts_with("i/o: "));
        let codec_err = CodecError::WrongPacketType;
        assert!(CoaError::Codec(codec_err)
            .to_string()
            .starts_with("codec: "));
    }

    #[test]
    fn error_from_io_and_codec_round_trip() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "x");
        let wrapped: CoaError = io_err.into();
        assert!(matches!(wrapped, CoaError::Io(_)));
        assert!(wrapped.source().is_some());

        let codec_err = CodecError::WrongPacketType;
        let wrapped: CoaError = codec_err.into();
        assert!(matches!(wrapped, CoaError::Codec(_)));
        assert!(wrapped.source().is_some());
    }

    #[test]
    fn error_source_returns_none_for_terminal_variants() {
        for err in [
            CoaError::Timeout,
            CoaError::InFlightLimit,
            CoaError::IdentifierExhausted,
            CoaError::AuthenticatorMismatch,
            CoaError::MessageAuthenticatorInvalid,
            CoaError::Cancelled,
            CoaError::UnexpectedReplyCode(Code(0)),
        ] {
            assert!(err.source().is_none(), "{err:?} should have no source");
        }
    }
}
