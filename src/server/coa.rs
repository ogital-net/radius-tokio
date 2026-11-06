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
//!   the shared secret, computed with both the M-A slot and the
//!   Authenticator field zeroed before computing the request MD5.
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

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::codec::header::Code;
use crate::codec::request::Request;
use crate::codec::{message_authenticator, CodecError, PacketBuffer};
use crate::exchange::{ClientConfig, ClientError};
use crate::transport::udp::UdpClient;
use crate::AttributesView;

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
    /// verify. Retained for compatibility; the originator silently
    /// discards invalid replies and continues waiting until timeout.
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

/// `CoA` / Disconnect originator over UDP.
///
/// One instance owns one bound UDP socket and a background reader
/// task. Share via `Arc` across the application.
pub struct CoaOriginator {
    transport: UdpClient,
    config: CoaConfig,
}

impl std::fmt::Debug for CoaOriginator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoaOriginator")
            .field("local_addr", &self.transport.local_addr().ok())
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
    /// Forwards any I/O error from [`tokio::net::UdpSocket::bind`].
    pub async fn bind(local_addr: SocketAddr, config: CoaConfig) -> io::Result<Self> {
        let transport = UdpClient::bind(
            local_addr,
            ClientConfig {
                initial_timeout: config.initial_timeout,
                max_retries: config.max_retries,
                backoff_multiplier: config.backoff_multiplier,
                max_in_flight_per_target: config.max_in_flight_per_target,
                ..ClientConfig::default()
            },
        )
        .await?;
        debug!(event = "coa_bind", local = %transport.local_addr()?);
        Ok(Self { transport, config })
    }

    /// Local address the reader is listening on (the port the NAS
    /// will see as the source of every request, and where it must
    /// send the ACK/NAK).
    ///
    /// # Errors
    ///
    /// Forwards [`tokio::net::UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
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
        let mut buf = PacketBuffer::new(code, 0);
        message_authenticator::append_zeroed_slot(&mut buf)?;
        build(&mut buf)?;
        let request = Request::from_buffer(buf);
        let mut _identifier = 0;
        let response = self
            .transport
            .send_with(
                target,
                secret,
                |identifier| request.seal(identifier, secret),
                |_attempt, _packet| {
                    _identifier = _packet.header().identifier;
                    if _attempt == 0 {
                        debug!(event = "coa_send", %target, code = code.0, id = _identifier, len = _packet.as_bytes().len());
                        count!("radius_tokio.coa_requests_sent", "code" => code.0.to_string());
                    } else {
                        debug!(event = "coa_retransmit", %target, attempt = _attempt, len = _packet.as_bytes().len());
                        count!("radius_tokio.coa_retransmits");
                    }
                },
            )
            .await
            .map_err(|error| match error {
                ClientError::Io(error) => CoaError::Io(error),
                ClientError::Codec(error) => CoaError::Codec(error),
                ClientError::Timeout => CoaError::Timeout,
                ClientError::InFlightLimit => CoaError::InFlightLimit,
                ClientError::IdentifierExhausted => CoaError::IdentifierExhausted,
                ClientError::Closed => CoaError::Cancelled,
            });
        let result = response.map(|response| {
            let attributes = response.attributes().raw_attributes().to_vec();
            if matches!(response.code(), Code::COA_ACK | Code::DISCONNECT_ACK) {
                CoaOutcome::Ack { attributes }
            } else {
                CoaOutcome::Nak { attributes }
            }
        });
        #[allow(clippy::match_same_arms)]
        // arms differ in obs calls; identical only when both features are off
        match &result {
            Ok(CoaOutcome::Ack { .. }) => {
                debug!(event = "coa_ack", %target, code = code.0, id = _identifier);
                count!("radius_tokio.coa_outcomes", "outcome" => "ack");
            }
            Ok(CoaOutcome::Nak { .. }) => {
                debug!(event = "coa_nak", %target, code = code.0, id = _identifier);
                count!("radius_tokio.coa_outcomes", "outcome" => "nak");
            }
            Err(CoaError::Timeout) => {
                debug!(event = "coa_error", %target, code = code.0, id = _identifier, error = %CoaError::Timeout);
                count!("radius_tokio.coa_outcomes", "outcome" => "timeout");
            }
            Err(_e) => {
                debug!(event = "coa_error", %target, code = code.0, id = _identifier, error = %_e);
                count!("radius_tokio.coa_outcomes", "outcome" => "error");
            }
        }
        result
    }
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
