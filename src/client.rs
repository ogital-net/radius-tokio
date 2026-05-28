//! Authenticator-side UDP originator for Access-Request.
//!
//! [`RadiusClient`](crate::client::RadiusClient) owns one bound UDP socket and a background reader
//! task. It allocates a fresh `Identifier` per outgoing request,
//! correlates inbound replies by `(peer, identifier)`, and
//! retransmits per RFC 5080 §2.2.1 until either a reply arrives or
//! the retry budget is exhausted.
//!
//! The caller supplies the per-target shared secret on every call,
//! so the client has no notion of a `ClientStore` — route by
//! whatever identity model you have (NAS-IP-Address, source IP,
//! tenant, …) and pass the right secret in.
//!
//! # Crypto
//!
//! Each `Access-Request` carries:
//!
//! * a 16-byte random Request Authenticator (RFC 2865 §3, drawn
//!   from [`crate::rand`]);
//! * a `Message-Authenticator` attribute (RFC 3579 §3.2) keyed on
//!   the shared secret.
//!
//! Both are populated by
//! [`PacketBuffer::seal_as_random_authenticator_request`](crate::PacketBuffer::seal_as_random_authenticator_request);
//! the build closure passed to [`RadiusClient::access_request`](crate::client::RadiusClient::access_request)
//! receives the random authenticator so it can pre-encrypt
//! `User-Password` with [`crate::user_password_encrypt`] before
//! sealing.
//!
//! Inbound replies are validated against the Request Authenticator:
//! the Response Authenticator (`MD5(reply-with-request-auth ||
//! secret)`) must match and a present `Message-Authenticator` must
//! verify. Anything else surfaces as [`crate::client::ClientError`]
//! rather than a silent drop, so the caller can log.
//!
//! # Identifier allocation
//!
//! The 1-byte `Identifier` field is owned per `peer`. A
//! `(peer → next-id)` counter walks the space, skipping values
//! still in flight to that peer.
//! [`RetryPolicy::max_in_flight_per_peer`](crate::client::RetryPolicy::max_in_flight_per_peer)
//! caps concurrency well below the 256-value ceiling.

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

/// Retry / backoff knobs for [`RadiusClient`]. Defaults follow
/// RFC 5080 §2.2.1 (1 s initial timeout, three attempts total,
/// ×2 backoff).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Wait this long for the first reply before retransmitting.
    pub initial_timeout: Duration,
    /// Maximum number of *transmissions* including the original.
    /// `1` disables retries.
    pub max_attempts: u32,
    /// Multiplier applied to the per-attempt timeout after each
    /// retransmission. `1` keeps the timeout constant.
    pub backoff_multiplier: u32,
    /// Cap on concurrent in-flight requests per peer. Hard-limited
    /// by the 1-byte `Identifier` field (256); operators usually
    /// want much less.
    pub max_in_flight_per_peer: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_timeout: Duration::from_secs(1),
            max_attempts: 3,
            backoff_multiplier: 2,
            max_in_flight_per_peer: 16,
        }
    }
}

/// Outcome of an originated Access-Request.
///
/// `authenticator` is the 16-byte Request Authenticator of the
/// original Access-Request, exposed so callers can decrypt
/// `MS-MPPE-{Send,Recv}-Key` (via [`crate::mppe::mppe_key_decrypt`])
/// or any other reply attribute whose obfuscation is keyed on it.
#[derive(Debug)]
pub enum AccessOutcome {
    /// `Access-Accept` (code 2).
    Accept {
        /// Request Authenticator that was sent.
        authenticator: [u8; 16],
        /// Owned attribute bytes from the reply. Iterate via
        /// [`crate::attributes::iter`].
        attributes: Vec<u8>,
    },
    /// `Access-Reject` (code 3).
    Reject {
        /// Request Authenticator that was sent.
        authenticator: [u8; 16],
        /// Owned attribute bytes from the reply.
        attributes: Vec<u8>,
    },
    /// `Access-Challenge` (code 11).
    Challenge {
        /// Request Authenticator that was sent.
        authenticator: [u8; 16],
        /// Owned attribute bytes from the reply.
        attributes: Vec<u8>,
    },
}

/// Errors surfaced by [`RadiusClient`].
#[derive(Debug)]
pub enum ClientError {
    /// I/O error on the bound socket. Terminal.
    Io(io::Error),
    /// The build closure or sealing produced a malformed packet.
    Codec(CodecError),
    /// All retries elapsed without a reply.
    Timeout,
    /// Too many requests already in flight to this peer — back off
    /// or raise [`RetryPolicy::max_in_flight_per_peer`].
    InFlightLimit,
    /// Every `Identifier` value is currently in flight to this peer.
    /// Should not be reachable while
    /// [`RetryPolicy::max_in_flight_per_peer`] is the default 16.
    IdentifierExhausted,
    /// The peer replied with a code we did not expect (anything
    /// other than Access-Accept / Reject / Challenge).
    UnexpectedReplyCode(Code),
    /// The Response Authenticator on the reply did not verify.
    AuthenticatorMismatch,
    /// The reply carried a `Message-Authenticator` that failed to
    /// verify. (Absence is *not* an error: RFC 3579 §3.2 only
    /// requires it on the request side; many servers omit it on
    /// Access-Accept / Reject. To force-require, inspect the reply
    /// attributes yourself.)
    MessageAuthenticatorInvalid,
    /// The client was dropped while a request was in flight.
    Cancelled,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Timeout => write!(f, "no reply within retry budget"),
            Self::InFlightLimit => write!(f, "per-peer in-flight limit reached"),
            Self::IdentifierExhausted => {
                write!(f, "every RADIUS Identifier value is in flight to this peer")
            }
            Self::UnexpectedReplyCode(c) => write!(f, "unexpected reply code {}", c.0),
            Self::AuthenticatorMismatch => write!(f, "reply Response Authenticator failed"),
            Self::MessageAuthenticatorInvalid => {
                write!(f, "reply Message-Authenticator failed to verify")
            }
            Self::Cancelled => write!(f, "client dropped before reply arrived"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Codec(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CodecError> for ClientError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

/// Reply payload delivered by the reader task. Carries the full
/// datagram so the validator can run authenticator checks against
/// exactly the bytes the peer sent.
struct RawReply {
    datagram: Vec<u8>,
}

struct Inflight {
    reply_tx: oneshot::Sender<RawReply>,
}

#[derive(Default)]
struct PeerState {
    inflight: HashMap<u8, Inflight>,
    next_identifier: u8,
}

impl PeerState {
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

/// Bound UDP originator for RADIUS Access-Request exchanges.
///
/// One instance owns one socket and one background reader task.
/// Share it across the application by value (it is internally
/// reference-counted via [`Arc`] on its socket and state).
pub struct RadiusClient {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    semaphores: Arc<Mutex<HashMap<SocketAddr, Arc<Semaphore>>>>,
    retry: RetryPolicy,
    reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for RadiusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadiusClient")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl RadiusClient {
    /// Bind a fresh UDP socket on `local_addr` with the default
    /// [`RetryPolicy`]. Use `0.0.0.0:0` (or `[::]:0`) to let the OS
    /// pick the ephemeral source port.
    ///
    /// # Errors
    ///
    /// Forwards any I/O error from [`UdpSocket::bind`].
    pub async fn bind(local_addr: SocketAddr) -> io::Result<Self> {
        Self::bind_with(local_addr, RetryPolicy::default()).await
    }

    /// Bind a fresh UDP socket with a caller-supplied retry policy.
    ///
    /// # Errors
    ///
    /// Forwards any I/O error from [`UdpSocket::bind`].
    pub async fn bind_with(local_addr: SocketAddr, retry: RetryPolicy) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local_addr).await?);
        let state: Arc<Mutex<HashMap<SocketAddr, PeerState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let reader = tokio::spawn(reader_loop(Arc::clone(&socket), Arc::clone(&state)));
        Ok(Self {
            socket,
            state,
            semaphores: Arc::new(Mutex::new(HashMap::new())),
            retry,
            reader,
        })
    }

    /// Local address the bound socket is listening on.
    ///
    /// # Errors
    ///
    /// Forwards [`UdpSocket::local_addr`].
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send an `Access-Request` to `peer` and await
    /// `Access-Accept` / `Reject` / `Challenge`.
    ///
    /// `secret` is the shared secret with the peer. `build` is
    /// invoked with an empty [`PacketBuffer`] (just the header) and
    /// the freshly-drawn 16-byte Request Authenticator: append
    /// attributes like `User-Name`, `NAS-IP-Address`, and — for
    /// PAP — a `User-Password` whose plaintext is obfuscated via
    /// [`crate::user_password_encrypt`] keyed on the same
    /// authenticator. The client seals the packet
    /// (`Message-Authenticator` + Authenticator field) on its way
    /// out.
    ///
    /// # Errors
    ///
    /// See [`ClientError`].
    pub async fn access_request<F>(
        &self,
        peer: SocketAddr,
        secret: &[u8],
        build: F,
    ) -> Result<AccessOutcome, ClientError>
    where
        F: FnOnce(&mut PacketBuffer, &[u8; 16]) -> Result<(), CodecError>,
    {
        // Per-peer rate limit.
        let sem = self.semaphore_for(peer).await;
        let _permit = sem
            .try_acquire_owned()
            .map_err(|_| ClientError::InFlightLimit)?;

        let request_authenticator = authenticator::random_request_authenticator();

        // Allocate Identifier + register the in-flight slot before
        // touching the wire, so a reply that races our send still
        // finds a waiter.
        let (identifier, reply_rx) = {
            let mut all = self.state.lock().await;
            let slot = all.entry(peer).or_default();
            let identifier = slot
                .find_free_identifier()
                .ok_or(ClientError::IdentifierExhausted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            slot.inflight.insert(identifier, Inflight { reply_tx });
            (identifier, reply_rx)
        };

        // Build + seal. On any failure here we still need to drop
        // the registered slot — wrap in a closure-style flow so the
        // `reclaim` below always runs.
        let bytes = match build_and_seal(
            identifier,
            &request_authenticator,
            secret,
            build,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.reclaim(peer, identifier).await;
                return Err(e);
            }
        };

        let outcome = send_and_await(&self.socket, peer, &bytes, reply_rx, &self.retry).await;
        self.reclaim(peer, identifier).await;

        let raw = outcome?;
        classify(&raw.datagram, &request_authenticator, secret)
    }

    async fn reclaim(&self, peer: SocketAddr, identifier: u8) {
        let mut all = self.state.lock().await;
        if let Some(slot) = all.get_mut(&peer) {
            slot.inflight.remove(&identifier);
        }
    }

    async fn semaphore_for(&self, peer: SocketAddr) -> Arc<Semaphore> {
        let mut map = self.semaphores.lock().await;
        Arc::clone(
            map.entry(peer)
                .or_insert_with(|| Arc::new(Semaphore::new(self.retry.max_in_flight_per_peer))),
        )
    }
}

impl Drop for RadiusClient {
    fn drop(&mut self) {
        // Stop the reader. Pending oneshot senders drop with it;
        // any in-flight waiter sees `ClientError::Cancelled`.
        self.reader.abort();
    }
}

fn build_and_seal<F>(
    identifier: u8,
    request_authenticator: &[u8; 16],
    secret: &[u8],
    build: F,
) -> Result<Vec<u8>, ClientError>
where
    F: FnOnce(&mut PacketBuffer, &[u8; 16]) -> Result<(), CodecError>,
{
    let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, identifier);
    build(&mut buf, request_authenticator)?;
    let sealed = buf.seal_as_random_authenticator_request(request_authenticator, secret)?;
    Ok(sealed.as_bytes().to_vec())
}

async fn send_and_await(
    socket: &UdpSocket,
    peer: SocketAddr,
    bytes: &[u8],
    mut reply_rx: oneshot::Receiver<RawReply>,
    retry: &RetryPolicy,
) -> Result<RawReply, ClientError> {
    let mut wait = retry.initial_timeout;
    let attempts = retry.max_attempts.max(1);
    for attempt in 0..attempts {
        socket.send_to(bytes, peer).await?;
        match timeout(wait, &mut reply_rx).await {
            Ok(Ok(reply)) => return Ok(reply),
            Ok(Err(_)) => return Err(ClientError::Cancelled),
            Err(_) => {
                if attempt + 1 < attempts {
                    wait = wait.saturating_mul(retry.backoff_multiplier.max(1));
                }
            }
        }
    }
    Err(ClientError::Timeout)
}

fn classify(
    datagram: &[u8],
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> Result<AccessOutcome, ClientError> {
    let (header, attrs) =
        Header::parse(datagram).map_err(|_| ClientError::AuthenticatorMismatch)?;

    if !authenticator::verify_response(datagram, request_authenticator, secret) {
        return Err(ClientError::AuthenticatorMismatch);
    }

    // RFC 3579 §3.2: if M-A is present on the reply it MUST verify;
    // absence is allowed for Access-Accept / Reject from servers
    // that don't emit it.
    match message_authenticator::verify(datagram, request_authenticator, secret) {
        Verification::Valid | Verification::Absent => {}
        Verification::Invalid => return Err(ClientError::MessageAuthenticatorInvalid),
    }

    let attrs = attrs.to_vec();
    match header.code {
        Code::ACCESS_ACCEPT => Ok(AccessOutcome::Accept {
            authenticator: *request_authenticator,
            attributes: attrs,
        }),
        Code::ACCESS_REJECT => Ok(AccessOutcome::Reject {
            authenticator: *request_authenticator,
            attributes: attrs,
        }),
        Code::ACCESS_CHALLENGE => Ok(AccessOutcome::Challenge {
            authenticator: *request_authenticator,
            attributes: attrs,
        }),
        other => Err(ClientError::UnexpectedReplyCode(other)),
    }
}

async fn reader_loop(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_defaults_are_rfc_5080() {
        let p = RetryPolicy::default();
        assert_eq!(p.initial_timeout, Duration::from_secs(1));
        assert_eq!(p.max_attempts, 3);
        assert_eq!(p.backoff_multiplier, 2);
        assert_eq!(p.max_in_flight_per_peer, 16);
    }

    #[test]
    fn error_display_covers_every_variant() {
        use std::error::Error as _;
        for e in [
            ClientError::Timeout,
            ClientError::InFlightLimit,
            ClientError::IdentifierExhausted,
            ClientError::UnexpectedReplyCode(Code::ACCESS_REQUEST),
            ClientError::AuthenticatorMismatch,
            ClientError::MessageAuthenticatorInvalid,
            ClientError::Cancelled,
        ] {
            assert!(!e.to_string().is_empty());
        }
        // Wrapped IO error surfaces its inner cause.
        let io_err = io::Error::other("boom");
        let wrapped = ClientError::Io(io_err);
        assert!(wrapped.to_string().starts_with("i/o: "));
        assert!(wrapped.source().is_some());
    }

    #[test]
    fn peer_state_walks_identifier_space() {
        let mut s = PeerState::default();
        let (tx, _rx) = oneshot::channel();
        s.inflight.insert(0, Inflight { reply_tx: tx });
        // First free is 1, not 0.
        assert_eq!(s.find_free_identifier(), Some(1));
        // Counter advances past the returned id.
        assert_eq!(s.find_free_identifier(), Some(2));
    }

    #[test]
    fn peer_state_returns_none_when_full() {
        let mut s = PeerState::default();
        for id in 0u8..=255 {
            let (tx, _rx) = oneshot::channel();
            s.inflight.insert(id, Inflight { reply_tx: tx });
        }
        assert_eq!(s.find_free_identifier(), None);
    }

    // End-to-end round-trip against a hand-rolled mock peer that
    // verifies the request and replies Access-Accept. Exercises
    // sealing, correlation, the Response-Authenticator check, and
    // the optional Message-Authenticator on the reply.
    #[tokio::test]
    async fn access_request_round_trip_accept() {
        use crate::codec::encode::Reply;
        let secret: &[u8] = b"shared";

        // Mock peer.
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();

        let peer = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_LEN];
            let (n, src) = peer_sock.recv_from(&mut buf).await.unwrap();
            let req = &buf[..n];
            let (header, _) = Header::parse(req).unwrap();
            let mut req_auth = [0u8; 16];
            req_auth.copy_from_slice(&req[4..20]);
            // Verify Message-Authenticator over the request.
            assert_eq!(
                message_authenticator::verify(req, &req_auth, secret),
                Verification::Valid
            );

            let mut reply = Reply::new(Code::ACCESS_ACCEPT, header.identifier);
            reply.add_attribute(1, b"alice").unwrap();
            let sealed = reply.seal_for(&req_auth, secret);
            peer_sock.send_to(sealed.as_bytes(), src).await.unwrap();
        });

        let client = RadiusClient::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let outcome = client
            .access_request(peer_addr, secret, |buf, _req_auth| {
                buf.add_attribute(1, b"alice")?;
                Ok(())
            })
            .await
            .unwrap();

        match outcome {
            AccessOutcome::Accept { attributes, .. } => {
                let user_name = crate::attributes::iter(&attributes)
                    .filter_map(Result::ok)
                    .find(|a| a.attribute_type() == 1)
                    .expect("User-Name attribute in reply");
                assert_eq!(user_name.value(), b"alice");
            }
            other => panic!("expected Accept, got {other:?}"),
        }
        peer.await.unwrap();
    }

    // Mock peer drops the request -> client must surface a timeout
    // once the retry budget is exhausted.
    #[tokio::test]
    async fn access_request_times_out_when_peer_silent() {
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        // Drop the socket promptly (after a short delay so the
        // client's first packet has somewhere to go and we don't
        // race the ICMP unreachable).
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(peer_sock);
        });

        let client = RadiusClient::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            RetryPolicy {
                initial_timeout: Duration::from_millis(20),
                max_attempts: 2,
                backoff_multiplier: 1,
                max_in_flight_per_peer: 4,
            },
        )
        .await
        .unwrap();
        let err = client
            .access_request(peer_addr, b"s", |_, _| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Timeout));
    }

    // Mock peer replies with the wrong code -> classify rejects it.
    #[tokio::test]
    async fn access_request_rejects_unexpected_reply_code() {
        use crate::codec::encode::Reply;
        let secret: &[u8] = b"s";
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_LEN];
            let (n, src) = peer_sock.recv_from(&mut buf).await.unwrap();
            let req = &buf[..n];
            let (header, _) = Header::parse(req).unwrap();
            let mut req_auth = [0u8; 16];
            req_auth.copy_from_slice(&req[4..20]);
            // Wrong code: CoA-ACK is not a valid reply to Access-Request.
            let reply = Reply::new(Code::COA_ACK, header.identifier);
            let sealed = reply.seal_for(&req_auth, secret);
            peer_sock.send_to(sealed.as_bytes(), src).await.unwrap();
        });
        let client = RadiusClient::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let err = client
            .access_request(peer_addr, secret, |_, _| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::UnexpectedReplyCode(_)));
    }
}
