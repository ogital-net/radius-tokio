//! EAP-MSCHAPv2 server state machine
//! (`draft-kamath-pppext-eap-mschapv2`, building on RFC 2759).
//!
//! Two consumers share this module:
//!
//! * [`crate::mschapv2::MsChapV2Server`] / [`crate::mschapv2::MsChapV2Factory`] — [`crate::inner::InnerEap`] driver
//!   used as the inner method inside a TLS tunnel (PEAP or
//!   EAP-TTLS). Feature: `peap`.
//! * [`crate::mschapv2::EapMsChapV2`] / [`crate::mschapv2::EapMsChapV2Factory`] — [`EapMethod`]
//!   driver for bare/native EAP-MSCHAPv2 over the wire (EAP type
//!   26, no outer TLS), targeting legacy wired 802.1X.
//!   Feature: `eap-mschapv2`.
//!
//! # Security caveats for bare/native EAP-MSCHAPv2
//!
//! Bare EAP-MSCHAPv2 leaks the username in cleartext and lets a
//! passive attacker capture the `(auth_challenge, peer_challenge,
//! NT-Response)` tuple for an offline NT-hash dictionary attack
//! (RFC 7457 §2, NIST SP 800-63B 4.2.1). It is therefore unfit
//! for any deployment where the link is not already trusted — use
//! PEAP, EAP-TTLS, or EAP-TLS for WPA2/3 Enterprise. The bare
//! variant is provided here only for legacy wired 802.1X
//! interoperability with switches and supplicants that still ship
//! it as the default.
//!
//! No MSK is derived (RFC 3079 GetMasterKey is not yet wired in);
//! the handler emits `EAP-Success` with no `MS-MPPE-{Send,Recv}-Key`
//! attributes, so the native driver is limited to wired
//! `key_mgmt=IEEE8021X` flows.
//!
//! # Wire format
//!
//! Inside a single [`radius_tokio::eap::Type::MSCHAPV2`] EAP type-data payload:
//!
//! ```text
//!   0       1       2 .. 3       4 ..
//!   +-------+-------+-----------+----
//!   |opcode |ms-id  | ms-length | body
//!   +-------+-------+-----------+----
//! ```
//!
//! * `opcode` — 1=Challenge, 2=Response, 3=Success, 4=Failure
//! * `ms-id` — MSCHAPv2 identifier (independent of the EAP id)
//! * `ms-length` — total length of the type-data including these
//!   first 4 bytes
//! * `body` — opcode-specific (see RFC 2759 §6)
//!
//! Ack packets for Success / Failure carry only the bare opcode
//! byte and omit the length header.
//!
//! # State machine — inner (PEAP / TTLS)
//!
//! ```text
//!   Init ── start() ──▶ EAP-Request/Identity
//!         ◀── EAP-Response/Identity ──
//!   AwaitingChallengeResponse
//!         ── EAP-Request/MSCHAPv2(Challenge) ──▶
//!         ◀── EAP-Response/MSCHAPv2(Response) ──
//!   AwaitingSuccessAck
//!         ── EAP-Request/MSCHAPv2(Success) ──▶
//!         ◀── EAP-Response/MSCHAPv2(Success-ack) ──
//!   Done(Success)        // → InnerOutcome::Success
//! ```
//!
//! # State machine — native ([`crate::mschapv2::EapMsChapV2`])
//!
//! Identity is owned by [`crate::handler::EapHandler`], so the
//! native driver skips the Identity round and begins at the
//! Challenge:
//!
//! ```text
//!   Init ── start() ──▶ MSCHAPv2(Challenge) type-data
//!         ◀── MSCHAPv2(Response) type-data ──
//!   AwaitingSuccessAck or AwaitingFailureAck
//!         ── MSCHAPv2(Success | Failure) type-data ──▶
//!         ◀── MSCHAPv2(ack) type-data ──
//!   Done(Success | Failure)
//! ```
//!
//! On a bad password the server emits `MSCHAPv2(Failure)` and
//! waits for the peer's Failure-ack before returning the failure
//! outcome.

use std::sync::Arc;

use radius_tokio::auth::mschap::{self, MsChapSecret};
use radius_tokio::eap::Type as EapType;
#[cfg(feature = "peap")]
use radius_tokio::eap::{self, Code as EapCode, Packet as EapPacket};
use radius_tokio::rand;

#[cfg(feature = "peap")]
use crate::inner::{InnerEap, InnerFactory, InnerOutcome};
#[cfg(feature = "eap-mschapv2")]
use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::Error;

const OP_CHALLENGE: u8 = 1;
const OP_RESPONSE: u8 = 2;
const OP_SUCCESS: u8 = 3;
const OP_FAILURE: u8 = 4;

/// Default `Name` field embedded in the `MSCHAPv2` Challenge — purely
/// informational, the peer doesn't authenticate it.
pub const DEFAULT_SERVER_NAME: &[u8] = b"radius-tokio";

/// Credential lookup hook used by [`MsChapV2Server`].
///
/// The server calls [`Credentials::lookup`] once it has the
/// EAP-Identity username, then compares the recomputed NT-Response
/// against the wire value in constant time. The store returns the
/// cleartext password (or NT hash — both are accepted via
/// [`MsChapSecret`]). Returning `None` triggers an inner
/// EAP-Failure.
///
/// `Arc<C>` is shared across every PEAP session the listener
/// accepts.
pub trait Credentials: Send + Sync + 'static {
    /// Resolve `username` to the credential the server will use
    /// to compute the expected NT-Response. Returns `None` for an
    /// unknown user.
    ///
    /// The returned future is `Send` so the EAP driver can `.await`
    /// it across runtime boundaries (e.g. while talking to a
    /// database or LDAP backend).
    fn lookup<'a>(
        &'a self,
        username: &'a [u8],
    ) -> impl std::future::Future<Output = Option<CredentialSecret>> + Send + 'a;
}

/// Cleartext-or-NT-hash secret returned from [`Credentials::lookup`].
///
/// Owning variant of [`MsChapSecret`] so credential stores that
/// fetch from a backend can hand back owned bytes without
/// borrowing.
pub enum CredentialSecret {
    /// UTF-8 cleartext password; the server NT-hashes it.
    Cleartext(String),
    /// Pre-computed 16-byte MD4 NT hash (`MD4(UTF-16LE(password))`).
    NtHash([u8; 16]),
}

impl CredentialSecret {
    fn as_mschap(&self) -> MsChapSecret<'_> {
        match self {
            Self::Cleartext(s) => MsChapSecret::Cleartext(s.as_str()),
            Self::NtHash(h) => MsChapSecret::NtHash(h),
        }
    }
}

/// In-memory single-user credential store. Useful for tests and
/// trivial deployments; production callers should plug in a real
/// backend via [`Credentials`].
pub struct StaticCredentials {
    username: Vec<u8>,
    secret: CredentialSecret,
}

impl StaticCredentials {
    /// Build a store that returns `password` for the single user
    /// `username` and `None` for everyone else.
    #[must_use]
    pub fn cleartext(username: impl Into<Vec<u8>>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            secret: CredentialSecret::Cleartext(password.into()),
        }
    }

    /// Build a store seeded with a precomputed NT hash.
    #[must_use]
    pub fn nt_hash(username: impl Into<Vec<u8>>, hash: [u8; 16]) -> Self {
        Self {
            username: username.into(),
            secret: CredentialSecret::NtHash(hash),
        }
    }
}

impl Credentials for StaticCredentials {
    async fn lookup(&self, username: &[u8]) -> Option<CredentialSecret> {
        if username == self.username.as_slice() {
            Some(match &self.secret {
                CredentialSecret::Cleartext(s) => CredentialSecret::Cleartext(s.clone()),
                CredentialSecret::NtHash(h) => CredentialSecret::NtHash(*h),
            })
        } else {
            None
        }
    }
}

#[cfg(feature = "peap")]
#[allow(clippy::enum_variant_names)] // every variant *is* an awaiting state.
enum State {
    /// Sent `EAP-Request/Identity`, waiting for response.
    AwaitingIdentity,
    /// Sent `EAP-Request/MSCHAPv2(Challenge)`, waiting for Response.
    AwaitingChallengeResponse {
        username: Vec<u8>,
        auth_challenge: [u8; 16],
    },
    /// Sent `EAP-Request/MSCHAPv2(Success)`, waiting for Success-ack.
    AwaitingSuccessAck,
    /// Sent `EAP-Request/MSCHAPv2(Failure)`, waiting for Failure-ack.
    AwaitingFailureAck,
}

/// EAP-MSCHAPv2 server state machine.
///
/// Build one per session via [`MsChapV2Factory`]. Identifiers are
/// allocated internally: the EAP id starts at `1` and increments
/// by one on each server-issued request; the `MSCHAPv2` id mirrors
/// the EAP id.
#[cfg(feature = "peap")]
pub struct MsChapV2Server<C: Credentials> {
    creds: Arc<C>,
    server_name: Vec<u8>,
    state: State,
    eap_id: u8,
}

#[cfg(feature = "peap")]
impl<C: Credentials> MsChapV2Server<C> {
    /// Build a fresh server state machine with the conventional
    /// [`DEFAULT_SERVER_NAME`].
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self::with_server_name(creds, DEFAULT_SERVER_NAME.to_vec())
    }

    /// Build a server state machine with a custom server name.
    #[must_use]
    pub fn with_server_name(creds: Arc<C>, server_name: Vec<u8>) -> Self {
        Self {
            creds,
            server_name,
            state: State::AwaitingIdentity,
            eap_id: 1,
        }
    }

    fn next_id(&mut self) -> u8 {
        let id = self.eap_id;
        self.eap_id = self.eap_id.wrapping_add(1);
        id
    }
}

#[cfg(feature = "peap")]
#[allow(clippy::manual_async_fn)] // explicit `+ Send` bound on the RPITIT future
impl<C: Credentials> InnerEap for MsChapV2Server<C> {
    fn start(&mut self) -> impl std::future::Future<Output = Result<Vec<u8>, Error>> + Send + '_ {
        async move {
            // Inner EAP-Request/Identity. RFC 3748 §5.1 says the
            // Type-Data may carry a UTF-8 prompt; we leave it empty —
            // wpa_supplicant ignores the prompt either way.
            let id = self.next_id();
            let mut out = Vec::with_capacity(5);
            eap::write_request(&mut out, id, EapType::IDENTITY, &[]).map_err(Error::Eap)?;
            Ok(out)
        }
    }

    fn step<'a>(
        &'a mut self,
        peer_packet: &'a [u8],
    ) -> impl std::future::Future<Output = Result<InnerOutcome, Error>> + Send + 'a {
        async move {
            let pkt = EapPacket::parse(peer_packet).map_err(Error::Eap)?;
            if pkt.code() != EapCode::RESPONSE {
                return Err(Error::Framing("inner EAP packet was not a Response"));
            }

            match (&self.state, pkt.typ()) {
                (State::AwaitingIdentity, Some(EapType::IDENTITY)) => {
                    let username = pkt.type_data().to_vec();
                    let mut auth_challenge = [0u8; 16];
                    rand::fill_secure(&mut auth_challenge);
                    let ms_id = self.eap_id; // mschap id mirrors next eap id
                    let eap_id = self.next_id();
                    let frame = build_challenge(eap_id, ms_id, &auth_challenge, &self.server_name);
                    self.state = State::AwaitingChallengeResponse {
                        username,
                        auth_challenge,
                    };
                    Ok(InnerOutcome::Continue(frame))
                }
                (
                    State::AwaitingChallengeResponse {
                        username,
                        auth_challenge,
                    },
                    Some(EapType::MSCHAPV2),
                ) => {
                    let type_data = pkt.type_data();
                    let op = type_data
                        .first()
                        .copied()
                        .ok_or(Error::Framing("MSCHAPv2 Response missing opcode byte"))?;
                    if op != OP_RESPONSE {
                        return Err(Error::Framing("expected MSCHAPv2 opcode 2 (Response)"));
                    }
                    // body starts after opcode+id+length (4 bytes)
                    let body = type_data
                        .get(4..)
                        .ok_or(Error::Framing("MSCHAPv2 Response truncated"))?;
                    let resp = parse_response_body(body)
                        .ok_or(Error::Framing("MSCHAPv2 Response body malformed"))?;

                    let Some(secret) = self.creds.lookup(username).await else {
                        let ms_id = self.eap_id;
                        let eap_id = self.next_id();
                        let frame = build_failure(eap_id, ms_id);
                        self.state = State::AwaitingFailureAck;
                        return Ok(InnerOutcome::Continue(frame));
                    };

                    let expected = mschap::v2_nt_response(
                        auth_challenge,
                        &resp.peer_challenge,
                        username,
                        secret.as_mschap(),
                    );
                    if expected != resp.nt_response {
                        let ms_id = self.eap_id;
                        let eap_id = self.next_id();
                        let frame = build_failure(eap_id, ms_id);
                        self.state = State::AwaitingFailureAck;
                        return Ok(InnerOutcome::Continue(frame));
                    }

                    let auth_resp = mschap::v2_authenticator_response(
                        auth_challenge,
                        &resp.peer_challenge,
                        &resp.nt_response,
                        username,
                        secret.as_mschap(),
                    );
                    let ms_id = self.eap_id;
                    let eap_id = self.next_id();
                    let frame = build_success(eap_id, ms_id, &auth_resp);
                    self.state = State::AwaitingSuccessAck;
                    Ok(InnerOutcome::Continue(frame))
                }
                (State::AwaitingSuccessAck, Some(EapType::MSCHAPV2)) => {
                    let op = pkt
                        .type_data()
                        .first()
                        .copied()
                        .ok_or(Error::Framing("MSCHAPv2 ack missing opcode byte"))?;
                    if op == OP_SUCCESS {
                        Ok(InnerOutcome::Success)
                    } else {
                        Ok(InnerOutcome::Failure)
                    }
                }
                (State::AwaitingFailureAck, Some(EapType::MSCHAPV2)) => {
                    // Peer must ack the failure (or send a Change-Password
                    // request, which we don't support). Either way the
                    // outcome is the same.
                    Ok(InnerOutcome::Failure)
                }
                _ => Err(Error::Framing(
                    "unexpected inner EAP type for MSCHAPv2 state",
                )),
            }
        }
    }
}

/// Factory producing fresh [`MsChapV2Server`] instances per PEAP
/// session. Holds the shared [`Credentials`] store behind an
/// [`Arc`].
#[cfg(feature = "peap")]
pub struct MsChapV2Factory<C: Credentials> {
    creds: Arc<C>,
    server_name: Vec<u8>,
}

#[cfg(feature = "peap")]
impl<C: Credentials> MsChapV2Factory<C> {
    /// Build a factory using [`DEFAULT_SERVER_NAME`].
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self {
            creds,
            server_name: DEFAULT_SERVER_NAME.to_vec(),
        }
    }

    /// Override the `MSCHAPv2` Challenge `Name` field.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.server_name = name.into();
        self
    }
}

#[cfg(feature = "peap")]
impl<C: Credentials> InnerFactory for MsChapV2Factory<C> {
    type Inner = MsChapV2Server<C>;

    fn create(&self) -> Result<Self::Inner, Error> {
        Ok(MsChapV2Server::with_server_name(
            Arc::clone(&self.creds),
            self.server_name.clone(),
        ))
    }
}

// ── Codec helpers ────────────────────────────────────────────────────────
//
// The type-data builders below produce the bytes that sit after
// the EAP `Code | Identifier | Length | Type` header — i.e. what an
// [`EapMethod`] driver hands back from `start`/`step`. The full
// EAP-packet builders (`build_challenge` and friends) used by the
// PEAP/TTLS [`InnerEap`] path are thin wrappers that prefix the
// EAP header.

struct ResponseFields {
    peer_challenge: [u8; 16],
    nt_response: [u8; 24],
}

fn parse_response_body(body: &[u8]) -> Option<ResponseFields> {
    // value-size(1)=49, peer-challenge(16), reserved(8),
    // NT-resp(24), flags(1), name(...)
    if body.len() < 1 + 49 {
        return None;
    }
    if body[0] != 49 {
        return None;
    }
    let mut peer = [0u8; 16];
    peer.copy_from_slice(&body[1..17]);
    let mut nt = [0u8; 24];
    nt.copy_from_slice(&body[25..49]);
    Some(ResponseFields {
        peer_challenge: peer,
        nt_response: nt,
    })
}

/// Build the `MSCHAPv2(Challenge)` type-data: `opcode | ms-id |
/// ms-length | value-size(1)=16 | challenge(16) | name(*)`.
fn build_challenge_type_data(ms_id: u8, challenge: &[u8; 16], name: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 16 + name.len());
    body.push(16);
    body.extend_from_slice(challenge);
    body.extend_from_slice(name);
    build_envelope_type_data(ms_id, OP_CHALLENGE, &body)
}

/// Build the `MSCHAPv2(Success)` type-data: opcode | ms-id |
/// ms-length | `"S=<40hex>"` (42 bytes).
fn build_success_type_data(ms_id: u8, auth_resp: &[u8; 42]) -> Vec<u8> {
    build_envelope_type_data(ms_id, OP_SUCCESS, auth_resp)
}

/// Build the `MSCHAPv2(Failure)` type-data with an empty body.
fn build_failure_type_data(ms_id: u8) -> Vec<u8> {
    // RFC 2759 §6.4 allows an "E=..." ASCII error string;
    // wpa_supplicant treats either way as a hard reject so we
    // send an empty body.
    build_envelope_type_data(ms_id, OP_FAILURE, &[])
}

/// Wrap `body` in the shared `MSCHAPv2` envelope (`opcode | ms-id
/// | ms-length | body`). `ms-length` covers the 4-byte header
/// plus `body`.
fn build_envelope_type_data(ms_id: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
    let ms_len = 4 + body.len();
    let mut type_data = Vec::with_capacity(ms_len);
    type_data.push(opcode);
    type_data.push(ms_id);
    type_data.extend_from_slice(&u16::try_from(ms_len).unwrap_or(u16::MAX).to_be_bytes());
    type_data.extend_from_slice(body);
    type_data
}

#[cfg(feature = "peap")]
fn build_challenge(eap_id: u8, ms_id: u8, challenge: &[u8; 16], name: &[u8]) -> Vec<u8> {
    wrap_in_eap_request(eap_id, &build_challenge_type_data(ms_id, challenge, name))
}

#[cfg(feature = "peap")]
fn build_success(eap_id: u8, ms_id: u8, auth_resp: &[u8; 42]) -> Vec<u8> {
    wrap_in_eap_request(eap_id, &build_success_type_data(ms_id, auth_resp))
}

#[cfg(feature = "peap")]
fn build_failure(eap_id: u8, ms_id: u8) -> Vec<u8> {
    wrap_in_eap_request(eap_id, &build_failure_type_data(ms_id))
}

#[cfg(feature = "peap")]
fn wrap_in_eap_request(eap_id: u8, type_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + type_data.len());
    eap::write_request(&mut out, eap_id, EapType::MSCHAPV2, type_data)
        .expect("MSCHAPv2 envelope fits in u16");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_body_round_trip() {
        let mut body = vec![49u8];
        body.extend_from_slice(&[0xAA; 16]); // peer challenge
        body.extend_from_slice(&[0u8; 8]); // reserved
        body.extend_from_slice(&[0xBB; 24]); // NT response
        body.push(0); // flags
        let parsed = parse_response_body(&body).expect("parses");
        assert_eq!(parsed.peer_challenge, [0xAA; 16]);
        assert_eq!(parsed.nt_response, [0xBB; 24]);
    }

    #[test]
    fn parse_response_body_rejects_short() {
        assert!(parse_response_body(&[49u8; 10]).is_none());
    }

    #[test]
    fn parse_response_body_rejects_bad_size() {
        let mut body = vec![48u8]; // wrong value-size
        body.extend_from_slice(&[0u8; 49]);
        assert!(parse_response_body(&body).is_none());
    }

    #[test]
    #[cfg(feature = "peap")]
    fn build_challenge_round_trips_through_eap_parser() {
        let chal = [0xCC; 16];
        let bytes = build_challenge(7, 7, &chal, b"server");
        let pkt = EapPacket::parse(&bytes).expect("parses");
        assert_eq!(pkt.code(), EapCode::REQUEST);
        assert_eq!(pkt.identifier(), 7);
        assert_eq!(pkt.typ(), Some(EapType::MSCHAPV2));
        let td = pkt.type_data();
        assert_eq!(td[0], OP_CHALLENGE);
        assert_eq!(td[1], 7);
        assert_eq!(td[4], 16);
        assert_eq!(&td[5..21], &chal[..]);
        assert_eq!(&td[21..], b"server");
    }

    #[test]
    #[cfg(feature = "peap")]
    fn build_failure_minimal_body() {
        let bytes = build_failure(3, 3);
        let pkt = EapPacket::parse(&bytes).expect("parses");
        assert_eq!(pkt.typ(), Some(EapType::MSCHAPV2));
        assert_eq!(pkt.type_data(), &[OP_FAILURE, 3, 0, 4]);
    }
}

// ── Native (bare) EAP-MSCHAPv2 ───────────────────────────────────────────
//
// The outer `EapHandler` already owns identity capture and EAP-id
// allocation, so the native driver works in type-data only and
// skips the inner-EAP Identity round.

#[cfg(feature = "eap-mschapv2")]
enum NativeState {
    /// Before [`start`] has been called.
    Init,
    /// Sent `MSCHAPv2(Challenge)`, waiting for the peer's Response.
    AwaitingResponse { auth_challenge: [u8; 16], ms_id: u8 },
    /// Sent `MSCHAPv2(Success)`, waiting for the peer's Success-ack.
    AwaitingSuccessAck,
    /// Sent `MSCHAPv2(Failure)`, waiting for the peer's Failure-ack.
    AwaitingFailureAck,
}

/// Native (bare) EAP-MSCHAPv2 server state machine — EAP type 26
/// over the wire with no outer TLS, targeting legacy wired 802.1X.
///
/// Build one per session via [`EapMsChapV2Factory`]. The peer
/// identity is captured by [`crate::handler::EapHandler`] from
/// `EAP-Response/Identity` and pushed into this state machine via
/// [`EapMethod::notify_peer_identity`] right before `start()`.
///
/// See the [module docs](self) for the security caveats that apply
/// to the bare variant.
#[cfg(feature = "eap-mschapv2")]
pub struct EapMsChapV2<C: Credentials> {
    creds: Arc<C>,
    server_name: Vec<u8>,
    username: Vec<u8>,
    state: NativeState,
}

#[cfg(feature = "eap-mschapv2")]
impl<C: Credentials> EapMsChapV2<C> {
    /// Build a fresh per-session state machine using the
    /// conventional [`DEFAULT_SERVER_NAME`] in the Challenge.
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self::with_server_name(creds, DEFAULT_SERVER_NAME.to_vec())
    }

    /// Build a fresh per-session state machine with a custom
    /// `Name` field in the Challenge.
    #[must_use]
    pub fn with_server_name(creds: Arc<C>, server_name: Vec<u8>) -> Self {
        Self {
            creds,
            server_name,
            username: Vec::new(),
            state: NativeState::Init,
        }
    }
}

#[cfg(feature = "eap-mschapv2")]
impl<C: Credentials> EapMethod for EapMsChapV2<C> {
    fn typ(&self) -> EapType {
        EapType::MSCHAPV2
    }

    fn notify_peer_identity(&mut self, identity: &[u8]) {
        if self.username.is_empty() {
            self.username = identity.to_vec();
        }
    }

    fn start(&mut self) -> crate::method::MethodFuture<'_> {
        Box::pin(async move {
            if !matches!(self.state, NativeState::Init) {
                return Err(Error::Framing("EAP-MSCHAPv2 start called after start"));
            }
            let mut auth_challenge = [0u8; 16];
            rand::fill_secure(&mut auth_challenge);
            // MSCHAPv2 id is independent of the EAP id and only needs
            // to be unguessably fresh per server message; one random
            // byte at the start, monotonically incremented, matches the
            // inner driver's convention.
            let mut ms_id_buf = [0u8; 1];
            rand::fill_secure(&mut ms_id_buf);
            let ms_id = ms_id_buf[0];
            let frame = build_challenge_type_data(ms_id, &auth_challenge, &self.server_name);
            self.state = NativeState::AwaitingResponse {
                auth_challenge,
                ms_id,
            };
            Ok(MethodOutcome::Continue(frame))
        })
    }

    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> crate::method::MethodFuture<'a> {
        Box::pin(async move {
            let op = peer_type_data
                .first()
                .copied()
                .ok_or(Error::Framing("MSCHAPv2 packet missing opcode byte"))?;
            match &self.state {
                NativeState::Init => Err(Error::Framing("EAP-MSCHAPv2 step called before start")),
                NativeState::AwaitingResponse {
                    auth_challenge,
                    ms_id,
                } => {
                    if op != OP_RESPONSE {
                        return Err(Error::Framing("expected MSCHAPv2 opcode 2 (Response)"));
                    }
                    let body = peer_type_data
                        .get(4..)
                        .ok_or(Error::Framing("MSCHAPv2 Response truncated"))?;
                    let resp = parse_response_body(body)
                        .ok_or(Error::Framing("MSCHAPv2 Response body malformed"))?;

                    let next_ms_id = ms_id.wrapping_add(1);
                    let auth_challenge = *auth_challenge;
                    let Some(secret) = self.creds.lookup(&self.username).await else {
                        let frame = build_failure_type_data(next_ms_id);
                        self.state = NativeState::AwaitingFailureAck;
                        return Ok(MethodOutcome::Continue(frame));
                    };

                    let expected = mschap::v2_nt_response(
                        &auth_challenge,
                        &resp.peer_challenge,
                        &self.username,
                        secret.as_mschap(),
                    );
                    if expected != resp.nt_response {
                        let frame = build_failure_type_data(next_ms_id);
                        self.state = NativeState::AwaitingFailureAck;
                        return Ok(MethodOutcome::Continue(frame));
                    }

                    let auth_resp = mschap::v2_authenticator_response(
                        &auth_challenge,
                        &resp.peer_challenge,
                        &resp.nt_response,
                        &self.username,
                        secret.as_mschap(),
                    );
                    let frame = build_success_type_data(next_ms_id, &auth_resp);
                    self.state = NativeState::AwaitingSuccessAck;
                    Ok(MethodOutcome::Continue(frame))
                }
                NativeState::AwaitingSuccessAck => {
                    if op == OP_SUCCESS {
                        // Bare EAP-MSCHAPv2 doesn't derive an MSK here
                        // (RFC 3079 GetMasterKey is not wired in); the
                        // handler honors empty MSK by skipping the
                        // MS-MPPE keys, restricting deployments to wired
                        // `key_mgmt=IEEE8021X` flows.
                        Ok(MethodOutcome::Success {
                            msk: Vec::new(),
                            emsk: Vec::new(),
                        })
                    } else {
                        Ok(MethodOutcome::Failure)
                    }
                }
                NativeState::AwaitingFailureAck => {
                    // Peer must ack the failure (or send a
                    // Change-Password request, which we don't support).
                    // Either way the outcome is the same.
                    Ok(MethodOutcome::Failure)
                }
            }
        })
    }
}

/// Factory producing fresh [`EapMsChapV2`] state machines per
/// session. Holds the shared [`Credentials`] store behind an
/// [`Arc`].
#[cfg(feature = "eap-mschapv2")]
pub struct EapMsChapV2Factory<C: Credentials> {
    creds: Arc<C>,
    server_name: Vec<u8>,
}

#[cfg(feature = "eap-mschapv2")]
impl<C: Credentials> EapMsChapV2Factory<C> {
    /// Build a factory using [`DEFAULT_SERVER_NAME`].
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self {
            creds,
            server_name: DEFAULT_SERVER_NAME.to_vec(),
        }
    }

    /// Override the `MSCHAPv2` Challenge `Name` field.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.server_name = name.into();
        self
    }
}

#[cfg(feature = "eap-mschapv2")]
impl<C: Credentials> MethodFactory for EapMsChapV2Factory<C> {
    type Method = EapMsChapV2<C>;

    fn create(&self) -> Result<Self::Method, Error> {
        Ok(EapMsChapV2::with_server_name(
            Arc::clone(&self.creds),
            self.server_name.clone(),
        ))
    }
}

#[cfg(all(test, feature = "eap-mschapv2"))]
mod native_tests {
    use super::*;
    use radius_tokio::auth::mschap;

    fn run_native(creds: Arc<StaticCredentials>) -> EapMsChapV2<StaticCredentials> {
        let mut m = EapMsChapV2::new(creds);
        m.notify_peer_identity(b"alice");
        m
    }

    fn parse_challenge(td: &[u8]) -> ([u8; 16], u8) {
        // opcode | ms-id | ms-len | value-size=16 | challenge(16) | name
        assert_eq!(td[0], OP_CHALLENGE);
        let ms_id = td[1];
        assert_eq!(td[4], 16);
        let mut chal = [0u8; 16];
        chal.copy_from_slice(&td[5..21]);
        (chal, ms_id)
    }

    fn build_response_type_data(ms_id: u8, peer_chal: [u8; 16], nt_resp: [u8; 24]) -> Vec<u8> {
        let mut body = Vec::with_capacity(49);
        body.push(49);
        body.extend_from_slice(&peer_chal);
        body.extend_from_slice(&[0u8; 8]); // reserved
        body.extend_from_slice(&nt_resp);
        body.push(0); // flags
        build_envelope_type_data(ms_id, OP_RESPONSE, &body)
    }

    #[tokio::test]
    async fn happy_path_succeeds_after_ack() {
        let creds = Arc::new(StaticCredentials::cleartext(b"alice".to_vec(), "hello"));
        let mut m = run_native(creds);
        let MethodOutcome::Continue(challenge_td) = m.start().await.expect("start") else {
            panic!("start did not Continue");
        };
        let (auth_chal, ms_id) = parse_challenge(&challenge_td);

        let peer_chal = [0xAB; 16];
        let nt = mschap::v2_nt_response(
            &auth_chal,
            &peer_chal,
            b"alice",
            MsChapSecret::Cleartext("hello"),
        );
        let response_td = build_response_type_data(ms_id, peer_chal, nt);
        let MethodOutcome::Continue(success_td) =
            m.step(&response_td).await.expect("step response")
        else {
            panic!("did not produce a Success request");
        };
        assert_eq!(success_td[0], OP_SUCCESS);

        // Peer acks the Success.
        let ack = [OP_SUCCESS];
        let outcome = m.step(&ack).await.expect("step ack");
        assert!(
            matches!(outcome, MethodOutcome::Success { ref msk, .. } if msk.is_empty()),
            "expected empty-MSK Success, got {outcome:?}",
        );
    }

    #[tokio::test]
    async fn wrong_password_emits_failure_then_failure_outcome() {
        let creds = Arc::new(StaticCredentials::cleartext(
            b"alice".to_vec(),
            "correct-horse",
        ));
        let mut m = run_native(creds);
        let MethodOutcome::Continue(challenge_td) = m.start().await.unwrap() else {
            unreachable!()
        };
        let (auth_chal, ms_id) = parse_challenge(&challenge_td);
        let peer_chal = [0x11; 16];
        let bad_nt = mschap::v2_nt_response(
            &auth_chal,
            &peer_chal,
            b"alice",
            MsChapSecret::Cleartext("battery-staple"),
        );
        let resp = build_response_type_data(ms_id, peer_chal, bad_nt);
        let MethodOutcome::Continue(fail_td) = m.step(&resp).await.expect("step") else {
            panic!("expected Continue with Failure type-data");
        };
        assert_eq!(fail_td[0], OP_FAILURE);
        let ack = [OP_FAILURE];
        assert!(matches!(
            m.step(&ack).await.unwrap(),
            MethodOutcome::Failure
        ));
    }

    #[tokio::test]
    async fn unknown_user_emits_failure() {
        let creds = Arc::new(StaticCredentials::cleartext(b"bob".to_vec(), "x"));
        let mut m = run_native(creds);
        let MethodOutcome::Continue(challenge_td) = m.start().await.unwrap() else {
            unreachable!()
        };
        let (_, ms_id) = parse_challenge(&challenge_td);
        let resp = build_response_type_data(ms_id, [0u8; 16], [0u8; 24]);
        let MethodOutcome::Continue(fail_td) = m.step(&resp).await.expect("step") else {
            panic!("expected Continue Failure");
        };
        assert_eq!(fail_td[0], OP_FAILURE);
    }

    #[tokio::test]
    async fn step_before_start_errors() {
        let creds = Arc::new(StaticCredentials::cleartext(b"alice".to_vec(), "x"));
        let mut m = EapMsChapV2::new(creds);
        m.notify_peer_identity(b"alice");
        assert!(m.step(&[OP_RESPONSE, 0, 0, 4]).await.is_err());
    }
}
