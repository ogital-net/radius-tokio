//! EAP-MD5-Challenge server state machine (RFC 3748 §5.4).
//!
//! EAP-MD5 is a bare, untunneled EAP method that piggybacks the PPP
//! CHAP algorithm of RFC 1994: the peer's response is
//! `MD5(eap_id || password || challenge)`, where `eap_id` is the
//! one-byte EAP `Identifier` copied from the `EAP-Request/MD5-Challenge`
//! that carried the challenge.
//!
//! # Security caveats
//!
//! EAP-MD5 provides **no** key derivation (no MSK/EMSK), no mutual
//! authentication, and no protection against offline dictionary
//! attack on a captured exchange. It is suitable for low-stakes
//! wired 802.1X deployments and as a regression target for the
//! codec; for anything WPA2/3-Enterprise use PEAP, EAP-TTLS, or
//! EAP-TLS from this crate.
//!
//! # Wire format
//!
//! The EAP type-data sits *after* the `Code | Identifier | Length
//! | Type=MD5_CHALLENGE` header:
//!
//! ```text
//!   0       1            17                ..
//!   +-------+------------+-----------------+
//!   |val-sz |  value(16) |   name (opt.)   |
//!   +-------+------------+-----------------+
//! ```
//!
//! `val-sz` MUST be `16` for the 16-byte MD5 challenge / response.
//! The trailing `name` field is informational; this implementation
//! emits no name and ignores it on the response.
//!
//! # State machine
//!
//! ```text
//!   Init ── start() ──▶ EAP-Request/MD5-Challenge(challenge)
//!         ◀── EAP-Response/MD5-Challenge(response) ──
//!   Done(Success/Failure)
//! ```
//!
//! Identity handling is owned by [`crate::handler::EapHandler`];
//! this module is only driven once the peer has produced
//! `EAP-Response/Identity`.

use std::sync::Arc;

use radius_tokio::auth::eap_md5 as primitives;
use radius_tokio::eap::Type as EapType;
use radius_tokio::rand;

use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::Error;

/// Credential lookup hook used by [`EapMd5`].
///
/// The handler hands the EAP-Identity `username` to
/// [`Credentials::lookup`] once, then this module recomputes the
/// expected MD5 response and compares in constant time. Returning
/// `None` triggers an EAP-Failure (`Access-Reject`).
///
/// Implementors typically wrap a backend store (LDAP, SQL,
/// configuration file). The trait is `Sync` because a single
/// `Arc<C>` is shared across every session the listener accepts.
pub trait Credentials: Send + Sync + 'static {
    /// Resolve `username` to the cleartext password used to derive
    /// the expected response. Returns `None` for an unknown user.
    ///
    /// The returned future is `Send` so the EAP driver can `.await`
    /// it across runtime boundaries (e.g. while talking to a
    /// database or LDAP backend).
    fn lookup<'a>(
        &'a self,
        username: &'a [u8],
    ) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send + 'a;
}

/// In-memory single-user credential store. Useful for tests and
/// trivial deployments; production callers should plug in a real
/// backend via [`Credentials`].
pub struct StaticCredentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl StaticCredentials {
    /// Build a store that returns `password` for the single user
    /// `username` and `None` for everyone else.
    #[must_use]
    pub fn cleartext(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl Credentials for StaticCredentials {
    async fn lookup<'a>(&'a self, username: &'a [u8]) -> Option<Vec<u8>> {
        if username == self.username.as_slice() {
            Some(self.password.clone())
        } else {
            None
        }
    }
}

enum State {
    /// Before [`start`] has been called.
    Init,
    /// Sent `EAP-Request/MD5-Challenge`, waiting for the response.
    /// `request_id` is the EAP `Identifier` we put on that request,
    /// captured via [`EapMethod::notify_request_id`].
    AwaitingResponse {
        challenge: [u8; primitives::RESPONSE_LEN],
        request_id: Option<u8>,
    },
}

/// EAP-MD5 server state machine.
///
/// Build one per session via [`EapMd5Factory`]. The peer identity
/// is captured by [`crate::handler::EapHandler`] from
/// `EAP-Response/Identity` and pushed into this state machine via
/// [`EapMethod::notify_peer_identity`] right before `start()`.
pub struct EapMd5<C: Credentials> {
    creds: Arc<C>,
    username: Vec<u8>,
    state: State,
}

impl<C: Credentials> EapMd5<C> {
    /// Build a fresh per-session state machine. The peer identity
    /// is recorded later via [`EapMethod::notify_peer_identity`].
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self {
            creds,
            username: Vec::new(),
            state: State::Init,
        }
    }
}

impl<C: Credentials> EapMethod for EapMd5<C> {
    fn typ(&self) -> EapType {
        EapType::MD5_CHALLENGE
    }

    fn notify_peer_identity(&mut self, identity: &[u8]) {
        // Only the first identity sticks; subsequent notifications
        // (the handler currently emits exactly one) are ignored.
        if self.username.is_empty() {
            self.username = identity.to_vec();
        }
    }

    fn start(&mut self) -> crate::method::MethodFuture<'_> {
        Box::pin(async move {
            if !matches!(self.state, State::Init) {
                return Err(Error::Framing("EAP-MD5 start called after start"));
            }
            let mut challenge = [0u8; primitives::RESPONSE_LEN];
            rand::fill_secure(&mut challenge);
            self.state = State::AwaitingResponse {
                challenge,
                request_id: None,
            };
            Ok(MethodOutcome::Continue(build_challenge_type_data(
                &challenge,
            )))
        })
    }

    fn notify_request_id(&mut self, eap_id: u8) {
        if let State::AwaitingResponse { request_id, .. } = &mut self.state {
            *request_id = Some(eap_id);
        }
    }

    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> crate::method::MethodFuture<'a> {
        Box::pin(async move {
            let State::AwaitingResponse {
                challenge,
                request_id,
            } = &self.state
            else {
                return Err(Error::Framing("EAP-MD5 step called before start"));
            };
            let challenge = *challenge;
            let request_id = request_id.ok_or(Error::Framing("EAP-MD5 missing request id"))?;

            let response = parse_response_type_data(peer_type_data)
                .ok_or(Error::Framing("EAP-MD5 response malformed"))?;

            let Some(password) = self.creds.lookup(&self.username).await else {
                return Ok(MethodOutcome::Failure);
            };

            if primitives::verify_response(request_id, &password, &challenge, &response) {
                // EAP-MD5 derives no keying material; emit Success with
                // empty MSK / EMSK. The handler honors empty MSK by
                // skipping MS-MPPE key emission.
                Ok(MethodOutcome::Success {
                    msk: Vec::new(),
                    emsk: Vec::new(),
                })
            } else {
                Ok(MethodOutcome::Failure)
            }
        })
    }
}

/// Factory producing fresh [`EapMd5`] state machines per session.
///
/// Holds the shared [`Credentials`] store behind an [`Arc`]. The
/// peer identity is pushed into each session by
/// [`crate::handler::EapHandler`] via
/// [`EapMethod::notify_peer_identity`] right before `start()`, so
/// the factory itself doesn't need to know it.
pub struct EapMd5Factory<C: Credentials> {
    creds: Arc<C>,
}

impl<C: Credentials> EapMd5Factory<C> {
    /// Build a factory against the supplied credential store.
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self { creds }
    }
}

impl<C: Credentials> MethodFactory for EapMd5Factory<C> {
    type Method = EapMd5<C>;

    fn create(&self) -> Result<Self::Method, Error> {
        Ok(EapMd5::new(Arc::clone(&self.creds)))
    }
}

// ── Wire codec helpers ───────────────────────────────────────────────────

/// Build the EAP-Request/MD5-Challenge type-data:
/// `Value-Size(1)=16 || Value(16)` (no `Name`).
fn build_challenge_type_data(challenge: &[u8; primitives::RESPONSE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + primitives::RESPONSE_LEN);
    out.push(u8::try_from(primitives::RESPONSE_LEN).expect("RESPONSE_LEN fits u8"));
    out.extend_from_slice(challenge);
    out
}

/// Parse the EAP-Response/MD5-Challenge type-data:
/// `Value-Size(1) || Value(16) || Name(*)`.
fn parse_response_type_data(body: &[u8]) -> Option<[u8; primitives::RESPONSE_LEN]> {
    if body.len() < 1 + primitives::RESPONSE_LEN {
        return None;
    }
    if body[0] != u8::try_from(primitives::RESPONSE_LEN).ok()? {
        return None;
    }
    let mut out = [0u8; primitives::RESPONSE_LEN];
    out.copy_from_slice(&body[1..=primitives::RESPONSE_LEN]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_type_data_round_trip() {
        let challenge = [0xABu8; primitives::RESPONSE_LEN];
        let buf = build_challenge_type_data(&challenge);
        assert_eq!(buf[0], 16);
        assert_eq!(&buf[1..], &challenge);
    }

    #[test]
    fn parse_response_rejects_short() {
        assert!(parse_response_type_data(&[16u8; 10]).is_none());
    }

    #[test]
    fn parse_response_rejects_bad_size() {
        let mut body = vec![15u8];
        body.extend_from_slice(&[0u8; 16]);
        assert!(parse_response_type_data(&body).is_none());
    }

    #[test]
    fn parse_response_round_trip() {
        let mut body = vec![16u8];
        body.extend_from_slice(&[0xCD; 16]);
        body.extend_from_slice(b"trailing-name-ignored");
        let parsed = parse_response_type_data(&body).expect("parses");
        assert_eq!(parsed, [0xCD; 16]);
    }

    #[tokio::test]
    async fn success_path_via_handler_calls() {
        let creds = Arc::new(StaticCredentials::cleartext(b"alice".to_vec(), b"hello"));
        let mut method = EapMd5::new(Arc::clone(&creds));
        method.notify_peer_identity(b"alice");
        let MethodOutcome::Continue(req_type_data) = method.start().await.expect("start ok") else {
            panic!("expected Continue from start()");
        };
        // simulate handler allocating id 7 for the outbound request
        method.notify_request_id(7);

        // compute the matching response
        assert_eq!(req_type_data[0], 16);
        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&req_type_data[1..17]);
        let response = primitives::challenge_response(7, b"hello", &challenge);

        let mut resp_type_data = vec![16u8];
        resp_type_data.extend_from_slice(&response);

        match method.step(&resp_type_data).await.expect("step ok") {
            MethodOutcome::Success { msk, emsk } => {
                assert!(msk.is_empty(), "EAP-MD5 derives no MSK");
                assert!(emsk.is_empty(), "EAP-MD5 derives no EMSK");
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let creds = Arc::new(StaticCredentials::cleartext(b"alice".to_vec(), b"hello"));
        let mut method = EapMd5::new(Arc::clone(&creds));
        method.notify_peer_identity(b"alice");
        let MethodOutcome::Continue(req_type_data) = method.start().await.expect("start ok") else {
            panic!("expected Continue");
        };
        method.notify_request_id(9);

        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&req_type_data[1..17]);
        let bad_response = primitives::challenge_response(9, b"wrong", &challenge);

        let mut resp_type_data = vec![16u8];
        resp_type_data.extend_from_slice(&bad_response);

        match method.step(&resp_type_data).await.expect("step ok") {
            MethodOutcome::Failure => {}
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_user_fails() {
        let creds = Arc::new(StaticCredentials::cleartext(b"alice".to_vec(), b"hello"));
        let mut method = EapMd5::new(Arc::clone(&creds));
        method.notify_peer_identity(b"unknown");
        let MethodOutcome::Continue(req_type_data) = method.start().await.expect("start ok") else {
            panic!("expected Continue");
        };
        method.notify_request_id(1);

        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&req_type_data[1..17]);
        let response = primitives::challenge_response(1, b"hello", &challenge);

        let mut resp_type_data = vec![16u8];
        resp_type_data.extend_from_slice(&response);

        match method.step(&resp_type_data).await.expect("step ok") {
            MethodOutcome::Failure => {}
            other => panic!("expected Failure for unknown user, got {other:?}"),
        }
    }
}
