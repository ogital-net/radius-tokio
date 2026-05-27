//! [`EapHandler`] — adapter wrapping any [`EapMethod`] (built by a
//! [`MethodFactory`]) into a [`radius_tokio::server::Handler`].
//!
//! The adapter owns the per-session lifecycle: it parses the
//! incoming `EAP-Message`, looks the session up by the request's
//! `State` attribute, drives the method one round, and emits an
//! `Access-Challenge` (carrying the next EAP-Request and a fresh
//! `State`), `Access-Accept` (carrying `EAP-Success` and the
//! MS-MPPE keys), or `Access-Reject` (carrying `EAP-Failure`).
//!
//! Session id allocation: the adapter mints a fresh 16-byte
//! [`SessionId`] from the CSPRNG re-exported by
//! [`radius_tokio::rand::fill_secure`]. 128 bits of unpredictable
//! state per session is enough that even a long-lived listener
//! won't see collisions or guessable `State` cookies.
//!
//! # Identity exchange
//!
//! The adapter does **not** issue `EAP-Request/Identity` on its
//! own — virtually every NAS pre-sends `EAP-Response/Identity` on
//! the first Access-Request. When the first request the adapter
//! sees is a Response/Identity, it records the identity on the
//! session and immediately drives the method's `start()`.
//!
//! # Method-type negotiation (`EAP-Nak`)
//!
//! Per RFC 3748 §5.3, if the peer doesn't want the offered method
//! it responds with `EAP-Response/Nak` listing methods it does
//! support. The current adapter treats any wrong-type response as
//! a hard failure (`EAP-Failure` / `Access-Reject`) rather than
//! trying to negotiate down — consumers that want graceful
//! fallback can layer a per-method dispatch in front of this.

use std::sync::Arc;

use radius_tokio::eap::{self, Code as EapCode, Packet as EapPacket, Type as EapType};
use radius_tokio::server::{Handler, HandlerResult, Request};
use radius_tokio::{attributes, Code as RadiusCode, CodecError, Reply};

use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::session::{InMemorySessionStore, Session, SessionId, SessionStore};

/// Context handed to an [`AcceptDecorator`] when [`EapHandler`] is
/// about to emit an `Access-Accept`.
///
/// All borrowed slices live only for the duration of the
/// `decorate` call; copy out anything you need to keep.
#[non_exhaustive]
pub struct AcceptContext<'a> {
    /// Identity the EAP method authenticated. For PEAP / EAP-TTLS
    /// this is the **inner** identity (e.g. the `MSCHAPv2` or PAP
    /// username) — not the outer `anonymous_identity` the
    /// supplicant sent in cleartext `User-Name`.
    pub peer_identity: Option<&'a [u8]>,
    /// Outer `User-Name` attribute as the NAS sent it. For
    /// EAP-MD5 / EAP-TLS this equals `peer_identity`; for tunnel
    /// methods with `anonymous_identity` set, this is the
    /// throwaway outer name (commonly `"anonymous"`).
    pub user_name: Option<&'a [u8]>,
    raw_attributes: &'a [u8],
}

impl<'a> AcceptContext<'a> {
    /// Walk the inbound request's attribute region to pull out
    /// NAS-side metadata such as `Called-Station-Id` (the AP MAC
    /// plus SSID for 802.1X), `NAS-IP-Address`, `NAS-Identifier`,
    /// or any vendor-specific attributes the NAS attached.
    #[must_use]
    pub fn request_attributes(&self) -> attributes::AttributesIter<'a> {
        attributes::iter(self.raw_attributes)
    }
}

/// Hook called by [`EapHandler`] right before each `Access-Accept`
/// is finalised — after `EAP-Success` and `MS-MPPE-{Send,Recv}-Key`
/// have been stamped, before the reply leaves the handler.
///
/// This is where authorisation attributes go:
///
/// * Dynamic VLAN assignment: `Tunnel-Type` (13 = VLAN),
///   `Tunnel-Medium-Type` (6 = IEEE-802),
///   `Tunnel-Private-Group-Id` (the VLAN id as ASCII).
/// * `Filter-Id` for ACL profile selection.
/// * `Session-Timeout` / `Idle-Timeout` / `Termination-Action`.
/// * `Class` for accounting correlation.
/// * Arbitrary vendor-specific attributes.
///
/// Returning [`CodecError`] turns the request into a silent drop.
/// Any blanket [`Fn`] impl with the right signature satisfies the
/// trait, so closures work directly:
///
/// ```ignore
/// let handler = EapHandler::new(factory).with_accept_decorator(
///     |ctx: &AcceptContext<'_>, reply: &mut Reply| {
///         if ctx.peer_identity == Some(b"alice".as_slice()) {
///             reply.add_attribute(64, &[0, 0, 0, 13])?;  // Tunnel-Type = VLAN
///             reply.add_attribute(65, &[0, 0, 0, 6])?;   // Tunnel-Medium = 802
///             reply.add_attribute(81, b"42")?;           // Tunnel-Private-Group-Id
///         }
///         Ok(())
///     },
/// );
/// ```
pub trait AcceptDecorator: Send + Sync + 'static {
    /// Stamp authorisation attributes on `reply` for the user
    /// described by `ctx`.
    ///
    /// The returned future is `Send` so the EAP handler can
    /// `.await` it across runtime boundaries (e.g. while talking
    /// to a policy backend).
    ///
    /// # Errors
    ///
    /// Any [`CodecError`] (e.g. an attribute value too long for
    /// its 253-byte slot) causes the handler to drop the request.
    fn decorate<'a>(
        &'a self,
        ctx: &'a AcceptContext<'a>,
        reply: &'a mut Reply,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CodecError>> + Send + 'a>>;
}

impl<F> AcceptDecorator for F
where
    F: Fn(&AcceptContext<'_>, &mut Reply) -> Result<(), CodecError> + Send + Sync + 'static,
{
    fn decorate<'a>(
        &'a self,
        ctx: &'a AcceptContext<'a>,
        reply: &'a mut Reply,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CodecError>> + Send + 'a>>
    {
        let result = (self)(ctx, reply);
        Box::pin(async move { result })
    }
}

/// Adapter wrapping a [`MethodFactory`] + [`SessionStore`] into a
/// [`Handler`].
///
/// Built via [`EapHandler::new`]. The handler is `Send + Sync +
/// 'static` (provided `F` and `S` are), suitable for
/// `Arc::new(handler)` and `serve_udp` / `serve_radsec`.
pub struct EapHandler<F, S>
where
    F: MethodFactory,
    S: SessionStore<Method = F::Method>,
{
    factory: F,
    store: S,
    accept_decorator: Option<Box<dyn AcceptDecorator>>,
}

impl<F> EapHandler<F, InMemorySessionStore<F::Method>>
where
    F: MethodFactory,
    F::Method: 'static,
{
    /// Build a handler backed by the bundled
    /// [`InMemorySessionStore`].
    #[must_use]
    pub fn new(factory: F) -> Self {
        Self {
            factory,
            store: InMemorySessionStore::<F::Method>::new(),
            accept_decorator: None,
        }
    }
}

impl<F, S> EapHandler<F, S>
where
    F: MethodFactory,
    S: SessionStore<Method = F::Method>,
{
    /// Build a handler against a custom session store.
    pub fn with_store(factory: F, store: S) -> Self {
        Self {
            factory,
            store,
            accept_decorator: None,
        }
    }

    /// Install an [`AcceptDecorator`] that stamps additional
    /// RADIUS attributes (VLAN assignment, ACL profiles, session
    /// timeouts, …) onto each emitted `Access-Accept`.
    ///
    /// Closures with the right signature satisfy the trait
    /// directly — see [`AcceptDecorator`].
    #[must_use]
    pub fn with_accept_decorator<D: AcceptDecorator>(mut self, decorator: D) -> Self {
        self.accept_decorator = Some(Box::new(decorator));
        self
    }
}

pub(crate) fn fresh_session_id() -> SessionId {
    let mut bytes = [0u8; SessionId::LEN];
    radius_tokio::rand::fill_secure(&mut bytes);
    SessionId(bytes)
}

/// Resolve the identity to record on a new session: prefer the
/// `EAP-Response/Identity` type-data, fall back to the outer
/// `User-Name` attribute. Shared by [`EapHandler`] and
/// [`crate::MultiEapHandler`] so both record identity identically.
pub(crate) fn resolve_peer_identity(
    eap_identity_type_data: &[u8],
    user_name: Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if eap_identity_type_data.is_empty() {
        user_name
    } else {
        Some(eap_identity_type_data.to_vec())
    }
}

/// Turn a method-produced [`MethodOutcome`] into a [`Dispatch`],
/// persisting the session for `Continue` and dropping it on the
/// terminal `Success` / `Failure` arms. Generic over the concrete
/// method type so [`EapHandler`] (typed) and
/// [`crate::MultiEapHandler`] (type-erased) share one
/// implementation.
pub(crate) async fn commit_outcome<M, S>(
    store: &S,
    outcome: MethodOutcome,
    mut session: Session<M>,
    peer_eap_id: u8,
    method_typ: EapType,
) -> Result<Dispatch, crate::Error>
where
    M: EapMethod,
    S: SessionStore<Method = M>,
{
    match outcome {
        MethodOutcome::Continue(payload) => {
            // Server-issued EAP id MUST differ from the peer's
            // last (RFC 3748 §4.1). Allocate from the per-session
            // counter; if we collide with `peer_eap_id`, bump again.
            let mut eap_id = session.allocate_eap_id();
            if eap_id == peer_eap_id {
                eap_id = session.allocate_eap_id();
            }
            // Inform the method of the id we just stamped on its
            // outbound Request so methods like EAP-MD5 (whose
            // response is `MD5(eap_id || password || challenge)`)
            // can remember it. Default impl is a no-op.
            session.method.notify_request_id(eap_id);
            // Let integrity-protected methods (notably EAP-AKA')
            // patch the type-data now that the Identifier byte —
            // which is part of the MAC-protected canonicalisation
            // — is finally known. Default impl is a no-op.
            let mut payload = payload;
            session.method.finalize_request(eap_id, &mut payload);
            let id = fresh_session_id();
            store.insert(id, session).await;
            Ok(Dispatch::Challenge {
                eap_payload: payload,
                eap_identifier: eap_id,
                eap_typ: method_typ,
                state: id,
            })
        }
        MethodOutcome::Success { msk, emsk: _ } => Ok(Dispatch::Accept {
            eap_identifier: peer_eap_id,
            msk,
            peer_identity: session.peer_identity.take(),
        }),
        MethodOutcome::Failure => Ok(Dispatch::Reject {
            eap_identifier: peer_eap_id,
        }),
    }
}

impl<F, S> Handler for EapHandler<F, S>
where
    F: MethodFactory + 'static,
    F::Method: 'static,
    S: SessionStore<Method = F::Method> + 'static,
{
    fn handle(
        &self,
        request: Request<'_>,
    ) -> impl std::future::Future<Output = HandlerResult> + Send {
        // Snapshot everything we need from the borrowed `Request`
        // before the async block: the future must be Send and
        // can't pin the request's lifetime.
        let radius_identifier = request.identifier();
        let req_auth: [u8; 16] = *request.authenticator();
        let secret: Arc<[u8]> = Arc::from(request.client().secret());
        let state = request.state().and_then(SessionId::from_bytes);
        let mut eap_buf = Vec::with_capacity(256);
        request.eap_message_into(&mut eap_buf);
        let user_name = request.user_name().map(<[u8]>::to_vec);
        // Cheap clone of the inbound attribute region so the
        // accept decorator (if any) can re-walk it after the
        // borrow on `Request` is gone.
        let raw_attributes: Vec<u8> = request.raw_attributes().to_vec();

        async move {
            let outcome = match self.dispatch(state, &eap_buf, user_name.clone()).await {
                Ok(o) => o,
                Err(_e) => Dispatch::Drop,
            };
            render_dispatch(
                outcome,
                radius_identifier,
                &req_auth,
                &secret,
                user_name.as_deref(),
                &raw_attributes,
                self.accept_decorator.as_deref(),
            )
            .await
        }
    }
}

impl<F, S> EapHandler<F, S>
where
    F: MethodFactory + 'static,
    F::Method: 'static,
    S: SessionStore<Method = F::Method> + 'static,
{
    /// Drive the method one round. Pure routing logic; the IO /
    /// reply-encoding is left to the caller (`handle()`).
    async fn dispatch(
        &self,
        existing: Option<SessionId>,
        eap_buf: &[u8],
        user_name: Option<Vec<u8>>,
    ) -> Result<Dispatch, crate::Error> {
        let Ok(pkt) = EapPacket::parse(eap_buf) else {
            return Ok(Dispatch::Drop);
        };
        if pkt.code() != EapCode::RESPONSE {
            return Ok(Dispatch::Drop);
        }
        let peer_id = pkt.identifier();

        // Identity round: bootstrap a session, capture identity,
        // call method.start().
        if pkt.typ() == Some(EapType::IDENTITY) {
            let mut method = self.factory.create()?;
            // Resolve the identity the handler will record on the
            // session, then notify the method before `start()` so
            // methods that bind credentials to the username
            // (EAP-MD5) can stash it.
            let peer_identity = resolve_peer_identity(pkt.type_data(), user_name);
            if let Some(id) = peer_identity.as_deref() {
                method.notify_peer_identity(id);
            }
            let outcome = method.start().await?;
            let method_typ = method.typ();
            let mut session = Session::new(method);
            session.peer_identity = peer_identity;
            return commit_outcome(&self.store, outcome, session, peer_id, method_typ).await;
        }

        // Continuing round: look up the session.
        let Some(id) = existing else {
            return Ok(Dispatch::Drop);
        };
        let Some(mut session) = self.store.take(id).await else {
            return Ok(Dispatch::Drop);
        };
        let method_typ = session.method.typ();
        if pkt.typ() != Some(method_typ) {
            // Wrong method type (most commonly EAP-Nak). Terminate.
            return Ok(Dispatch::Reject {
                eap_identifier: peer_id,
            });
        }
        let outcome = session.method.step(pkt.type_data()).await?;
        commit_outcome(&self.store, outcome, session, peer_id, method_typ).await
    }
}

/// Internal: what we decided to do this round, before turning into
/// a [`HandlerResult`].
pub(crate) enum Dispatch {
    Challenge {
        eap_payload: Vec<u8>,
        eap_identifier: u8,
        eap_typ: EapType,
        state: SessionId,
    },
    Accept {
        eap_identifier: u8,
        msk: Vec<u8>,
        peer_identity: Option<Vec<u8>>,
    },
    Reject {
        eap_identifier: u8,
    },
    Drop,
}

pub(crate) async fn render_dispatch(
    outcome: Dispatch,
    radius_identifier: u8,
    req_auth: &[u8; 16],
    secret: &[u8],
    user_name: Option<&[u8]>,
    raw_attributes: &[u8],
    decorator: Option<&dyn AcceptDecorator>,
) -> HandlerResult {
    match outcome {
        Dispatch::Challenge {
            eap_payload,
            eap_identifier,
            eap_typ,
            state,
        } => {
            let mut reply = Reply::new(RadiusCode::ACCESS_CHALLENGE, radius_identifier);
            let mut wire = Vec::with_capacity(eap_payload.len() + 5);
            if eap::write_request(&mut wire, eap_identifier, eap_typ, &eap_payload).is_err() {
                return HandlerResult::Drop;
            }
            if reply.add_eap_message(&wire).is_err() || reply.add_state(state.as_bytes()).is_err() {
                return HandlerResult::Drop;
            }
            HandlerResult::Reply(reply)
        }
        Dispatch::Accept {
            eap_identifier,
            msk,
            peer_identity,
        } => {
            let mut reply = Reply::new(RadiusCode::ACCESS_ACCEPT, radius_identifier);
            if reply.add_eap_success(eap_identifier).is_err() {
                return HandlerResult::Drop;
            }
            // RFC 5216 §2.3: MSK[0..32] = MS-MPPE-Recv-Key,
            // MSK[32..64] = MS-MPPE-Send-Key.
            if msk.len() >= 64 {
                let recv_key = &msk[0..32];
                let send_key = &msk[32..64];
                if reply
                    .add_mppe_keys(send_key, recv_key, req_auth, secret)
                    .is_err()
                {
                    return HandlerResult::Drop;
                }
            }
            if let Some(decorator) = decorator {
                let ctx = AcceptContext {
                    peer_identity: peer_identity.as_deref(),
                    user_name,
                    raw_attributes,
                };
                if decorator.decorate(&ctx, &mut reply).await.is_err() {
                    return HandlerResult::Drop;
                }
            }
            HandlerResult::Reply(reply)
        }
        Dispatch::Reject { eap_identifier } => {
            let mut reply = Reply::new(RadiusCode::ACCESS_REJECT, radius_identifier);
            if reply.add_eap_failure(eap_identifier).is_err() {
                return HandlerResult::Drop;
            }
            HandlerResult::Reply(reply)
        }
        Dispatch::Drop => HandlerResult::Drop,
    }
}
