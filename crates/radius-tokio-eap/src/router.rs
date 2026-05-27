//! Multi-method EAP dispatcher.
//!
//! [`EapHandler`](crate::EapHandler) drives a single, statically
//! chosen EAP method to completion. A realistic deployment usually
//! needs more than that:
//!
//! * The supplicant population is mixed — some endpoints speak
//!   PEAP+MSCHAPv2, others EAP-TLS, a handful only EAP-MD5 on
//!   wired 802.1X. The NAS has no idea which one any given user
//!   prefers; it just blindly forwards whatever the supplicant
//!   sent.
//! * Even a single supplicant negotiates: per RFC 3748 §5.3 it
//!   may answer the server's offered method with `EAP-Response/Nak`
//!   listing the methods it actually supports. A useful server
//!   pivots to one of those instead of hard-failing.
//!
//! This module ships the small amount of "batteries included" glue
//! that turns the per-method state machines in this crate
//! (`EapMd5`, `EapTls`, `Peap`, `EapTtls`, `EapMsChapV2`, …) into
//! a single [`Handler`] you can drop straight into
//! `radius_tokio::server::Server::builder().handler(...)`.
//!
//! # Pieces
//!
//! * [`DynMethodFactory`] — object-safe
//!   sibling of [`MethodFactory`](crate::MethodFactory). Implemented
//!   automatically for any `MethodFactory` via the
//!   [`DynFactory`](crate::DynFactory) adapter.
//! * [`EapRouter`] — the registration table: EAP `Type` → factory,
//!   plus the preferred type to offer on the very first round.
//! * [`MultiEapHandler`] — a [`Handler`] that drives whichever
//!   method the router picked. Handles `EAP-Response/Nak` by
//!   pivoting to the next supported method the peer suggested,
//!   tracks already-tried methods so the peer can't loop forever,
//!   and otherwise behaves exactly like
//!   [`EapHandler`](crate::EapHandler) (same session store,
//!   same [`AcceptDecorator`] hook, same
//!   MS-MPPE key emission).
//!
//! # Example
//!
//! ```ignore
//! use radius_tokio::eap::Type as EapType;
//! use radius_tokio_eap::{
//!     DynFactory, EapRouter, MultiEapHandler,
//!     eap_md5::EapMd5Factory,
//!     peap::PeapFactory,
//! };
//!
//! let router = EapRouter::builder()
//!     .preferred(EapType::PEAP)
//!     .register_typed(EapType::PEAP, peap_factory)
//!     .register_typed(EapType::MD5_CHALLENGE, md5_factory)
//!     .build()
//!     .expect("preferred type must be registered");
//!
//! let handler = MultiEapHandler::new(router);
//! ```
//!
//! [`Handler`]: radius_tokio::server::Handler

use std::collections::HashMap;
use std::sync::Arc;

use radius_tokio::eap::{self, Code as EapCode, Packet as EapPacket, Type as EapType};
use radius_tokio::server::{Handler, HandlerResult, Request};
use radius_tokio::AttributesView;

use crate::handler::{
    commit_outcome, render_dispatch, resolve_peer_identity, AcceptDecorator, Dispatch,
};
use crate::method::{BoxedEapMethod, DynMethodFactory};
use crate::session::{InMemorySessionStore, Session, SessionId, SessionStore};

/// Registration table mapping EAP `Type` bytes to the factories
/// that produce a state machine for them.
///
/// Built via [`EapRouter::builder`]. Cheap to clone (everything is
/// behind `Arc`), so the same table can back several listeners /
/// handlers if you need to.
#[derive(Clone)]
pub struct EapRouter {
    methods: HashMap<u8, Arc<dyn DynMethodFactory>>,
    preferred: EapType,
}

impl std::fmt::Debug for EapRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut types: Vec<u8> = self.methods.keys().copied().collect();
        types.sort_unstable();
        f.debug_struct("EapRouter")
            .field("preferred", &self.preferred.0)
            .field("registered_types", &types)
            .finish()
    }
}

impl EapRouter {
    /// Start configuring a router.
    #[must_use]
    pub fn builder() -> EapRouterBuilder {
        EapRouterBuilder::default()
    }

    /// EAP `Type` the router offers on the very first round
    /// (before the peer has had a chance to `Nak` anything).
    #[must_use]
    pub fn preferred(&self) -> EapType {
        self.preferred
    }

    /// Look up the factory registered for `typ`, if any.
    #[must_use]
    pub fn lookup(&self, typ: EapType) -> Option<&Arc<dyn DynMethodFactory>> {
        self.methods.get(&typ.0)
    }

    /// True if `typ` is in the routing table.
    #[must_use]
    pub fn supports(&self, typ: EapType) -> bool {
        self.methods.contains_key(&typ.0)
    }

    /// Iterate every `(type, factory)` registered with the router,
    /// in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = (EapType, &Arc<dyn DynMethodFactory>)> {
        self.methods.iter().map(|(&t, f)| (EapType(t), f))
    }
}

/// Builder for [`EapRouter`].
#[derive(Default)]
pub struct EapRouterBuilder {
    methods: HashMap<u8, Arc<dyn DynMethodFactory>>,
    preferred: Option<EapType>,
}

/// Errors surfaced by [`EapRouterBuilder::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouterBuildError {
    /// No factories were registered.
    NoMethods,
    /// No preferred type was set with [`EapRouterBuilder::preferred`].
    NoPreferred,
    /// The preferred type isn't registered in the table.
    PreferredNotRegistered(EapType),
}

impl std::fmt::Display for RouterBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterBuildError::NoMethods => f.write_str("EapRouter: no methods registered"),
            RouterBuildError::NoPreferred => f.write_str("EapRouter: no preferred type set"),
            RouterBuildError::PreferredNotRegistered(t) => {
                write!(f, "EapRouter: preferred EAP type {} is not registered", t.0)
            }
        }
    }
}

impl std::error::Error for RouterBuildError {}

impl EapRouterBuilder {
    /// Set the EAP `Type` the router offers on the first round.
    ///
    /// The peer may still `Nak` to a different supported type; the
    /// preferred type just decides what gets offered before any
    /// negotiation happens.
    #[must_use]
    pub fn preferred(mut self, typ: EapType) -> Self {
        self.preferred = Some(typ);
        self
    }

    /// Register a [`DynMethodFactory`]. The factory's
    /// [`DynMethodFactory::typ`] decides which EAP `Type` byte it
    /// answers for; replaces any previously-registered factory for
    /// the same type.
    #[must_use]
    pub fn register<F: DynMethodFactory>(mut self, factory: F) -> Self {
        let typ = factory.typ();
        self.methods.insert(typ.0, Arc::new(factory));
        self
    }

    /// Convenience: wrap a typed [`MethodFactory`](crate::MethodFactory)
    /// in [`DynFactory`](crate::DynFactory) and register it under
    /// `typ`.
    #[must_use]
    pub fn register_typed<F>(self, typ: EapType, factory: F) -> Self
    where
        F: crate::method::MethodFactory,
        F::Method: 'static,
    {
        self.register(crate::method::DynFactory::new(typ, factory))
    }

    /// Finalise the router.
    ///
    /// # Errors
    ///
    /// Returns [`RouterBuildError`] if no methods were registered,
    /// no preferred type was set, or the preferred type isn't in
    /// the table.
    pub fn build(self) -> Result<EapRouter, RouterBuildError> {
        if self.methods.is_empty() {
            return Err(RouterBuildError::NoMethods);
        }
        let preferred = self.preferred.ok_or(RouterBuildError::NoPreferred)?;
        if !self.methods.contains_key(&preferred.0) {
            return Err(RouterBuildError::PreferredNotRegistered(preferred));
        }
        Ok(EapRouter {
            methods: self.methods,
            preferred,
        })
    }
}

/// [`Handler`] backed by an [`EapRouter`] — dispatches the inbound
/// `EAP-Message` to whichever method the peer ended up agreeing on.
///
/// On the very first `EAP-Response/Identity` round the handler
/// offers `router.preferred()`. If the peer instead sends
/// `EAP-Response/Nak` listing other methods it supports, the
/// handler pivots to the first one that's registered with the
/// router *and* hasn't been tried on this session yet (per
/// RFC 3748 §5.3). When every router-supported type the peer
/// suggests has already been tried, the handler emits
/// `EAP-Failure` / `Access-Reject`.
///
/// Everything else — session storage, `State`-cookie minting,
/// MS-MPPE key emission, the [`AcceptDecorator`] hook — works
/// identically to [`EapHandler`](crate::EapHandler).
pub struct MultiEapHandler<S = InMemorySessionStore<BoxedEapMethod>>
where
    S: SessionStore<Method = BoxedEapMethod>,
{
    router: EapRouter,
    store: S,
    accept_decorator: Option<Box<dyn AcceptDecorator>>,
}

impl MultiEapHandler<InMemorySessionStore<BoxedEapMethod>> {
    /// Build a handler backed by the bundled
    /// [`InMemorySessionStore`].
    #[must_use]
    pub fn new(router: EapRouter) -> Self {
        Self {
            router,
            store: InMemorySessionStore::<BoxedEapMethod>::new(),
            accept_decorator: None,
        }
    }
}

impl<S> MultiEapHandler<S>
where
    S: SessionStore<Method = BoxedEapMethod>,
{
    /// Build a handler against a custom session store. The store's
    /// `Method` type must be the type-erased [`BoxedEapMethod`]
    /// since the router may stash any of several method state
    /// machines on a given session.
    pub fn with_store(router: EapRouter, store: S) -> Self {
        Self {
            router,
            store,
            accept_decorator: None,
        }
    }

    /// Install an [`AcceptDecorator`] that stamps additional
    /// RADIUS attributes onto each emitted `Access-Accept`. Same
    /// semantics as [`EapHandler::with_accept_decorator`](crate::EapHandler::with_accept_decorator).
    #[must_use]
    pub fn with_accept_decorator<D: AcceptDecorator>(mut self, decorator: D) -> Self {
        self.accept_decorator = Some(Box::new(decorator));
        self
    }

    /// Borrow the routing table this handler dispatches against.
    #[must_use]
    pub fn router(&self) -> &EapRouter {
        &self.router
    }
}

impl<S> Handler for MultiEapHandler<S>
where
    S: SessionStore<Method = BoxedEapMethod> + 'static,
{
    fn handle(
        &self,
        request: Request<'_>,
    ) -> impl std::future::Future<Output = HandlerResult> + Send {
        let radius_identifier = request.identifier();
        let req_auth: [u8; 16] = *request.authenticator();
        let secret: Arc<[u8]> = Arc::from(request.client().secret());
        let state = request.state().and_then(SessionId::from_bytes);
        let mut eap_buf = Vec::with_capacity(256);
        request.eap_message_into(&mut eap_buf);
        let user_name = request.user_name().map(<[u8]>::to_vec);
        let raw_attributes: Vec<u8> = request.raw_attributes().to_vec();

        async move {
            let outcome = match self
                .dispatch_round(state, &eap_buf, user_name.clone(), &raw_attributes)
                .await
            {
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

impl<S> MultiEapHandler<S>
where
    S: SessionStore<Method = BoxedEapMethod> + 'static,
{
    // Observability instrumentation inflates the line count past the
    // pedantic default; the control flow itself is still a single
    // linear dispatcher and splitting it would obscure the spec mapping.
    #[allow(clippy::too_many_lines)]
    async fn dispatch_round(
        &self,
        existing: Option<SessionId>,
        eap_buf: &[u8],
        user_name: Option<Vec<u8>>,
        outer_attributes: &[u8],
    ) -> Result<Dispatch, crate::Error> {
        let Ok(pkt) = EapPacket::parse(eap_buf) else {
            return Ok(Dispatch::Drop);
        };
        if pkt.code() != EapCode::RESPONSE {
            return Ok(Dispatch::Drop);
        }
        let peer_id = pkt.identifier();

        // Identity round: pick the preferred method and start it.
        if pkt.typ() == Some(eap::Type::IDENTITY) {
            let preferred_typ = self.router.preferred();
            let factory = self
                .router
                .lookup(preferred_typ)
                .expect("EapRouter::build verified preferred is registered");
            let mut method = factory.create()?;
            let peer_identity = resolve_peer_identity(pkt.type_data(), user_name);
            if let Some(id) = peer_identity.as_deref() {
                method.notify_peer_identity(id);
            }
            let outcome = method.start(outer_attributes).await?;
            debug!(
                event = "session_started",
                method = preferred_typ.0,
                via = "identity_router_preferred",
            );
            count!(
                crate::obs::metrics::SESSIONS_CREATED,
                "method" => preferred_typ.0.to_string(),
            );
            let mut session = Session::new(method);
            session.peer_identity = peer_identity;
            session.tried_types.push(preferred_typ);
            return commit_outcome(&self.store, outcome, session, peer_id, preferred_typ).await;
        }

        // Continuing round: look up the session.
        let Some(id) = existing else {
            return Ok(Dispatch::Drop);
        };
        let Some(mut session) = self.store.take(id).await else {
            return Ok(Dispatch::Drop);
        };

        // EAP-Nak fallback: peer didn't want the offered method
        // and listed alternatives. Pivot to the first registered
        // alternative we haven't already tried.
        if pkt.typ() == Some(eap::Type::NAK) {
            // Collect candidates: peer's listed desired types,
            // filtered to those the router knows about and we
            // haven't already offered on this session.
            let desired: Vec<EapType> = pkt
                .type_data()
                .iter()
                .copied()
                .map(EapType)
                .filter(|t| {
                    // RFC 3748 §5.3.1: a desired-type byte of 0 is
                    // the "no acceptable alternative" sentinel.
                    t.0 != 0 && self.router.supports(*t) && !session.tried_types.contains(t)
                })
                .collect();

            let Some(next_typ) = desired.into_iter().next() else {
                debug!(event = "nak_reject", current = session.method.typ().0,);
                count!(crate::obs::metrics::NAK_REJECTS);
                count!(
                    crate::obs::metrics::SESSIONS_COMPLETED,
                    "method" => session.method.typ().0.to_string(),
                    "outcome" => "dropped",
                );
                return Ok(Dispatch::Reject {
                    eap_identifier: peer_id,
                });
            };

            let from_typ = session.method.typ();
            debug!(event = "nak_pivot", from = from_typ.0, to = next_typ.0,);
            count!(
                crate::obs::metrics::NAK_PIVOTS,
                "from" => from_typ.0.to_string(),
                "to" => next_typ.0.to_string(),
            );
            let _ = from_typ;
            let factory = self
                .router
                .lookup(next_typ)
                .expect("supports() returned true above");
            let mut method = factory.create()?;
            if let Some(id) = session.peer_identity.as_deref() {
                method.notify_peer_identity(id);
            }
            let outcome = method.start(outer_attributes).await?;
            // Replace the session's method, keep peer_identity /
            // tried_types / next_eap_id.
            session.method = method;
            session.tried_types.push(next_typ);
            return commit_outcome(&self.store, outcome, session, peer_id, next_typ).await;
        }

        let current_typ = session.method.typ();
        if pkt.typ() != Some(current_typ) {
            // Wrong type and not a Nak — terminate.
            debug!(
                event = "session_wrong_type",
                expected = current_typ.0,
                got = pkt.typ().map_or(0u8, |t| t.0),
            );
            count!(
                crate::obs::metrics::SESSIONS_COMPLETED,
                "method" => current_typ.0.to_string(),
                "outcome" => "dropped",
            );
            return Ok(Dispatch::Reject {
                eap_identifier: peer_id,
            });
        }
        let outcome = session
            .method
            .step(pkt.type_data(), outer_attributes)
            .await?;
        commit_outcome(&self.store, outcome, session, peer_id, current_typ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{EapMethod, MethodFactory, MethodOutcome};
    use crate::Error;

    struct DummyMethod {
        typ: EapType,
        succeed: bool,
        started: bool,
    }

    impl EapMethod for DummyMethod {
        fn typ(&self) -> EapType {
            self.typ
        }
        fn start<'a>(&'a mut self, _outer: &'a [u8]) -> crate::method::MethodFuture<'a> {
            Box::pin(async move {
                self.started = true;
                Ok(MethodOutcome::Continue(b"hello".to_vec()))
            })
        }
        fn step<'a>(
            &'a mut self,
            _: &'a [u8],
            _outer: &'a [u8],
        ) -> crate::method::MethodFuture<'a> {
            Box::pin(async move {
                if self.succeed {
                    Ok(MethodOutcome::Success {
                        msk: vec![0u8; 64],
                        emsk: vec![],
                    })
                } else {
                    Ok(MethodOutcome::Failure)
                }
            })
        }
    }

    struct DummyFactory {
        typ: EapType,
        succeed: bool,
    }

    impl MethodFactory for DummyFactory {
        type Method = DummyMethod;
        fn create(&self) -> Result<Self::Method, Error> {
            Ok(DummyMethod {
                typ: self.typ,
                succeed: self.succeed,
                started: false,
            })
        }
    }

    #[test]
    fn builder_rejects_empty() {
        let err = EapRouter::builder().build().unwrap_err();
        assert!(matches!(err, RouterBuildError::NoMethods));
    }

    #[test]
    fn builder_rejects_missing_preferred() {
        let err = EapRouter::builder()
            .register_typed(
                EapType::MD5_CHALLENGE,
                DummyFactory {
                    typ: EapType::MD5_CHALLENGE,
                    succeed: true,
                },
            )
            .build()
            .unwrap_err();
        assert!(matches!(err, RouterBuildError::NoPreferred));
    }

    #[test]
    fn builder_rejects_unregistered_preferred() {
        let err = EapRouter::builder()
            .preferred(EapType::PEAP)
            .register_typed(
                EapType::MD5_CHALLENGE,
                DummyFactory {
                    typ: EapType::MD5_CHALLENGE,
                    succeed: true,
                },
            )
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            RouterBuildError::PreferredNotRegistered(t) if t == EapType::PEAP
        ));
    }

    #[test]
    fn builder_accepts_valid() {
        let router = EapRouter::builder()
            .preferred(EapType::MD5_CHALLENGE)
            .register_typed(
                EapType::MD5_CHALLENGE,
                DummyFactory {
                    typ: EapType::MD5_CHALLENGE,
                    succeed: true,
                },
            )
            .register_typed(
                EapType::PEAP,
                DummyFactory {
                    typ: EapType::PEAP,
                    succeed: false,
                },
            )
            .build()
            .unwrap();
        assert_eq!(router.preferred(), EapType::MD5_CHALLENGE);
        assert!(router.supports(EapType::MD5_CHALLENGE));
        assert!(router.supports(EapType::PEAP));
        assert!(!router.supports(EapType::TLS));
        assert_eq!(router.iter().count(), 2);
    }

    #[test]
    fn router_debug_lists_sorted_types_and_preferred() {
        let router = EapRouter::builder()
            .preferred(EapType::MD5_CHALLENGE)
            .register_typed(
                EapType::PEAP,
                DummyFactory {
                    typ: EapType::PEAP,
                    succeed: false,
                },
            )
            .register_typed(
                EapType::MD5_CHALLENGE,
                DummyFactory {
                    typ: EapType::MD5_CHALLENGE,
                    succeed: true,
                },
            )
            .build()
            .unwrap();
        let dbg = format!("{router:?}");
        // Preferred byte (4) + sorted [4, 25] for MD5, PEAP.
        assert!(dbg.contains("preferred: 4"), "got: {dbg}");
        assert!(dbg.contains("registered_types: [4, 25]"), "got: {dbg}");
    }

    #[test]
    fn router_build_error_display() {
        assert_eq!(
            RouterBuildError::NoMethods.to_string(),
            "EapRouter: no methods registered"
        );
        assert_eq!(
            RouterBuildError::NoPreferred.to_string(),
            "EapRouter: no preferred type set"
        );
        assert_eq!(
            RouterBuildError::PreferredNotRegistered(EapType::PEAP).to_string(),
            "EapRouter: preferred EAP type 25 is not registered"
        );
    }

    // ── dispatch tests ───────────────────────────────────────────
    //
    // Drive `MultiEapHandler::dispatch` directly, bypassing the
    // full `Handler::handle` pipeline. This exercises the routing
    // logic (identity round, normal step, Nak fallback, anti-loop
    // tracking) without needing a real Server + UDP listener +
    // RADIUS encode/decode round trip.

    use radius_tokio::eap::{write_response, Type as EapTypeRT};

    fn build_router(preferred: EapType, succeed_md5: bool) -> EapRouter {
        EapRouter::builder()
            .preferred(preferred)
            .register_typed(
                EapType::PEAP,
                DummyFactory {
                    typ: EapType::PEAP,
                    succeed: true,
                },
            )
            .register_typed(
                EapType::MD5_CHALLENGE,
                DummyFactory {
                    typ: EapType::MD5_CHALLENGE,
                    succeed: succeed_md5,
                },
            )
            .build()
            .unwrap()
    }

    fn handler_for(router: EapRouter) -> MultiEapHandler<InMemorySessionStore<BoxedEapMethod>> {
        MultiEapHandler::with_store(router, InMemorySessionStore::new())
    }

    // Thin shim so the existing tests don't have to pass an
    // outer-request snapshot — they exercise routing logic that
    // doesn't read the outer attributes.
    impl<S> MultiEapHandler<S>
    where
        S: SessionStore<Method = BoxedEapMethod> + 'static,
    {
        async fn dispatch(
            &self,
            existing: Option<SessionId>,
            eap_buf: &[u8],
            user_name: Option<Vec<u8>>,
        ) -> Result<Dispatch, crate::Error> {
            self.dispatch_round(existing, eap_buf, user_name, &[]).await
        }
    }

    fn make_packet(id: u8, typ: EapTypeRT, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_response(&mut buf, id, typ, payload).unwrap();
        buf
    }

    #[tokio::test]
    async fn dispatch_identity_round_offers_preferred() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let pkt = make_packet(7, EapTypeRT::IDENTITY, b"alice");
        let d = handler
            .dispatch(None, &pkt, Some(b"alice".to_vec()))
            .await
            .unwrap();
        match d {
            Dispatch::Challenge { eap_typ, .. } => assert_eq!(eap_typ, EapType::PEAP),
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        }
    }

    #[tokio::test]
    async fn dispatch_drops_non_response() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        // Hand-build an EAP-Request (Code=1).
        let pkt = vec![1, 1, 0, 5, EapTypeRT::IDENTITY.0];
        let d = handler.dispatch(None, &pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Drop));
    }

    #[tokio::test]
    async fn dispatch_drops_malformed_buffer() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let d = handler.dispatch(None, &[2, 1, 0], None).await.unwrap();
        assert!(matches!(d, Dispatch::Drop));
    }

    #[tokio::test]
    async fn dispatch_drops_continuing_round_without_state() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        // Non-identity response, no State attribute carried.
        let pkt = make_packet(2, EapType::PEAP, b"");
        let d = handler.dispatch(None, &pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Drop));
    }

    #[tokio::test]
    async fn dispatch_drops_unknown_state() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let bogus = SessionId([0xAB; SessionId::LEN]);
        let pkt = make_packet(2, EapType::PEAP, b"");
        let d = handler.dispatch(Some(bogus), &pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Drop));
    }

    #[tokio::test]
    async fn dispatch_nak_pivots_to_supported_alternative() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        // Round 1: identity → Challenge(PEAP), session created.
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // Round 2: peer Naks to EAP-MD5.
        let nak_pkt = make_packet(2, EapTypeRT::NAK, &[EapType::MD5_CHALLENGE.0]);
        match handler.dispatch(Some(state), &nak_pkt, None).await.unwrap() {
            Dispatch::Challenge { eap_typ, .. } => {
                assert_eq!(eap_typ, EapType::MD5_CHALLENGE);
            }
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        }
    }

    #[tokio::test]
    async fn dispatch_nak_filters_zero_sentinel() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // Nak desired-types = [0] is the RFC 3748 §5.3.1 "no
        // acceptable alternative" sentinel — must reject, not pivot.
        let nak_pkt = make_packet(2, EapTypeRT::NAK, &[0]);
        let d = handler.dispatch(Some(state), &nak_pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Reject { .. }));
    }

    #[tokio::test]
    async fn dispatch_nak_to_unregistered_type_rejects() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // EAP-TLS isn't in the router.
        let nak_pkt = make_packet(2, EapTypeRT::NAK, &[EapType::TLS.0]);
        let d = handler.dispatch(Some(state), &nak_pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Reject { .. }));
    }

    #[tokio::test]
    async fn dispatch_nak_loop_to_already_tried_rejects() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        // Round 1: identity → PEAP challenge.
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // Round 2: peer Naks to PEAP (already offered) → reject.
        let nak_pkt = make_packet(2, EapTypeRT::NAK, &[EapType::PEAP.0]);
        let d = handler.dispatch(Some(state), &nak_pkt, None).await.unwrap();
        assert!(matches!(d, Dispatch::Reject { .. }));
    }

    #[tokio::test]
    async fn dispatch_wrong_type_response_rejects() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        // Round 1: identity → PEAP challenge.
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // Round 2: peer responds with a non-PEAP, non-Nak type.
        let bogus = make_packet(2, EapType::MD5_CHALLENGE, b"");
        let d = handler.dispatch(Some(state), &bogus, None).await.unwrap();
        assert!(matches!(d, Dispatch::Reject { .. }));
    }

    #[tokio::test]
    async fn dispatch_step_success_yields_accept() {
        let handler = handler_for(build_router(EapType::PEAP, true));
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        // PEAP factory is configured to Succeed on step().
        let step_pkt = make_packet(2, EapType::PEAP, b"any");
        match handler
            .dispatch(Some(state), &step_pkt, None)
            .await
            .unwrap()
        {
            Dispatch::Accept { msk, .. } => assert_eq!(msk.len(), 64),
            other => panic!("expected Accept, got {:?}", DispatchTag::of(&other)),
        }
    }

    #[tokio::test]
    async fn dispatch_step_failure_yields_reject() {
        // PEAP succeeds, MD5 fails. Drive PEAP→Nak→MD5→Failure.
        let handler = handler_for(build_router(EapType::PEAP, false));
        let id_pkt = make_packet(1, EapTypeRT::IDENTITY, b"alice");
        let state = match handler
            .dispatch(None, &id_pkt, Some(b"alice".to_vec()))
            .await
            .unwrap()
        {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        let nak_pkt = make_packet(2, EapTypeRT::NAK, &[EapType::MD5_CHALLENGE.0]);
        let state = match handler.dispatch(Some(state), &nak_pkt, None).await.unwrap() {
            Dispatch::Challenge { state, .. } => state,
            other => panic!("expected Challenge, got {:?}", DispatchTag::of(&other)),
        };
        let step_pkt = make_packet(3, EapType::MD5_CHALLENGE, b"any");
        let d = handler
            .dispatch(Some(state), &step_pkt, None)
            .await
            .unwrap();
        assert!(matches!(d, Dispatch::Reject { .. }));
    }

    // Tiny helper so panic messages on the variant-mismatch paths
    // don't require Dispatch itself to impl Debug.
    #[derive(Debug)]
    enum DispatchTag {
        Challenge,
        Accept,
        Reject,
        Drop,
    }
    impl DispatchTag {
        fn of(d: &Dispatch) -> Self {
            match d {
                Dispatch::Challenge { .. } => DispatchTag::Challenge,
                Dispatch::Accept { .. } => DispatchTag::Accept,
                Dispatch::Reject { .. } => DispatchTag::Reject,
                Dispatch::Drop => DispatchTag::Drop,
            }
        }
    }
}
