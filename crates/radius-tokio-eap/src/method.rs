//! [`EapMethod`] trait — the small, uniform surface every method
//! driver (EAP-TLS, PEAP, TTLS) implements so the
//! [`crate::handler::EapHandler`] adapter can drive any of them
//! without per-method dispatch logic.
//!
//! # Round model
//!
//! An EAP authentication is a sequence of *rounds*. In each round
//! the server sends one `EAP-Request` and the peer answers with
//! one `EAP-Response`, both tagged with the method's Type byte
//! (RFC 3748 §4.1). The round terminates when the method emits
//! [`MethodOutcome::Success`] or [`MethodOutcome::Failure`].
//!
//! The trait packages each round as `step(&mut self,
//! peer_type_data) -> MethodOutcome` and the initial server-issued
//! message as `start(&mut self) -> Vec<u8>`. Type-data is the
//! method-specific payload that sits *after* the EAP `Code |
//! Identifier | Length | Type` header — i.e. exactly what
//! [`radius_tokio::eap::write_request`] takes as its `type_data`
//! argument and what [`radius_tokio::eap::Packet::type_data`]
//! returns.
//!
//! For TLS-tunnelled methods (EAP-TLS / PEAP / TTLS), the
//! type-data is one of [`crate::framing::Frame`]'s encoded
//! representations. Method drivers own the framing/reassembly
//! state internally so the handler adapter remains method-agnostic.

use std::future::Future;
use std::pin::Pin;

use crate::Error;

/// Convenience alias for the boxed-future return type that
/// [`EapMethod::start`] / [`EapMethod::step`] produce. Boxing keeps
/// the trait object-safe (`Box<dyn EapMethod>` / [`BoxedEapMethod`])
/// so the [`crate::EapRouter`] can hold heterogeneous methods
/// behind one type-erased pointer.
pub type MethodFuture<'a> = Pin<Box<dyn Future<Output = Result<MethodOutcome, Error>> + Send + 'a>>;

/// Outcome of a single [`EapMethod::step`] (or the initial
/// [`EapMethod::start`]).
#[derive(Debug)]
pub enum MethodOutcome {
    /// Emit the wrapped bytes as the next `EAP-Request`'s
    /// type-data and wait for the peer's next `EAP-Response`.
    ///
    /// Empty `Vec` is *not* the same as no-output: it requests an
    /// EAP-Request with empty type-data, which several TLS-EAP
    /// methods use as a fragment-acknowledgement marker.
    Continue(Vec<u8>),

    /// Authentication succeeded. The handler adapter will emit an
    /// `Access-Accept` carrying `EAP-Success` plus, when `msk`
    /// is non-empty, the MS-MPPE Send / Recv keys derived from it
    /// per RFC 2548 §2.4 + RFC 3580 §3.16.
    ///
    /// MSK layout (RFC 5247 §1.2 / RFC 5216 §2.3): `msk[0..32]` is
    /// the MS-MPPE-Recv-Key (peer → authenticator direction key)
    /// and `msk[32..64]` is the MS-MPPE-Send-Key. The handler
    /// applies that split when assembling the reply.
    Success {
        /// Master Session Key — 64 bytes for every EAP method this
        /// crate ships. Empty `Vec` skips MS-MPPE key emission
        /// (legitimate for proxy / pass-through deployments where
        /// the downstream link is not encrypted).
        msk: Vec<u8>,
        /// Extended Master Session Key — 64 bytes per RFC 5247
        /// §1.2. Not transmitted in RADIUS today; surfaced here so
        /// future EMSK-based primitives (e.g. RFC 5295 USRK
        /// derivation) can be wired in by the consumer.
        emsk: Vec<u8>,
    },

    /// Authentication failed. The handler adapter will emit an
    /// `Access-Reject` carrying `EAP-Failure`.
    Failure,
}

/// One method's worth of EAP state machine.
///
/// Implementations are *not* required to be `Sync` — the handler
/// adapter holds them behind a per-session lock. They must be
/// `Send` so the underlying RADIUS server can dispatch them across
/// worker tasks.
///
/// See [`crate::eap_tls::EapTls`] for the canonical implementation.
///
/// `start` and `step` return boxed futures rather than `async fn`
/// or RPITIT so the trait stays object-safe behind
/// [`BoxedEapMethod`] — the [`crate::EapRouter`] needs to hold
/// heterogeneous method state machines through one trait object.
/// Implementations typically `Box::pin(async move { … })` around
/// the body.
pub trait EapMethod: Send {
    /// EAP Type byte this method advertises in `EAP-Request /
    /// Response` packets it emits and accepts.
    fn typ(&self) -> radius_tokio::eap::Type;

    /// Produce the very first server-issued message — typically the
    /// method's `Start` frame.
    ///
    /// Called once per session, immediately after the
    /// [`EapMethod`] is constructed by a [`MethodFactory`].
    ///
    /// # Errors
    ///
    /// Method-specific. EAP-TLS surfaces [`Error::Tls`] on context
    /// initialization failure.
    fn start(&mut self) -> MethodFuture<'_>;

    /// Informational hook called by the handler adapter on the
    /// initial round (after [`MethodFactory::create`], before
    /// [`start`]) with the identity the peer asserted in
    /// `EAP-Response/Identity`. Falls back to the outer
    /// `User-Name` attribute when the EAP Identity type-data is
    /// empty.
    ///
    /// Default: no-op. Methods that bind credentials to the
    /// asserted identity (notably EAP-MD5) override this to
    /// remember the username for use at credential-lookup time.
    /// TLS-tunnelled methods (EAP-TLS / PEAP / TTLS) capture
    /// identity inside the tunnel and ignore the outer name.
    ///
    /// [`start`]: EapMethod::start
    fn notify_peer_identity(&mut self, _identity: &[u8]) {}

    /// Informational hook called by the handler adapter after it
    /// allocates the EAP `Identifier` byte for an outbound
    /// `EAP-Request` produced by [`start`] or [`step`]
    /// ([`MethodOutcome::Continue`]). The peer's matching response
    /// will carry the same identifier per RFC 3748 §4.1.
    ///
    /// Default: no-op. Methods that need the request id in their
    /// response computation (notably EAP-MD5, whose response is
    /// `MD5(eap_id || password || challenge)`) override this to
    /// remember it. TLS-tunnelled methods (EAP-TLS / PEAP / TTLS)
    /// do their own framing and ignore it.
    ///
    /// [`start`]: EapMethod::start
    /// [`step`]: EapMethod::step
    fn notify_request_id(&mut self, _eap_id: u8) {}

    /// In-place patch hook called by the handler adapter after
    /// it has allocated the EAP `Identifier` byte but before the
    /// outbound `EAP-Request` bytes leave the handler. `type_data`
    /// is the buffer [`start`] or [`step`] returned via
    /// [`MethodOutcome::Continue`]; mutations here flow straight
    /// onto the wire.
    ///
    /// Default: no-op. Methods that compute an integrity MAC over
    /// the *complete* EAP packet (notably EAP-AKA' `AT_MAC` =
    /// HMAC-SHA-256-128 over `Code|Identifier|Length|Type|...`)
    /// override this to fill in the MAC value field now that
    /// every header byte is known.
    ///
    /// Implementations MUST NOT change the length of `type_data`;
    /// the handler has already committed to that length. Methods
    /// that reserved a MAC slot with a known offset can simply
    /// overwrite it in place.
    ///
    /// [`start`]: EapMethod::start
    /// [`step`]: EapMethod::step
    fn finalize_request(&mut self, _eap_id: u8, _type_data: &mut [u8]) {}

    /// Consume one peer `EAP-Response`'s type-data and produce the
    /// next outcome.
    ///
    /// `peer_type_data` is the bytes following the EAP `Type` byte
    /// in the peer's response — typically what
    /// [`radius_tokio::eap::Packet::type_data`] returns when the
    /// `typ()` matched.
    ///
    /// # Errors
    ///
    /// - [`Error::Framing`] / [`Error::ReassemblyOverflow`] /
    ///   [`Error::MissingTotalLength`] for malformed TLS-EAP
    ///   fragments.
    /// - [`Error::Tls`] for TLS record-layer or handshake errors.
    /// - [`Error::Eap`] for EAP-layer encoder failures.
    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> MethodFuture<'a>;
}

/// Per-session factory: the handler adapter calls
/// [`MethodFactory::create`] each time it sees a fresh session and
/// drives the returned [`EapMethod`] to completion.
///
/// Implementations hold the long-lived configuration the method
/// needs — e.g. a [`radius_tokio::tls::TlsContext`] for EAP-TLS,
/// or a credential database handle for PEAP's inner `MSCHAPv2`.
///
/// `Send + Sync + 'static` so the handler adapter (also `Send +
/// Sync + 'static`) can hold one inside an `Arc`.
pub trait MethodFactory: Send + Sync + 'static {
    /// Concrete method state machine type produced by [`create`].
    ///
    /// [`create`]: MethodFactory::create
    type Method: EapMethod;

    /// Build a fresh per-session method state machine.
    ///
    /// # Errors
    ///
    /// Method-specific. EAP-TLS surfaces [`Error::Tls`] if the
    /// per-session SSL handle cannot be allocated.
    fn create(&self) -> Result<Self::Method, Error>;
}

// ── Type-erased plumbing for the multi-method handler ────────────────

/// Boxed [`EapMethod`] trait object — what
/// [`crate::EapRouter`] and [`crate::MultiEapHandler`] store inside
/// a session so several different method state machines can share
/// one handler / one session store.
pub type BoxedEapMethod = Box<dyn EapMethod>;

impl<T: EapMethod + ?Sized> EapMethod for Box<T> {
    fn typ(&self) -> radius_tokio::eap::Type {
        (**self).typ()
    }
    fn start(&mut self) -> MethodFuture<'_> {
        (**self).start()
    }
    fn notify_peer_identity(&mut self, identity: &[u8]) {
        (**self).notify_peer_identity(identity);
    }
    fn notify_request_id(&mut self, eap_id: u8) {
        (**self).notify_request_id(eap_id);
    }
    fn finalize_request(&mut self, eap_id: u8, type_data: &mut [u8]) {
        (**self).finalize_request(eap_id, type_data);
    }
    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> MethodFuture<'a> {
        (**self).step(peer_type_data)
    }
}

/// Object-safe sibling of [`MethodFactory`] used by
/// [`crate::EapRouter`] to hold heterogeneous factories behind one
/// trait object.
///
/// Most callers don't implement this directly — wrap an existing
/// [`MethodFactory`] with [`DynFactory::new`] (or use the
/// convenience methods on [`crate::EapRouterBuilder`]) and the
/// blanket adapter takes care of the boxing.
pub trait DynMethodFactory: Send + Sync + 'static {
    /// EAP Type byte the methods this factory produces will
    /// advertise. Used by [`crate::EapRouter`] to dispatch
    /// `EAP-Response/Nak` to the right alternative.
    fn typ(&self) -> radius_tokio::eap::Type;

    /// Build a fresh per-session method state machine, boxed for
    /// type erasure.
    ///
    /// # Errors
    ///
    /// Same conditions as [`MethodFactory::create`].
    fn create(&self) -> Result<BoxedEapMethod, Error>;
}

/// Adapter that lifts any [`MethodFactory`] into a
/// [`DynMethodFactory`] by pairing it with the EAP `Type` byte its
/// methods advertise.
///
/// `radius-tokio-eap` deliberately keeps the EAP `Type` off
/// [`MethodFactory`] itself (the type is a property of the method
/// instance, not its factory) — this adapter lets the multi-method
/// router make routing decisions without instantiating a throw-away
/// method just to ask for its type.
pub struct DynFactory<F: MethodFactory> {
    typ: radius_tokio::eap::Type,
    inner: F,
}

impl<F: MethodFactory> DynFactory<F> {
    /// Wrap `inner`, tagging it with the EAP `Type` its methods
    /// advertise (must match `inner.create()?.typ()`).
    ///
    /// The tag is what the router matches against on
    /// `EAP-Response/Nak`, and what it picks as the offered method
    /// when the router elects this factory as the preferred one.
    pub fn new(typ: radius_tokio::eap::Type, inner: F) -> Self {
        Self { typ, inner }
    }
}

impl<F: MethodFactory> DynMethodFactory for DynFactory<F>
where
    F::Method: 'static,
{
    fn typ(&self) -> radius_tokio::eap::Type {
        self.typ
    }

    fn create(&self) -> Result<BoxedEapMethod, Error> {
        Ok(Box::new(self.inner.create()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_tokio::eap::Type as EapType;
    use std::cell::Cell;

    /// Records every trait-method invocation so the test can assert
    /// the `Box<dyn EapMethod>` adapter forwards each one.
    struct Tracer {
        identity_notifications: Cell<u32>,
        id_notifications: Cell<u32>,
        last_step: Cell<Option<u8>>,
    }

    impl EapMethod for Tracer {
        fn typ(&self) -> EapType {
            EapType::MD5_CHALLENGE
        }
        fn start(&mut self) -> MethodFuture<'_> {
            Box::pin(async move { Ok(MethodOutcome::Continue(b"start".to_vec())) })
        }
        fn notify_peer_identity(&mut self, _identity: &[u8]) {
            self.identity_notifications
                .set(self.identity_notifications.get() + 1);
        }
        fn notify_request_id(&mut self, eap_id: u8) {
            self.id_notifications.set(self.id_notifications.get() + 1);
            self.last_step.set(Some(eap_id));
        }
        fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> MethodFuture<'a> {
            self.last_step.set(peer_type_data.first().copied());
            Box::pin(async move { Ok(MethodOutcome::Failure) })
        }
    }

    struct TracerFactory;
    impl MethodFactory for TracerFactory {
        type Method = Tracer;
        fn create(&self) -> Result<Self::Method, Error> {
            Ok(Tracer {
                identity_notifications: Cell::new(0),
                id_notifications: Cell::new(0),
                last_step: Cell::new(None),
            })
        }
    }

    #[tokio::test]
    async fn box_dyn_forwards_every_method() {
        let mut boxed: BoxedEapMethod = Box::new(Tracer {
            identity_notifications: Cell::new(0),
            id_notifications: Cell::new(0),
            last_step: Cell::new(None),
        });
        assert_eq!(boxed.typ(), EapType::MD5_CHALLENGE);
        boxed.notify_peer_identity(b"alice");
        boxed.notify_request_id(42);
        let out = boxed.start().await.unwrap();
        assert!(matches!(out, MethodOutcome::Continue(_)));
        let out = boxed.step(&[0xCC]).await.unwrap();
        assert!(matches!(out, MethodOutcome::Failure));
    }

    #[test]
    fn dyn_factory_reports_tag_and_boxes_method() {
        let f: DynFactory<TracerFactory> = DynFactory::new(EapType::PEAP, TracerFactory);
        // The tag is what the router matches against; it can
        // legitimately differ from the inner method's typ() —
        // adapters take responsibility for keeping them in sync.
        assert_eq!(f.typ(), EapType::PEAP);
        let boxed = f.create().unwrap();
        assert_eq!(boxed.typ(), EapType::MD5_CHALLENGE);
    }
}
