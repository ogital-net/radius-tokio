//! Per-session container + storage trait the handler adapter uses to
//! stitch multi-round EAP exchanges together across independent
//! RADIUS requests.
//!
//! EAP authentications span many `Access-Request` / `Access-Challenge`
//! round trips, but RADIUS itself is stateless: each request lands
//! on whatever worker the server dispatches it to. The standard
//! glue is the `State` attribute (RFC 2865 §5.24) — the server mints
//! an opaque token, sticks it on the challenge, and the NAS echoes
//! it on the follow-up request. The handler keys per-session state
//! off that token.
//!
//! This module provides:
//!
//! * [`SessionId`] — a 16-byte opaque token, randomly minted, that
//!   doubles as the `State` attribute value on the wire.
//! * [`Session`] — the in-memory record: the method state machine,
//!   the next EAP identifier, the peer's claimed identity, and
//!   whatever the handler needs to remember.
//! * [`SessionStore`] — async storage trait. The default
//!   [`InMemorySessionStore`] is a tokio `Mutex<HashMap>` that's
//!   adequate for single-process deployments; replace with a Redis
//!   / DynamoDB-backed impl for HA.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::method::EapMethod;

/// Opaque 16-byte per-session token. Doubles as the `State`
/// attribute value the handler emits on `Access-Challenge` and
/// expects to see echoed back on the next `Access-Request`.
///
/// 16 bytes (128 bits) is enough that a CSPRNG-minted token is
/// effectively unguessable, and it fits comfortably inside the
/// 253-byte RADIUS attribute value cap with room to spare for any
/// envelope a consumer might want to layer on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Length of [`SessionId`] in bytes.
    pub const LEN: usize = 16;

    /// Try to interpret a raw `State` attribute value as a session
    /// id. Returns `None` if the slice is the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; Self::LEN]>::try_from(bytes).ok().map(Self)
    }

    /// Borrow the underlying bytes for direct use as a `State`
    /// attribute value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Per-session record. Owned by the [`SessionStore`].
///
/// `M` is the concrete [`EapMethod`] implementation the
/// authenticator selected for this session — pinned at session
/// creation time and not changed thereafter (EAP method
/// renegotiation via `Nak` is handled by the handler adapter
/// before the session is committed to the store).
pub struct Session<M: EapMethod> {
    /// Method state machine driving this exchange.
    pub method: M,
    /// EAP `Identifier` byte to use on the *next* server-issued
    /// `EAP-Request`. The handler adapter increments this after
    /// every emit; per RFC 3748 §4.1 the value must change between
    /// consecutive requests so the peer can pair its response with
    /// the right outstanding request.
    pub next_eap_id: u8,
    /// Identity the peer asserted in `EAP-Response/Identity`, if
    /// the handler captured it. Surfaced verbatim — the handler
    /// doesn't try to normalize it.
    pub peer_identity: Option<Vec<u8>>,
    /// EAP `Type` bytes of methods already offered to this peer on
    /// this session. Populated by [`crate::MultiEapHandler`] so a
    /// peer cannot loop forever by `EAP-Nak`'ing every method the
    /// server pivots to. The single-method [`crate::EapHandler`]
    /// never touches it.
    pub tried_types: Vec<radius_tokio::eap::Type>,
}

impl<M: EapMethod> Session<M> {
    /// Build a new record around a freshly-created method state
    /// machine. The first server-issued EAP packet should use
    /// identifier `1` (chosen by [`Session::new`]).
    pub fn new(method: M) -> Self {
        Self {
            method,
            next_eap_id: 1,
            peer_identity: None,
            tried_types: Vec::new(),
        }
    }

    /// Allocate the next EAP identifier and advance the counter
    /// (wrapping at 256). The returned byte is what the handler
    /// stamps on the outbound `EAP-Request`.
    pub fn allocate_eap_id(&mut self) -> u8 {
        let id = self.next_eap_id;
        self.next_eap_id = self.next_eap_id.wrapping_add(1);
        id
    }
}

/// Storage trait the handler adapter uses to look up, persist, and
/// retire per-session state.
///
/// The trait is **async** so a future Redis/DynamoDB-backed impl
/// can do I/O inside its methods without resorting to
/// `tokio::task::block_in_place`. The bundled
/// [`InMemorySessionStore`] only needs a `tokio::sync::Mutex`, so
/// its futures resolve immediately.
///
/// All three methods take `&self` because the handler is shared
/// across worker tasks behind an `Arc`.
pub trait SessionStore: Send + Sync + 'static {
    /// Method state-machine type stored in this store.
    type Method: EapMethod;

    /// Insert a fresh session keyed by `id`. Replaces any existing
    /// entry with the same id (which would only happen if the
    /// caller's [`SessionId`] minter returned a collision — vanishingly
    /// unlikely at 128 bits).
    fn insert(
        &self,
        id: SessionId,
        session: Session<Self::Method>,
    ) -> impl std::future::Future<Output = ()> + Send;

    /// Remove and return the session for `id`, if present. The
    /// handler adapter takes the session out for the duration of a
    /// request and re-inserts it on completion (or drops it on
    /// terminal Success/Failure).
    fn take(
        &self,
        id: SessionId,
    ) -> impl std::future::Future<Output = Option<Session<Self::Method>>> + Send;
}

/// Process-local [`SessionStore`] backed by a `tokio::sync::Mutex<HashMap>`.
///
/// Adequate for single-process deployments where the same RADIUS
/// listener handles every request in a session. For HA / multi-process
/// deployments use an out-of-process store (Redis, `DynamoDB`, …) so
/// any worker can serve any session.
pub struct InMemorySessionStore<M: EapMethod> {
    inner: Arc<Mutex<HashMap<SessionId, Session<M>>>>,
}

impl<M: EapMethod> Default for InMemorySessionStore<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: EapMethod> InMemorySessionStore<M> {
    /// Build an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<M: EapMethod + 'static> SessionStore for InMemorySessionStore<M> {
    type Method = M;

    async fn insert(&self, id: SessionId, session: Session<Self::Method>) {
        self.inner.lock().await.insert(id, session);
    }

    async fn take(&self, id: SessionId) -> Option<Session<Self::Method>> {
        self.inner.lock().await.remove(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::MethodOutcome;

    struct Dummy;
    impl EapMethod for Dummy {
        fn typ(&self) -> radius_tokio::eap::Type {
            radius_tokio::eap::Type::TLS
        }
        fn start(&mut self) -> crate::method::MethodFuture<'_> {
            Box::pin(async move { Ok(MethodOutcome::Continue(vec![])) })
        }
        fn step<'a>(&'a mut self, _: &'a [u8]) -> crate::method::MethodFuture<'a> {
            Box::pin(async move { Ok(MethodOutcome::Failure) })
        }
    }

    #[test]
    fn session_id_round_trips_through_bytes() {
        let raw = [0xAB; SessionId::LEN];
        let id = SessionId::from_bytes(&raw).unwrap();
        assert_eq!(id.as_bytes(), &raw);
        assert!(SessionId::from_bytes(&[0u8; 15]).is_none());
        assert!(SessionId::from_bytes(&[0u8; 17]).is_none());
    }

    #[test]
    fn session_allocates_monotonic_then_wraps() {
        let mut s = Session::new(Dummy);
        assert_eq!(s.allocate_eap_id(), 1);
        assert_eq!(s.allocate_eap_id(), 2);
        s.next_eap_id = 255;
        assert_eq!(s.allocate_eap_id(), 255);
        assert_eq!(s.allocate_eap_id(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_store_round_trip() {
        let store: InMemorySessionStore<Dummy> = InMemorySessionStore::new();
        let id = SessionId([1; 16]);
        store.insert(id, Session::new(Dummy)).await;
        assert!(store.take(id).await.is_some());
        assert!(store.take(id).await.is_none());
    }
}
