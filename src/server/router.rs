//! [`CodeRouter`] — a [`Handler`] adapter that dispatches by RADIUS
//! [`Code`] so individual sub-handlers never have to re-check
//! `request.code()` themselves.
//!
//! ## Motivation
//!
//! Every [`ListenerRole`](super::ListenerRole) already drops
//! mismatched codes before any cryptographic work, so by the time a
//! [`Handler::handle`] call fires the request is guaranteed to carry
//! a code legal for *that listener*. A deployment that runs auth,
//! accounting, and CoA on the same [`Server`](super::Server) (or a
//! single multiplexed RadSec listener carrying all three) still has
//! to disambiguate at the handler level, though — typically with a
//! verbose `match request.code()` at the top of `handle`.
//!
//! `CodeRouter` collapses that boilerplate. Slot the per-code logic
//! into the builder once, hand the router to
//! [`ServerBuilder::handler`](super::ServerBuilder::handler), and
//! the library does the second check on every dispatch.
//!
//! ## Transport story
//!
//! `CodeRouter` is itself a [`Handler`], so the server stores a
//! single `Arc<CodeRouter>` and clones it into every UDP datagram
//! task and every RadSec connection task. Sub-handlers are shared
//! across **all** listeners by construction — no per-transport
//! wiring, no duplicate state.
//!
//! ## Example
//!
//! ```ignore
//! use radius_tokio::server::{CodeRouter, Server, ListenerRole};
//!
//! let router = CodeRouter::builder()
//!     .access_request(auth_handler)
//!     .accounting(acct_handler)
//!     .coa(coa_handler)
//!     .disconnect(disconnect_handler)
//!     .build();
//!
//! Server::builder()
//!     .clients(store)
//!     .handler(router)
//!     .listen_udp("0.0.0.0:1812".parse()?)
//!     .listen_udp_with("0.0.0.0:1813".parse()?, ListenerRole::Acct)
//!     .listen_udp_with("0.0.0.0:3799".parse()?, ListenerRole::Any)
//!     // .listen_radsec(":2083".parse()?, tls)  // same router, all codes
//!     .build();
//! ```
//!
//! ## Cost
//!
//! Each dispatch pays for one `Box::pin` allocation of the
//! sub-handler's future. This is negligible next to the MD5 /
//! HMAC-MD5 / socket work the surrounding pipeline already does,
//! and matches the dispatch pattern used by the major Rust web
//! frameworks (`axum`, `tower`). Consumers who want zero-allocation
//! dispatch can still hand-roll a single `Handler` impl that
//! matches on `request.code()` directly.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::codec::header::Code;

use super::handler::{Handler, HandlerResult, Request};

/// Boxed-future shim so `CodeRouter` can hold heterogeneously
/// typed sub-handlers behind a single trait object.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Internal object-safe view of [`Handler`].
///
/// `Handler::handle` returns `impl Future + Send`, which is not
/// object-safe. We bridge to a boxed future here so the router can
/// store sub-handlers behind `Arc<dyn DynHandler>` without forcing
/// every slot to share a concrete type.
trait DynHandler: Send + Sync + 'static {
    fn handle_dyn<'a>(&'a self, request: Request<'a>) -> BoxFuture<'a, HandlerResult>;
}

impl<H: Handler> DynHandler for H {
    #[inline]
    fn handle_dyn<'a>(&'a self, request: Request<'a>) -> BoxFuture<'a, HandlerResult> {
        Box::pin(Handler::handle(self, request))
    }
}

/// [`Handler`] adapter that dispatches by RADIUS [`Code`].
///
/// See the [module-level docs](self) for the motivation and the
/// transport story.
pub struct CodeRouter {
    access_request: Option<Arc<dyn DynHandler>>,
    accounting: Option<Arc<dyn DynHandler>>,
    coa: Option<Arc<dyn DynHandler>>,
    disconnect: Option<Arc<dyn DynHandler>>,
    status_server: Option<Arc<dyn DynHandler>>,
    fallback: Option<Arc<dyn DynHandler>>,
}

impl std::fmt::Debug for CodeRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeRouter")
            .field("access_request", &self.access_request.is_some())
            .field("accounting", &self.accounting.is_some())
            .field("coa", &self.coa.is_some())
            .field("disconnect", &self.disconnect.is_some())
            .field("status_server", &self.status_server.is_some())
            .field("fallback", &self.fallback.is_some())
            .finish()
    }
}

impl CodeRouter {
    /// Start a fresh builder. Every slot defaults to unset; an
    /// unmatched code falls through to the [`fallback`] handler if
    /// one is configured, otherwise [`HandlerResult::Drop`].
    ///
    /// [`fallback`]: CodeRouterBuilder::fallback
    #[must_use]
    pub fn builder() -> CodeRouterBuilder {
        CodeRouterBuilder::default()
    }

    /// Pick the sub-handler for `code`, falling back to the
    /// catch-all if no code-specific handler was registered.
    fn route(&self, code: Code) -> Option<&Arc<dyn DynHandler>> {
        let slot = match code {
            Code::ACCESS_REQUEST => self.access_request.as_ref(),
            Code::ACCOUNTING_REQUEST => self.accounting.as_ref(),
            Code::COA_REQUEST => self.coa.as_ref(),
            Code::DISCONNECT_REQUEST => self.disconnect.as_ref(),
            Code::STATUS_SERVER => self.status_server.as_ref(),
            _ => None,
        };
        slot.or(self.fallback.as_ref())
    }
}

impl Handler for CodeRouter {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        match self.route(request.code()) {
            Some(handler) => handler.handle_dyn(request).await,
            None => HandlerResult::Drop,
        }
    }
}

/// Builder for [`CodeRouter`].
///
/// Slots default to unset. An unset slot drops the request (or
/// delegates to [`fallback`](Self::fallback) if one is configured)
/// — handy when a deployment intentionally hosts only one code
/// family.
#[derive(Default)]
pub struct CodeRouterBuilder {
    access_request: Option<Arc<dyn DynHandler>>,
    accounting: Option<Arc<dyn DynHandler>>,
    coa: Option<Arc<dyn DynHandler>>,
    disconnect: Option<Arc<dyn DynHandler>>,
    status_server: Option<Arc<dyn DynHandler>>,
    fallback: Option<Arc<dyn DynHandler>>,
}

impl std::fmt::Debug for CodeRouterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeRouterBuilder")
            .field("access_request", &self.access_request.is_some())
            .field("accounting", &self.accounting.is_some())
            .field("coa", &self.coa.is_some())
            .field("disconnect", &self.disconnect.is_some())
            .field("status_server", &self.status_server.is_some())
            .field("fallback", &self.fallback.is_some())
            .finish()
    }
}

impl CodeRouterBuilder {
    /// Handler for `Access-Request` (code 1).
    #[must_use]
    pub fn access_request<H: Handler>(mut self, handler: H) -> Self {
        self.access_request = Some(Arc::new(handler));
        self
    }

    /// Handler for `Accounting-Request` (code 4, RFC 2866).
    #[must_use]
    pub fn accounting<H: Handler>(mut self, handler: H) -> Self {
        self.accounting = Some(Arc::new(handler));
        self
    }

    /// Handler for `CoA-Request` (code 43, RFC 5176).
    #[must_use]
    pub fn coa<H: Handler>(mut self, handler: H) -> Self {
        self.coa = Some(Arc::new(handler));
        self
    }

    /// Handler for `Disconnect-Request` (code 40, RFC 5176).
    #[must_use]
    pub fn disconnect<H: Handler>(mut self, handler: H) -> Self {
        self.disconnect = Some(Arc::new(handler));
        self
    }

    /// Handler for `Status-Server` (code 12, RFC 5997).
    ///
    /// Note: the built-in
    /// [`StatusResponder`](super::status::StatusResponder)
    /// intercepts Status-Server probes before they reach the user
    /// handler whenever
    /// [`StatusServerPolicy`](super::status::StatusServerPolicy)
    /// is `Enabled` (the default). This slot is therefore only
    /// reached when the policy is `Disabled` and the operator
    /// wants to answer probes from their own logic.
    #[must_use]
    pub fn status_server<H: Handler>(mut self, handler: H) -> Self {
        self.status_server = Some(Arc::new(handler));
        self
    }

    /// Catch-all handler invoked for any code without a specific
    /// slot, and for unknown / vendor-extension codes.
    ///
    /// Without a fallback, unmatched codes resolve to
    /// [`HandlerResult::Drop`].
    #[must_use]
    pub fn fallback<H: Handler>(mut self, handler: H) -> Self {
        self.fallback = Some(Arc::new(handler));
        self
    }

    /// Finalize the router.
    #[must_use]
    pub fn build(self) -> CodeRouter {
        CodeRouter {
            access_request: self.access_request,
            accounting: self.accounting,
            coa: self.coa,
            disconnect: self.disconnect,
            status_server: self.status_server,
            fallback: self.fallback,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::server::handler::test_support::MockRequest;
    use crate::server::Client;

    /// Test handler that records every code it sees and replies
    /// with a fixed reply code (so we can also confirm the
    /// dispatch wired through the right sub-handler).
    struct Recorder {
        hits: Arc<AtomicU8>,
        reply_code: Code,
    }

    impl Handler for Recorder {
        async fn handle(&self, request: Request<'_>) -> HandlerResult {
            self.hits.fetch_add(1, Ordering::SeqCst);
            HandlerResult::Reply(request.reply(self.reply_code))
        }
    }

    fn make_recorder(reply_code: Code) -> (Recorder, Arc<AtomicU8>) {
        let hits = Arc::new(AtomicU8::new(0));
        (
            Recorder {
                hits: hits.clone(),
                reply_code,
            },
            hits,
        )
    }

    fn run_with_code(router: &CodeRouter, code: Code) -> HandlerResult {
        let client = Arc::new(Client::new(b"s".as_slice()));
        let mock = MockRequest::new().code(code);
        let req = mock.build(&client);
        // The dispatch never awaits its future on the recorder
        // futures (they're not async-await pending on I/O), so a
        // tiny block_on is fine for unit testing.
        futures_executor_block_on(router.handle(req))
    }

    /// Minimal future executor — pulls in no extra deps.
    fn futures_executor_block_on<F: Future>(mut fut: F) -> F::Output {
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let waker: Waker = Arc::new(NoopWaker).into();
        let mut cx = Context::from_waker(&waker);
        // Safety: we own `fut` and never move it after this point.
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn router_dispatches_each_code_to_its_slot() {
        let (auth, auth_hits) = make_recorder(Code::ACCESS_ACCEPT);
        let (acct, acct_hits) = make_recorder(Code::ACCOUNTING_RESPONSE);
        let (coa, coa_hits) = make_recorder(Code::COA_ACK);
        let (disc, disc_hits) = make_recorder(Code::DISCONNECT_ACK);

        let router = CodeRouter::builder()
            .access_request(auth)
            .accounting(acct)
            .coa(coa)
            .disconnect(disc)
            .build();

        for (code, expected_reply, hits) in [
            (Code::ACCESS_REQUEST, Code::ACCESS_ACCEPT, &auth_hits),
            (
                Code::ACCOUNTING_REQUEST,
                Code::ACCOUNTING_RESPONSE,
                &acct_hits,
            ),
            (Code::COA_REQUEST, Code::COA_ACK, &coa_hits),
            (Code::DISCONNECT_REQUEST, Code::DISCONNECT_ACK, &disc_hits),
        ] {
            let result = run_with_code(&router, code);
            match result {
                HandlerResult::Reply(reply) => {
                    let client = Arc::new(Client::new(b"s".as_slice()));
                    let sealed = reply.seal_for(&[0; 16], client.secret());
                    assert_eq!(sealed.header().code, expected_reply, "code {code:?}");
                }
                HandlerResult::Drop => panic!("expected reply for code {code:?}"),
            }
            assert_eq!(hits.load(Ordering::SeqCst), 1, "hits for code {code:?}");
        }
    }

    #[test]
    fn unmatched_code_drops_without_fallback() {
        let router = CodeRouter::builder().build();
        let result = run_with_code(&router, Code::ACCESS_REQUEST);
        assert!(matches!(result, HandlerResult::Drop));
    }

    #[test]
    fn fallback_catches_unmatched_codes() {
        let (fallback, hits) = make_recorder(Code::ACCESS_REJECT);
        let router = CodeRouter::builder().fallback(fallback).build();

        let result = run_with_code(&router, Code::ACCESS_REQUEST);
        assert!(matches!(result, HandlerResult::Reply(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // And an unknown code likewise lands on the fallback.
        let result = run_with_code(&router, Code(99));
        assert!(matches!(result, HandlerResult::Reply(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn specific_slot_wins_over_fallback() {
        let (auth, auth_hits) = make_recorder(Code::ACCESS_ACCEPT);
        let (fallback, fallback_hits) = make_recorder(Code::ACCESS_REJECT);
        let router = CodeRouter::builder()
            .access_request(auth)
            .fallback(fallback)
            .build();

        let _ = run_with_code(&router, Code::ACCESS_REQUEST);
        assert_eq!(auth_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);

        // Accounting has no specific slot → fallback.
        let _ = run_with_code(&router, Code::ACCOUNTING_REQUEST);
        assert_eq!(auth_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sub_handlers_can_share_state_via_arc() {
        // Shared counter across two slots — proves a single
        // Arc<State> can be cloned into multiple sub-handlers and
        // observed from each.
        struct Counting {
            shared: Arc<AtomicU8>,
            reply: Code,
        }
        impl Handler for Counting {
            async fn handle(&self, request: Request<'_>) -> HandlerResult {
                self.shared.fetch_add(1, Ordering::SeqCst);
                HandlerResult::Reply(request.reply(self.reply))
            }
        }

        let shared = Arc::new(AtomicU8::new(0));
        let router = CodeRouter::builder()
            .access_request(Counting {
                shared: shared.clone(),
                reply: Code::ACCESS_ACCEPT,
            })
            .accounting(Counting {
                shared: shared.clone(),
                reply: Code::ACCOUNTING_RESPONSE,
            })
            .build();

        let _ = run_with_code(&router, Code::ACCESS_REQUEST);
        let _ = run_with_code(&router, Code::ACCOUNTING_REQUEST);
        let _ = run_with_code(&router, Code::ACCESS_REQUEST);
        assert_eq!(shared.load(Ordering::SeqCst), 3);
    }
}
