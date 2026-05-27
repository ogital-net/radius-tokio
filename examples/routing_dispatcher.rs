//! Example: two layers of routing.
//!
//! 1. **Outer (code-based)** — [`CodeRouter`] dispatches by RADIUS
//!    [`Code`] so each sub-handler only sees the code it
//!    registered for. The same router is shared across every
//!    listener (UDP auth, UDP accounting, and — if the `radsec`
//!    feature is enabled — a multiplexed RadSec connection that
//!    carries all four request codes).
//! 2. **Inner (attribute-based)** — inside the Access-Request
//!    sub-handler, dispatch on the credential the NAS supplied
//!    (EAP / PAP / CHAP) in a single pass over the attribute
//!    region using [`Request::attributes_iter`] +
//!    [`RawAttribute::matches`]. This is the idiom for multi-
//!    attribute presence routing — one walk, zero allocation, no
//!    extra API surface.
//!
//! Run with:
//!
//! ```text
//! cargo run --example routing_dispatcher
//! ```
//!
//! ## Why the inner layer is still hand-rolled
//!
//! `radius-tokio` deliberately does not ship a presence-bitmap
//! helper. When a sub-handler needs to dispatch on the combined
//! presence of several attributes, the opinionated idiom is:
//!
//! 1. Walk [`Request::attributes_iter`] *once*.
//! 2. Fold the predicates you care about into local booleans using
//!    [`RawAttribute::matches`] / [`matches_vsa`] / [`matches_tlv`].
//! 3. Match on the resulting tuple and hand off.
//!
//! For a single-attribute presence check use [`Request::contains`]
//! instead — it short-circuits on the first match.
//!
//! [`Handler`]: radius_tokio::server::Handler
//! [`CodeRouter`]: radius_tokio::server::CodeRouter
//! [`Request::attributes_iter`]: radius_tokio::server::Request::attributes_iter
//! [`Request::contains`]: radius_tokio::server::Request::contains
//! [`RawAttribute::matches`]: radius_tokio::codec::attributes::RawAttribute::matches
//! [`matches_vsa`]: radius_tokio::codec::attributes::RawAttribute::matches_vsa
//! [`matches_tlv`]: radius_tokio::codec::attributes::RawAttribute::matches_tlv

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use radius_tokio::dict::rfc::attrs;
use radius_tokio::server::{
    Client, CodeRouter, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server,
    StaticClients,
};
use radius_tokio::Code;

// ─── inner dispatch: which credential did the NAS supply? ──────

/// Which credential the NAS supplied, decided in one walk over the
/// request's attribute region.
#[derive(Debug, Clone, Copy)]
enum AuthType {
    Eap,
    Pap,
    Chap,
    /// Access-Request with no recognised credential — most NASes
    /// never send this, but it's a reply-Reject path worth keeping
    /// explicit rather than letting it fall through silently.
    Unknown,
}

/// Classify the request in one pass. Stops at the first malformed
/// attribute (the iterator yields `Err`), matching the rest of the
/// library's "halt on corruption" behaviour.
fn classify(req: &Request<'_>) -> AuthType {
    let (mut eap, mut pap, mut chap) = (false, false, false);
    for slot in req.attributes_iter() {
        let Ok(raw) = slot else { break };
        eap |= raw.matches(attrs::EAP_MESSAGE);
        pap |= raw.matches(attrs::USER_PASSWORD);
        chap |= raw.matches(attrs::CHAP_PASSWORD);
    }
    // EAP wins if present — an EAP-capable supplicant may also send
    // a dummy User-Password ("\0") per RFC 3579 §3.3, and routing on
    // PAP first would mis-dispatch those.
    match (eap, pap, chap) {
        (true, _, _) => AuthType::Eap,
        (_, true, _) => AuthType::Pap,
        (_, _, true) => AuthType::Chap,
        _ => AuthType::Unknown,
    }
}

// ─── shared state ──────────────────────────────────────────────

/// Trivial state object shared across every sub-handler. In a real
/// deployment this would hold a session store, a credential
/// backend, an EAP state-machine cache, etc. The point of using an
/// `Arc<Stats>` here is to show that sub-handlers can freely share
/// per-server state without the router having to know about it.
#[derive(Default)]
struct Stats {
    access: AtomicU64,
    accounting: AtomicU64,
    coa: AtomicU64,
    disconnect: AtomicU64,
}

impl Stats {
    fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.access.load(Ordering::Relaxed),
            self.accounting.load(Ordering::Relaxed),
            self.coa.load(Ordering::Relaxed),
            self.disconnect.load(Ordering::Relaxed),
        )
    }
}

// ─── per-code sub-handlers ─────────────────────────────────────
//
// Each sub-handler is its own `Handler` impl. None of them need to
// check `request.code()` — the outer `CodeRouter` already routed
// the request to the right slot.

/// Access-Request sub-handler. Performs the attribute-based inner
/// dispatch (EAP / PAP / CHAP / Unknown).
struct AccessHandler {
    stats: Arc<Stats>,
}

impl Handler for AccessHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.stats.access.fetch_add(1, Ordering::Relaxed);

        let flavour = classify(&request);
        let reply_code = match flavour {
            AuthType::Eap | AuthType::Pap | AuthType::Chap => Code::ACCESS_ACCEPT,
            AuthType::Unknown => Code::ACCESS_REJECT,
        };

        println!(
            "access:    id={} src={} flavour={:?} -> {:?}",
            request.identifier(),
            request.src(),
            flavour,
            reply_code,
        );

        let mut reply = request.reply(reply_code);
        if matches!(reply_code, Code::ACCESS_ACCEPT) {
            reply.add(attrs::SESSION_TIMEOUT, 3600u32).unwrap();
        }
        HandlerResult::Reply(reply)
    }
}

/// Accounting-Request sub-handler. Echoes with the canonical
/// Accounting-Response per RFC 2866 §4.2.
struct AccountingHandler {
    stats: Arc<Stats>,
}

impl Handler for AccountingHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.stats.accounting.fetch_add(1, Ordering::Relaxed);
        println!(
            "acct:      id={} src={} status={:?}",
            request.identifier(),
            request.src(),
            request.acct_status_type(),
        );
        HandlerResult::Reply(request.reply(Code::ACCOUNTING_RESPONSE))
    }
}

/// CoA-Request sub-handler. Replies with CoA-ACK using the typed
/// helper [`Request::coa_ack`].
struct CoaHandler {
    stats: Arc<Stats>,
}

impl Handler for CoaHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.stats.coa.fetch_add(1, Ordering::Relaxed);
        println!(
            "coa:       id={} src={}",
            request.identifier(),
            request.src(),
        );
        // `coa_ack()` returns Some on CoA-Request / Disconnect-Request
        // and None on anything else — but the router guarantees we
        // only see CoA-Request here, so the unwrap is structurally
        // safe.
        HandlerResult::Reply(
            request
                .coa_ack()
                .expect("CodeRouter guarantees CoA-Request"),
        )
    }
}

/// Disconnect-Request sub-handler. Same shape as the CoA handler —
/// kept separate to make the routing structure obvious.
struct DisconnectHandler {
    stats: Arc<Stats>,
}

impl Handler for DisconnectHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.stats.disconnect.fetch_add(1, Ordering::Relaxed);
        println!(
            "disc:      id={} src={}",
            request.identifier(),
            request.src(),
        );
        HandlerResult::Reply(
            request
                .coa_ack()
                .expect("CodeRouter guarantees Disconnect-Request"),
        )
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Single shared state object cloned into every sub-handler —
    // exactly the pattern a real deployment uses to plumb a session
    // store, credential backend, etc.
    let stats = Arc::new(Stats::default());

    // Build the outer router. Each slot is its own `Handler` and
    // sees only the code it registered for; no `match request.code()`
    // boilerplate inside the sub-handlers.
    let router = CodeRouter::builder()
        .access_request(AccessHandler {
            stats: stats.clone(),
        })
        .accounting(AccountingHandler {
            stats: stats.clone(),
        })
        .coa(CoaHandler {
            stats: stats.clone(),
        })
        .disconnect(DisconnectHandler {
            stats: stats.clone(),
        })
        .build();

    let client = Arc::new(Client::new(b"shared-secret".as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    // The same `router` is reused across every listener. The
    // per-listener `ListenerRole` filter drops mismatched codes
    // before they ever reach the router, so e.g. the auth socket
    // can never accidentally invoke the accounting sub-handler.
    //
    // If the `radsec` feature is enabled, you'd typically add:
    //
    //   .listen_radsec(":2083".parse().unwrap(), tls_ctx)
    //
    // which carries every request code on one TLS connection and
    // fans them out through the same router — illustrating the
    // "single handler set, every transport" payoff of `CodeRouter`.
    let server = Server::builder()
        .clients(store)
        .handler(router)
        .listen_udp("127.0.0.1:1812".parse().unwrap()) // auth (Access-Request only)
        .listen_udp_with("127.0.0.1:1813".parse().unwrap(), ListenerRole::Acct)
        .listen_udp_with("127.0.0.1:3799".parse().unwrap(), ListenerRole::Any) // CoA + Disconnect
        .build()?;

    println!("radius-tokio routing example listening:");
    println!("  127.0.0.1:1812  auth    (Access-Request)");
    println!("  127.0.0.1:1813  acct    (Accounting-Request)");
    println!("  127.0.0.1:3799  dynauth (CoA + Disconnect)");
    println!();

    // Periodic counters so the shared-state pattern is observable.
    let stats_for_ticker = stats.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            let (a, b, c, d) = stats_for_ticker.snapshot();
            println!("stats: access={a} acct={b} coa={c} disc={d}");
        }
    });

    server.run().await
}
