//! Internal observability shim.
//!
//! Provides a tiny set of macros that expand to [`tracing`] events
//! when the `tracing` Cargo feature is enabled and to nothing when it
//! is not. Centralising the conditional compile keeps the call sites
//! free of `#[cfg(feature = "tracing")]` clutter and guarantees that
//! the *off* configuration costs literally zero — every macro becomes
//! an empty token sequence at parse time.
//!
//! # Why not call `tracing::event!` directly?
//!
//! Two reasons:
//!
//! 1. We want truly zero overhead when the feature is off, including
//!    no formatter argument evaluation. The `tracing` crate's own
//!    macros are already cheap when no subscriber is installed (an
//!    atomic load + branch), but they always evaluate format args.
//!    Wrapping in `cfg!` would help; wrapping in `#[cfg]` is better.
//!
//! 2. We want the *shape* of our diagnostics to be a deliberate API
//!    rather than a scatter of one-off `tracing::debug!` calls. The
//!    field set used here (`event = "name", code = ?, ...`) is the
//!    contract the tracing-subscriber tests pin against.
//!
//! All events are scoped to the [`TARGET`] string so consumers can
//! filter the crate's noise independently from their own
//! (`RUST_LOG=radius_tokio=debug`).

/// `tracing` target string applied to every event and span this
/// crate emits. Exposed as a `pub(crate)` constant so the value is
/// defined in one place; downstream filter strings (`RUST_LOG=...`)
/// must match it byte-for-byte.
pub(crate) const TARGET: &str = "radius_tokio";

/// `tracing::Level` re-export so call sites can name levels without
/// adding the dependency themselves.
#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub(crate) use tracing::Level;

/// Stand-in for [`tracing::Level`] when the `tracing` feature is off.
/// Carries the same associated constants so `obs::Level::DEBUG`
/// type-checks in either configuration.
#[cfg(not(feature = "tracing"))]
#[allow(dead_code)]
pub(crate) struct Level;

#[cfg(not(feature = "tracing"))]
#[allow(dead_code)]
impl Level {
    pub(crate) const ERROR: Level = Level;
    pub(crate) const WARN: Level = Level;
    pub(crate) const INFO: Level = Level;
    pub(crate) const DEBUG: Level = Level;
    pub(crate) const TRACE: Level = Level;
}

/// Emit an `INFO`-level event. Used for lifecycle (bind, shutdown,
/// `CoA` originator construction) — anything an operator wants in
/// the log even at default verbosity.
#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! info {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::INFO, $($tt)*) };
}

#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($tt:tt)*) => {
        ()
    };
}

/// Emit a `DEBUG`-level event. Used per-packet on the happy path
/// (request accepted, reply sent). Off at default verbosity.
#[cfg(feature = "tracing")]
macro_rules! debug {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::DEBUG, $($tt)*) };
}

#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($tt:tt)*) => {
        ()
    };
}

/// Emit a `WARN`-level event. Used for silent-drop conditions an
/// operator probably wants to see (bad authenticator, malformed
/// header from a known client, retransmit storm).
#[cfg(feature = "tracing")]
macro_rules! warn {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::WARN, $($tt)*) };
}

#[cfg(not(feature = "tracing"))]
macro_rules! warn {
    ($($tt:tt)*) => {
        ()
    };
}

/// Emit a `TRACE`-level event. Used for the noisiest details (per-
/// attribute decisions, dedup key composition). Almost certainly off
/// in production.
#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! trace {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::TRACE, $($tt)*) };
}

#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! trace {
    ($($tt:tt)*) => {
        ()
    };
}

/// Open a span. Returns a `tracing::Span` when the feature is on, or
/// `()` when off. Call sites use it as
/// `let _enter = obs::span!(...).entered();` — the `.entered()`
/// shim below preserves the same call shape in both configurations.
#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! span {
    ($lvl:expr, $name:expr, $($tt:tt)*) => {
        ::tracing::span!(target: $crate::obs::TARGET, $lvl, $name, $($tt)*)
    };
    ($lvl:expr, $name:expr) => {
        ::tracing::span!(target: $crate::obs::TARGET, $lvl, $name)
    };
}

#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! span {
    ($lvl:expr, $name:expr, $($tt:tt)*) => {
        $crate::obs::NoopSpan
    };
    ($lvl:expr, $name:expr) => {
        $crate::obs::NoopSpan
    };
}

/// Stand-in for [`tracing::Span`] when the feature is off. Implements
/// the subset of the API our call sites use (`entered()`).
#[cfg(not(feature = "tracing"))]
#[derive(Clone, Copy)]
pub(crate) struct NoopSpan;

#[cfg(not(feature = "tracing"))]
impl NoopSpan {
    /// No-op stand-in for [`tracing::Span::entered`]. Returns a guard
    /// that does nothing on drop.
    #[inline]
    #[must_use]
    #[allow(clippy::unused_self)] // mirrors tracing::Span::entered() signature intentionally
    pub(crate) const fn entered(self) -> NoopGuard {
        NoopGuard
    }
}

/// Guard returned by `NoopSpan::entered`. Zero-sized; dropping it is
/// a no-op.
#[cfg(not(feature = "tracing"))]
pub(crate) struct NoopGuard;

/// Increment a named counter by 1. Usage:
///
/// ```ignore
/// count!("radius_tokio.packets_dropped", "reason" => "unknown_client");
/// ```
///
/// Expands to [`metrics::counter!`] when the `metrics` feature is enabled
/// and to nothing when it is not.
#[cfg(feature = "metrics")]
macro_rules! count {
    ($name:expr $(,)?) => {
        ::metrics::counter!($name).increment(1)
    };
    ($name:expr, $($key:literal => $val:expr),+ $(,)?) => {
        ::metrics::counter!($name, $($key => $val),+).increment(1)
    };
}

#[cfg(not(feature = "metrics"))]
#[allow(unused_macros)]
macro_rules! count {
    ($($tt:tt)*) => {
        ()
    };
}

/// Record an [`f64`] observation into a histogram. Usage:
///
/// ```ignore
/// observe!("radius_tokio.handler_duration_seconds", elapsed.as_secs_f64());
/// ```
///
/// Expands to [`metrics::histogram!`] when the `metrics` feature is enabled
/// and to nothing when it is not.
#[cfg(feature = "metrics")]
macro_rules! observe {
    ($name:expr, $value:expr $(,)?) => {
        ::metrics::histogram!($name).record($value)
    };
}

#[cfg(not(feature = "metrics"))]
#[allow(unused_macros)]
macro_rules! observe {
    ($($tt:tt)*) => {
        ()
    };
}

/// Set a named gauge to an absolute value. Usage:
///
/// ```ignore
/// gauge!("radius_tokio.radsec_active_connections", count as f64);
/// gauge!("radius_tokio.client_cache_size", size as f64, "role" => "udp");
/// ```
///
/// Expands to [`metrics::gauge!`] when the `metrics` feature is
/// enabled and to nothing when it is not.
#[cfg(feature = "metrics")]
#[allow(unused_macros)]
macro_rules! gauge {
    ($name:expr, $value:expr $(,)?) => {
        ::metrics::gauge!($name).set($value)
    };
    ($name:expr, $value:expr, $($key:literal => $val:expr),+ $(,)?) => {
        ::metrics::gauge!($name, $($key => $val),+).set($value)
    };
}

#[cfg(not(feature = "metrics"))]
#[allow(unused_macros)]
macro_rules! gauge {
    ($($tt:tt)*) => {
        ()
    };
}

/// Stable metric names emitted by the crate.
///
/// Every `count!` / `observe!` call site in the runtime uses one of
/// these constants instead of a string literal, so a typo is caught
/// at compile time and operators have a single place to consult when
/// wiring up a dashboard. The string values are part of the
/// observability contract — renaming any of them is a breaking change
/// for downstream metric scrapes.
///
/// All names share the `radius_tokio.` prefix; tags / labels are
/// applied per-call-site at the emit point.
#[allow(dead_code)] // Some constants only used when specific features are enabled.
pub(crate) mod metrics {
    /// Counter: packets the receive pipeline discarded before
    /// dispatch. Tag `reason` distinguishes `unknown_client`,
    /// `malformed_header`, `bad_request_authenticator`,
    /// `missing_message_authenticator`, `bad_message_authenticator`,
    /// `handler_drop`, `dispatch_error`, `unsupported_code`.
    pub(crate) const PACKETS_DROPPED: &str = "radius_tokio.packets_dropped";

    /// Counter: requests handed to the consumer handler. Tag `code`
    /// carries the decimal RADIUS code byte.
    pub(crate) const REQUESTS_DISPATCHED: &str = "radius_tokio.requests_dispatched";

    /// Counter: dedup-cache hits where a cached reply was
    /// retransmitted in place of running the handler again.
    pub(crate) const DEDUP_HITS: &str = "radius_tokio.dedup_hits";

    /// Counter: replies successfully written to the wire. Tag `code`
    /// carries the decimal RADIUS reply code byte.
    pub(crate) const REPLIES_SENT: &str = "radius_tokio.replies_sent";

    /// Counter: send-side I/O errors from the transport socket.
    pub(crate) const SEND_ERRORS: &str = "radius_tokio.send_errors";

    /// Counter: built-in Status-Server replies emitted (RFC 5997).
    /// Tag `transport` is `udp` or `radsec`.
    pub(crate) const STATUS_SERVER_REPLIES: &str = "radius_tokio.status_server_replies";

    /// Counter: `RadSec` connections rejected by the pre-handshake
    /// admission gate ([`ClientStore::admit_radsec`]).
    ///
    /// [`ClientStore::admit_radsec`]: crate::server::ClientStore::admit_radsec
    pub(crate) const RADSEC_ADMIT_REJECTS: &str = "radius_tokio.radsec_admit_rejects";

    /// Counter: `RadSec` mTLS handshakes that failed.
    pub(crate) const RADSEC_HANDSHAKE_FAILURES: &str = "radius_tokio.radsec_handshake_failures";

    /// Counter: post-handshake cert-to-client lookups that failed.
    /// Tag `reason` is `missing` or `denied`.
    pub(crate) const RADSEC_CERT_LOOKUP_FAILURES: &str = "radius_tokio.radsec_cert_lookup_failures";

    /// Counter: `RadSec` connections that completed the handshake
    /// and entered the per-connection serve loop.
    pub(crate) const RADSEC_CONNECTIONS: &str = "radius_tokio.radsec_connections";

    /// Counter: peer-initiated TLS key updates handled mid-connection.
    pub(crate) const RADSEC_KEY_UPDATES: &str = "radius_tokio.radsec_key_updates";

    /// Counter: live `RadSec` connections torn down by
    /// [`Server::close_connections_for`](crate::server::Server::close_connections_for).
    pub(crate) const RADSEC_REVOCATIONS_APPLIED: &str = "radius_tokio.radsec_revocations_applied";

    /// Histogram: wall-clock seconds spent inside the consumer
    /// handler, sampled per dispatched request.
    pub(crate) const HANDLER_DURATION_SECONDS: &str = "radius_tokio.handler_duration_seconds";

    // ---- CoA originator (RFC 5176) ----------------------------------

    /// Counter: requests the [`CoaOriginator`](crate::server::coa::CoaOriginator)
    /// emitted on the wire. Tag `code` carries the decimal RADIUS
    /// code byte (40 = Disconnect-Request, 43 = CoA-Request).
    pub(crate) const COA_REQUESTS_SENT: &str = "radius_tokio.coa_requests_sent";

    /// Counter: CoA / Disconnect retransmissions (excluding the
    /// initial send). Untagged — the retry path does not know the
    /// originating code at the point it ticks.
    pub(crate) const COA_RETRANSMITS: &str = "radius_tokio.coa_retransmits";

    /// Counter: terminal outcome for each originated CoA /
    /// Disconnect. Tag `outcome` is `ack`, `nak`, `timeout`, or
    /// `error`.
    pub(crate) const COA_OUTCOMES: &str = "radius_tokio.coa_outcomes";

    // ---- Gauges (lifecycle / cache occupancy) -----------------------

    /// Gauge: number of `RadSec` connections currently held in the
    /// per-server [`ConnectionRegistry`](crate::server::radsec).
    /// Updated on every connection accept and drop. A monotonically
    /// rising value is a leak; a sustained ceiling indicates a NAS
    /// holding connections open without traffic.
    pub(crate) const RADSEC_ACTIVE_CONNECTIONS: &str = "radius_tokio.radsec_active_connections";

    /// Gauge: total entries across every shard of the
    /// dedup / retransmit cache. Updated after each `insert` (which
    /// is also when the cache is swept for expired entries), so the
    /// value lags by at most one packet per source.
    pub(crate) const DEDUP_CACHE_SIZE: &str = "radius_tokio.dedup_cache_size";

    /// Gauge: entries currently held in the
    /// [`CachedStore`](crate::server::CachedStore) client cache.
    /// Sum of resolved positive, resolved negative, and in-flight
    /// (`Pending`) slots.
    pub(crate) const CLIENT_CACHE_SIZE: &str = "radius_tokio.client_cache_size";

    /// Counter: client-cache lookups that returned a fresh hit
    /// without consulting the backend.
    pub(crate) const CLIENT_CACHE_HITS: &str = "radius_tokio.client_cache_hits";

    /// Counter: client-cache lookups that missed and triggered a
    /// backend call. Tag `result` is `positive` or `negative`
    /// depending on what the backend returned.
    pub(crate) const CLIENT_CACHE_MISSES: &str = "radius_tokio.client_cache_misses";
}
