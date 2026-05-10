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
macro_rules! warn_ {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::WARN, $($tt)*) };
}

#[cfg(not(feature = "tracing"))]
macro_rules! warn_ {
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
