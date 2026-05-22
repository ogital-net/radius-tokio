//! Crate-local observability shim mirroring `radius_tokio::obs`.
//!
//! Mirrors the parent crate's pattern: the `info!` / `debug!` /
//! `warn!` / `trace!` / `count!` / `gauge!` macros expand to
//! `tracing` and `metrics` calls when their respective features
//! are enabled and to `()` when they are not. Call sites never
//! gate themselves on the features — they just emit, and the cfg
//! lives here.
//!
//! All events carry `target = "radius_tokio_eap"` so consumers
//! can filter the EAP crate independently of the core RADIUS
//! crate (`target = "radius_tokio"`).
//!
//! Stable metric names live in the [`metrics`] submodule and
//! are part of the observability contract.

/// Tracing target string for every event emitted by this crate.
#[allow(dead_code)] // unused when the `tracing` feature is off
pub(crate) const TARGET: &str = "radius_tokio_eap";

#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub(crate) use tracing::Level;

/// Stand-in for [`tracing::Level`] when the feature is off.
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

// ---- event macros --------------------------------------------------

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! info {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::INFO, $($tt)*) };
}
#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! info {
    ($($tt:tt)*) => {
        ()
    };
}

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! debug {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::DEBUG, $($tt)*) };
}
#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! debug {
    ($($tt:tt)*) => {
        ()
    };
}

#[cfg(feature = "tracing")]
#[allow(unused_macros)]
macro_rules! warn {
    ($($tt:tt)*) => { ::tracing::event!(target: $crate::obs::TARGET, ::tracing::Level::WARN, $($tt)*) };
}
#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! warn {
    ($($tt:tt)*) => {
        ()
    };
}

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

// ---- metric macros -------------------------------------------------

#[cfg(feature = "metrics")]
#[allow(unused_macros)]
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

// ---- stable metric names -------------------------------------------

/// Stable metric names for every counter / gauge this crate may
/// emit. All names share the `radius_tokio_eap.` prefix so they
/// don't collide with the core RADIUS crate's `radius_tokio.`
/// space. Renaming any constant is a breaking change for
/// downstream metric scrapes.
#[allow(dead_code)] // some constants only used when specific features are enabled
pub(crate) mod metrics {
    /// Counter: a new EAP session was created and registered in the
    /// per-handler table. Tag `method` carries the lowercase method
    /// name (`md5`, `mschapv2`, `tls`, `peap`, `ttls`).
    pub(crate) const SESSIONS_CREATED: &str = "radius_tokio_eap.sessions_created";

    /// Counter: an EAP session reached a terminal outcome. Tag
    /// `method` is the method name (as above); tag `outcome` is
    /// `success` (EAP-Success emitted), `failure` (EAP-Failure
    /// emitted), or `dropped` (router discarded the packet without
    /// reply).
    pub(crate) const SESSIONS_COMPLETED: &str = "radius_tokio_eap.sessions_completed";

    /// Counter: peer sent a Legacy-Nak proposing a different method
    /// and we pivoted to it. Tag `from` and `to` carry the lowercase
    /// method names involved.
    pub(crate) const NAK_PIVOTS: &str = "radius_tokio_eap.nak_pivots";

    /// Counter: peer sent a Legacy-Nak but the proposed method is
    /// not configured in the router. The session is terminated.
    pub(crate) const NAK_REJECTS: &str = "radius_tokio_eap.nak_rejects";

    /// Counter: inbound EAP fragment chain exceeded the configured
    /// reassembly bound. Always a drop — the supplicant either
    /// lied about the Total-Length or is attempting a resource
    /// exhaustion. Treated as a security event.
    pub(crate) const REASSEMBLY_OVERFLOWS: &str = "radius_tokio_eap.reassembly_overflows";

    /// Counter: an EAP method returned `MethodOutcome::Error`.
    /// Tag `method` carries the method name. Distinct from
    /// `SESSIONS_COMPLETED{outcome="failure"}` (which counts
    /// graceful EAP-Failure emission) — this counts internal
    /// errors before a Failure can be sent.
    pub(crate) const METHOD_ERRORS: &str = "radius_tokio_eap.method_errors";

    /// Counter: a TLS-tunnelled method finished its outer
    /// handshake. Tag `method` is `tls`, `peap`, or `ttls`.
    pub(crate) const TLS_HANDSHAKES_COMPLETED: &str = "radius_tokio_eap.tls_handshakes_completed";

    /// Counter: a TLS-tunnelled method exported keying material
    /// (RFC 5705) for the MSK / EMSK. Tag `method` is `tls`,
    /// `peap`, or `ttls`. One per successfully completed session.
    pub(crate) const MSK_DERIVATIONS: &str = "radius_tokio_eap.msk_derivations";

    /// Gauge: live entries in the per-`EapHandler` session table.
    /// Updated on every create and remove. A monotonically rising
    /// value across a steady-state workload indicates a leak in
    /// session reaping.
    pub(crate) const ACTIVE_SESSIONS: &str = "radius_tokio_eap.active_sessions";
}
