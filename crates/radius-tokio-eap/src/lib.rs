//! TLS-tunnelled EAP methods for [`radius-tokio`](radius_tokio).
//!
//! The core `radius-tokio` crate ships the credential primitives
//! used by password-based RADIUS authentication (PAP, CHAP,
//! MS-CHAPv1/v2 verifiers, and the EAP-MD5 `MD5(eap_id || password
//! || challenge)` building blocks). This crate adds the EAP
//! *server state machines* that drive those primitives over the
//! `EAP-Message` codec:
//!
//! | Method        | Spec              | Inner method               | Cargo feature   |
//! |---------------|-------------------|----------------------------|-----------------|
//! | EAP-MD5       | RFC 3748 §5.4     | (none — bare)              | `eap-md5`       |
//! | EAP-MSCHAPv2  | draft-kamath §3   | (none — bare, legacy wired)| `eap-mschapv2`  |
//! | EAP-TLS       | RFC 5216 / 9190   | (none — TLS cert)          | `eap-tls`       |
//! | EAP-PEAP      | draft-josefsson   | EAP (commonly `MSCHAPv2`)  | `peap`          |
//! | EAP-TTLS      | RFC 5281          | AVP (PAP/CHAP/MS-CHAP/EAP) | `eap-ttls`      |
//!
//! All three share a TLS record stream wrapped in EAP-Message
//! fragmentation (RFC 5216 §3.1), so the [`framing`] module is
//! always available. Method drivers live behind their respective
//! cargo features.
//!
//! # Architecture
//!
//! ```text
//!   RADIUS Access-Request
//!         │
//!         ▼  EAP-Message reassembly  (radius_tokio::codec::eap)
//!   ┌────────────────┐
//!   │  EAP packet    │ Code/Identifier/Length/Type
//!   └────────────────┘
//!         │
//!         ▼  Type ∈ {TLS, PEAP, TTLS}
//!   ┌────────────────┐   Flags  L|M|S|Reserved|Version
//!   │  TLS-EAP frame │   [Length]  TLS-data fragment
//!   └────────────────┘   (this crate: framing.rs)
//!         │
//!         ▼  inbound reassembly / outbound fragmentation
//!   ┌────────────────┐
//!   │ TlsConnection  │   (radius_tokio::crypto::tls)
//!   └────────────────┘
//!         │
//!         ▼  TLS-protected payload → method-specific inner exchange
//!   ┌────────────────┐
//!   │  PEAP / TTLS   │   (method modules, feature-gated)
//!   │  inner         │
//!   └────────────────┘
//! ```
//!
//! # Scope
//!
//! This crate handles the *authentication server* side. The
//! supplicant (peer) side is out of scope: a RADIUS server library
//! never plays that role.
//!
//! # Stability
//!
//! Pre-1.0. The framing layer is stable in its shape (the spec
//! pins it); the method-driver APIs may shift as we shake them out
//! against real supplicants.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![warn(clippy::pedantic)]

pub mod error;
pub mod framing;
pub mod handler;
pub mod identity;
pub mod method;
pub mod router;
pub mod session;

/// Shared TLS-tunnel pipe used by every TLS-tunnelled EAP driver.
/// Compiled whenever any of `eap-tls`, `peap`, `eap-ttls` is on.
#[cfg(any(feature = "eap-tls", feature = "peap", feature = "eap-ttls"))]
pub(crate) mod tls_tunnel;

/// EAP-MD5-Challenge (RFC 3748 §5.4) server state machine.
/// Feature: `eap-md5`. Wraps the `radius_tokio::auth::eap_md5`
/// primitives in the [`EapMethod`] / [`MethodFactory`] surface so
/// it slots into [`EapHandler`] alongside the TLS-tunnelled
/// methods.
#[cfg(feature = "eap-md5")]
pub mod eap_md5;

/// EAP-TLS (RFC 5216 / RFC 9190) state machine. Feature: `eap-tls`.
#[cfg(feature = "eap-tls")]
pub mod eap_tls;

/// Trait surface for inner EAP methods carried inside a TLS
/// tunnel (PEAP today; future tunnel methods can plug in via the
/// same trait). Feature: `peap`.
#[cfg(feature = "peap")]
pub mod inner;

/// EAP-MSCHAPv2 server state machine. Carries two driver flavours
/// behind a shared codec:
///
/// * `MsChapV2Server` / `MsChapV2Factory` — inner method for
///   PEAP / EAP-TTLS tunnels (feature `peap`).
/// * `EapMsChapV2` / `EapMsChapV2Factory` — native/bare EAP type 26
///   for legacy wired 802.1X (feature `eap-mschapv2`).
#[cfg(any(feature = "peap", feature = "eap-mschapv2"))]
pub mod mschapv2;

/// PEAPv0 outer state machine (`draft-josefsson-pppext-eap-tls-eap`).
/// Feature: `peap`.
#[cfg(feature = "peap")]
pub mod peap;

/// EAP-TTLS outer state machine (RFC 5281), with a bundled PAP
/// inner method. Feature: `eap-ttls`.
#[cfg(feature = "eap-ttls")]
pub mod eap_ttls;

pub use error::Error;
pub use handler::{AcceptContext, AcceptDecorator, EapHandler};
pub use method::{
    BoxedEapMethod, DynFactory, DynMethodFactory, EapMethod, MethodFactory, MethodOutcome,
};
pub use router::{EapRouter, EapRouterBuilder, MultiEapHandler, RouterBuildError};
pub use session::{InMemorySessionStore, Session, SessionId, SessionStore};
