//! Trait surface for **inner** EAP methods carried inside a TLS
//! tunnel (PEAP today; EAP-TTLS in the future).
//!
//! The split exists because the outer driver (PEAP / TTLS) is
//! responsible for TLS framing, fragmentation, MSK derivation, and
//! the eventual `EAP-Success` / `EAP-Failure` on the *outer* EAP
//! conversation. The inner method only sees plaintext EAP packets:
//!
//! ```text
//!   peer ─┐                                ┌─ server
//!         │   outer TLS-EAP fragments      │
//!         ├────────────────────────────────┤
//!         │                                │
//!         │   plaintext inner EAP          │
//!         │   ┌──────────────┐             │
//!         └──▶│ InnerEap     │◀────────────┘
//!             │ (this trait) │
//!             └──────────────┘
//! ```
//!
//! Inner methods are EAP-aware state machines: they consume
//! full EAP packets (Code | Identifier | Length | Type | Data) and
//! produce full EAP packets in reply. The outer driver decrypts
//! TLS records into inner EAP packets before calling
//! [`crate::inner::InnerEap::step`] and re-encrypts each emitted packet before
//! shipping it.
//!
//! Inner methods do **not** observe TLS framing, identifier
//! allocation for the outer EAP conversation, RADIUS `State`, or
//! MS-MPPE key emission. The outer driver owns all of that.

use crate::Error;

/// Server-side inner EAP state machine.
///
/// Implementors are owned per-PEAP-session and dropped when the
/// session terminates. They are `Send` so that the outer handler
/// can move them across `.await` points; they need not be `Sync`.
pub trait InnerEap: Send {
    /// Build the first inner EAP packet the server sends right
    /// after the TLS handshake completes.
    ///
    /// The conventional choice is `EAP-Request/Identity`, which
    /// lets the inner method bind the username to the established
    /// TLS channel rather than trusting the outer identity (often
    /// an anonymous placeholder like `"anonymous@example.com"`).
    /// Implementations may instead start directly with a
    /// method-specific request (e.g. an `EAP-Request/MSCHAPv2`
    /// Challenge) when re-binding identity isn't needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Eap`] if packet construction fails or
    /// [`Error::Tls`] for unexpected lower-layer failures.
    fn start(&mut self) -> Result<Vec<u8>, Error>;

    /// Process one inner EAP-Response from the peer, returning the
    /// next outcome. `peer_packet` is a full EAP packet
    /// (Code/Id/Length/Type/Data) decrypted from the TLS tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Eap`] on malformed inner packets or
    /// [`Error::Tls`] / method-specific errors otherwise.
    fn step(&mut self, peer_packet: &[u8]) -> Result<InnerOutcome, Error>;
}

/// Outcome of one inner [`InnerEap::step`] (or [`InnerEap::start`]
/// when treated uniformly).
#[derive(Debug)]
pub enum InnerOutcome {
    /// Inner conversation still running — send this full EAP
    /// packet to the peer (wrapped in a TLS application-data
    /// record by the outer driver).
    Continue(Vec<u8>),
    /// Inner method authenticated the peer. The outer driver
    /// MUST send an inner `EAP-Success` over the TLS tunnel, wait
    /// for the peer's acknowledging empty PEAP fragment, then
    /// emit an outer `EAP-Success` plus MS-MPPE keys derived
    /// from the TLS exporter.
    Success,
    /// Inner method rejected the peer. The outer driver MUST
    /// send an inner `EAP-Failure` over the TLS tunnel, wait
    /// for the peer's acknowledging empty PEAP fragment, then
    /// emit an outer `EAP-Failure`.
    Failure,
}

/// Factory producing a fresh [`InnerEap`] per PEAP session.
///
/// Mirrors [`crate::method::MethodFactory`] for the outer EAP
/// state machine.
pub trait InnerFactory: Send + Sync + 'static {
    /// Concrete inner method type produced by this factory.
    type Inner: InnerEap;
    /// Build a fresh inner state machine for a new PEAP session.
    ///
    /// # Errors
    ///
    /// Returns whatever error the inner method surfaces during
    /// construction.
    fn create(&self) -> Result<Self::Inner, Error>;
}
