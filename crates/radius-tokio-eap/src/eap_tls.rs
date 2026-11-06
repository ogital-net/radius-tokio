//! EAP-TLS (RFC 5216, with TLS 1.3 awareness per RFC 9190) state
//! machine.
//!
//! EAP-TLS is the simplest of the TLS-tunnelled EAP methods: the
//! TLS handshake itself *is* the authentication. The peer presents
//! a client certificate which the server validates against a
//! configured CA; on success both sides export 64 + 64 bytes of
//! MSK / EMSK keying material via RFC 5705 / RFC 8446 §7.5 with a
//! method-specific label and a successful authentication is
//! signalled to the NAS via `EAP-Success` plus MS-MPPE keys
//! (RFC 2548 §2.4 / RFC 3580 §3.16).
//!
//! # State machine
//!
//! ```text
//!   Start ── EAP-Request(Flags=S, no payload) ──▶ peer
//!   Handshaking ◀─ EAP-Response(TLS bytes, possibly fragmented) ──
//!   (drive `TlsConnection::process` while there are bytes both ways)
//!   ── EAP-Request(TLS bytes, possibly fragmented) ──▶ peer
//!   …
//!   Established ── peer sends empty ACK ─▶ Success { msk, emsk }
//! ```
//!
//! Fragmentation, handshake driving, ciphertext buffering, and
//! keying-material export are all delegated to the shared
//! `TlsTunnel` (crate-internal).
//!
//! # Keying material
//!
//! Per RFC 5216 §2.3, the MSK on a TLS 1.2 connection is derived
//! with the exporter label `"client EAP encryption"`. On TLS 1.3
//! (RFC 9190 §2.3) the label changes to
//! `"EXPORTER_EAP_TLS_Key_Material"` with the one-byte context `0x0D`,
//! and per RFC 9190 §2.5 the
//! server must additionally send a one-byte (0x00) protected
//! "commitment" record over the established TLS session *before*
//! the EAP-Success / MS-MPPE-Keys land in the Access-Accept. The
//! driver does both automatically based on
//! [`radius_tokio::tls::TlsConnection::is_tls13`].
//!
//! # Limits
//!
//! * The inbound reassembler's 64 KiB cap is inherited; oversize
//!   certificate chains will surface as
//!   [`Error::ReassemblyOverflow`].

use std::sync::Arc;

use radius_tokio::eap::Type;
use radius_tokio::tls::{TlsConnection, TlsContext};

use crate::framing::Frame;
use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::tls_tunnel::{self, TlsTunnel};
use crate::Error;

pub use crate::tls_tunnel::{DEFAULT_FRAME_MTU, EMSK_LEN, MSK_LEN};

/// TLS exporter label for EAP-TLS over TLS 1.2 (RFC 5216 §2.3).
pub const LABEL_TLS12: &str = "client EAP encryption";
/// TLS exporter label for EAP-TLS over TLS 1.3 (RFC 9190 §2.3).
pub const LABEL_TLS13: &str = "EXPORTER_EAP_TLS_Key_Material";

/// Per-session EAP-TLS state machine.
///
/// Build one via [`EapTlsFactory`] (the [`MethodFactory`] impl
/// the handler adapter consumes); rarely constructed directly.
pub struct EapTls {
    tunnel: TlsTunnel,
    state: State,
}

enum State {
    Handshaking,
    AwaitingFragmentAck,
    AwaitingFinalAck,
    Finished,
}

impl EapTls {
    /// Build a fresh state machine bound to `ctx`. The handshake
    /// has not started yet; call [`EapMethod::start`] to emit the
    /// initial `Start` frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] if `ctx` does not require and validate client
    /// certificates, or if the per-session SSL handle cannot be allocated.
    pub fn new(ctx: &TlsContext) -> Result<Self, Error> {
        if !ctx.requires_client_certificate() {
            return Err(Error::Tls(
                "EAP-TLS requires a server context with client certificate authentication".into(),
            ));
        }
        Ok(Self {
            tunnel: TlsTunnel::new(ctx, DEFAULT_FRAME_MTU)?,
            state: State::Handshaking,
        })
    }

    /// Override the default outbound fragmentation budget.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0` — fragmentation can't progress.
    #[must_use]
    pub fn with_frame_mtu(mut self, mtu: usize) -> Self {
        self.tunnel.set_frame_mtu(mtu);
        self
    }

    /// Borrow the underlying TLS connection. Useful for inspecting
    /// the peer certificate after `MethodOutcome::Success`.
    #[must_use]
    pub fn tls(&self) -> &TlsConnection {
        self.tunnel.tls()
    }

    fn export_msk_emsk(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Pick the exporter label corresponding to the negotiated
        // record-layer version:
        // * TLS 1.2 → RFC 5216 §2.3: "client EAP encryption".
        // * TLS 1.3 → RFC 9190 §2.3: "EXPORTER_EAP_TLS_Key_Material".
        if self.tunnel.tls().is_tls13() {
            self.tunnel.export_msk_emsk(LABEL_TLS13, Some(&[0x0d]))
        } else {
            self.tunnel.export_msk_emsk(LABEL_TLS12, None)
        }
    }

    fn check_peer_records(&mut self) -> Result<(), Error> {
        let mut plaintext = Vec::new();
        self.tunnel.drain_decrypted(&mut plaintext)?;
        if !plaintext.is_empty() || self.tunnel.tls().received_close_notify() {
            return Err(Error::Tls(
                "EAP-TLS peer sent application data or closed before completion".into(),
            ));
        }
        Ok(())
    }

    fn process_response(&mut self, peer_type_data: &[u8]) -> Result<MethodOutcome, Error> {
        match self.state {
            State::Finished => return Ok(MethodOutcome::Failure),
            State::AwaitingFragmentAck | State::AwaitingFinalAck => {
                let frame = Frame::parse(peer_type_data)?;
                if frame.flags.length_included()
                    || frame.flags.more_fragments()
                    || frame.flags.start()
                    || !frame.payload.is_empty()
                {
                    return Ok(MethodOutcome::Failure);
                }
                if matches!(self.state, State::AwaitingFinalAck) {
                    self.check_peer_records()?;
                    let (msk, emsk) = self.export_msk_emsk()?;
                    return Ok(MethodOutcome::Success { msk, emsk });
                }
            }
            State::Handshaking => {
                if let Some(tls_bytes) = self.tunnel.ingest_peer_frame(peer_type_data)? {
                    self.tunnel.feed_tls(&tls_bytes)?;
                    if self.tunnel.drive_handshake()? {
                        self.check_peer_records()?;
                        if self.tunnel.tls().is_tls13() {
                            self.tunnel.write_tls13_commitment()?;
                        }
                    }
                    self.tunnel.refill_pending_tx()?;
                }
            }
        }

        if self.tunnel.has_pending_tx() {
            let fragment = self.tunnel.emit_next_outbound_fragment();
            self.state = if self.tunnel.has_pending_tx() {
                State::AwaitingFragmentAck
            } else if self.tunnel.is_handshake_done() {
                State::AwaitingFinalAck
            } else {
                State::Handshaking
            };
            return Ok(MethodOutcome::Continue(fragment));
        }

        Ok(MethodOutcome::Continue(tls_tunnel::ack_frame()))
    }
}

impl EapMethod for EapTls {
    fn typ(&self) -> Type {
        Type::TLS
    }

    fn start<'a>(&'a mut self, _outer_attributes: &'a [u8]) -> crate::method::MethodFuture<'a> {
        Box::pin(async move { Ok(MethodOutcome::Continue(tls_tunnel::start_frame())) })
    }

    fn step<'a>(
        &'a mut self,
        peer_type_data: &'a [u8],
        _outer_attributes: &'a [u8],
    ) -> crate::method::MethodFuture<'a> {
        Box::pin(async move {
            let result = self.process_response(peer_type_data);
            if !matches!(&result, Ok(MethodOutcome::Continue(_))) {
                self.state = State::Finished;
            }
            result
        })
    }
}

/// Long-lived factory backing an [`EapTls`] state machine per
/// session. Holds the shared [`TlsContext`] (one per server / one
/// per virtual host).
///
/// Construct from an `Arc<TlsContext>` and hand to the handler
/// adapter:
///
/// ```ignore
/// use std::sync::Arc;
/// use radius_tokio::tls::TlsContext;
/// use radius_tokio_eap::eap_tls::EapTlsFactory;
///
/// let ctx = Arc::new(TlsContext::server(cert_pem, key_pem, client_ca_pem)?);
/// let factory = EapTlsFactory::new(ctx);
/// ```
#[derive(Clone)]
pub struct EapTlsFactory {
    ctx: Arc<TlsContext>,
    frame_mtu: usize,
}

impl EapTlsFactory {
    /// Build a factory bound to `ctx`. Uses [`DEFAULT_FRAME_MTU`].
    #[must_use]
    pub fn new(ctx: Arc<TlsContext>) -> Self {
        Self {
            ctx,
            frame_mtu: DEFAULT_FRAME_MTU,
        }
    }

    /// Override the outbound fragmentation budget for every session
    /// created by this factory.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0`.
    #[must_use]
    pub fn with_frame_mtu(mut self, mtu: usize) -> Self {
        assert!(mtu > 0, "frame_mtu must be positive");
        self.frame_mtu = mtu;
        self
    }
}

impl MethodFactory for EapTlsFactory {
    type Method = EapTls;

    fn create(&self) -> Result<Self::Method, Error> {
        Ok(EapTls::new(&self.ctx)?.with_frame_mtu(self.frame_mtu))
    }
}
