//! PEAP outer state machine
//! (`draft-josefsson-pppext-eap-tls-eap`, "PEAPv0").
//!
//! PEAP wraps an inner EAP method
//! (see [`crate::inner::InnerEap`] — most commonly
//! [`crate::mschapv2::MsChapV2Server`]) inside a
//! server-authenticated TLS tunnel. Unlike EAP-TLS, the peer
//! does **not** present a certificate; the inner method does the
//! peer authentication.
//!
//! # Differences from EAP-TLS
//!
//! * EAP type is [`Type::PEAP`] (25) instead of [`Type::TLS`] (13).
//! * The [`TlsContext`] is built via
//!   [`TlsContext::server_without_client_auth`] — no
//!   `CertificateRequest` is sent during the handshake.
//! * After the TLS handshake completes, the server drives an
//!   inner EAP conversation by encrypting inner EAP packets into
//!   the TLS application-data stream.
//! * MSK derivation uses the same exporter labels as EAP-TLS
//!   (`"client EAP encryption"` for TLS 1.2, RFC 9190
//!   `"EXPORTER_EAP_TLS_Key_Material"` for TLS 1.3). The crypto-
//!   binding TLV / IPMK derivation variants of PEAPv0 are *not*
//!   implemented; this matches what `eapol_test` /
//!   `wpa_supplicant` negotiate by default.
//!
//! # End-of-conversation sequence
//!
//! After the inner method returns [`InnerOutcome::Success`]:
//!
//! 1. The driver wraps an inner `EAP-Success` packet
//!    (`Code=3, Id=last_peer_inner_id+1, Length=4`) in TLS
//!    application data and ships it to the peer.
//! 2. The peer ACKs with an empty PEAP fragment.
//! 3. The driver derives the MSK / EMSK and returns
//!    [`MethodOutcome::Success`]; the outer
//!    [`crate::EapHandler`] then sends RADIUS `Access-Accept`
//!    carrying outer `EAP-Success` + MS-MPPE-Send/Recv-Key.
//!
//! Failure mirrors this but with `EAP-Failure` + `Access-Reject`.

use std::sync::Arc;

use radius_tokio::eap::Type;
use radius_tokio::tls::{TlsConnection, TlsContext};

use crate::inner::{InnerEap, InnerFactory, InnerOutcome};
use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::tls_tunnel::{self, TlsTunnel};
use crate::Error;

pub use crate::tls_tunnel::{DEFAULT_FRAME_MTU, EMSK_LEN, MSK_LEN};

/// TLS exporter label for PEAP keying material on TLS 1.2.
pub const LABEL_TLS12: &str = "client EAP encryption";
/// TLS exporter label for PEAP keying material on TLS 1.3
/// (RFC 9190 §2.3, used by hostap when PEAP negotiates over
/// TLS 1.3).
pub const LABEL_TLS13: &str = "EXPORTER_EAP_TLS_Key_Material";

#[derive(Clone, Copy)]
enum InnerResult {
    Success,
    Failure,
}

/// PEAP outer state machine driving TLS phase 1 + an inner EAP
/// conversation in phase 2.
pub struct Peap<I: InnerEap> {
    tunnel: TlsTunnel,
    inner: I,
    inner_started: bool,
    /// Decrypted plaintext bytes pending inner EAP packet
    /// extraction. May span multiple TLS records.
    inner_rx_buf: Vec<u8>,
    /// Tracks the last EAP id we saw from the peer on the *inner*
    /// conversation. The inner EAP-Success / EAP-Failure that
    /// terminates phase 2 uses `last + 1`.
    last_inner_peer_id: u8,
    /// Tracks the EAP id of the most recent inner request the
    /// server sent. Used to synthesise a full EAP header when the
    /// peer replies in `PEAPv0` "compressed" form (type+data only,
    /// no Code/Id/Length — `wpa_supplicant`'s default).
    last_inner_request_id: u8,
    /// Set once the inner method has terminated. Once `Some`, the
    /// driver is just waiting for the peer's ACK of the inner
    /// `EAP-Success` / `EAP-Failure` before declaring outcome.
    inner_terminator: Option<InnerResult>,
    /// `PEAPv0` Result-TLV phase (RFC draft-josefsson-pppext-eap-tls-eap
    /// §2.2 / hostap `eap_peap.c`): after the inner method reports
    /// Success/Failure we send an `EAP-Request/TLV` containing a
    /// `Result-TLV` and wait for the peer's matching response
    /// before announcing the outer outcome.
    awaiting_result_ack: bool,
    /// EAP id used for the Result-TLV request.
    result_tlv_id: u8,
}

impl<I: InnerEap> Peap<I> {
    /// Build a fresh state machine bound to `ctx` (which must be
    /// constructed via [`TlsContext::server_without_client_auth`])
    /// and `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] if the per-session SSL handle cannot
    /// be allocated.
    pub fn new(ctx: &TlsContext, inner: I) -> Result<Self, Error> {
        Ok(Self {
            tunnel: TlsTunnel::new(ctx, DEFAULT_FRAME_MTU)?,
            inner,
            inner_started: false,
            inner_rx_buf: Vec::new(),
            last_inner_peer_id: 0,
            last_inner_request_id: 0,
            inner_terminator: None,
            awaiting_result_ack: false,
            result_tlv_id: 0,
        })
    }

    /// Override the default outbound fragmentation budget.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0`.
    #[must_use]
    pub fn with_frame_mtu(mut self, mtu: usize) -> Self {
        self.tunnel.set_frame_mtu(mtu);
        self
    }

    /// Borrow the underlying TLS connection.
    #[must_use]
    pub fn tls(&self) -> &TlsConnection {
        self.tunnel.tls()
    }

    /// Write `inner_eap_packet` into the TLS application-data
    /// stream. Records the request id so a subsequent `PEAPv0`
    /// "compressed" peer reply can be reconstituted.
    fn write_inner(&mut self, inner_eap_packet: &[u8]) -> Result<(), Error> {
        if inner_eap_packet.len() >= 2 {
            self.last_inner_request_id = inner_eap_packet[1];
        }
        // PEAPv0 inner-frame shape (hostap supplicant
        // `eap_peap_decrypt`): the supplicant only keeps the
        // server-supplied EAP header for the special case of a
        // 5-byte `EAP-Request/Identity` (FreeRADIUS quirk) and
        // for TLV (type 33) packets. Every other inner message
        // must be sent in *compressed* form — `Type|Data` only,
        // with the supplicant prepending a freshly synthesised
        // EAP header. If we leave our header on, the supplicant
        // reinterprets bytes `[0..4]` as `Type|Data` and the
        // method dispatch ends up on `Type=1` (Identity) for
        // every message.
        let payload: &[u8] =
            if is_full_identity_request(inner_eap_packet) || is_tlv_request(inner_eap_packet) {
                inner_eap_packet
            } else if inner_eap_packet.len() >= 5 {
                &inner_eap_packet[4..]
            } else {
                // Headerless 4-byte EAP-Success/Failure has no
                // Type byte and cannot be sent inside PEAPv0; we
                // signal completion via MethodOutcome instead and
                // never call write_inner for these.
                return Ok(());
            };
        self.tunnel.write_app_data(payload)
    }

    /// Attempt to peel off a single complete inner EAP packet from
    /// the front of `inner_rx_buf`. Returns `None` if no complete
    /// packet is buffered yet.
    ///
    /// `PEAPv0` allows two inner-packet shapes:
    ///
    /// 1. **Full EAP packet** — `Code|Id|Length|Type|Data`, byte
    ///    layout identical to bare-wire EAP. Microsoft `PEAPv0`
    ///    implementations use this form.
    /// 2. **Compressed EAP** — `Type|Data` only; the receiver
    ///    synthesises `Code = 2 (Response)` and reuses the last
    ///    request's `Id`. This is `wpa_supplicant` /
    ///    `eapol_test`'s default for Phase 2 responses.
    ///
    /// We accept either: probe for a parseable full EAP header
    /// first, otherwise treat the whole buffer as compressed and
    /// wrap it.
    fn try_extract_inner_packet(&mut self) -> Option<Vec<u8>> {
        if self.inner_rx_buf.is_empty() {
            return None;
        }
        // Form (1): looks like a full EAP packet?
        if self.inner_rx_buf.len() >= 4 && (1u8..=4).contains(&self.inner_rx_buf[0]) {
            let len = u16::from_be_bytes([self.inner_rx_buf[2], self.inner_rx_buf[3]]) as usize;
            if (4..=4096).contains(&len) && self.inner_rx_buf.len() >= len {
                let pkt: Vec<u8> = self.inner_rx_buf.drain(..len).collect();
                return Some(pkt);
            }
        }
        // Form (2): wrap everything buffered as an EAP-Response
        // using the most recent request id.
        let type_and_data: Vec<u8> = self.inner_rx_buf.drain(..).collect();
        let total = u16::try_from(4 + type_and_data.len()).unwrap_or(u16::MAX);
        let mut pkt = Vec::with_capacity(usize::from(total));
        pkt.push(2); // EAP Code = Response
        pkt.push(self.last_inner_request_id);
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&type_and_data);
        Some(pkt)
    }

    fn export_msk_emsk(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let label = if self.tunnel.tls().is_tls13() {
            LABEL_TLS13
        } else {
            LABEL_TLS12
        };
        self.tunnel.export_msk_emsk(label)
    }

    /// Emit a `PEAPv0` `EAP-Request/TLV` carrying a Result-TLV.
    /// Sent over the TLS tunnel; the peer must echo back an
    /// `EAP-Response/TLV` with the same Result before we declare
    /// the outer outcome.
    fn send_result_tlv(&mut self, status: ResultTlvStatus) -> Result<(), Error> {
        let id = self.last_inner_peer_id.wrapping_add(1);
        self.result_tlv_id = id;
        self.awaiting_result_ack = true;
        // Full EAP packet: 4-byte header + Type(33) + Result-TLV.
        // Length = 4 (hdr) + 1 (type) + 2 (TLV type, M-bit set)
        //        + 2 (TLV length=2) + 2 (status) = 11.
        let mut pkt = Vec::with_capacity(11);
        pkt.push(0x01); // Code = Request
        pkt.push(id);
        pkt.extend_from_slice(&11u16.to_be_bytes());
        pkt.push(0x21); // Type = TLV (33)
        pkt.extend_from_slice(&0x8003u16.to_be_bytes()); // M-bit | Result-TLV
        pkt.extend_from_slice(&2u16.to_be_bytes()); // TLV length
        pkt.extend_from_slice(&(status as u16).to_be_bytes());
        self.write_inner(&pkt)
    }
}

impl<I: InnerEap> EapMethod for Peap<I> {
    fn typ(&self) -> Type {
        Type::PEAP
    }

    fn start(&mut self) -> Result<MethodOutcome, Error> {
        // RFC 5216 §3.2 / PEAP §2.1: server-issued Start frame is
        // a single Flags byte with S set.
        Ok(MethodOutcome::Continue(tls_tunnel::start_frame()))
    }

    #[allow(clippy::too_many_lines)] // intentionally a single-flow step()
    fn step(&mut self, peer_type_data: &[u8]) -> Result<MethodOutcome, Error> {
        // 1. Ingest the peer's PEAP fragment and, if a full TLS
        //    message just reassembled, feed libssl + drive the
        //    handshake.
        if let Some(tls_bytes) = self.tunnel.ingest_peer_frame(peer_type_data)? {
            self.tunnel.feed_tls(&tls_bytes)?;
            let just_completed = self.tunnel.drive_handshake()?;
            if just_completed && self.tunnel.tls().is_tls13() {
                // RFC 9190 §2.5: on TLS 1.3 the server emits a
                // 0x00 commitment record. PEAP doesn't reference
                // this directly, but libssl + hostap interop
                // relies on it when TLS 1.3 is negotiated.
                self.tunnel.write_tls13_commitment()?;
            }
        }

        // 2. Once the handshake is up, pull any decrypted inner
        //    EAP bytes out of libssl.
        if self.tunnel.is_handshake_done() {
            self.tunnel.drain_decrypted(&mut self.inner_rx_buf)?;
        }

        // 3. Drain ciphertext libssl produced (handshake
        //    completion records or earlier inner writes) into
        //    the outbound buffer, then send the next fragment if
        //    any remains.
        //
        //    CRITICAL: we MUST drain the handshake completion
        //    records before queueing the first inner
        //    EAP-Request — `wpa_supplicant` rejects an inner
        //    `EAP-Request/Identity` that is piggy-backed in the
        //    same TLS flight as the server `Finished`
        //    ("Application Data in Finished message" → exit 252).
        self.tunnel.refill_pending_tx()?;
        if self.tunnel.has_pending_tx() {
            return Ok(MethodOutcome::Continue(
                self.tunnel.emit_next_outbound_fragment(),
            ));
        }

        // 4. Handshake done and ciphertext fully flushed; kick off
        //    the inner method on the next round-trip after the
        //    peer ACKs our last handshake fragment.
        if self.tunnel.is_handshake_done() && !self.inner_started {
            self.inner_started = true;
            let msg = self.inner.start()?;
            self.write_inner(&msg)?;
        }

        // 5. Drive the inner method while we have complete inner
        //    EAP packets to feed it and the inner conversation
        //    hasn't terminated yet. After inner termination, run
        //    the PEAPv0 Result-TLV exchange before announcing
        //    the outer outcome (hostap requires this when
        //    `crypto_binding != NO_BINDING`, which is the
        //    default).
        while let Some(pkt_bytes) = self.try_extract_inner_packet() {
            if pkt_bytes.len() >= 2 {
                self.last_inner_peer_id = pkt_bytes[1];
            }
            if self.awaiting_result_ack {
                // Expect a full-EAP Response/TLV from the peer
                // matching our Result-TLV request id.
                if is_result_tlv_response(&pkt_bytes, self.result_tlv_id) {
                    self.awaiting_result_ack = false;
                    // inner_terminator already set; fall through.
                }
                // Either way, no further inner work.
                break;
            }
            if self.inner_terminator.is_some() {
                break;
            }
            match self.inner.step(&pkt_bytes)? {
                InnerOutcome::Continue(msg) => self.write_inner(&msg)?,
                InnerOutcome::Success => {
                    self.inner_terminator = Some(InnerResult::Success);
                    self.send_result_tlv(ResultTlvStatus::Success)?;
                }
                InnerOutcome::Failure => {
                    self.inner_terminator = Some(InnerResult::Failure);
                    self.send_result_tlv(ResultTlvStatus::Failure)?;
                }
            }
        }

        // 6. Drain any ciphertext produced by step 4 / step 5
        //    and ship it.
        self.tunnel.refill_pending_tx()?;
        if self.tunnel.has_pending_tx() {
            return Ok(MethodOutcome::Continue(
                self.tunnel.emit_next_outbound_fragment(),
            ));
        }

        // 7. Nothing left to send. If the inner method has
        //    terminated AND the PEAPv0 Result-TLV has been
        //    acked, declare outcome.
        if let Some(term) = self.inner_terminator {
            if !self.awaiting_result_ack {
                return Ok(match term {
                    InnerResult::Success => {
                        let (msk, emsk) = self.export_msk_emsk()?;
                        MethodOutcome::Success { msk, emsk }
                    }
                    InnerResult::Failure => MethodOutcome::Failure,
                });
            }
        }

        // 8. Otherwise the peer is mid-fragmentation or just
        //    ACKed an interim message — emit our own ACK.
        Ok(MethodOutcome::Continue(tls_tunnel::ack_frame()))
    }
}

/// `PEAPv0` supplicants (hostap `eap_peap_decrypt`) keep the
/// server-supplied EAP header only for a literal 5-byte
/// `EAP-Request/Identity`.
fn is_full_identity_request(pkt: &[u8]) -> bool {
    pkt.len() == 5
        && pkt[0] == 0x01            // Code = Request
        && pkt[2] == 0x00 && pkt[3] == 0x05 // Length = 5
        && pkt[4] == 0x01 // Type = Identity
}

/// And for EAP-TLV (type 33) Requests, used by `PEAPv0`
/// cryptobinding. We don't emit any today but accept them here
/// for forward-compat.
fn is_tlv_request(pkt: &[u8]) -> bool {
    pkt.len() >= 5 && pkt[0] == 0x01 && pkt[4] == 0x21
}

/// `PEAPv0` Result-TLV status code (draft §2.2).
#[derive(Clone, Copy)]
#[repr(u16)]
enum ResultTlvStatus {
    Success = 1,
    Failure = 2,
}

/// True iff `pkt` is a full-EAP `Response/TLV` whose payload is
/// a Result-TLV matching `id`. Does not enforce the result value
/// (the peer always echoes our status).
fn is_result_tlv_response(pkt: &[u8], id: u8) -> bool {
    pkt.len() >= 11
        && pkt[0] == 0x02            // Code = Response
        && pkt[1] == id              // matching id
        && pkt[4] == 0x21            // Type = TLV (33)
        // TLV type with mandatory bit stripped == Result-TLV (3)
        && (u16::from_be_bytes([pkt[5], pkt[6]]) & 0x3fff) == 3
}

/// Long-lived factory backing a [`Peap`] state machine per
/// session. Holds the shared [`TlsContext`] and the inner
/// [`InnerFactory`].
pub struct PeapFactory<F: InnerFactory> {
    ctx: Arc<TlsContext>,
    inner: Arc<F>,
    frame_mtu: usize,
}

impl<F: InnerFactory> PeapFactory<F> {
    /// Build a factory bound to `ctx` + `inner`. Uses
    /// [`DEFAULT_FRAME_MTU`].
    #[must_use]
    pub fn new(ctx: Arc<TlsContext>, inner: Arc<F>) -> Self {
        Self {
            ctx,
            inner,
            frame_mtu: DEFAULT_FRAME_MTU,
        }
    }

    /// Override the outbound fragmentation budget for every
    /// session created by this factory.
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

impl<F: InnerFactory> MethodFactory for PeapFactory<F> {
    type Method = Peap<F::Inner>;

    fn create(&self) -> Result<Self::Method, Error> {
        let inner = self.inner.create()?;
        Ok(Peap::new(&self.ctx, inner)?.with_frame_mtu(self.frame_mtu))
    }
}
