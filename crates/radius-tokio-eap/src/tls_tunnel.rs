//! Shared TLS-tunnel pipe for the TLS-tunnelled EAP methods.
//!
//! EAP-TLS, EAP-PEAP, and EAP-TTLS all wrap a single TLS session
//! in the same [`crate::framing`] envelope and all do the same
//! plumbing around it:
//!
//! * Reassemble inbound TLS-EAP fragments into TLS records and
//!   feed them to libssl.
//! * Drive the handshake state machine.
//! * Pull decrypted application bytes out for the inner
//!   conversation.
//! * Encrypt outbound inner bytes via [`TlsConnection::write`].
//! * Drain the resulting ciphertext from the wbio and fragment it
//!   into outbound TLS-EAP frames sized to the per-session
//!   [`Self::frame_mtu`].
//!
//! [`TlsTunnel`] owns exactly that state and exposes the small
//! interface each driver needs; the per-method `step()` then
//! reduces to the method-specific sequencing (Start frame, inner
//! method dispatch, Result-TLV exchange, AVP parsing, …).

use radius_tokio::tls::{HandshakeState, TlsConnection, TlsContext};

use crate::framing::{self, Flags, Frame, Reassembler};
use crate::Error;

/// Default outbound TLS-EAP frame budget in bytes.
///
/// Sized to comfortably fit in a single RADIUS Access-Challenge:
/// the EAP-Request header is 5 bytes, the TLS-EAP frame header is
/// 1–5 bytes, leaving ~1014 bytes of TLS payload — well under the
/// per-attribute 253-byte cap that `Reply::add_eap_message`
/// fragments at, and within the common 1500-byte NAS MTU.
pub const DEFAULT_FRAME_MTU: usize = 1020;

/// MSK length in bytes (RFC 5247 §1.2).
pub const MSK_LEN: usize = 64;
/// EMSK length in bytes (RFC 5247 §1.2).
pub const EMSK_LEN: usize = 64;

/// State and pipe shared by every TLS-tunnelled EAP driver.
pub(crate) struct TlsTunnel {
    tls: TlsConnection,
    reassembler: Reassembler,
    pending_tx: Vec<u8>,
    tx_offset: usize,
    frame_mtu: usize,
    handshake_done: bool,
}

impl TlsTunnel {
    /// Build a fresh tunnel bound to `ctx`. The handshake has not
    /// started yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] if the per-session SSL handle cannot
    /// be allocated.
    pub fn new(ctx: &TlsContext, frame_mtu: usize) -> Result<Self, Error> {
        let tls = TlsConnection::accept(ctx).map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Self {
            tls,
            reassembler: Reassembler::new(),
            pending_tx: Vec::new(),
            tx_offset: 0,
            frame_mtu,
            handshake_done: false,
        })
    }

    /// Borrow the underlying TLS connection (e.g. to inspect the
    /// peer certificate after the handshake).
    pub fn tls(&self) -> &TlsConnection {
        &self.tls
    }

    /// Override the outbound fragmentation budget.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0` — fragmentation can't progress.
    pub fn set_frame_mtu(&mut self, mtu: usize) {
        assert!(mtu > 0, "frame_mtu must be positive");
        self.frame_mtu = mtu;
    }

    /// Has the handshake completed at least once?
    pub fn is_handshake_done(&self) -> bool {
        self.handshake_done
    }

    /// Ingest one inbound TLS-EAP frame from the peer. Returns
    /// `Ok(Some(tls_bytes))` if this frame completed a TLS
    /// message (and clears the internal reassembler), or
    /// `Ok(None)` if more fragments are expected. An empty
    /// `peer_type_data` is a no-op.
    pub fn ingest_peer_frame(&mut self, peer_type_data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if peer_type_data.is_empty() {
            return Ok(None);
        }
        let frame = Frame::parse(peer_type_data)?;
        if self.reassembler.push(&frame)? {
            let bytes = self.reassembler.take();
            self.reassembler.reset();
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    /// Feed reassembled TLS bytes into libssl.
    pub fn feed_tls(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.tls
            .feed_input(bytes)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(())
    }

    /// Drive the handshake state machine. Returns `true` exactly
    /// once — on the call that transitions to
    /// [`HandshakeState::Established`].
    pub fn drive_handshake(&mut self) -> Result<bool, Error> {
        if self.handshake_done {
            return Ok(false);
        }
        match self.tls.process().map_err(|e| Error::Tls(e.to_string()))? {
            HandshakeState::Established => {
                self.handshake_done = true;
                debug!(event = "tls_tunnel_handshake_complete");
                count!(crate::obs::metrics::TLS_HANDSHAKES_COMPLETED);
                Ok(true)
            }
            HandshakeState::NeedsRead | HandshakeState::NeedsWrite => Ok(false),
        }
    }

    /// Drain decrypted plaintext from libssl into `out`.
    pub fn drain_decrypted(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut scratch = [0u8; 4096];
        loop {
            let n = self
                .tls
                .read(&mut scratch)
                .map_err(|e| Error::Tls(e.to_string()))?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&scratch[..n]);
        }
        Ok(())
    }

    /// Encrypt `plaintext` into the TLS application-data stream.
    /// Ciphertext is buffered in libssl's wbio and will be drained
    /// on the next [`Self::refill_pending_tx`].
    ///
    /// A zero-byte `SSL_write` (libssl asked for more network
    /// input mid-write) surfaces as [`Error::Tls`] — it shouldn't
    /// ever happen for the small inner-EAP / AVP frames we ship,
    /// and if it does the tunnel is wedged.
    pub fn write_app_data(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let mut written = 0;
        while written < plaintext.len() {
            let n = self
                .tls
                .write(&plaintext[written..])
                .map_err(|e| Error::Tls(e.to_string()))?;
            if n == 0 {
                return Err(Error::Tls(
                    "SSL_write returned WANT_*; tunnel cannot make progress".to_owned(),
                ));
            }
            written += n;
        }
        Ok(())
    }

    /// RFC 9190 §2.5 "commitment" record — write a single 0x00
    /// protected application-data byte. Caller should only invoke
    /// this on TLS 1.3 just after the handshake completes.
    pub fn write_tls13_commitment(&mut self) -> Result<(), Error> {
        let n = self
            .tls
            .write(&[0x00])
            .map_err(|e| Error::Tls(e.to_string()))?;
        debug_assert_eq!(n, 1);
        Ok(())
    }

    /// Drain ciphertext from libssl's wbio into the outbound
    /// fragment buffer.
    ///
    /// `pending_output` borrows directly from the BIO's internal
    /// buffer (no copy), and `consume_output` only runs once the
    /// slice has been appended — NLL drops the borrow at the
    /// `extend_from_slice` call, so the borrow checker is happy
    /// with the back-to-back access.
    pub fn refill_pending_tx(&mut self) -> Result<(), Error> {
        loop {
            let chunk = self.tls.pending_output();
            if chunk.is_empty() {
                break;
            }
            self.pending_tx.extend_from_slice(chunk);
            self.tls
                .consume_output()
                .map_err(|e| Error::Tls(e.to_string()))?;
        }
        self.tx_offset = 0;
        Ok(())
    }

    /// Is there outbound ciphertext waiting to be fragmented?
    pub fn has_pending_tx(&self) -> bool {
        self.tx_offset < self.pending_tx.len()
    }

    /// Emit the next outbound TLS-EAP frame from the pending
    /// ciphertext buffer, respecting [`Self::frame_mtu`].
    ///
    /// Sets L + Length on the first fragment of a multi-fragment
    /// message (RFC 5216 §3.2) and M on every fragment except the
    /// last.
    pub fn emit_next_outbound_fragment(&mut self) -> Vec<u8> {
        let total_remaining = self.pending_tx.len() - self.tx_offset;
        let take = total_remaining.min(self.frame_mtu);
        let slice = self.pending_tx[self.tx_offset..self.tx_offset + take].to_vec();
        let is_first_fragment = self.tx_offset == 0;
        let multi_fragment = self.pending_tx.len() > self.frame_mtu;
        let more = self.tx_offset + take < self.pending_tx.len();

        let mut flags_byte = 0u8;
        if more {
            flags_byte |= Flags::M;
        }
        let total_length = if is_first_fragment && multi_fragment {
            Some(u32::try_from(self.pending_tx.len()).unwrap_or(u32::MAX))
        } else {
            None
        };

        let mut out = Vec::with_capacity(slice.len() + 5);
        framing::encode(&mut out, Flags::from_byte(flags_byte), total_length, &slice);
        self.tx_offset += take;
        if !more {
            self.pending_tx.clear();
            self.tx_offset = 0;
        }
        out
    }

    /// Export RFC 5705 / RFC 8446 §7.5 keying material from the
    /// established TLS session.
    pub fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), Error> {
        self.tls
            .export_keying_material(label, context, out)
            .map_err(|e| Error::Tls(e.to_string()))
    }

    /// Export the conventional 64-byte MSK + 64-byte EMSK pair
    /// (RFC 5247 §1.2) under `label`, with an empty exporter
    /// context. Every TLS-tunnelled method this crate ships uses
    /// exactly this shape — only the label differs.
    pub fn export_msk_emsk(&self, label: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut keymat = vec![0u8; MSK_LEN + EMSK_LEN];
        self.export_keying_material(label, None, &mut keymat)?;
        let emsk = keymat.split_off(MSK_LEN);
        debug!(event = "tls_tunnel_msk_derived", label = label);
        count!(crate::obs::metrics::MSK_DERIVATIONS);
        Ok((keymat, emsk))
    }
}

/// Server-issued Start frame (RFC 5216 §3.2): a single Flags byte
/// with the S bit set. Used identically by all three TLS-tunnelled
/// methods to kick off the conversation.
pub(crate) fn start_frame() -> Vec<u8> {
    vec![Flags::S]
}

/// Empty ACK frame (RFC 5216 §3.2): a single all-zero Flags byte.
/// Sent when the server has nothing else to say but the peer is
/// still mid-fragmentation.
pub(crate) fn ack_frame() -> Vec<u8> {
    vec![0u8]
}
