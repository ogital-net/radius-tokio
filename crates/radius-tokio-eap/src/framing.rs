//! TLS-EAP frame parse / encode and the inbound-reassembly buffer.
//!
//! All three TLS-tunnelled EAP methods (EAP-TLS, PEAP, EAP-TTLS)
//! wrap their TLS record stream in the same envelope —
//! the only delta is the EAP `Type` byte (13, 25, 21
//! respectively). This module owns that shared wire shape.
//!
//! # Wire layout (RFC 5216 §3.1, mirrored by 5281/4851 and updated
//! by RFC 9190 for TLS 1.3)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |L M S R R R R R|                 TLS Message Length...         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  TLS Message Length (cont., 4 bytes total when L=1)           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       TLS Data ...                                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! * **L** — Length included. When set, the next 4 bytes are the
//!   total TLS-message length (the sum across all fragments).
//!   MUST be set on the first fragment of a multi-fragment message
//!   and MUST NOT be set on subsequent fragments (RFC 5216 §3.2).
//!   May be unset on an unfragmented message; setting it on an
//!   unfragmented message is legal but redundant.
//! * **M** — More fragments. Set on every fragment except the last
//!   of a multi-fragment message. The peer responds to an M=1
//!   fragment with an empty (zero-byte TLS Data) acknowledgement.
//! * **S** — Start. Set on the very first packet of an EAP-TLS
//!   session (the server's "EAP-TLS Start"). PEAP/TTLS reuse
//!   this bit identically. Bytes-data is empty on a Start.
//! * **R** — Reserved (five bits, RFC 5216 §3.1) / Version (three
//!   bits for PEAP). We treat them as opaque "reserved" bytes and
//!   surface them verbatim — method drivers that care about
//!   version bits can mask them out of [`Flags::reserved_bits`].
//!
//! # Module split
//!
//! * [`Flags`] / [`Frame`] / [`encode`] — pure parse / encode of a
//!   single TLS-EAP frame (one EAP packet's worth of bytes).
//! * [`Reassembler`] — accumulate inbound fragments into a complete
//!   TLS message, validating the L-bit invariants as it goes.
//! * [`Fragmenter`] — chunk an outbound TLS message into the
//!   correct sequence of frames given a per-frame MTU.

use crate::Error;

/// First-byte bitfield of a TLS-EAP frame.
///
/// Stored verbatim so callers can round-trip reserved bits (PEAP
/// repurposes the low 3 bits as a version number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// Bit 7 — Length included.
    pub const L: u8 = 0b1000_0000;
    /// Bit 6 — More fragments.
    pub const M: u8 = 0b0100_0000;
    /// Bit 5 — Start.
    pub const S: u8 = 0b0010_0000;

    /// Wrap a raw flags byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Unwrap to the raw flags byte (handy for tracing / tests).
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// `true` if the L bit is set (a 4-byte total-length field
    /// follows immediately).
    #[must_use]
    pub const fn length_included(self) -> bool {
        self.0 & Self::L != 0
    }

    /// `true` if the M bit is set (this is not the last fragment).
    #[must_use]
    pub const fn more_fragments(self) -> bool {
        self.0 & Self::M != 0
    }

    /// `true` if the S bit is set (this is an EAP-TLS "Start").
    #[must_use]
    pub const fn start(self) -> bool {
        self.0 & Self::S != 0
    }

    /// The low 5 bits, preserved verbatim. PEAP uses the lowest 3
    /// as a version number (RFC 7170 §3.2 / `PEAPv2` draft);
    /// EAP-TLS / TTLS treat them as RFC-mandated zeros.
    #[must_use]
    pub const fn reserved_bits(self) -> u8 {
        self.0 & 0b0001_1111
    }
}

impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{:05b}",
            if self.length_included() { 'L' } else { '-' },
            if self.more_fragments() { 'M' } else { '-' },
            if self.start() { 'S' } else { '-' },
            self.reserved_bits(),
        )
    }
}

/// Borrowed view of a single decoded TLS-EAP frame.
///
/// `payload` is the TLS-data slice with the Flags / Length header
/// stripped — feed it straight into
/// [`Reassembler::push`] or, if you already know it's an unfragmented
/// message, into `TlsConnection::feed_input`.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// The decoded flags byte.
    pub flags: Flags,
    /// The 4-byte total length advertised by the first fragment
    /// (only present when `flags.length_included()`).
    pub total_length: Option<u32>,
    /// The TLS-data fragment carried by this frame.
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse a TLS-EAP frame out of the EAP Type-Data slice.
    ///
    /// `type_data` is the payload of an EAP packet whose Type byte
    /// is one of {13, 21, 25, 43} — i.e. what
    /// [`radius_tokio::eap::Packet::type_data`] returns.
    ///
    /// # Errors
    ///
    /// - [`Error::Framing`] when `type_data` is shorter than the
    ///   1-byte Flags header, or shorter than the 5-byte
    ///   Flags+Length prefix when the L bit is set.
    pub fn parse(type_data: &'a [u8]) -> Result<Self, Error> {
        let (&flags_byte, rest) = type_data
            .split_first()
            .ok_or(Error::Framing("missing flags byte"))?;
        let flags = Flags::from_byte(flags_byte);

        let (total_length, payload) = if flags.length_included() {
            if rest.len() < 4 {
                return Err(Error::Framing(
                    "L bit set but fewer than 4 length bytes follow",
                ));
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            (Some(len), &rest[4..])
        } else {
            (None, rest)
        };

        Ok(Frame {
            flags,
            total_length,
            payload,
        })
    }
}

/// Append an encoded TLS-EAP frame (Flags + optional Length +
/// payload) to `out`.
///
/// Returns the number of bytes appended. Pair the resulting buffer
/// with [`radius_tokio::eap::write_request`] to wrap it in an
/// EAP-Request packet and then with
/// [`radius_tokio::Reply::add_eap_message`] to fragment that into
/// `EAP-Message` attributes on the RADIUS reply.
pub fn encode(out: &mut Vec<u8>, flags: Flags, total_length: Option<u32>, payload: &[u8]) -> usize {
    let start = out.len();
    let final_flags = if total_length.is_some() {
        flags.to_byte() | Flags::L
    } else {
        flags.to_byte() & !Flags::L
    };
    out.push(final_flags);
    if let Some(len) = total_length {
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(payload);
    out.len() - start
}

/// Inbound TLS-message reassembly buffer.
///
/// Drive the supplicant's incoming fragments through [`Reassembler::push`].
/// When [`Reassembler::is_complete`] returns true, take the
/// accumulated bytes via [`Reassembler::take`] and hand them to
/// `TlsConnection::feed_input`.
///
/// Validates RFC 5216 §3.2 invariants as it goes:
/// * First fragment of a multi-part message MUST set the L bit.
/// * Subsequent fragments MUST NOT set L.
/// * Total accumulated bytes MUST NOT exceed the L-bit length.
///
/// # Sizing
///
/// The reassembler enforces a configurable upper bound on
/// `total_length` to keep a malicious supplicant from inflating a
/// session's footprint. The cap defaults to **64 KiB**, comfortably
/// above any realistic TLS handshake (the server's certificate
/// chain dominates, and even a long EV chain fits in ~16 KiB).
#[derive(Debug)]
pub struct Reassembler {
    buf: Vec<u8>,
    /// `Some(n)` once the L-bit fragment is seen; reassembly is
    /// complete when `buf.len() == n`.
    expected: Option<u32>,
    /// Latched true when a single-fragment message (no L, no M)
    /// was pushed and is therefore already complete. Cleared by
    /// [`Reassembler::take`] and [`Reassembler::reset`].
    single_fragment_complete: bool,
    max_total_length: u32,
}

impl Reassembler {
    /// Default `max_total_length` cap. 64 KiB.
    pub const DEFAULT_MAX_TOTAL_LENGTH: u32 = 64 * 1024;

    /// Fresh reassembler with the default 64 KiB cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_total_length(Self::DEFAULT_MAX_TOTAL_LENGTH)
    }

    /// Reassembler with a caller-chosen cap on `total_length`.
    /// Bytes beyond this cap surface as
    /// [`Error::ReassemblyOverflow`].
    #[must_use]
    pub fn with_max_total_length(max_total_length: u32) -> Self {
        Self {
            buf: Vec::new(),
            expected: None,
            single_fragment_complete: false,
            max_total_length,
        }
    }

    /// Discard the in-progress message. Called between TLS records
    /// when the method driver is about to start receiving a new one.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.expected = None;
        self.single_fragment_complete = false;
    }

    /// `true` once the buffered bytes equal the L-bit length (or
    /// once a single-fragment message with no M bit was pushed).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        match self.expected {
            Some(n) => self.buf.len() as u64 == u64::from(n),
            // Single-fragment, L-bit-absent path: complete iff we
            // have any bytes at all and the last `push` cleared M.
            None => !self.buf.is_empty() && self.single_fragment_complete,
        }
    }

    /// Take the reassembled bytes, leaving the reassembler ready
    /// for the next message. Returns an empty vec if reassembly is
    /// not yet complete (callers should check
    /// [`Self::is_complete`] first).
    #[must_use]
    pub fn take(&mut self) -> Vec<u8> {
        let out = std::mem::take(&mut self.buf);
        self.expected = None;
        self.single_fragment_complete = false;
        out
    }

    /// How many bytes have been buffered so far.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The total length advertised by the L-bit fragment, if seen.
    #[must_use]
    pub fn expected_length(&self) -> Option<u32> {
        self.expected
    }

    /// Absorb one frame's payload, returning whether the message
    /// is now complete.
    ///
    /// `frame` is what [`Frame::parse`] produced for the current
    /// EAP-Message reassembly. The reassembler:
    /// 1. Validates L/M invariants against its prior state.
    /// 2. Appends `frame.payload` to the internal buffer.
    /// 3. Returns `Ok(true)` iff the message is now complete.
    ///
    /// # Errors
    ///
    /// - [`Error::Framing`] for L-bit invariant violations.
    /// - [`Error::MissingTotalLength`] when the first fragment of a
    ///   multi-part message (M=1) omits the L bit.
    /// - [`Error::ReassemblyOverflow`] when the buffered length
    ///   would exceed the advertised total or the configured cap.
    ///
    /// # Panics
    ///
    /// Panics if a frame reports `length_included()` but no
    /// `total_length` value — an invariant upheld by
    /// [`Frame::parse`], so this only triggers on a hand-built
    /// `Frame` that violates it.
    pub fn push(&mut self, frame: &Frame<'_>) -> Result<bool, Error> {
        let already = self.expected.is_some() || !self.buf.is_empty();

        if frame.flags.length_included() {
            // L bit set: must be the first fragment we see for
            // this message.
            if already {
                return Err(Error::Framing(
                    "L bit set on a non-initial fragment of an in-progress message",
                ));
            }
            let total = frame
                .total_length
                .expect("Frame::parse guarantees Some(total_length) when L bit is set");
            if total > self.max_total_length {
                warn!(
                    event = "reassembly_overflow",
                    site = "declared_total_exceeds_cap",
                    declared = total,
                    cap = self.max_total_length,
                );
                count!(crate::obs::metrics::REASSEMBLY_OVERFLOWS);
                return Err(Error::ReassemblyOverflow {
                    expected: total,
                    buffered: 0,
                    attempted: usize::try_from(total).unwrap_or(usize::MAX),
                });
            }
            self.expected = Some(total);
            self.buf.reserve(usize::try_from(total).unwrap_or(0));
        } else if frame.flags.more_fragments() && !already {
            // First fragment of a multi-part message omitted the L
            // bit — RFC 5216 §3.2 requires it.
            return Err(Error::MissingTotalLength);
        }

        // Length check before extending.
        if let Some(expected) = self.expected {
            let would_be = self.buf.len().saturating_add(frame.payload.len());
            if would_be as u64 > u64::from(expected) {
                warn!(
                    event = "reassembly_overflow",
                    site = "fragments_exceed_declared",
                    expected,
                    buffered = self.buf.len(),
                    attempted = frame.payload.len(),
                );
                count!(crate::obs::metrics::REASSEMBLY_OVERFLOWS);
                return Err(Error::ReassemblyOverflow {
                    expected,
                    buffered: self.buf.len(),
                    attempted: frame.payload.len(),
                });
            }
        } else {
            // No L-bit length in play — still bound the buffer to
            // the configured cap so an attacker can't OOM us by
            // sending many M-bit-cleared single-fragment messages
            // in sequence (we reset between messages, so this is
            // really just per-call protection).
            if frame.payload.len() as u64 > u64::from(self.max_total_length) {
                warn!(
                    event = "reassembly_overflow",
                    site = "unbounded_single_fragment_exceeds_cap",
                    cap = self.max_total_length,
                    attempted = frame.payload.len(),
                );
                count!(crate::obs::metrics::REASSEMBLY_OVERFLOWS);
                return Err(Error::ReassemblyOverflow {
                    expected: self.max_total_length,
                    buffered: 0,
                    attempted: frame.payload.len(),
                });
            }
        }

        self.buf.extend_from_slice(frame.payload);

        // Single-fragment messages (no L, no M) are complete in
        // one push.
        if self.expected.is_none() && !frame.flags.more_fragments() {
            self.single_fragment_complete = true;
        }

        Ok(self.is_complete())
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

// Outbound fragmentation -------------------------------------------------

/// Chunk an outbound TLS message into the sequence of
/// `(Flags, Option<total_length>, payload_slice)` frames the EAP-TLS
/// wire format expects.
///
/// `tls_bytes` is the complete TLS message produced by
/// `TlsConnection::take_output`. `frame_mtu` is the maximum number
/// of *EAP-TLS payload bytes* (i.e. TLS-data bytes, not counting the
/// 1-byte Flags or 4-byte Length header) the fragmenter is allowed
/// to put in a single frame.
///
/// A common `frame_mtu` for RADIUS over UDP is ~1004 bytes: the
/// 4096-byte RADIUS cap minus the headers, message-authenticator,
/// EAP-Message attribute envelopes, and any other AVPs the server
/// is also emitting. Picking the value is the consumer's job —
/// fragmenter has no opinion.
///
/// # Yielded frames
///
/// * **First frame (only one when unfragmented)**: Flags carry the
///   caller-supplied `extra_flags` (typically `Flags::S` for the
///   very first packet of a session, else `0`) plus the L bit if
///   `tls_bytes.len() > frame_mtu`, plus the M bit when more
///   fragments will follow. `total_length = Some(tls_bytes.len())`
///   when the L bit is set, else `None`.
/// * **Subsequent frames**: only the M bit is set (cleared on the
///   final fragment).
///
/// # Panics
///
/// Panics if `frame_mtu == 0` (caller error — fragmentation can't
/// progress).
#[must_use]
pub fn fragmenter(tls_bytes: &[u8], frame_mtu: usize, extra_flags: u8) -> Fragmenter<'_> {
    assert!(frame_mtu > 0, "frame_mtu must be positive");
    Fragmenter {
        bytes: tls_bytes,
        offset: 0,
        frame_mtu,
        extra_flags,
        emitted_first: false,
    }
}

/// Iterator returned by [`fragmenter`]. Yields
/// `(Flags, Option<total_length>, payload_slice)` per frame, in
/// transmission order.
#[derive(Debug)]
pub struct Fragmenter<'a> {
    bytes: &'a [u8],
    offset: usize,
    frame_mtu: usize,
    extra_flags: u8,
    emitted_first: bool,
}

impl<'a> Iterator for Fragmenter<'a> {
    type Item = (Flags, Option<u32>, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() && self.emitted_first {
            return None;
        }
        let remaining = self.bytes.len() - self.offset;
        let take = remaining.min(self.frame_mtu);
        let slice = &self.bytes[self.offset..self.offset + take];
        self.offset += take;

        let mut flags_byte = if self.emitted_first {
            0
        } else {
            self.extra_flags
        };

        let multi_fragment = self.bytes.len() > self.frame_mtu;
        let is_first = !self.emitted_first;
        let more_to_come = self.offset < self.bytes.len();

        if more_to_come {
            flags_byte |= Flags::M;
        }

        let total_length = if is_first && multi_fragment {
            flags_byte |= Flags::L;
            // The wire field is a u32; oversized TLS messages here
            // are a programming error — surface it via the
            // saturating conversion rather than panic so the
            // remote sees a truncated length and the handshake
            // fails predictably.
            Some(u32::try_from(self.bytes.len()).unwrap_or(u32::MAX))
        } else {
            None
        };

        self.emitted_first = true;
        Some((Flags::from_byte(flags_byte), total_length, slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Flags --------------------------------------------------

    #[test]
    fn flags_round_trip_individual_bits() {
        let f = Flags::from_byte(Flags::L | Flags::M | Flags::S | 0b0000_0001);
        assert!(f.length_included());
        assert!(f.more_fragments());
        assert!(f.start());
        assert_eq!(f.reserved_bits(), 0b0000_0001);
        assert_eq!(f.to_byte(), Flags::L | Flags::M | Flags::S | 1);
    }

    #[test]
    fn flags_display_renders_letters_and_reserved_bits() {
        let f = Flags::from_byte(Flags::L | Flags::S | 0b0000_0010);
        assert_eq!(format!("{f}"), "L-S00010");
    }

    // ---- Frame::parse -------------------------------------------

    #[test]
    fn parse_unfragmented_no_length_field() {
        // Flags=0, then 4 bytes of TLS data.
        let bytes = [0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!(f.flags.to_byte(), 0);
        assert_eq!(f.total_length, None);
        assert_eq!(f.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_first_fragment_with_length_field() {
        // Flags=L|M, Length=300, then 4 bytes of payload.
        let mut bytes = vec![Flags::L | Flags::M, 0, 0, 0x01, 0x2C];
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        let f = Frame::parse(&bytes).unwrap();
        assert!(f.flags.length_included());
        assert!(f.flags.more_fragments());
        assert_eq!(f.total_length, Some(300));
        assert_eq!(f.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn parse_start_frame_is_payload_less() {
        // EAP-TLS Start: Flags=S, no length, no payload.
        let bytes = [Flags::S];
        let f = Frame::parse(&bytes).unwrap();
        assert!(f.flags.start());
        assert_eq!(f.total_length, None);
        assert_eq!(f.payload, &[] as &[u8]);
    }

    #[test]
    fn parse_short_buffer_errors() {
        assert!(matches!(Frame::parse(&[]), Err(Error::Framing(_))));
        // L bit set but only 3 length bytes.
        assert!(matches!(
            Frame::parse(&[Flags::L, 0, 0, 1]),
            Err(Error::Framing(_)),
        ));
    }

    // ---- encode -------------------------------------------------

    #[test]
    fn encode_unfragmented_omits_length_field() {
        let mut out = Vec::new();
        let n = encode(&mut out, Flags::from_byte(Flags::S), None, &[]);
        assert_eq!(n, 1);
        assert_eq!(out, vec![Flags::S]);
    }

    #[test]
    fn encode_first_fragment_writes_length() {
        let mut out = Vec::new();
        let payload = [0xAA, 0xBB];
        let n = encode(&mut out, Flags::from_byte(Flags::M), Some(257), &payload);
        assert_eq!(n, 1 + 4 + 2);
        assert_eq!(
            out[0],
            Flags::L | Flags::M,
            "L bit auto-set when length supplied"
        );
        assert_eq!(&out[1..5], &[0, 0, 0x01, 0x01]);
        assert_eq!(&out[5..], &payload);
    }

    #[test]
    fn encode_strips_l_bit_when_no_length() {
        // Caller passed an L bit in flags but no total_length —
        // encoder normalises it off.
        let mut out = Vec::new();
        encode(
            &mut out,
            Flags::from_byte(Flags::L | Flags::S),
            None,
            &[1, 2],
        );
        assert_eq!(out[0], Flags::S, "L bit stripped when no length");
        assert_eq!(&out[1..], &[1, 2]);
    }

    // ---- Reassembler --------------------------------------------

    fn frame(flags: u8, total: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode(&mut v, Flags::from_byte(flags), total, payload);
        v
    }

    #[test]
    fn reassembler_single_fragment_completes_immediately() {
        let mut r = Reassembler::new();
        let wire = frame(0, None, &[1, 2, 3]);
        let f = Frame::parse(&wire).unwrap();
        assert!(r.push(&f).unwrap());
        assert!(r.is_complete());
        assert_eq!(r.take(), vec![1, 2, 3]);
    }

    #[test]
    fn reassembler_multi_fragment_walks_to_completion() {
        let mut r = Reassembler::new();
        // First fragment: L+M, total=6, payload=[1,2,3].
        let w1 = frame(Flags::M, Some(6), &[1, 2, 3]);
        let f1 = Frame::parse(&w1).unwrap();
        assert!(!r.push(&f1).unwrap());
        assert_eq!(r.buffered(), 3);
        assert_eq!(r.expected_length(), Some(6));

        // Second fragment: M, payload=[4,5].
        let w2 = frame(Flags::M, None, &[4, 5]);
        let f2 = Frame::parse(&w2).unwrap();
        assert!(!r.push(&f2).unwrap());
        assert_eq!(r.buffered(), 5);

        // Final fragment: no flags, payload=[6].
        let w3 = frame(0, None, &[6]);
        let f3 = Frame::parse(&w3).unwrap();
        assert!(r.push(&f3).unwrap());
        assert!(r.is_complete());
        assert_eq!(r.take(), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn reassembler_rejects_l_bit_on_non_initial_fragment() {
        let mut r = Reassembler::new();
        let w1 = frame(Flags::M, Some(10), &[1, 2, 3]);
        r.push(&Frame::parse(&w1).unwrap()).unwrap();
        // Sneaky peer re-sends L bit mid-stream.
        let w2 = frame(Flags::L | Flags::M, Some(20), &[4, 5]);
        let err = r.push(&Frame::parse(&w2).unwrap()).unwrap_err();
        assert!(matches!(err, Error::Framing(_)), "got {err:?}");
    }

    #[test]
    fn reassembler_rejects_first_multi_fragment_without_l_bit() {
        let mut r = Reassembler::new();
        // M bit set but no L bit on the first fragment we see.
        let w = frame(Flags::M, None, &[1, 2, 3]);
        let err = r.push(&Frame::parse(&w).unwrap()).unwrap_err();
        assert!(matches!(err, Error::MissingTotalLength), "got {err:?}");
    }

    #[test]
    fn reassembler_rejects_overflow_past_advertised_length() {
        let mut r = Reassembler::new();
        let w1 = frame(Flags::M, Some(4), &[1, 2, 3]);
        r.push(&Frame::parse(&w1).unwrap()).unwrap();
        // Peer claims 2 more bytes but the cap is 4 total and we
        // already buffered 3.
        let w2 = frame(0, None, &[4, 5]);
        let err = r.push(&Frame::parse(&w2).unwrap()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::ReassemblyOverflow {
                    expected: 4,
                    buffered: 3,
                    attempted: 2
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn reassembler_rejects_advertised_length_past_cap() {
        let mut r = Reassembler::with_max_total_length(1024);
        let w = frame(Flags::M, Some(2048), &[1]);
        let err = r.push(&Frame::parse(&w).unwrap()).unwrap_err();
        assert!(
            matches!(err, Error::ReassemblyOverflow { expected: 2048, .. }),
            "got {err:?}",
        );
    }

    #[test]
    fn reassembler_reset_clears_state() {
        let mut r = Reassembler::new();
        let w = frame(Flags::M, Some(10), &[1, 2, 3]);
        r.push(&Frame::parse(&w).unwrap()).unwrap();
        r.reset();
        assert_eq!(r.buffered(), 0);
        assert_eq!(r.expected_length(), None);
        // Should now accept a fresh single-fragment message.
        let w2 = frame(0, None, &[9]);
        assert!(r.push(&Frame::parse(&w2).unwrap()).unwrap());
        assert_eq!(r.take(), vec![9]);
    }

    // ---- Fragmenter ---------------------------------------------

    #[test]
    fn fragmenter_unfragmented_emits_single_frame_without_l_bit() {
        let data = [1u8, 2, 3];
        let frames: Vec<_> = fragmenter(&data, 16, Flags::S).collect();
        assert_eq!(frames.len(), 1);
        let (flags, total, slice) = frames[0];
        assert_eq!(flags.to_byte(), Flags::S);
        assert_eq!(total, None);
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn fragmenter_multi_fragment_sets_l_and_m_correctly() {
        let data: Vec<u8> = (0u8..10).collect();
        // mtu=4 → frames of 4, 4, 2.
        let frames: Vec<_> = fragmenter(&data, 4, 0).collect();
        assert_eq!(frames.len(), 3);

        // First: L + M, length=10, payload=0..4.
        let (f0, t0, p0) = frames[0];
        assert!(f0.length_included() && f0.more_fragments() && !f0.start());
        assert_eq!(t0, Some(10));
        assert_eq!(p0, &[0, 1, 2, 3]);

        // Middle: only M, payload=4..8.
        let (f1, t1, p1) = frames[1];
        assert!(!f1.length_included() && f1.more_fragments());
        assert_eq!(t1, None);
        assert_eq!(p1, &[4, 5, 6, 7]);

        // Last: no flags, payload=8..10.
        let (f2, t2, p2) = frames[2];
        assert_eq!(f2.to_byte(), 0);
        assert_eq!(t2, None);
        assert_eq!(p2, &[8, 9]);
    }

    #[test]
    fn fragmenter_then_reassembler_round_trip() {
        let original: Vec<u8> = (0u8..255).collect();
        let mut r = Reassembler::with_max_total_length(1024);

        for (flags, total, payload) in fragmenter(&original, 64, 0) {
            let mut wire = Vec::new();
            encode(&mut wire, flags, total, payload);
            let frame = Frame::parse(&wire).unwrap();
            r.push(&frame).unwrap();
        }
        assert!(r.is_complete());
        assert_eq!(r.take(), original);
    }

    #[test]
    fn fragmenter_zero_length_message_yields_single_empty_frame() {
        let frames: Vec<_> = fragmenter(&[], 16, Flags::S).collect();
        assert_eq!(frames.len(), 1);
        let (flags, total, slice) = frames[0];
        assert_eq!(flags.to_byte(), Flags::S);
        assert_eq!(total, None);
        assert!(slice.is_empty());
    }

    #[test]
    #[should_panic(expected = "frame_mtu must be positive")]
    fn fragmenter_zero_mtu_panics() {
        let _ = fragmenter(&[1, 2, 3], 0, 0);
    }
}
