//! RADIUS packet codec: encoding, decoding, and attribute access.
//!
//! # Module layout
//!
//! * [`header`] — fixed 20-byte header parser (RFC 2865 §3).
//! * [`attributes`] — zero-copy iterator over the TLV attribute list
//!   (RFC 2865 §5).
//! * [`typed`] — wire-type markers + typed handles produced by the
//!   dictionary codegen.
//! * [`authenticator`] — Request / Response Authenticator computation
//!   and verification (RFC 2865 §3, RFC 2866 §3).
//! * [`message_authenticator`] — Message-Authenticator (attribute 80)
//!   helpers, including the *secure-default* policy described below.
//! * [`eap`] — `EAP-Message` (attribute 79) reassembly view (RFC 3579
//!   §3.1).
//! * [`encode`] — high-level reply builder that wires the pieces above
//!   together.
//!
//! # Security defaults
//!
//! Two policies the codec applies by default — both can be relaxed per
//! request when an integration genuinely requires it:
//!
//! 1. **Reply-side Message-Authenticator is mandatory.**
//!    Every reply we encode (Access-Accept/Reject/Challenge,
//!    Accounting-Response, CoA-ACK/NAK, Disconnect-ACK/NAK) carries an
//!    `Message-Authenticator` attribute (RFC 3579 §3.2) computed over
//!    the final packet bytes. This blunts the `BlastRADIUS` class of
//!    attacks (CVE-2024-3596) by binding the response to the shared
//!    secret with HMAC-MD5, not just MD5 of `Code||ID||Length||…`.
//!    Historically this attribute was only required for EAP and
//!    Status-Server packets; we apply it to *every* reply.
//!
//! 2. **Request-side Message-Authenticator is verified when present.**
//!    If a request carries a Message-Authenticator, the codec validates
//!    it before any handler runs and rejects the packet on mismatch —
//!    independent of whether the request also carries an EAP-Message.
//!    A future server-level policy hook will let operators *require*
//!    the attribute on inbound Access-Requests as well, which is the
//!    direction RFC drafts (`draft-ietf-radext-deprecating-radius`)
//!    are heading.
//!
//! # Send / receive flow
//!
//! Send: [`encode::Reply::new`] → `add_attribute` → `seal_for(request,
//! secret)` → `as_bytes()` → socket. The seal step inserts the
//! Message-Authenticator placeholder, patches the length, computes the
//! HMAC, and finally computes the Response Authenticator.
//!
//! Receive: [`PacketBuffer::from_bytes`] (or [`header::Header::parse`]
//! for stack-only parsing) → [`PacketBuffer::attributes_iter`] →
//! per-attribute typed `get`s → optional
//! [`message_authenticator::verify`] / [`authenticator::verify_request`].

pub mod attributes;
pub mod authenticator;
pub mod dissect;
pub mod eap;
pub mod encode;
pub mod header;
pub mod message_authenticator;
pub mod typed;

use attributes::AttributesIter;
use header::{Code, Header, HeaderError, MAX_PACKET_LEN, MIN_PACKET_LEN};

/// Maximum encoded length of a single attribute's value field
/// (RFC 2865 §5: the Length byte is 1 octet and counts the 2-byte TLV
/// header).
const MAX_ATTRIBUTE_VALUE_LEN: usize = u8::MAX as usize - 2;

/// Type code for the Vendor-Specific Attribute (RFC 2865 §5.26).
const VENDOR_SPECIFIC_TYPE: u8 = 26;

/// Errors produced while building or sealing a packet.
///
/// Receive-side errors live on [`header::HeaderError`] /
/// [`attributes::AttributeError`]; this enum covers the encode path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Appending the attribute would push the packet past 4 096 bytes.
    PacketTooLarge {
        /// Current packet length before the failed append.
        current: usize,
        /// Number of bytes the failed append would have added (TLV
        /// header + value).
        attempted: usize,
    },
    /// The supplied attribute value exceeds the 253-byte maximum a
    /// single Length byte can describe (RFC 2865 §5).
    AttributeValueTooLong {
        /// Length of the value the caller passed in.
        len: usize,
    },
    /// The attribute is not permitted in a packet of this code.
    ///
    /// For example, `Tunnel-Password` (RFC 2868 §3.5) may only appear
    /// in an `Access-Accept` packet.
    WrongPacketType,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::PacketTooLarge { current, attempted } => write!(
                f,
                "packet would exceed {MAX_PACKET_LEN} bytes (current {current} + {attempted})",
            ),
            CodecError::AttributeValueTooLong { len } => write!(
                f,
                "attribute value of {len} bytes exceeds the {MAX_ATTRIBUTE_VALUE_LEN}-byte limit",
            ),
            CodecError::WrongPacketType => {
                f.write_str("attribute not permitted in a packet of this type")
            }
        }
    }
}

impl std::error::Error for CodecError {}

/// Owns the raw bytes of a single RADIUS packet.
///
/// On the send path, construct with [`PacketBuffer::new`], append
/// attributes, then hand to [`encode::Reply::seal_for`] (or call the
/// sealing helpers directly) to patch the length field and finalize
/// the Authenticator.
///
/// On the receive path, [`PacketBuffer::from_bytes`] takes a datagram,
/// validates the header, and stores the bytes for subsequent attribute
/// iteration.
///
/// The internal `Vec<u8>` representation is an implementation detail —
/// callers never see `Deref<Target = Vec<u8>>` and must not depend on
/// the storage. A future revision may swap in a slab- or pool-backed
/// allocator.
#[derive(Debug)]
pub struct PacketBuffer {
    inner: Vec<u8>,
}

/// Builder handed to the closure passed to
/// [`PacketBuffer::add_tlv`] / [`PacketBuffer::add_vsa_tlv`].
///
/// Each call appends one sub-attribute as
/// `sub_type (1) || sub_length (1) || value` directly into the parent
/// attribute's value region. Values larger than 253 bytes are
/// rejected with [`CodecError::AttributeValueTooLong`]; the parent
/// attribute is rolled back wholesale by the caller on any error so
/// the wire never sees a half-written TLV. Multi-level nesting
/// (TLV inside TLV) is not supported here.
#[derive(Debug)]
pub struct TlvWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> TlvWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    /// Append a typed TLV child by handle.
    ///
    /// The `attr.parent` field is **not** validated against the
    /// enclosing parent's type byte — it is the caller's job to use
    /// matching handles. Mixing children from different parents
    /// silently produces a packet that is well-framed but does not
    /// match any dictionary.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] when the
    /// encoded value exceeds 253 bytes.
    pub fn add<T, V>(&mut self, attr: typed::TlvAttr<T>, value: V) -> Result<&mut Self, CodecError>
    where
        T: typed::WireType,
        V: typed::IntoWire<T>,
    {
        self.write_child(attr.child, value)
    }

    /// Vendor TLV equivalent of [`add`](Self::add): emit a child
    /// described by a [`typed::VsaTlvAttr`] handle.
    ///
    /// Inside [`PacketBuffer::add_vsa_tlv`] the writer is already
    /// scoped to a specific vendor and parent, so only the handle's
    /// `child` byte is consulted. The `vendor` and `parent` fields
    /// are not cross-checked against the enclosing envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] when the
    /// encoded value exceeds 253 bytes.
    pub fn add_vsa<T, V>(
        &mut self,
        attr: typed::VsaTlvAttr<T>,
        value: V,
    ) -> Result<&mut Self, CodecError>
    where
        T: typed::WireType,
        V: typed::IntoWire<T>,
    {
        self.write_child(attr.child, value)
    }

    /// Inner shared encoder used by both typed entry points.
    fn write_child<T, V>(&mut self, sub_type: u8, value: V) -> Result<&mut Self, CodecError>
    where
        T: typed::WireType,
        V: typed::IntoWire<T>,
    {
        let header_pos = self.out.len();
        self.out.push(sub_type);
        self.out.push(0); // length placeholder
        let val_start = self.out.len();
        value.write_value(self.out);
        let val_len = self.out.len() - val_start;
        if val_len > MAX_ATTRIBUTE_VALUE_LEN {
            // Roll back this child only; the outer machinery will
            // truncate the whole parent when we propagate the error.
            self.out.truncate(header_pos);
            return Err(CodecError::AttributeValueTooLong { len: val_len });
        }
        // u8 cast safe: val_len <= 253, so val_len + 2 <= 255.
        self.out[header_pos + 1] =
            u8::try_from(val_len + 2).expect("val_len + 2 <= 255 by checks above");
        Ok(self)
    }

    /// Append a TLV child by raw `(sub_type, value)`.
    ///
    /// Escape hatch for sub-attributes that have no typed handle
    /// (custom vendor extensions, opaque blobs, future dictionary
    /// entries). Validates the sub-length budget the same way
    /// [`add`](Self::add) does.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] when `value`
    /// exceeds 253 bytes.
    pub fn add_raw(&mut self, sub_type: u8, value: &[u8]) -> Result<&mut Self, CodecError> {
        if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
            return Err(CodecError::AttributeValueTooLong { len: value.len() });
        }
        self.out.push(sub_type);
        // Cast safe: bounds check above keeps `value.len() + 2` <= 255.
        self.out
            .push(u8::try_from(value.len() + 2).expect("checked above"));
        self.out.extend_from_slice(value);
        Ok(self)
    }
}

impl PacketBuffer {
    /// Build a fresh buffer pre-loaded with a 20-byte header.
    ///
    /// Equivalent to [`with_capacity`](Self::with_capacity) using the
    /// protocol maximum (4 096 bytes). Use [`with_capacity`](Self::with_capacity)
    /// when the expected reply is small and the up-front allocation matters.
    ///
    /// Length is initialized to 20 (header-only) so the buffer is
    /// always [`Header::parse`]-clean; the encode-side seal patches
    /// the Length and Authenticator fields with their final values.
    #[must_use]
    pub fn new(code: Code, identifier: u8) -> Self {
        Self::with_capacity(code, identifier, MAX_PACKET_LEN)
    }

    /// Like [`new`](Self::new) but the underlying `Vec` is allocated
    /// with the supplied capacity hint instead of the protocol
    /// maximum. The hint is clamped to `[MIN_PACKET_LEN, MAX_PACKET_LEN]`.
    ///
    /// # Panics
    ///
    /// Never — `MIN_PACKET_LEN` is a small constant that always fits
    /// in `u16`.
    #[must_use]
    pub fn with_capacity(code: Code, identifier: u8, capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_PACKET_LEN, MAX_PACKET_LEN);
        let mut inner = Vec::with_capacity(capacity);
        inner.push(code.0);
        inner.push(identifier);
        // Placeholder length = MIN_PACKET_LEN; rewritten by `patch_length`.
        inner.extend_from_slice(&u16::try_from(MIN_PACKET_LEN).unwrap().to_be_bytes());
        inner.extend_from_slice(&[0; 16]); // Authenticator placeholder.
        debug_assert_eq!(inner.len(), MIN_PACKET_LEN);
        Self { inner }
    }

    /// Construct from a received datagram.
    ///
    /// Runs [`Header::parse`] for validation; the resulting buffer
    /// owns *exactly* the on-wire length of the packet (any trailing
    /// padding in the datagram is dropped here).
    ///
    /// # Errors
    ///
    /// Forwards every [`HeaderError`] variant.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderError> {
        let (header, _attrs) = Header::parse(bytes)?;
        let len = header.length as usize;
        // `Header::parse` already verified `len <= bytes.len()`.
        let mut inner = Vec::with_capacity(len);
        inner.extend_from_slice(&bytes[..len]);
        Ok(Self { inner })
    }

    /// Recycle this buffer for a new packet without freeing its
    /// backing allocation. The header is rewritten with the supplied
    /// `code` / `identifier`, the Authenticator placeholder is
    /// re-zeroed, the length is reset to `MIN_PACKET_LEN`, and the
    /// attribute region is cleared.
    ///
    /// Designed for hot-path consumers that hold a `PacketBuffer`
    /// across many requests (e.g. a per-task scratch buffer or a
    /// pool); pairs with [`Reply::from_buffer`](encode::Reply::from_buffer)
    /// to drop the per-reply allocation.
    ///
    /// # Panics
    ///
    /// Never — `MIN_PACKET_LEN` is a small constant that always fits
    /// in `u16`.
    pub fn reset(&mut self, code: Code, identifier: u8) {
        self.inner.clear();
        self.inner.push(code.0);
        self.inner.push(identifier);
        self.inner
            .extend_from_slice(&u16::try_from(MIN_PACKET_LEN).unwrap().to_be_bytes());
        self.inner.extend_from_slice(&[0; 16]);
        debug_assert_eq!(self.inner.len(), MIN_PACKET_LEN);
    }

    /// Borrow the wire bytes. Only meaningful after the buffer has
    /// been sealed (length patched, authenticator computed).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Re-parse and return the fixed header. Cheap — the bytes are
    /// already validated, so this never fails.
    ///
    /// # Panics
    ///
    /// Panics only if the buffer's invariants have been violated by
    /// internal misuse; never on construction-validated input.
    #[must_use]
    pub fn header(&self) -> Header {
        Header::parse(&self.inner)
            .expect("PacketBuffer invariants guarantee a parseable header")
            .0
    }

    /// Slice of the attribute region (everything after the 20-byte
    /// header, up to the wire length field).
    #[inline]
    #[must_use]
    pub fn attributes(&self) -> &[u8] {
        // Length-byte trimming was done at construction time; for
        // freshly built buffers the whole tail past the header is
        // attribute bytes.
        &self.inner[MIN_PACKET_LEN..]
    }

    /// Zero-copy iterator over the attribute list.
    #[inline]
    #[must_use]
    pub fn attributes_iter(&self) -> AttributesIter<'_> {
        attributes::iter(self.attributes())
    }

    /// Append a single attribute slot.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] when `val` would
    /// not fit in one Length byte, or [`CodecError::PacketTooLarge`]
    /// when the append would push the buffer past 4 096 bytes.
    /// Append a TLV attribute to the packet.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] if `val` exceeds
    /// 253 bytes, or [`CodecError::PacketTooLarge`] if appending
    /// would push the packet past 4 096 bytes.
    ///
    /// # Panics
    ///
    /// Never — the bounds check above guarantees the length cast fits
    /// in `u8`.
    pub fn add_attribute(&mut self, typ: u8, val: &[u8]) -> Result<(), CodecError> {
        if val.len() > MAX_ATTRIBUTE_VALUE_LEN {
            return Err(CodecError::AttributeValueTooLong { len: val.len() });
        }
        let added = 2 + val.len();
        if self.inner.len() + added > MAX_PACKET_LEN {
            return Err(CodecError::PacketTooLarge {
                current: self.inner.len(),
                attempted: added,
            });
        }
        self.inner.push(typ);
        // u8 cast is safe: bounds check above keeps `added` <= 255.
        self.inner.push(u8::try_from(added).expect("checked above"));
        self.inner.extend_from_slice(val);
        Ok(())
    }

    /// Append a TLV attribute whose value bytes are produced by a
    /// closure writing directly into the packet buffer.
    ///
    /// Reserves the 2-byte TLV header, hands the closure a mutable
    /// `Vec<u8>` to extend, then patches the length byte. On any
    /// length-bound violation the buffer is rolled back to its
    /// pre-call state and the corresponding [`CodecError`] is
    /// returned, so callers never observe a half-written attribute.
    ///
    /// This is the encode-side primitive the typed [`add`]
    /// and [`add_vsa`] helpers build on; consumers wanting
    /// to hand-pack a non-trivial framing (e.g. nested TLVs) can use
    /// it directly.
    ///
    /// [`add`]: Self::add
    /// [`add_vsa`]: Self::add_vsa
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::AttributeValueTooLong`] when the closure
    /// wrote more than 253 bytes, or [`CodecError::PacketTooLarge`]
    /// when the resulting packet would exceed 4 096 bytes.
    ///
    /// # Panics
    ///
    /// Never — the length-bound checks above guarantee the final
    /// `u8` cast for the TLV length byte fits.
    pub fn add_attribute_with<F>(&mut self, typ: u8, write: F) -> Result<(), CodecError>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        let header_pos = self.inner.len();
        // Reserve TLV header up front. If even the header overflows
        // the protocol cap there is no room left for the closure;
        // bail out before invoking it.
        if header_pos + 2 > MAX_PACKET_LEN {
            return Err(CodecError::PacketTooLarge {
                current: header_pos,
                attempted: 2,
            });
        }
        self.inner.push(typ);
        self.inner.push(0); // length placeholder, patched below
        let val_start = self.inner.len();
        write(&mut self.inner);
        let val_len = self.inner.len() - val_start;

        if val_len > MAX_ATTRIBUTE_VALUE_LEN {
            self.inner.truncate(header_pos);
            return Err(CodecError::AttributeValueTooLong { len: val_len });
        }
        if self.inner.len() > MAX_PACKET_LEN {
            let attempted = 2 + val_len;
            self.inner.truncate(header_pos);
            return Err(CodecError::PacketTooLarge {
                current: header_pos,
                attempted,
            });
        }
        // u8 cast safe: val_len <= 253 (checked above), so
        // val_len + 2 <= 255.
        self.inner[header_pos + 1] =
            u8::try_from(val_len + 2).expect("val_len + 2 <= 255 by checks above");
        Ok(())
    }

    /// Append a top-level attribute described by a typed handle,
    /// converting `value` through [`typed::IntoWire`].
    ///
    /// The wire-type marker on the handle picks the encoding, so
    /// `add(attrs::USER_NAME, "alice")` writes the UTF-8
    /// bytes while `add(attrs::NAS_PORT, 12u32)` writes the
    /// big-endian 4-byte integer — no manual conversion at the call
    /// site.
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`add_attribute_with`](Self::add_attribute_with).
    pub fn add<T, V>(&mut self, attr: typed::Attr<T>, value: V) -> Result<(), CodecError>
    where
        T: typed::WireType,
        V: typed::IntoWire<T>,
    {
        self.add_attribute_with(attr.code, |out| value.write_value(out))
    }

    /// Append a Vendor-Specific Attribute described by a typed handle.
    ///
    /// Builds the RFC 2865 §5.26 envelope —
    /// `26 | total-len | vendor-id (4) | vendor-type | vendor-len | value` —
    /// around the value bytes produced by [`typed::IntoWire`]. Multi-VSA
    /// packing inside a single type-26 slot is intentionally not done;
    /// each call writes one VSA in its own attribute, matching the
    /// `FreeRADIUS` / Microsoft NPS interop default.
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`add_attribute_with`](Self::add_attribute_with). The
    /// effective payload limit is 247 bytes (253 − 6 for the vendor
    /// envelope).
    pub fn add_vsa<T, V>(&mut self, attr: typed::VsaAttr<T>, value: V) -> Result<(), CodecError>
    where
        T: typed::WireType,
        V: typed::IntoWire<T>,
    {
        self.add_attribute_with(VENDOR_SPECIFIC_TYPE, |out| {
            out.extend_from_slice(&attr.vendor.to_be_bytes());
            out.push(attr.vendor_type);
            let len_pos = out.len();
            out.push(0); // vendor-length placeholder
            let val_start = out.len();
            value.write_value(out);
            let vsa_len = out.len() - val_start + 2;
            // If the inner length would not fit a u8 the outer
            // attribute length check is guaranteed to fail
            // (vsa_len > 255 implies the outer value is > 253), so
            // the half-written buffer will be rolled back. Saturate
            // here to keep the placeholder byte well-formed in the
            // intermediate state.
            out[len_pos] = u8::try_from(vsa_len).unwrap_or(u8::MAX);
        })
    }

    /// Append a top-level TLV-typed parent attribute, building its
    /// nested sub-attributes through a closure.
    ///
    /// `parent_type` is the parent's attribute type byte
    /// (e.g. 173 for `IPv6-6rd-Configuration`). The closure receives
    /// a [`TlvWriter`] for emitting children with either a typed
    /// [`TlvAttr`] handle ([`TlvWriter::add`]) or a raw
    /// `(sub_type, value)` pair ([`TlvWriter::add_raw`]). Each child
    /// is framed as `sub_type (1) || sub_length (1) || value` inside
    /// the parent's value bytes.
    ///
    /// Children write straight into the parent's value region with
    /// no intermediate buffer. On any error the underlying buffer is
    /// rolled back to its pre-call state, so partial writes never
    /// reach the wire.
    ///
    /// [`TlvAttr`]: typed::TlvAttr
    ///
    /// # Errors
    ///
    /// - [`CodecError::AttributeValueTooLong`] — a single child's
    ///   bytes would not fit in one sub-length byte (`> 253`), or
    ///   the assembled parent value exceeds 253 bytes.
    /// - [`CodecError::PacketTooLarge`] — appending would push the
    ///   packet past 4 096 bytes.
    pub fn add_tlv<F>(&mut self, parent_type: u8, build: F) -> Result<(), CodecError>
    where
        F: FnOnce(&mut TlvWriter<'_>) -> Result<(), CodecError>,
    {
        // Snapshot for closure-error rollback. `add_attribute_with`
        // handles its own length-overflow rollback, but a child
        // returning `Err` partway through leaves the outer attribute
        // committed; we undo that by truncating back to here.
        let snapshot = self.inner.len();
        let mut child_err: Option<CodecError> = None;
        self.add_attribute_with(parent_type, |out| {
            let mut w = TlvWriter::new(out);
            if let Err(e) = build(&mut w) {
                child_err = Some(e);
            }
        })?;
        if let Some(e) = child_err {
            self.inner.truncate(snapshot);
            return Err(e);
        }
        Ok(())
    }

    /// Append a Vendor-Specific Attribute whose body is a TLV parent.
    ///
    /// Wraps the standard VSA envelope —
    /// `26 || total-len || vendor-id (4) || vendor-type ||
    /// vendor-len || data` — around a TLV region built by `build`.
    /// Inside `data`, each child the closure adds is laid out as
    /// `sub_type (1) || sub_length (1) || value`, matching
    /// [`add_tlv`](Self::add_tlv).
    ///
    /// # Errors
    ///
    /// - [`CodecError::AttributeValueTooLong`] — a single child
    ///   exceeds the 253-byte sub-length limit, or the assembled
    ///   parent value (vendor envelope + TLV region) exceeds 253
    ///   bytes. The effective TLV-region budget is 247 bytes
    ///   (253 − 6 for the vendor envelope).
    /// - [`CodecError::PacketTooLarge`] — appending would push the
    ///   packet past 4 096 bytes.
    pub fn add_vsa_tlv<F>(
        &mut self,
        vendor: u32,
        vendor_type: u8,
        build: F,
    ) -> Result<(), CodecError>
    where
        F: FnOnce(&mut TlvWriter<'_>) -> Result<(), CodecError>,
    {
        let snapshot = self.inner.len();
        let mut child_err: Option<CodecError> = None;
        self.add_attribute_with(VENDOR_SPECIFIC_TYPE, |out| {
            out.extend_from_slice(&vendor.to_be_bytes());
            out.push(vendor_type);
            let len_pos = out.len();
            out.push(0); // vendor-length placeholder
            let val_start = out.len();
            {
                let mut w = TlvWriter::new(out);
                if let Err(e) = build(&mut w) {
                    child_err = Some(e);
                }
            }
            let vsa_len = out.len() - val_start + 2;
            // Saturate; if the inner exceeds 255 the outer length
            // check fails too and rolls everything back.
            out[len_pos] = u8::try_from(vsa_len).unwrap_or(u8::MAX);
        })?;
        if let Some(e) = child_err {
            self.inner.truncate(snapshot);
            return Err(e);
        }
        Ok(())
    }

    /// Patch the Length field in the header to match the current
    /// buffer size. Called by [`encode::seal`] before the
    /// Authenticator is computed.
    pub(crate) fn patch_length(&mut self) {
        let len =
            u16::try_from(self.inner.len()).expect("PacketBuffer never exceeds MAX_PACKET_LEN");
        self.inner[2..4].copy_from_slice(&len.to_be_bytes());
    }

    /// Overwrite the 16-byte Authenticator field.
    pub(crate) fn set_authenticator(&mut self, auth: [u8; 16]) {
        self.inner[4..MIN_PACKET_LEN].copy_from_slice(&auth);
    }

    /// Overwrite the Identifier byte. Used by the `CoA` originator to
    /// stamp an allocated identifier into a buffer that was built
    /// with a placeholder.
    pub(crate) fn set_identifier(&mut self, identifier: u8) {
        self.inner[1] = identifier;
    }

    /// Mutable view of the attribute region. Used by the
    /// `message_authenticator` patcher to overwrite the placeholder
    /// HMAC slot.
    pub(crate) fn attributes_mut(&mut self) -> &mut [u8] {
        &mut self.inner[MIN_PACKET_LEN..]
    }

    /// Truncate the attribute region to `new_len` bytes. Used by the
    /// reply builder to drop a reserved Message-Authenticator
    /// placeholder when the caller opts out.
    pub(crate) fn truncate_attributes_to(&mut self, new_len: usize) {
        self.inner.truncate(MIN_PACKET_LEN + new_len);
    }

    /// Finalize this buffer as an outbound RFC 2866 / RFC 5176
    /// request: patch the Length field, then compute the Authenticator
    /// as `MD5(packet-with-zeroed-auth || secret)` and write it into
    /// place. Returns the wire bytes.
    ///
    /// The same formula covers `Accounting-Request` (RFC 2866 §3),
    /// `CoA-Request`, and `Disconnect-Request` (RFC 5176 §2). Do *not*
    /// use this for `Access-Request`: that code carries a 16-byte
    /// random value in the Authenticator field, generated via
    /// [`authenticator::random_request_authenticator`].
    ///
    /// Most consumers do not need this directly — the server pipeline
    /// receives requests, it does not originate them. The helper is
    /// exposed for the `CoA` / Disconnect originator and for
    /// integration tests / fuzz harnesses that craft request packets.
    #[must_use]
    pub fn seal_as_zeroed_request(mut self, secret: &[u8]) -> Self {
        self.patch_length();
        let auth = authenticator::compute_zeroed_request(self.as_bytes(), secret);
        self.set_authenticator(auth);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_writes_header() {
        let pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 7);
        let h = pkt.header();
        assert_eq!(h.code, Code::ACCESS_ACCEPT);
        assert_eq!(h.identifier, 7);
        // Length placeholder = MIN_PACKET_LEN until seal.
        assert_eq!(h.length as usize, MIN_PACKET_LEN);
        assert_eq!(h.authenticator, [0; 16]);
        assert!(pkt.attributes().is_empty());
    }

    #[test]
    fn append_attribute_roundtrips() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_attribute(1, b"alice").unwrap();
        pkt.add_attribute(5, &7u32.to_be_bytes()).unwrap();
        let raws: Vec<_> = pkt.attributes_iter().map(Result::unwrap).collect();
        assert_eq!(raws.len(), 2);
        assert_eq!(raws[0].attribute_type(), 1);
        assert_eq!(raws[0].value(), b"alice");
        assert_eq!(raws[1].attribute_type(), 5);
        assert_eq!(raws[1].value(), &7u32.to_be_bytes());
    }

    #[test]
    fn append_value_too_long() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let big = vec![0u8; MAX_ATTRIBUTE_VALUE_LEN + 1];
        assert_eq!(
            pkt.add_attribute(1, &big),
            Err(CodecError::AttributeValueTooLong { len: big.len() }),
        );
    }

    #[test]
    fn append_packet_too_large() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        // Fill with maximum-size attributes until the next one cannot fit.
        let chunk = vec![0u8; MAX_ATTRIBUTE_VALUE_LEN];
        loop {
            match pkt.add_attribute(1, &chunk) {
                Ok(()) => {}
                Err(CodecError::PacketTooLarge { .. }) => break,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn patch_length_and_authenticator() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_attribute(1, b"x").unwrap();
        pkt.patch_length();
        pkt.set_authenticator([0xab; 16]);
        let h = pkt.header();
        assert_eq!(h.length as usize, MIN_PACKET_LEN + 3);
        assert_eq!(h.authenticator, [0xab; 16]);
    }

    #[test]
    fn from_bytes_round_trip() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_REQUEST, 9);
        pkt.add_attribute(1, b"bob").unwrap();
        pkt.patch_length();
        pkt.set_authenticator([0xcd; 16]);
        let wire = pkt.as_bytes().to_vec();
        let parsed = PacketBuffer::from_bytes(&wire).unwrap();
        assert_eq!(parsed.header().code, Code::ACCESS_REQUEST);
        assert_eq!(parsed.header().identifier, 9);
        let raw = parsed.attributes_iter().next().unwrap().unwrap();
        assert_eq!(raw.value(), b"bob");
    }

    #[test]
    fn from_bytes_rejects_invalid() {
        let too_short = [0u8; 10];
        assert!(PacketBuffer::from_bytes(&too_short).is_err());
    }

    #[test]
    fn append_typed_writes_canonical_value() {
        use crate::codec::typed::{Attr, WInteger, WText};

        const USER_NAME: Attr<WText> = Attr::new(1);
        const NAS_PORT: Attr<WInteger> = Attr::new(5);

        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add(USER_NAME, "alice").unwrap();
        pkt.add(NAS_PORT, 7u32).unwrap();

        let raws: Vec<_> = pkt.attributes_iter().map(Result::unwrap).collect();
        assert_eq!(raws[0].attribute_type(), 1);
        assert_eq!(raws[0].value(), b"alice");
        assert_eq!(raws[1].attribute_type(), 5);
        assert_eq!(raws[1].value(), &7u32.to_be_bytes());

        // Round-trip through the typed decoder.
        assert_eq!(raws[0].get(USER_NAME), Some("alice"));
        assert_eq!(raws[1].get(NAS_PORT), Some(7));
    }

    #[test]
    fn append_vsa_typed_builds_rfc_2865_envelope() {
        use crate::codec::typed::{VsaAttr, WText};

        // Cisco PEN 9, Cisco-AVPair = 1, type=string.
        const CISCO_AVPAIR: VsaAttr<WText> = VsaAttr::new(9, 1);

        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_vsa(CISCO_AVPAIR, "shell:priv-lvl=15").unwrap();

        let raw = pkt.attributes_iter().next().unwrap().unwrap();
        assert_eq!(raw.attribute_type(), VENDOR_SPECIFIC_TYPE);
        // 4 PEN + 1 vsa-type + 1 vsa-len + 17 payload = 23.
        assert_eq!(raw.value().len(), 4 + 2 + 17);
        assert_eq!(&raw.value()[..4], &9u32.to_be_bytes());
        assert_eq!(raw.value()[4], 1); // vsa-type
        assert_eq!(raw.value()[5] as usize, 2 + 17); // vsa-len incl. header
        assert_eq!(&raw.value()[6..], b"shell:priv-lvl=15");

        // Decode-side helper agrees.
        assert_eq!(raw.get_vsa(CISCO_AVPAIR), Some("shell:priv-lvl=15"));
    }

    #[test]
    fn append_attribute_with_rolls_back_on_oversize_value() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        let err = pkt
            .add_attribute_with(7, |out| {
                out.extend(std::iter::repeat(0xAA).take(MAX_ATTRIBUTE_VALUE_LEN + 1));
            })
            .unwrap_err();
        assert!(matches!(
            err,
            CodecError::AttributeValueTooLong { len } if len == MAX_ATTRIBUTE_VALUE_LEN + 1
        ));
        // Buffer state is restored byte-for-byte.
        assert_eq!(pkt.as_bytes().len(), before);
    }

    #[test]
    fn append_vsa_typed_oversize_payload_rolls_back() {
        use crate::codec::typed::{VsaAttr, WBytes};
        const BIG_VSA: VsaAttr<WBytes> = VsaAttr::new(9, 1);

        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        // 248 bytes of payload + 6 bytes of envelope = 254 > 253; the
        // outer attribute length cap must catch this and revert.
        let payload = vec![0u8; 248];
        let err = pkt.add_vsa(BIG_VSA, &payload[..]).unwrap_err();
        assert!(matches!(err, CodecError::AttributeValueTooLong { .. }));
        assert_eq!(pkt.as_bytes().len(), before);
    }

    // ── TLV encoder ────────────────────────────────────────────────

    #[test]
    fn add_tlv_writes_nested_children() {
        use crate::codec::attributes;
        use crate::codec::typed::{TlvAttr, WByte, WIpv4};
        // Synthetic top-level TLV parent at type 173 with two
        // typed children. Decode side then walks them back.
        const MASK: TlvAttr<WByte> = TlvAttr::new(173, 1);
        const ADDR: TlvAttr<WIpv4> = TlvAttr::new(173, 3);

        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_tlv(173, |t| {
            t.add(MASK, 32u8)?;
            t.add(ADDR, std::net::Ipv4Addr::new(192, 0, 2, 1))?;
            Ok(())
        })
        .unwrap();

        let parent = attributes::iter(pkt.attributes()).next().unwrap().unwrap();
        assert_eq!(parent.attribute_type(), 173);
        assert_eq!(parent.get_tlv(MASK), Some(32));
        assert_eq!(
            parent.get_tlv(ADDR),
            Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        );
    }

    #[test]
    fn add_tlv_rolls_back_on_oversize_child() {
        use crate::codec::typed::{TlvAttr, WBytes};
        const CHILD: TlvAttr<WBytes> = TlvAttr::new(173, 1);
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        let big = vec![0u8; MAX_ATTRIBUTE_VALUE_LEN + 1];
        let err = pkt
            .add_tlv(173, |t| {
                t.add(CHILD, &big[..])?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, CodecError::AttributeValueTooLong { .. }));
        assert_eq!(pkt.as_bytes().len(), before, "buffer must be restored");
    }

    #[test]
    fn add_tlv_rolls_back_on_oversize_parent() {
        // Several children whose sum overflows the 253-byte parent
        // value budget. The outer `add_attribute_with` length cap
        // catches this and rolls back.
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        let chunk = vec![0u8; 100];
        let err = pkt
            .add_tlv(173, |t| {
                t.add_raw(1, &chunk)?;
                t.add_raw(2, &chunk)?;
                t.add_raw(3, &chunk)?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, CodecError::AttributeValueTooLong { .. }));
        assert_eq!(pkt.as_bytes().len(), before);
    }

    #[test]
    fn add_vsa_tlv_round_trip() {
        use crate::codec::attributes;
        use crate::codec::typed::{VsaTlvAttr, WInteger, WText};
        // Vendor 25053 (Ruckus), parent vendor-type 146 with two
        // children: 146.1 (string), 146.2 (integer).
        const NAME: VsaTlvAttr<WText> = VsaTlvAttr::new(25053, 146, 1);
        const QUOTA: VsaTlvAttr<WInteger> = VsaTlvAttr::new(25053, 146, 2);

        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_vsa_tlv(25053, 146, |t| {
            t.add_vsa(NAME, "tc-name")?;
            t.add_vsa(QUOTA, 7u32)?;
            Ok(())
        })
        .unwrap();

        let parent = attributes::iter(pkt.attributes()).next().unwrap().unwrap();
        assert_eq!(parent.attribute_type(), VENDOR_SPECIFIC_TYPE);
        assert_eq!(parent.get_vsa_tlv(NAME), Some("tc-name"));
        assert_eq!(parent.get_vsa_tlv(QUOTA), Some(7));
    }

    #[test]
    fn add_vsa_tlv_rolls_back_on_oversize_value() {
        use crate::codec::typed::{VsaTlvAttr, WBytes};
        const CHILD: VsaTlvAttr<WBytes> = VsaTlvAttr::new(25053, 146, 1);
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        // 250-byte child + 2-byte sub-TLV header + 6-byte vendor
        // envelope > 253 — outer cap catches this.
        let big = vec![0u8; 250];
        let err = pkt
            .add_vsa_tlv(25053, 146, |t| {
                t.add_vsa(CHILD, &big[..])?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, CodecError::AttributeValueTooLong { .. }));
        assert_eq!(pkt.as_bytes().len(), before);
    }

    #[test]
    fn add_tlv_propagates_explicit_closure_error() {
        // A closure that fails on its own (no length issue) must
        // still leave the buffer untouched.
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        let before = pkt.as_bytes().len();
        let err = pkt
            .add_tlv(173, |t| {
                t.add_raw(1, b"ok")?;
                Err(CodecError::WrongPacketType)
            })
            .unwrap_err();
        assert!(matches!(err, CodecError::WrongPacketType));
        assert_eq!(pkt.as_bytes().len(), before);
    }
}
