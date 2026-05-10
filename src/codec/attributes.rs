//! Zero-copy iteration over the attribute list of a RADIUS packet
//! (RFC 2865 §5).
//!
//! Each attribute on the wire is `Type (1) || Length (1) || Value
//! (Length-2)`, where `Length` is at least 2 (covers the header itself)
//! and at most 255. Attributes are concatenated without padding;
//! parsing is a flat walk.
//!
//! # Total over input
//!
//! [`AttributesIter`] never panics on malformed input. Each step
//! validates the next TLV and yields a [`Result`]: `Ok(RawAttribute)`
//! on a well-formed slot, `Err(AttributeError)` on the first
//! corruption. After an error the iterator returns `None` (fused) — a
//! single bad attribute terminates the walk, matching `FreeRADIUS`
//! behaviour (and avoiding redundant errors when the length field
//! itself is the problem).
//!
//! # Lifetimes
//!
//! [`RawAttribute<'a>`] borrows the attribute byte range *directly*
//! from the source slice, with no intermediate allocation. The `'a`
//! lifetime threads back to whoever owns the bytes
//! ([`super::Header::parse`]'s caller, typically a receive buffer).

use std::fmt;

use super::typed::{Attr, VsaAttr, WireType};

/// Smallest legal attribute on the wire: 1-byte type + 1-byte length
/// (with no value). RFC 2865 §5 sets `Length >= 2`.
const MIN_ATTRIBUTE_LEN: usize = 2;

/// Reasons attribute-list iteration can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeError {
    /// Bytes remain in the attribute region but fewer than the 2-byte
    /// TLV header — the trailing slot is truncated.
    TruncatedHeader {
        /// Number of bytes left in the attribute region.
        remaining: usize,
    },
    /// The Length byte is below the protocol minimum of 2.
    LengthUnderflow {
        /// Length byte as read from the wire.
        length: u8,
    },
    /// The Length byte declares more bytes than remain in the region.
    LengthExceedsRemaining {
        /// Length byte as read from the wire.
        length: u8,
        /// Number of bytes left in the attribute region.
        remaining: usize,
    },
}

impl fmt::Display for AttributeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttributeError::TruncatedHeader { remaining } => write!(
                f,
                "attribute region has {remaining} trailing bytes, fewer than the 2-byte TLV header",
            ),
            AttributeError::LengthUnderflow { length } => write!(
                f,
                "attribute length byte {length} is below the 2-byte minimum",
            ),
            AttributeError::LengthExceedsRemaining { length, remaining } => write!(
                f,
                "attribute length byte {length} exceeds the {remaining} bytes remaining",
            ),
        }
    }
}

impl std::error::Error for AttributeError {}

/// Borrowed view of a single attribute slot inside the source bytes.
///
/// Holds the full TLV (`type || length || value`) so accessors can
/// decode either the header bytes or the value payload without further
/// bounds-checking. `'a` is the lifetime of the underlying byte slice.
#[derive(Debug, Clone, Copy)]
pub struct RawAttribute<'a> {
    tlv: &'a [u8],
}

impl<'a> RawAttribute<'a> {
    /// Attribute type byte (RFC 2865 §5 field 1).
    #[inline]
    #[must_use]
    pub fn attribute_type(&self) -> u8 {
        self.tlv[0]
    }

    /// Encoded length byte (RFC 2865 §5 field 2). Includes the 2-byte
    /// type+length header, so `val().len() == len() - 2`.
    #[inline]
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // wire length byte, not a container length
    pub fn wire_len(&self) -> u8 {
        self.tlv[1]
    }

    /// Value octets (RFC 2865 §5 field 3) without the header.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        &self.tlv[2..]
    }

    /// Match this attribute against a typed handle and decode in one step.
    ///
    /// Returns `Some(view)` on a code match *and* a clean decode under
    /// `T`. Type mismatches and decode failures both return `None` so a
    /// caller can iterate-and-match without distinguishing them.
    #[inline]
    #[must_use]
    // `Attr<T>` is `Copy` and only a `u8` wide; pass-by-value lets the
    // call site fold the constant into the comparison.
    #[allow(clippy::needless_pass_by_value)]
    pub fn get<T: WireType>(&self, attr: Attr<T>) -> Option<T::View<'a>> {
        if self.attribute_type() == attr.code {
            T::decode(self.value())
        } else {
            None
        }
    }

    /// Match this attribute against a Vendor-Specific handle and decode
    /// the per-vendor value.
    ///
    /// On the wire a VSA is type 26 carrying
    /// `vendor-id (4) || vendor-type (1) || vendor-length (1) || data`.
    /// This helper validates the outer type, the vendor PEN, and the
    /// per-vendor type code, then runs `T::decode` on the inner data
    /// slice. Multi-VSA packing inside one type-26 slot is not unwrapped
    /// here.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_vsa<T: WireType>(&self, attr: VsaAttr<T>) -> Option<T::View<'a>> {
        if self.attribute_type() != 26 {
            return None;
        }
        let val = self.value();
        let (pen_bytes, rest) = val.split_first_chunk::<4>()?;
        if u32::from_be_bytes(*pen_bytes) != attr.vendor {
            return None;
        }
        let (&[v_type, v_len], data) = rest.split_first_chunk::<2>()?;
        if v_type != attr.vendor_type {
            return None;
        }
        // `v_len` counts the per-vendor type+length+data bytes; the
        // payload is therefore `v_len - 2`.
        let data_len = (v_len as usize).checked_sub(2)?;
        let data = data.get(..data_len)?;
        T::decode(data)
    }
}

/// Iterator over the attribute slots in a packet's attribute region.
///
/// Construct via [`iter`] (or, eventually, [`super::PacketBuffer`]
/// once it exposes its attribute region). The iterator is fused: after
/// yielding any error it returns `None` forever.
#[derive(Debug, Clone)]
pub struct AttributesIter<'a> {
    rest: &'a [u8],
    /// Set once a malformed attribute is hit so we don't re-emit the
    /// same error on subsequent `next()` calls.
    halted: bool,
}

impl<'a> Iterator for AttributesIter<'a> {
    type Item = Result<RawAttribute<'a>, AttributeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.halted || self.rest.is_empty() {
            return None;
        }
        // 2-byte TLV header.
        if self.rest.len() < MIN_ATTRIBUTE_LEN {
            self.halted = true;
            return Some(Err(AttributeError::TruncatedHeader {
                remaining: self.rest.len(),
            }));
        }
        let length = self.rest[1];
        if (length as usize) < MIN_ATTRIBUTE_LEN {
            self.halted = true;
            return Some(Err(AttributeError::LengthUnderflow { length }));
        }
        if length as usize > self.rest.len() {
            self.halted = true;
            return Some(Err(AttributeError::LengthExceedsRemaining {
                length,
                remaining: self.rest.len(),
            }));
        }
        let (tlv, rest) = self.rest.split_at(length as usize);
        self.rest = rest;
        Some(Ok(RawAttribute { tlv }))
    }
}

impl std::iter::FusedIterator for AttributesIter<'_> {}

/// Build an iterator over the attribute region carved out by
/// [`super::Header::parse`].
#[inline]
#[must_use]
pub fn iter(attrs: &[u8]) -> AttributesIter<'_> {
    AttributesIter {
        rest: attrs,
        halted: false,
    }
}

/// Find the first attribute matching a typed handle and return its
/// decoded value.
///
/// One pass, no allocation. Stops at the first match *or* the first
/// malformed slot — whichever comes first. Use [`iter`] directly when
/// you need to surface the parse error.
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn first<T: WireType>(attrs: &[u8], attr: Attr<T>) -> Option<T::View<'_>> {
    for slot in iter(attrs) {
        let raw = slot.ok()?;
        if let Some(v) = raw.get(attr) {
            return Some(v);
        }
    }
    None
}

/// VSA equivalent of [`first`].
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn first_vsa<T: WireType>(attrs: &[u8], attr: VsaAttr<T>) -> Option<T::View<'_>> {
    for slot in iter(attrs) {
        let raw = slot.ok()?;
        if let Some(v) = raw.get_vsa(attr) {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenate `[type, len, value...]` triples into a single byte
    /// region. `len` is computed as `2 + value.len()` automatically.
    fn region(attrs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for (typ, val) in attrs {
            v.push(*typ);
            v.push(u8::try_from(2 + val.len()).unwrap());
            v.extend_from_slice(val);
        }
        v
    }

    #[test]
    fn empty_region_yields_nothing() {
        assert!(iter(&[]).next().is_none());
    }

    #[test]
    fn walks_well_formed_attributes() {
        let bytes = region(&[(1, b"alice"), (5, &[0, 0, 0, 7])]);
        let mut it = iter(&bytes);
        let a = it.next().unwrap().unwrap();
        assert_eq!(a.attribute_type(), 1);
        assert_eq!(a.wire_len(), 7);
        assert_eq!(a.value(), b"alice");
        let b = it.next().unwrap().unwrap();
        assert_eq!(b.attribute_type(), 5);
        assert_eq!(b.value(), &[0, 0, 0, 7]);
        assert!(it.next().is_none());
    }

    #[test]
    fn typed_get_decodes() {
        // User-Name (1) = "bob", NAS-Port (5) = 42.
        let bytes = region(&[(1, b"bob"), (5, &[0, 0, 0, 42])]);
        let mut it = iter(&bytes);
        let user = it.next().unwrap().unwrap();
        assert_eq!(
            user.get(super::super::typed::Attr::<super::super::typed::WText>::new(1)),
            Some("bob")
        );
        let port = it.next().unwrap().unwrap();
        assert_eq!(
            port.get(super::super::typed::Attr::<super::super::typed::WInteger>::new(5)),
            Some(42),
        );
    }

    #[test]
    fn truncated_header_is_reported_then_fused() {
        // 1 trailing byte is shorter than a TLV header.
        let bytes = vec![1u8];
        let mut it = iter(&bytes);
        assert_eq!(
            it.next().unwrap().unwrap_err(),
            AttributeError::TruncatedHeader { remaining: 1 },
        );
        assert!(it.next().is_none(), "iterator must fuse after error");
    }

    #[test]
    fn length_underflow_is_reported() {
        // Length byte = 1, illegal (minimum is 2).
        let bytes = vec![1u8, 1u8];
        let mut it = iter(&bytes);
        assert_eq!(
            it.next().unwrap().unwrap_err(),
            AttributeError::LengthUnderflow { length: 1 },
        );
        assert!(it.next().is_none());
    }

    #[test]
    fn length_overrun_is_reported() {
        // Length claims 10 but only 4 bytes remain after the type byte
        // (2-byte header + 2-byte value).
        let bytes = vec![1u8, 10u8, 0, 0];
        let mut it = iter(&bytes);
        assert_eq!(
            it.next().unwrap().unwrap_err(),
            AttributeError::LengthExceedsRemaining {
                length: 10,
                remaining: 4
            },
        );
        assert!(it.next().is_none());
    }

    #[test]
    fn first_finds_match_short_circuits() {
        let bytes = region(&[(2, b"x"), (1, b"alice"), (1, b"second")]);
        let v = first(
            &bytes,
            super::super::typed::Attr::<super::super::typed::WText>::new(1),
        )
        .unwrap();
        // First match wins; the second User-Name is not visited.
        assert_eq!(v, "alice");
    }

    #[test]
    fn first_returns_none_on_no_match() {
        let bytes = region(&[(2, b"x")]);
        assert_eq!(
            first(
                &bytes,
                super::super::typed::Attr::<super::super::typed::WText>::new(1),
            ),
            None,
        );
    }

    #[test]
    fn first_stops_at_first_parse_error() {
        // Underflow on the very first slot — no attributes are ever
        // visible.
        let bytes = vec![1u8, 1u8, 9, 9, 9];
        assert_eq!(
            first(
                &bytes,
                super::super::typed::Attr::<super::super::typed::WText>::new(1),
            ),
            None,
        );
    }

    #[test]
    fn vsa_decode_round_trip() {
        // type=26, vendor=9 (Cisco), vendor-type=1, vendor-len=2+5=7,
        // data="hello".
        let mut value = Vec::new();
        value.extend_from_slice(&9u32.to_be_bytes());
        value.push(1); // vendor-type
        value.push(7); // vendor-len = 2 + data.len()
        value.extend_from_slice(b"hello");
        let bytes = region(&[(26, &value)]);
        let v = first_vsa(
            &bytes,
            super::super::typed::VsaAttr::<super::super::typed::WText>::new(9, 1),
        )
        .unwrap();
        assert_eq!(v, "hello");
    }

    #[test]
    fn vsa_wrong_vendor_skipped() {
        let mut value = Vec::new();
        value.extend_from_slice(&9u32.to_be_bytes());
        value.push(1);
        value.push(7);
        value.extend_from_slice(b"hello");
        let bytes = region(&[(26, &value)]);
        // Asking for vendor 14823 (Aruba) — no match.
        assert_eq!(
            first_vsa(
                &bytes,
                super::super::typed::VsaAttr::<super::super::typed::WText>::new(14823, 1),
            ),
            None,
        );
    }
}
