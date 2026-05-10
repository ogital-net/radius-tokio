//! Compile-time-typed handles for known dictionary attributes.
//!
//! The build-time codegen emits one `const` per `ATTRIBUTE` line: an
//! [`Attr<T>`] for top-level attributes or a [`VsaAttr<T>`] for those
//! living inside a `BEGIN-VENDOR` block. The marker type `T` records
//! the wire type so the value decoder is selected at the call site —
//! no runtime dispatch, no allocation, fully inlinable.
//!
//! Callers use these handles via the codec's `RawAttribute::get` accessor
//! (per-attribute match in an iterator) or the free `first` / `first_vsa`
//! lookups in `radius_tokio::attributes`.
//!
//! ```ignore
//! use radius_tokio::dict::generated::rfc::attrs;
//!
//! for attr in packet.attributes_iter() {
//!     if let Some(name) = attr.get(attrs::USER_NAME) {
//!         // name: &str
//!     }
//! }
//! ```

use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Wire-type marker. Implementors describe how a slice of value octets
/// (the bytes after the 2-byte type+length header) decodes into a
/// borrowed Rust view.
///
/// `decode` returns `None` on any malformed input — wrong length for a
/// fixed-size scalar, invalid UTF-8 for a [`WText`], etc. Callers treat
/// `None` as "skip this attribute" rather than a hard error so a single
/// mangled attribute does not poison the whole packet.
pub trait WireType: 'static {
    /// Borrowed view returned by [`decode`](Self::decode). The lifetime
    /// is tied to the source byte slice, which itself borrows from the
    /// owning packet buffer.
    type View<'a>;

    /// Decode value octets. `bytes` is the slice *after* the type+length
    /// header.
    fn decode(bytes: &[u8]) -> Option<Self::View<'_>>;
}

// ---------- markers ----------------------------------------------------

/// UTF-8 text (`string` in dictionaries; RFC 8044 §3.4 nominates UTF-8).
/// Decodes via [`std::str::from_utf8`]; non-UTF-8 yields `None`.
/// Reach for [`WBytes`] if you need to tolerate legacy non-UTF-8 strings.
pub struct WText;

/// Variable-length opaque octets (`octets`, container types, anything
/// we do not specialize further).
pub struct WBytes;

/// 1-byte unsigned integer (`byte`).
pub struct WByte;
/// 2-byte big-endian unsigned integer (`short`).
pub struct WShort;
/// 4-byte big-endian unsigned integer (`integer`, `uint32`, `date`).
pub struct WInteger;
/// 8-byte big-endian unsigned integer (`integer64`).
pub struct WInteger64;
/// 4-byte big-endian signed integer (`signed`).
pub struct WSigned;
/// 4-byte IPv4 address (`ipaddr`).
pub struct WIpv4;
/// 16-byte IPv6 address (`ipv6addr`).
pub struct WIpv6;
/// 6-byte Ethernet MAC (`ether`).
pub struct WEther;
/// 8-byte interface identifier (`ifid`).
pub struct WIfid;

/// Tagged UTF-8 text (RFC 2868 §3.5: `string has_tag`).
///
/// Wire layout: an optional 1-byte tag in the range `0x01..=0x1F`
/// followed by the UTF-8 payload. If the first byte is `> 0x1F` it is
/// not a tag and forms part of the string. Decodes into
/// [`Tagged<&str>`]; encodes from [`Tagged<&str>`] or `(u8, &str)`.
pub struct WTaggedText;

/// Tagged 32-bit unsigned integer (RFC 2868 §3.6: `integer has_tag`).
///
/// Wire layout is always 4 bytes: the first byte is the tag and the
/// remaining 3 bytes are the big-endian integer value (24-bit range).
/// If the first byte is `> 0x1F` it is treated as the high-order octet
/// of a normal 32-bit integer and no tag is reported. Decodes into
/// [`Tagged<u32>`]; encodes from [`Tagged<u32>`] or `(u8, u32)`.
pub struct WTaggedInteger;

/// Value-plus-tag pair returned for tagged attributes (RFC 2868 §3.1).
///
/// `tag` is `Some(t)` when the on-wire encoding carried a tag byte in
/// the `0x00..=0x1F` range that groups this attribute with other
/// attributes for the same tunnel; it is `None` when the attribute was
/// encoded without a tag (string: first byte `> 0x1F`; integer: first
/// byte `> 0x1F`, in which case `value` holds the full 32-bit integer).
///
/// On encode, `Some(t)` writes the tag byte (clamped to `t & 0x1F`)
/// and `None` omits it — except for tagged integers, where the wire
/// format is always 4 bytes; an untagged tagged-integer therefore
/// writes the full `u32` and the caller must ensure the high byte is
/// `> 0x1F` (otherwise a peer will decode it as a tagged value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tagged<V> {
    /// RFC 2868 §3.1 tag in the range `0x00..=0x1F`, or `None` if the
    /// attribute was sent untagged.
    pub tag: Option<u8>,
    /// The attribute's typed value.
    pub value: V,
}

impl<V> Tagged<V> {
    /// Build a tagged pair. The tag is masked to its lower 5 bits per
    /// RFC 2868 §3.1.
    #[inline]
    #[must_use]
    pub const fn new(tag: u8, value: V) -> Self {
        Self {
            tag: Some(tag & 0x1F),
            value,
        }
    }

    /// Build a pair with no tag byte on the wire.
    #[inline]
    #[must_use]
    pub const fn untagged(value: V) -> Self {
        Self { tag: None, value }
    }
}

impl<V> From<(u8, V)> for Tagged<V> {
    #[inline]
    fn from((tag, value): (u8, V)) -> Self {
        Tagged::new(tag, value)
    }
}

// ---------- impls ------------------------------------------------------

impl WireType for WText {
    type View<'a> = &'a str;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<&str> {
        std::str::from_utf8(bytes).ok()
    }
}

impl WireType for WBytes {
    type View<'a> = &'a [u8];
    #[inline]
    fn decode(bytes: &[u8]) -> Option<&[u8]> {
        Some(bytes)
    }
}

impl WireType for WByte {
    type View<'a> = u8;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<u8> {
        match bytes {
            [b] => Some(*b),
            _ => None,
        }
    }
}

impl WireType for WShort {
    type View<'a> = u16;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<u16> {
        bytes.try_into().ok().map(u16::from_be_bytes)
    }
}

impl WireType for WInteger {
    type View<'a> = u32;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<u32> {
        bytes.try_into().ok().map(u32::from_be_bytes)
    }
}

impl WireType for WInteger64 {
    type View<'a> = u64;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<u64> {
        bytes.try_into().ok().map(u64::from_be_bytes)
    }
}

impl WireType for WSigned {
    type View<'a> = i32;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<i32> {
        bytes.try_into().ok().map(i32::from_be_bytes)
    }
}

impl WireType for WIpv4 {
    type View<'a> = Ipv4Addr;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<Ipv4Addr> {
        let octets: [u8; 4] = bytes.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }
}

impl WireType for WIpv6 {
    type View<'a> = Ipv6Addr;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<Ipv6Addr> {
        let octets: [u8; 16] = bytes.try_into().ok()?;
        Some(Ipv6Addr::from(octets))
    }
}

impl WireType for WEther {
    type View<'a> = [u8; 6];
    #[inline]
    fn decode(bytes: &[u8]) -> Option<[u8; 6]> {
        bytes.try_into().ok()
    }
}

impl WireType for WIfid {
    type View<'a> = [u8; 8];
    #[inline]
    fn decode(bytes: &[u8]) -> Option<[u8; 8]> {
        bytes.try_into().ok()
    }
}

/// Split a tagged value's leading byte into `(tag, rest)`.
///
/// Returns `(Some(t), &bytes[1..])` if `bytes[0]` lies in the
/// reserved tag range `0x00..=0x1F`, otherwise `(None, bytes)` —
/// matching the RFC 2868 §3.1 rule that values above `0x1F` are
/// payload bytes, not tags.
#[inline]
fn split_tag(bytes: &[u8]) -> (Option<u8>, &[u8]) {
    match bytes.split_first() {
        Some((&t, rest)) if t <= 0x1F => (Some(t), rest),
        _ => (None, bytes),
    }
}

impl WireType for WTaggedText {
    type View<'a> = Tagged<&'a str>;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<Tagged<&str>> {
        let (tag, rest) = split_tag(bytes);
        std::str::from_utf8(rest)
            .ok()
            .map(|value| Tagged { tag, value })
    }
}

impl WireType for WTaggedInteger {
    type View<'a> = Tagged<u32>;
    #[inline]
    fn decode(bytes: &[u8]) -> Option<Tagged<u32>> {
        // RFC 2868 §3.6 fixes the on-wire size at 4 bytes.
        let octets: [u8; 4] = bytes.try_into().ok()?;
        if octets[0] <= 0x1F {
            // Tagged: first byte is the tag, remaining 3 bytes are the
            // big-endian 24-bit value.
            let value = u32::from_be_bytes([0, octets[1], octets[2], octets[3]]);
            Some(Tagged {
                tag: Some(octets[0]),
                value,
            })
        } else {
            // Untagged: full 32-bit integer.
            Some(Tagged {
                tag: None,
                value: u32::from_be_bytes(octets),
            })
        }
    }
}

// ---------- handles ----------------------------------------------------

/// Typed handle to a top-level attribute. Carries only the 1-byte type
/// code plus a zero-sized wire-type marker, so it is `Copy`, `const`-
/// constructible, and disappears entirely after monomorphization.
#[derive(Debug)]
pub struct Attr<T: WireType> {
    /// RADIUS attribute type code (RFC 2865 §5 field 1).
    pub code: u8,
    _wire: PhantomData<fn() -> T>,
}

// Hand-impl `Copy`/`Clone` so the bound stays free of `T: Copy` — the
// derive would add it even though `PhantomData<fn() -> T>` is `Copy`
// for any `T`.
impl<T: WireType> Copy for Attr<T> {}
impl<T: WireType> Clone for Attr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: WireType> Attr<T> {
    /// Build a handle for the given attribute code. Used by codegen.
    #[must_use]
    pub const fn new(code: u8) -> Self {
        Self {
            code,
            _wire: PhantomData,
        }
    }
}

/// Typed handle to a Vendor-Specific Attribute. Pairs the IANA Private
/// Enterprise Number with the per-vendor type code; the wire-type marker
/// drives the value decoder exactly as for [`Attr`].
#[derive(Debug)]
pub struct VsaAttr<T: WireType> {
    /// IANA Private Enterprise Number of the owning vendor.
    pub vendor: u32,
    /// Per-vendor attribute type code.
    pub vendor_type: u8,
    _wire: PhantomData<fn() -> T>,
}

// See `Attr`'s `Copy`/`Clone` impls for the rationale.
impl<T: WireType> Copy for VsaAttr<T> {}
impl<T: WireType> Clone for VsaAttr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: WireType> VsaAttr<T> {
    /// Build a handle for the given vendor PEN + per-vendor type. Used
    /// by codegen.
    #[must_use]
    pub const fn new(vendor: u32, vendor_type: u8) -> Self {
        Self {
            vendor,
            vendor_type,
            _wire: PhantomData,
        }
    }
}

// ---------- encode side -----------------------------------------------

/// Conversion from a Rust value into the wire-format value bytes of a
/// dictionary attribute.
///
/// Parameterised by the wire-type marker `T` so a single Rust type can
/// be encoded multiple ways (e.g. `&[u8]` is `IntoWire<WBytes>` only,
/// not `IntoWire<WText>` — UTF-8 input goes through `&str` instead).
/// The `T` parameter is supplied by the [`Attr<T>`] / [`VsaAttr<T>`]
/// handle at the call site, so type inference picks the right impl
/// without callers spelling `T` out.
///
/// Implementors `extend` `out` with exactly the value octets — no
/// type/length header, no vendor framing. The packet builder owns
/// that envelope.
pub trait IntoWire<T: WireType> {
    /// Append the encoded value bytes to `out`.
    fn write_value(self, out: &mut Vec<u8>);
}

impl IntoWire<WText> for &str {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl IntoWire<WText> for &String {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

impl IntoWire<WBytes> for &[u8] {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> IntoWire<WBytes> for &[u8; N] {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl IntoWire<WBytes> for &Vec<u8> {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl IntoWire<WByte> for u8 {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.push(self);
    }
}

impl IntoWire<WShort> for u16 {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl IntoWire<WInteger> for u32 {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl IntoWire<WInteger64> for u64 {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl IntoWire<WSigned> for i32 {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl IntoWire<WIpv4> for Ipv4Addr {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.octets());
    }
}

impl IntoWire<WIpv6> for Ipv6Addr {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.octets());
    }
}

impl IntoWire<WEther> for [u8; 6] {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self);
    }
}

impl IntoWire<WIfid> for [u8; 8] {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self);
    }
}

// --- tagged encoders ---------------------------------------------------
//
// Tag bytes are masked to 5 bits (`& 0x1F`) on emit, matching the
// RFC 2868 §3.1 tag space; passing a wider value silently truncates
// rather than corrupting the wire by spilling into the payload range.

impl IntoWire<WTaggedText> for Tagged<&str> {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        if let Some(tag) = self.tag {
            out.push(tag & 0x1F);
        }
        out.extend_from_slice(self.value.as_bytes());
    }
}

impl IntoWire<WTaggedText> for Tagged<&String> {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        Tagged {
            tag: self.tag,
            value: self.value.as_str(),
        }
        .write_value(out);
    }
}

/// Shorthand: `(tag, value)` always writes a tag byte. Use
/// [`Tagged::untagged`] to omit it.
impl IntoWire<WTaggedText> for (u8, &str) {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        Tagged::new(self.0, self.1).write_value(out);
    }
}

impl IntoWire<WTaggedInteger> for Tagged<u32> {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        // RFC 2868 §3.6 forces a 4-byte wire form. When the caller
        // requests a tag, emit `tag (1) || value[1..4] (3)` so the
        // 24-bit value occupies the lower three octets. When they
        // omit the tag, emit the full 32-bit big-endian integer; the
        // caller is responsible for ensuring the high byte is `>
        // 0x1F` so peers parse it as untagged.
        if let Some(tag) = self.tag {
            out.push(tag & 0x1F);
            let bytes = self.value.to_be_bytes();
            out.extend_from_slice(&bytes[1..4]);
        } else {
            out.extend_from_slice(&self.value.to_be_bytes());
        }
    }
}

/// Shorthand: `(tag, value)` always writes a tag byte. Use
/// [`Tagged::untagged`] to omit it.
impl IntoWire<WTaggedInteger> for (u8, u32) {
    #[inline]
    fn write_value(self, out: &mut Vec<u8>) {
        Tagged::new(self.0, self.1).write_value(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_decoders() {
        assert_eq!(WByte::decode(&[0x2a]), Some(0x2a));
        assert_eq!(WByte::decode(&[1, 2]), None);
        assert_eq!(WShort::decode(&[0x12, 0x34]), Some(0x1234));
        assert_eq!(WInteger::decode(&[0, 0, 0, 5]), Some(5));
        assert_eq!(WInteger::decode(&[0, 0, 5]), None);
        assert_eq!(WInteger64::decode(&[0, 0, 0, 0, 0, 0, 0, 9]), Some(9));
        assert_eq!(WSigned::decode(&[0xff, 0xff, 0xff, 0xff]), Some(-1));
    }

    #[test]
    fn text_and_bytes() {
        assert_eq!(WText::decode(b"hi"), Some("hi"));
        assert_eq!(WText::decode(&[0xff, 0xfe]), None); // invalid utf-8
        assert_eq!(WBytes::decode(&[1, 2, 3]), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn address_decoders() {
        assert_eq!(
            WIpv4::decode(&[10, 0, 0, 1]),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(WIpv4::decode(&[10, 0, 0]), None);
        let v6 = WIpv6::decode(&[0; 16]).unwrap();
        assert_eq!(v6, Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            WEther::decode(&[1, 2, 3, 4, 5, 6]),
            Some([1, 2, 3, 4, 5, 6])
        );
        assert_eq!(WIfid::decode(&[0; 8]), Some([0; 8]));
    }

    #[test]
    fn handles_are_compact() {
        // Marker is ZST; only the byte payload survives.
        assert_eq!(
            std::mem::size_of::<Attr<WInteger>>(),
            std::mem::size_of::<u8>()
        );
        // VsaAttr carries PEN + vendor-type; alignment may pad it to a u32.
        assert!(std::mem::size_of::<VsaAttr<WBytes>>() <= std::mem::size_of::<u32>() * 2);
    }

    #[test]
    fn tagged_text_decode_with_tag() {
        // `0x01 || "vpn0"` — tag 1, value "vpn0".
        let v = WTaggedText::decode(b"\x01vpn0").unwrap();
        assert_eq!(v.tag, Some(1));
        assert_eq!(v.value, "vpn0");
    }

    #[test]
    fn tagged_text_decode_untagged_when_high_byte() {
        // First byte 0x76 ('v') > 0x1F — no tag, whole string is value.
        let v = WTaggedText::decode(b"vpn0").unwrap();
        assert_eq!(v.tag, None);
        assert_eq!(v.value, "vpn0");
    }

    #[test]
    fn tagged_text_decode_empty_value_with_tag() {
        let v = WTaggedText::decode(b"\x05").unwrap();
        assert_eq!(v.tag, Some(5));
        assert_eq!(v.value, "");
    }

    #[test]
    fn tagged_text_decode_rejects_bad_utf8() {
        assert!(WTaggedText::decode(b"\x01\xff\xfe").is_none());
    }

    #[test]
    fn tagged_integer_decode_with_tag() {
        // tag=1, value=0x000006 (IPSec ESP).
        let v = WTaggedInteger::decode(&[0x01, 0x00, 0x00, 0x06]).unwrap();
        assert_eq!(v.tag, Some(1));
        assert_eq!(v.value, 6);
    }

    #[test]
    fn tagged_integer_decode_untagged() {
        // First byte 0xAA > 0x1F — whole word is the integer value.
        let v = WTaggedInteger::decode(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        assert_eq!(v.tag, None);
        assert_eq!(v.value, 0xAABB_CCDD);
    }

    #[test]
    fn tagged_integer_decode_rejects_wrong_length() {
        assert!(WTaggedInteger::decode(&[0x01, 0x00, 0x06]).is_none());
        assert!(WTaggedInteger::decode(&[0x01, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn tagged_text_encode_with_tag() {
        let mut out = Vec::new();
        Tagged::new(2, "vpn0").write_value(&mut out);
        assert_eq!(out, b"\x02vpn0");
    }

    #[test]
    fn tagged_text_encode_untagged() {
        let mut out = Vec::new();
        Tagged::untagged("vpn0").write_value(&mut out);
        assert_eq!(out, b"vpn0");
    }

    #[test]
    fn tagged_text_encode_tuple_shorthand() {
        let mut out = Vec::new();
        IntoWire::<WTaggedText>::write_value((3u8, "ipsec"), &mut out);
        assert_eq!(out, b"\x03ipsec");
    }

    #[test]
    fn tagged_text_encode_masks_oversized_tag() {
        // 0x21 (> 0x1F) must be truncated to 0x01 so the byte cannot
        // be misread as the first byte of the payload.
        let mut out = Vec::new();
        Tagged::new(0x21, "vpn0").write_value(&mut out);
        assert_eq!(out, b"\x01vpn0");
    }

    #[test]
    fn tagged_integer_encode_with_tag() {
        let mut out = Vec::new();
        Tagged::new(1, 6u32).write_value(&mut out);
        // tag(1) || 0x00 0x00 0x06
        assert_eq!(out, [0x01, 0x00, 0x00, 0x06]);
    }

    #[test]
    fn tagged_integer_encode_drops_top_byte_when_tagged() {
        // value 0xFF_00_00_06 collides with the tagged 24-bit space;
        // the top byte is silently dropped to keep the wire valid.
        let mut out = Vec::new();
        Tagged::new(1, 0xFF00_0006u32).write_value(&mut out);
        assert_eq!(out, [0x01, 0x00, 0x00, 0x06]);
    }

    #[test]
    fn tagged_integer_encode_untagged_emits_full_word() {
        let mut out = Vec::new();
        Tagged::untagged(0xAABB_CCDDu32).write_value(&mut out);
        assert_eq!(out, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn tagged_integer_roundtrip() {
        let mut buf = Vec::new();
        Tagged::new(7, 0x12_3456u32).write_value(&mut buf);
        let v = WTaggedInteger::decode(&buf).unwrap();
        assert_eq!(v, Tagged::new(7, 0x12_3456));
    }

    #[test]
    fn tagged_text_roundtrip() {
        let mut buf = Vec::new();
        Tagged::new(4, "alpha").write_value(&mut buf);
        let v = WTaggedText::decode(&buf).unwrap();
        assert_eq!(v.tag, Some(4));
        assert_eq!(v.value, "alpha");
    }
}
