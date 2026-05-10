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
}
