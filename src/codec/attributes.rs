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

use super::typed::{Attr, TlvAttr, VsaAttr, VsaTlvAttr, WireType};

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

    /// Presence-only check against a typed handle.
    ///
    /// Returns `true` iff the attribute type byte equals `attr.code`.
    /// Does *not* attempt to decode the value, so a malformed payload
    /// still counts as present — the right semantics for top-level
    /// dispatch (`if req contains EAP-Message do EAP else …`) where
    /// the handler's job is *to* parse the value.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn matches<T: WireType>(&self, attr: Attr<T>) -> bool {
        self.attribute_type() == attr.code
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

    /// Presence-only check against a Vendor-Specific handle.
    ///
    /// Returns `true` iff this attribute is type 26, carries the
    /// requested PEN + vendor-type, and has a structurally valid VSA
    /// envelope (vendor-length fits within the outer value). The
    /// payload bytes are *not* run through `T::decode`.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn matches_vsa<T: WireType>(&self, attr: VsaAttr<T>) -> bool {
        if self.attribute_type() != 26 {
            return false;
        }
        let val = self.value();
        let Some((pen_bytes, rest)) = val.split_first_chunk::<4>() else {
            return false;
        };
        if u32::from_be_bytes(*pen_bytes) != attr.vendor {
            return false;
        }
        let Some((&[v_type, v_len], data)) = rest.split_first_chunk::<2>() else {
            return false;
        };
        if v_type != attr.vendor_type {
            return false;
        }
        let Some(data_len) = (v_len as usize).checked_sub(2) else {
            return false;
        };
        data.len() >= data_len
    }

    /// Walk this attribute's value bytes as a sequence of TLV
    /// sub-attributes (each `sub_type (1) || sub_length (1) || data`).
    ///
    /// Suitable for top-level `tlv`-typed parents (e.g.
    /// `IPv6-6rd-Configuration` from RFC 6930). The iterator is the
    /// same flat walker [`iter`] uses for the outer attribute region;
    /// errors and fusing behave identically.
    #[inline]
    #[must_use]
    pub fn tlv_children(&self) -> AttributesIter<'a> {
        iter(self.value())
    }

    /// If this attribute is a Vendor-Specific Attribute (type 26)
    /// matching `vendor` / `vendor_type`, walk the per-vendor data
    /// region as a sequence of TLV sub-attributes.
    ///
    /// Returns `None` on a type or vendor mismatch, on a truncated
    /// VSA envelope, or on a vendor-length that overruns the value
    /// bytes — in every case there is no valid TLV region to walk.
    #[inline]
    #[must_use]
    pub fn vsa_tlv_children(&self, vendor: u32, vendor_type: u8) -> Option<AttributesIter<'a>> {
        if self.attribute_type() != 26 {
            return None;
        }
        let val = self.value();
        let (pen_bytes, rest) = val.split_first_chunk::<4>()?;
        if u32::from_be_bytes(*pen_bytes) != vendor {
            return None;
        }
        let (&[v_type, v_len], data) = rest.split_first_chunk::<2>()?;
        if v_type != vendor_type {
            return None;
        }
        let data_len = (v_len as usize).checked_sub(2)?;
        let data = data.get(..data_len)?;
        Some(iter(data))
    }

    /// Match this attribute against a TLV child handle and decode the
    /// sub-attribute value.
    ///
    /// Returns `Some(view)` only when the parent attribute type
    /// matches `attr.parent`, the parent's value walks cleanly under
    /// [`tlv_children`](Self::tlv_children), the requested child
    /// sub-type appears, *and* its bytes decode cleanly under `T`.
    /// Anything else — wrong parent, malformed inner TLV, missing or
    /// undecodable child — yields `None` so callers can iterate-and-
    /// match without distinguishing reasons.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_tlv<T: WireType>(&self, attr: TlvAttr<T>) -> Option<T::View<'a>> {
        if self.attribute_type() != attr.parent {
            return None;
        }
        for slot in self.tlv_children() {
            let child = slot.ok()?;
            if child.attribute_type() == attr.child {
                return T::decode(child.value());
            }
        }
        None
    }

    /// Presence-only check against a TLV child handle.
    ///
    /// Returns `true` iff the outer attribute matches `attr.parent`
    /// and its TLV children contain a well-formed slot whose
    /// sub-type equals `attr.child`. The child's value bytes are
    /// *not* decoded under `T`.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn matches_tlv<T: WireType>(&self, attr: TlvAttr<T>) -> bool {
        if self.attribute_type() != attr.parent {
            return false;
        }
        for slot in self.tlv_children() {
            let Ok(child) = slot else { return false };
            if child.attribute_type() == attr.child {
                return true;
            }
        }
        false
    }

    /// VSA equivalent of [`get_tlv`](Self::get_tlv): match a
    /// vendor-specific TLV child handle.
    ///
    /// On the wire the parent must be type 26 carrying the supplied
    /// vendor PEN + vendor-type; its data region is then walked as
    /// nested TLV sub-attributes. Failure modes mirror
    /// [`get_tlv`](Self::get_tlv).
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_vsa_tlv<T: WireType>(&self, attr: VsaTlvAttr<T>) -> Option<T::View<'a>> {
        let inner = self.vsa_tlv_children(attr.vendor, attr.parent)?;
        for slot in inner {
            let child = slot.ok()?;
            if child.attribute_type() == attr.child {
                return T::decode(child.value());
            }
        }
        None
    }

    /// Presence-only check against a vendor-specific TLV child handle.
    ///
    /// Returns `true` iff this attribute carries a structurally valid
    /// VSA envelope for `attr.vendor` / `attr.parent` and the inner
    /// TLV region contains a well-formed slot whose sub-type equals
    /// `attr.child`. The child's value bytes are *not* decoded
    /// under `T`.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn matches_vsa_tlv<T: WireType>(&self, attr: VsaTlvAttr<T>) -> bool {
        let Some(inner) = self.vsa_tlv_children(attr.vendor, attr.parent) else {
            return false;
        };
        for slot in inner {
            let Ok(child) = slot else { return false };
            if child.attribute_type() == attr.child {
                return true;
            }
        }
        false
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

/// Find the first TLV sub-attribute matching a typed child handle.
///
/// Walks the attribute region for any slot whose top-level type
/// matches the parent, then inspects that parent's TLV children for
/// the requested sub-type. Stops at the first match or the first
/// malformed slot — whichever comes first.
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn first_tlv<T: WireType>(attrs: &[u8], attr: TlvAttr<T>) -> Option<T::View<'_>> {
    for slot in iter(attrs) {
        let raw = slot.ok()?;
        if let Some(v) = raw.get_tlv(attr) {
            return Some(v);
        }
    }
    None
}

/// VSA equivalent of [`first_tlv`]: find the first vendor-specific
/// TLV sub-attribute matching `attr`.
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn first_vsa_tlv<T: WireType>(attrs: &[u8], attr: VsaTlvAttr<T>) -> Option<T::View<'_>> {
    for slot in iter(attrs) {
        let raw = slot.ok()?;
        if let Some(v) = raw.get_vsa_tlv(attr) {
            return Some(v);
        }
    }
    None
}

/// Presence-only walk: `true` iff some well-formed slot in `attrs`
/// matches `attr` under [`RawAttribute::matches`].
///
/// The value bytes are *not* decoded — the right primitive for
/// dispatch (e.g. "does this packet carry an `EAP-Message`?"). Walks
/// stop at the first match *or* the first malformed slot, whichever
/// comes first; a parse error before a hit yields `false`.
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn contains<T: WireType>(attrs: &[u8], attr: Attr<T>) -> bool {
    for slot in iter(attrs) {
        let Ok(raw) = slot else { return false };
        if raw.matches(attr) {
            return true;
        }
    }
    false
}

/// VSA equivalent of [`contains`].
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn contains_vsa<T: WireType>(attrs: &[u8], attr: VsaAttr<T>) -> bool {
    for slot in iter(attrs) {
        let Ok(raw) = slot else { return false };
        if raw.matches_vsa(attr) {
            return true;
        }
    }
    false
}

/// Presence-only walk for a TLV child handle. Mirrors [`first_tlv`]
/// but skips the inner `T::decode`.
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn contains_tlv<T: WireType>(attrs: &[u8], attr: TlvAttr<T>) -> bool {
    for slot in iter(attrs) {
        let Ok(raw) = slot else { return false };
        if raw.matches_tlv(attr) {
            return true;
        }
    }
    false
}

/// VSA equivalent of [`contains_tlv`].
#[inline]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn contains_vsa_tlv<T: WireType>(attrs: &[u8], attr: VsaTlvAttr<T>) -> bool {
    for slot in iter(attrs) {
        let Ok(raw) = slot else { return false };
        if raw.matches_vsa_tlv(attr) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------
// Multi-attribute routing
// ---------------------------------------------------------------------
//
// The library deliberately does *not* ship a bitmap / set type for
// "which attributes are present in this packet". A 256-bit map only
// covers RFC top-level codes — VSAs all collapse onto bit 26, TLV
// children aren't visible — so any consumer wanting to route on a
// vendor attribute would have to mix in a second walk anyway. Two
// ways to ask the same question, two performance profiles, two code
// paths under test.
//
// The opinionated idiom is therefore: when you need to inspect
// several attributes in one pass (a root dispatcher, for example),
// walk the attribute region once with [`iter`] / `Request::attributes_iter`
// and fold the predicates inline. See `Request::attributes_iter` for
// the worked example.
//
// For a one-off presence check, [`contains`] / [`contains_vsa`] /
// [`contains_tlv`] (and the matching `Request::contains*` methods)
// are the right shortcut — they short-circuit and only walk as far
// as the first match.

// ---------------------------------------------------------------------
// AttributesView — shared trait for borrowed-attribute accessors
// ---------------------------------------------------------------------

/// Borrowed view over a RADIUS attribute region.
///
/// Implementors expose a single `&'a [u8]` slice via
/// [`raw_attributes`](Self::raw_attributes); every other accessor is
/// a default method built on top of it. Implemented by
/// [`crate::server::Request`] (the live handler view), by
/// `radius_tokio_eap::Outer` (the snapshot handed to EAP credential
/// traits), and by anything else that owns or borrows an attribute
/// region.
///
/// The point of the trait is API consistency: write generic helpers
/// like
///
/// ```ignore
/// fn looks_like_eap<'a, A: radius_tokio::AttributesView<'a>>(view: &A) -> bool {
///     view.contains_raw(79) // EAP-Message
/// }
/// ```
///
/// once and apply them anywhere a borrowed attribute region is in
/// scope, without re-walking the bytes through ad-hoc free
/// functions.
///
/// All methods are stop-at-first-malformed-slot: a parse error
/// upstream of the predicate is treated the same as "not present".
/// Callers that need to distinguish "absent" from "malformed
/// payload" can fall back to [`first_raw`](Self::first_raw) (which
/// surfaces [`AttributeError`]) or to [`iter`] on
/// [`raw_attributes`](Self::raw_attributes).
pub trait AttributesView<'a> {
    /// Borrow the underlying attribute region as a contiguous byte
    /// slice. The only required method — every other accessor
    /// defaults to walking the region returned here.
    fn raw_attributes(&self) -> &'a [u8];

    /// Walk the attribute region one slot at a time.
    #[inline]
    fn attributes_iter(&self) -> AttributesIter<'a> {
        iter(self.raw_attributes())
    }

    /// Find the first well-formed attribute with the given type
    /// byte. Returns `Ok(None)` when no attribute of that type was
    /// present and `Err` when a malformed slot was hit first.
    ///
    /// # Errors
    ///
    /// Forwards [`AttributeError`] from [`AttributesIter`].
    #[inline]
    fn first_raw(&self, typ: u8) -> Result<Option<RawAttribute<'a>>, AttributeError> {
        for slot in self.attributes_iter() {
            let raw = slot?;
            if raw.attribute_type() == typ {
                return Ok(Some(raw));
            }
        }
        Ok(None)
    }

    /// Presence-only check for a raw attribute type byte. A
    /// malformed slot before a match yields `false`.
    #[inline]
    #[must_use]
    fn contains_raw(&self, typ: u8) -> bool {
        for slot in self.attributes_iter() {
            let Ok(raw) = slot else { return false };
            if raw.attribute_type() == typ {
                return true;
            }
        }
        false
    }

    /// Presence-only check for a typed attribute handle.
    #[inline]
    #[must_use]
    fn contains<T: WireType>(&self, attr: Attr<T>) -> bool {
        contains(self.raw_attributes(), attr)
    }

    /// Presence-only check for a Vendor-Specific attribute handle.
    #[inline]
    #[must_use]
    fn contains_vsa<T: WireType>(&self, attr: VsaAttr<T>) -> bool {
        contains_vsa(self.raw_attributes(), attr)
    }

    /// Presence-only check for a TLV child handle.
    #[inline]
    #[must_use]
    fn contains_tlv<T: WireType>(&self, attr: TlvAttr<T>) -> bool {
        contains_tlv(self.raw_attributes(), attr)
    }

    /// Presence-only check for a vendor-specific TLV child handle.
    #[inline]
    #[must_use]
    fn contains_vsa_tlv<T: WireType>(&self, attr: VsaTlvAttr<T>) -> bool {
        contains_vsa_tlv(self.raw_attributes(), attr)
    }

    /// Borrowed value of the `User-Name` attribute (RFC 2865 §5.1,
    /// attribute type 1) if present.
    #[inline]
    #[must_use]
    fn user_name(&self) -> Option<&'a [u8]> {
        self.first_raw(1).ok().flatten().map(|raw| raw.value())
    }

    /// Value of the `State` attribute (RFC 2865 §5.24, attribute
    /// type 24) if present.
    #[inline]
    #[must_use]
    fn state(&self) -> Option<&'a [u8]> {
        self.first_raw(24).ok().flatten().map(|raw| raw.value())
    }

    /// Reassemble every `EAP-Message` (RFC 3579 §3.1) attribute on
    /// this view into a fresh `Vec<u8>`. Empty when none present.
    #[inline]
    #[must_use]
    fn eap_message(&self) -> Vec<u8> {
        crate::codec::eap::reassemble(self.raw_attributes())
    }

    /// Reassemble every `EAP-Message` attribute on this view into
    /// `out`, returning the number of bytes appended. `out` is
    /// appended to, not cleared.
    #[inline]
    fn eap_message_into(&self, out: &mut Vec<u8>) -> usize {
        crate::codec::eap::reassemble_into(self.raw_attributes(), out)
    }

    /// Decompose [`user_name`](Self::user_name) into
    /// `(user, realm)`, recognising the three forms historical
    /// deployments use:
    ///
    /// * `user@realm` — RFC 7542 NAI. Split on the **last** `@`
    ///   (the username half MUST NOT contain an unescaped `@`,
    ///   but the realm half by definition can't, so the last
    ///   `@` is the unambiguous boundary).
    /// * `DOMAIN\user` — Windows down-level logon name. Split on
    ///   the **first** `\\`; the domain precedes the user.
    /// * `user%realm` — legacy Cisco style. Split on the first
    ///   `%`.
    ///
    /// Returns `Some((user, None))` when `User-Name` is present
    /// but carries no delimiter, `None` when `User-Name` itself
    /// is absent. The slices borrow straight from the inbound
    /// attribute region — no allocation, no UTF-8 validation
    /// (RADIUS `User-Name` is a byte string per RFC 2865 §5.1).
    ///
    /// Detection order matches the precedence above: `@` wins
    /// over `\\` wins over `%`. A `User-Name` of `dom\\user@realm`
    /// therefore parses as NAI `(b"dom\\user", b"realm")` — the
    /// outer realm is the routing key.
    //
    // Implementation note: we deliberately do *not* pull in the
    // `memchr` crate for this single 1-to-253-byte slice scan.
    // `slice::iter().position()` lowers to the same SWAR loop on
    // tier-1 targets and `User-Name` is too short for SIMD to
    // pay back the dependency. Revisit if a bench shows it.
    #[inline]
    #[must_use]
    fn user_name_realm(&self) -> Option<(&'a [u8], Option<&'a [u8]>)> {
        let raw = self.user_name()?;
        if let Some(i) = raw.iter().rposition(|&b| b == b'@') {
            return Some((&raw[..i], Some(&raw[i + 1..])));
        }
        if let Some(i) = raw.iter().position(|&b| b == b'\\') {
            return Some((&raw[i + 1..], Some(&raw[..i])));
        }
        if let Some(i) = raw.iter().position(|&b| b == b'%') {
            return Some((&raw[..i], Some(&raw[i + 1..])));
        }
        Some((raw, None))
    }
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

    /// Build a TLV value region: a flat sequence of
    /// `[sub_type, sub_length, value...]` triples — same framing as
    /// the outer attribute region. Used by the TLV-walker tests
    /// below.
    fn tlv_region(children: &[(u8, &[u8])]) -> Vec<u8> {
        region(children)
    }

    #[test]
    fn tlv_children_walks_value_bytes() {
        // Top-level attribute 173 (IPv6-6rd-Configuration) carrying
        // two children: 173.1 = 32 (1-byte mask len) and 173.3 =
        // 192.0.2.1.
        use super::super::typed::{TlvAttr, WByte, WIpv4};
        let children = tlv_region(&[(1, &[32]), (3, &[192, 0, 2, 1])]);
        let bytes = region(&[(173, &children)]);
        let parent = iter(&bytes).next().unwrap().unwrap();
        // Iterator yields the two children in order.
        let kids: Vec<u8> = parent
            .tlv_children()
            .map(|r| r.unwrap().attribute_type())
            .collect();
        assert_eq!(kids, vec![1, 3]);
        // Typed lookups decode each child.
        assert_eq!(parent.get_tlv(TlvAttr::<WByte>::new(173, 1)), Some(32));
        assert_eq!(
            parent.get_tlv(TlvAttr::<WIpv4>::new(173, 3)),
            Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        );
        // Wrong parent → None.
        assert_eq!(parent.get_tlv(TlvAttr::<WByte>::new(174, 1)), None);
        // Missing child → None.
        assert_eq!(parent.get_tlv(TlvAttr::<WByte>::new(173, 9)), None);
    }

    #[test]
    fn vsa_tlv_children_walks_inner_data() {
        use super::super::typed::{VsaTlvAttr, WInteger, WText};
        // Vendor 25053 (Ruckus), vendor-type 146 (TLV parent), with
        // children 146.1 = "tc-name" and 146.2 = 7.
        let inner = tlv_region(&[(1, b"tc-name"), (2, &[0, 0, 0, 7])]);
        let mut value = Vec::new();
        value.extend_from_slice(&25053u32.to_be_bytes());
        value.push(146); // vendor-type
                         // vendor-len = 2 (vtype + vlen) + inner.len()
        value.push(u8::try_from(2 + inner.len()).unwrap());
        value.extend_from_slice(&inner);
        let bytes = region(&[(26, &value)]);
        let parent = iter(&bytes).next().unwrap().unwrap();

        // Typed lookups.
        assert_eq!(
            parent.get_vsa_tlv(VsaTlvAttr::<WText>::new(25053, 146, 1)),
            Some("tc-name"),
        );
        assert_eq!(
            parent.get_vsa_tlv(VsaTlvAttr::<WInteger>::new(25053, 146, 2)),
            Some(7),
        );
        // Wrong vendor / parent / child → None.
        assert_eq!(
            parent.get_vsa_tlv(VsaTlvAttr::<WText>::new(9, 146, 1)),
            None,
        );
        assert_eq!(
            parent.get_vsa_tlv(VsaTlvAttr::<WText>::new(25053, 99, 1)),
            None,
        );
        assert_eq!(
            parent.get_vsa_tlv(VsaTlvAttr::<WText>::new(25053, 146, 9)),
            None,
        );
        // Iterator over the inner region.
        let kids: Vec<u8> = parent
            .vsa_tlv_children(25053, 146)
            .unwrap()
            .map(|r| r.unwrap().attribute_type())
            .collect();
        assert_eq!(kids, vec![1, 2]);
        // Mismatch → no iterator.
        assert!(parent.vsa_tlv_children(9, 146).is_none());
    }

    #[test]
    fn first_tlv_finds_match_across_outer_attributes() {
        use super::super::typed::{TlvAttr, WByte};
        let kids = tlv_region(&[(1, &[7])]);
        // Decoy attribute first, then the parent.
        let bytes = region(&[(2, b"x"), (173, &kids)]);
        assert_eq!(first_tlv(&bytes, TlvAttr::<WByte>::new(173, 1)), Some(7),);
        assert_eq!(first_tlv(&bytes, TlvAttr::<WByte>::new(173, 9)), None);
    }

    #[test]
    fn first_vsa_tlv_finds_match() {
        use super::super::typed::{VsaTlvAttr, WText};
        let inner = tlv_region(&[(1, b"hello")]);
        let mut value = Vec::new();
        value.extend_from_slice(&25053u32.to_be_bytes());
        value.push(146);
        value.push(u8::try_from(2 + inner.len()).unwrap());
        value.extend_from_slice(&inner);
        let bytes = region(&[(26, &value)]);
        assert_eq!(
            first_vsa_tlv(&bytes, VsaTlvAttr::<WText>::new(25053, 146, 1)),
            Some("hello"),
        );
    }

    #[test]
    fn tlv_children_propagates_inner_corruption() {
        // Outer attribute 173 with a malformed inner TLV: sub-length
        // byte 1 is below the 2-byte minimum. The walker yields the
        // error, then fuses.
        let bytes = region(&[(173, &[5u8, 1u8])]);
        let parent = iter(&bytes).next().unwrap().unwrap();
        let mut it = parent.tlv_children();
        assert!(matches!(
            it.next(),
            Some(Err(AttributeError::LengthUnderflow { length: 1 })),
        ));
        assert!(it.next().is_none());
    }

    #[test]
    fn vsa_tlv_children_rejects_short_envelope() {
        // VSA with vendor + vendor-type but no vendor-length byte.
        let mut value = Vec::new();
        value.extend_from_slice(&25053u32.to_be_bytes());
        value.push(146);
        let bytes = region(&[(26, &value)]);
        let parent = iter(&bytes).next().unwrap().unwrap();
        assert!(parent.vsa_tlv_children(25053, 146).is_none());
    }

    #[test]
    fn contains_top_level() {
        use super::super::typed::{Attr, WInteger, WText};
        let bytes = region(&[(1, b"bob"), (5, &[0, 0, 0, 42])]);
        assert!(contains(&bytes, Attr::<WText>::new(1)));
        assert!(contains(&bytes, Attr::<WInteger>::new(5)));
        // Absent code.
        assert!(!contains(&bytes, Attr::<WText>::new(2)));
    }

    #[test]
    fn contains_ignores_decode_failure() {
        use super::super::typed::{Attr, WInteger};
        // Attribute type 5 with a 1-byte value — would fail `WInteger`
        // decode (expects 4 bytes), but presence is still reported.
        let bytes = region(&[(5, &[0xff])]);
        assert!(contains(&bytes, Attr::<WInteger>::new(5)));
        // And first() — which *does* decode — returns None on the
        // same input, confirming the two helpers split cleanly.
        assert_eq!(first(&bytes, Attr::<WInteger>::new(5)), None);
    }

    #[test]
    fn contains_returns_false_on_parse_error_before_match() {
        use super::super::typed::{Attr, WText};
        // Underflow on the very first slot; the User-Name we'd
        // otherwise find never becomes visible.
        let mut bytes = vec![1u8, 1u8]; // length byte < 2
        bytes.extend(region(&[(1, b"alice")]));
        assert!(!contains(&bytes, Attr::<WText>::new(1)));
    }

    #[test]
    fn contains_vsa_matches_envelope_without_decoding() {
        use super::super::typed::{VsaAttr, WInteger};
        // Cisco (PEN 9), vendor-type 1, value = b"abc" (3 bytes).
        // `WInteger` would reject this, but `contains_vsa` only
        // validates the envelope.
        let mut value = Vec::new();
        value.extend_from_slice(&9u32.to_be_bytes());
        value.push(1);
        value.push(5); // vendor-len = 2 + 3
        value.extend_from_slice(b"abc");
        let bytes = region(&[(26, &value)]);
        assert!(contains_vsa(&bytes, VsaAttr::<WInteger>::new(9, 1)));
        // Wrong vendor / vendor-type.
        assert!(!contains_vsa(&bytes, VsaAttr::<WInteger>::new(9, 2)));
        assert!(!contains_vsa(&bytes, VsaAttr::<WInteger>::new(14823, 1)));
    }

    #[test]
    fn contains_tlv_and_vsa_tlv() {
        use super::super::typed::{TlvAttr, VsaTlvAttr, WByte, WText};
        // RFC TLV: 173.1 = [7]
        let kids = tlv_region(&[(1, &[7])]);
        let rfc = region(&[(173, &kids)]);
        assert!(contains_tlv(&rfc, TlvAttr::<WByte>::new(173, 1)));
        assert!(!contains_tlv(&rfc, TlvAttr::<WByte>::new(173, 9)));
        assert!(!contains_tlv(&rfc, TlvAttr::<WByte>::new(174, 1)));

        // VSA TLV: Ruckus / 146.1 = "hi"
        let inner = tlv_region(&[(1, b"hi")]);
        let mut value = Vec::new();
        value.extend_from_slice(&25053u32.to_be_bytes());
        value.push(146);
        value.push(u8::try_from(2 + inner.len()).unwrap());
        value.extend_from_slice(&inner);
        let vsa = region(&[(26, &value)]);
        assert!(contains_vsa_tlv(
            &vsa,
            VsaTlvAttr::<WText>::new(25053, 146, 1),
        ));
        assert!(!contains_vsa_tlv(
            &vsa,
            VsaTlvAttr::<WText>::new(25053, 146, 9),
        ));
        assert!(!contains_vsa_tlv(&vsa, VsaTlvAttr::<WText>::new(9, 146, 1),));
    }

    #[test]
    fn matches_helpers_on_raw_attribute() {
        use super::super::typed::{Attr, VsaAttr, WInteger, WText};
        let mut vsa_value = Vec::new();
        vsa_value.extend_from_slice(&9u32.to_be_bytes());
        vsa_value.push(1);
        vsa_value.push(7);
        vsa_value.extend_from_slice(b"hello");
        let bytes = region(&[(1, b"bob"), (26, &vsa_value)]);
        let mut it = iter(&bytes);
        let user = it.next().unwrap().unwrap();
        assert!(user.matches(Attr::<WText>::new(1)));
        assert!(!user.matches(Attr::<WInteger>::new(2)));
        let vsa = it.next().unwrap().unwrap();
        assert!(vsa.matches_vsa(VsaAttr::<WText>::new(9, 1)));
        assert!(!vsa.matches_vsa(VsaAttr::<WText>::new(9, 2)));
        assert!(!vsa.matches_vsa(VsaAttr::<WText>::new(14823, 1)));
    }

    /// Tiny [`AttributesView`] impl over a borrowed slice, used to
    /// exercise the trait defaults without spinning up a full
    /// `Request`.
    struct View<'a>(&'a [u8]);
    impl<'a> AttributesView<'a> for View<'a> {
        fn raw_attributes(&self) -> &'a [u8] {
            self.0
        }
    }

    #[test]
    fn user_name_realm_absent_user_name() {
        let bytes = region(&[]);
        assert_eq!(View(&bytes).user_name_realm(), None);
    }

    #[test]
    fn user_name_realm_no_delimiter() {
        let bytes = region(&[(1, b"alice")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"alice".as_slice(), None))
        );
    }

    #[test]
    fn user_name_realm_nai() {
        let bytes = region(&[(1, b"alice@example.com")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"alice".as_slice(), Some(b"example.com".as_slice())))
        );
    }

    #[test]
    fn user_name_realm_nai_splits_on_last_at() {
        // Realm cannot contain '@', so the last '@' is the boundary.
        let bytes = region(&[(1, b"weird@user@example.com")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"weird@user".as_slice(), Some(b"example.com".as_slice())))
        );
    }

    #[test]
    fn user_name_realm_windows_downlevel() {
        let bytes = region(&[(1, b"CORP\\alice")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"alice".as_slice(), Some(b"CORP".as_slice())))
        );
    }

    #[test]
    fn user_name_realm_cisco_percent() {
        let bytes = region(&[(1, b"alice%legacy")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"alice".as_slice(), Some(b"legacy".as_slice())))
        );
    }

    #[test]
    fn user_name_realm_nai_wins_over_backslash_and_percent() {
        // Outer realm is the routing key.
        let bytes = region(&[(1, b"CORP\\alice@example.com")]);
        assert_eq!(
            View(&bytes).user_name_realm(),
            Some((b"CORP\\alice".as_slice(), Some(b"example.com".as_slice())))
        );
    }

    #[test]
    fn user_name_realm_preserves_empty_halves() {
        let at_only = region(&[(1, b"@realm")]);
        assert_eq!(
            View(&at_only).user_name_realm(),
            Some((b"".as_slice(), Some(b"realm".as_slice())))
        );
        let trailing = region(&[(1, b"user@")]);
        assert_eq!(
            View(&trailing).user_name_realm(),
            Some((b"user".as_slice(), Some(b"".as_slice())))
        );
    }
}
