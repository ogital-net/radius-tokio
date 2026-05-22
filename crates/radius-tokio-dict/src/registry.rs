//! Runtime lookup over the compile-time dictionary tables.
//!
//! The codegen in [`super::generated`] emits, per enabled `dict-*`
//! Cargo feature, a small set of `pub const fn` dispatchers:
//!
//! - `attrs::lookup(code: u8) -> Option<AttrInfo>` for top-level
//!   attributes (vendor-less, single-component OID);
//! - `attrs::lookup_vsa(pen: u32, vt: u8) -> Option<AttrInfo>` for
//!   single-component Vendor-Specific attributes;
//! - `attrs::lookup_vendor(pen: u32) -> Option<VendorInfo>` for
//!   `VENDOR` directives;
//! - `values::value_name(attr: &str, n: i64) -> Option<&'static str>`
//!   for integer enumerators.
//!
//! This module unifies them behind a small set of name-resolution
//! helpers intended for **diagnostic** paths: packet dissection, log
//! lines, tracing spans. None of these helpers run on the steady-state
//! encode / decode hot path.
//!
//! # Cost model
//!
//! Each per-group dispatcher is a `match` expression that the compiler
//! is free to compile to a direct branch, an `if`-chain, or a jump
//! table. Lookups cascade across enabled groups in declaration order
//! and short-circuit on the first hit. There is no `.rodata` slice to
//! scan and no `&'static AttributeEntry` materialised at compile time;
//! the returned [`AttrInfo`] / [`VendorInfo`] are small `Copy` records
//! assembled on demand from inline name string-slice literals plus a
//! one-byte [`AttrKind`].
//!
//! # Disabled features
//!
//! Lookups silently skip groups whose Cargo feature is off. A consumer
//! that builds with `--no-default-features` gets `None` for every
//! attribute, which is the right behaviour: we should not pretend to
//! know names we have not been asked to compile in.

use super::{AttrInfo, VendorInfo};

/// Cascade a `lookup`-style call across every enabled `dict-*`
/// dictionary group, short-circuiting on the first `Some(_)`.
///
/// Centralising the per-feature `cfg` list here means adding a new
/// dictionary group is a single-line edit (in `generated.rs` and
/// `Cargo.toml`) instead of fanning out across each registry entry
/// point.
macro_rules! cascade_lookup {
    ($call:ident ( $($args:expr),* $(,)? )) => {{
        #[cfg(feature = "dict-rfc")]
        if let Some(x) = super::generated::rfc::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-cisco")]
        if let Some(x) = super::generated::cisco::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-aruba")]
        if let Some(x) = super::generated::aruba::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-ascend")]
        if let Some(x) = super::generated::ascend::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-fortinet")]
        if let Some(x) = super::generated::fortinet::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-hp")]
        if let Some(x) = super::generated::hp::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-juniper")]
        if let Some(x) = super::generated::juniper::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-meraki")]
        if let Some(x) = super::generated::meraki::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-microsoft")]
        if let Some(x) = super::generated::microsoft::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-mikrotik")]
        if let Some(x) = super::generated::mikrotik::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-ruckus")]
        if let Some(x) = super::generated::ruckus::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-tplink")]
        if let Some(x) = super::generated::tplink::attrs::$call($($args),*) {
            return Some(x);
        }
        #[cfg(feature = "dict-wispr")]
        if let Some(x) = super::generated::wispr::attrs::$call($($args),*) {
            return Some(x);
        }
        None
    }};
}

/// Look up a top-level attribute by its 1-byte type code.
///
/// Returns the first matching entry (RFC tables consulted first) with
/// a single-component OID and no owning vendor. TLV / extended
/// children (multi-component OIDs) are excluded by the codegen.
#[must_use]
pub fn attribute(code: u8) -> Option<AttrInfo> {
    cascade_lookup!(lookup(code))
}

/// Look up a Vendor-Specific Attribute by `(PEN, vendor-type)`.
///
/// Searches every enabled dictionary group; the first hit wins. Sub-VSA
/// (multi-component OID) entries are excluded by the codegen.
#[must_use]
pub fn vsa(vendor_id: u32, vendor_type: u8) -> Option<AttrInfo> {
    cascade_lookup!(lookup_vsa(vendor_id, vendor_type))
}

/// Look up a `VENDOR` directive by its IANA Private Enterprise Number.
#[must_use]
pub fn vendor(id: u32) -> Option<VendorInfo> {
    cascade_lookup!(lookup_vendor(id))
}

/// Look up a TLV child by its `(parent, child)` 1-byte codes inside the
/// top-level (non-vendor) RFC namespace.
///
/// Use when the parent attribute is itself `AttrKind::Tlv` and the
/// payload holds back-to-back `[type, length, value]` triples — each
/// inner `type` resolves to a leaf `AttrInfo` via this lookup.
#[must_use]
pub fn tlv_child(parent: u8, child: u8) -> Option<AttrInfo> {
    cascade_lookup!(lookup_tlv(parent, child))
}

/// Resolve an enumerator name for `attribute`'s integer value `number`.
///
/// `attribute` is the dictionary name (e.g. `"Service-Type"`); it is
/// matched case-sensitively, exactly as written in the dictionary.
/// Returns `None` for unknown enumerators.
///
/// Dispatches into each enabled dictionary group's generated
/// `values::value_name(attr, number)` (a string `match` that routes
/// into the appropriate typed newtype's `name()` impl). The first
/// hit wins. Non-integer attributes carry no typed enumerators and
/// are never resolved here.
#[must_use]
pub fn value_name(attribute: &str, number: i64) -> Option<&'static str> {
    // Each closure resolves the lookup against one enabled dictionary
    // group; `cfg`-gating keeps the array length tracking the active
    // feature set. The `_` binding silences `unused_imports` when the
    // entire feature set is off.
    let _ = (attribute, number);
    let groups: &[fn(&str, i64) -> Option<&'static str>] = &[
        #[cfg(feature = "dict-rfc")]
        super::generated::rfc::values::value_name,
        #[cfg(feature = "dict-cisco")]
        super::generated::cisco::values::value_name,
        #[cfg(feature = "dict-aruba")]
        super::generated::aruba::values::value_name,
        #[cfg(feature = "dict-ascend")]
        super::generated::ascend::values::value_name,
        #[cfg(feature = "dict-fortinet")]
        super::generated::fortinet::values::value_name,
        #[cfg(feature = "dict-hp")]
        super::generated::hp::values::value_name,
        #[cfg(feature = "dict-juniper")]
        super::generated::juniper::values::value_name,
        #[cfg(feature = "dict-meraki")]
        super::generated::meraki::values::value_name,
        #[cfg(feature = "dict-microsoft")]
        super::generated::microsoft::values::value_name,
        #[cfg(feature = "dict-mikrotik")]
        super::generated::mikrotik::values::value_name,
        #[cfg(feature = "dict-ruckus")]
        super::generated::ruckus::values::value_name,
        #[cfg(feature = "dict-tplink")]
        super::generated::tplink::values::value_name,
        #[cfg(feature = "dict-wispr")]
        super::generated::wispr::values::value_name,
    ];
    for resolve in groups {
        if let Some(name) = resolve(attribute, number) {
            return Some(name);
        }
    }
    None
}

#[cfg(all(test, feature = "dict-rfc"))]
mod tests {
    use super::*;

    #[test]
    fn well_known_attributes_resolve() {
        assert_eq!(attribute(1).map(|a| a.name), Some("User-Name"));
        assert_eq!(attribute(4).map(|a| a.name), Some("NAS-IP-Address"));
        assert_eq!(attribute(80).map(|a| a.name), Some("Message-Authenticator"));
    }

    #[test]
    fn unknown_attribute_returns_none() {
        // Code 0 ("Invalid") is reserved and not in any RFC dictionary.
        assert!(attribute(0).is_none());
    }

    #[test]
    fn service_type_enumerators_resolve() {
        assert_eq!(value_name("Service-Type", 1), Some("Login-User"));
        assert_eq!(value_name("Service-Type", 2), Some("Framed-User"));
        assert!(value_name("Service-Type", 9999).is_none());
    }
}
