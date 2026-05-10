//! Runtime lookup over the compile-time dictionary tables.
//!
//! The codegen in [`super::generated`] emits one `pub static` slice per
//! enabled `dict-*` Cargo feature (`rfc`, `cisco`, `aruba`, …). This
//! module unifies them behind a small set of name-resolution helpers
//! intended for **diagnostic** paths: packet dissection, log lines,
//! tracing spans. None of these helpers run on the steady-state encode
//! / decode hot path.
//!
//! # Cost model
//!
//! Each lookup is a linear scan of the relevant static slice — fine
//! for human-facing output (a packet has at most a few dozen
//! attributes; the largest RFC table is a few hundred entries) and
//! free of allocation. If a future profile shows these on a hot path,
//! swap the impl for a `OnceLock<HashMap>` without changing the API.
//!
//! # Disabled features
//!
//! Lookups silently skip groups whose Cargo feature is off. A consumer
//! that builds with `--no-default-features` gets `None` for every
//! attribute, which is the right behaviour: we should not pretend to
//! know names we have not been asked to compile in.

use super::generated::{AttributeEntry, ValueEntry, VendorEntry};

/// All compile-time-enabled attribute tables, in lookup order.
///
/// RFC entries come first so they shadow vendor tables for any code
/// reuse (none today, but the order matters for symmetry with the
/// `VENDORS` and `VALUES` aggregates below).
// `static` rather than `const` so we can reference the codegen'd `static`
// tables in `super::generated::*`. `const_refs_to_static` only stabilised
// in Rust 1.83; our MSRV is 1.79.
static ATTRIBUTE_TABLES: &[&[AttributeEntry]] = &[
    #[cfg(feature = "dict-rfc")]
    super::generated::rfc::ATTRIBUTES,
    #[cfg(feature = "dict-cisco")]
    super::generated::cisco::ATTRIBUTES,
    #[cfg(feature = "dict-aruba")]
    super::generated::aruba::ATTRIBUTES,
    #[cfg(feature = "dict-ascend")]
    super::generated::ascend::ATTRIBUTES,
    #[cfg(feature = "dict-fortinet")]
    super::generated::fortinet::ATTRIBUTES,
    #[cfg(feature = "dict-hp")]
    super::generated::hp::ATTRIBUTES,
    #[cfg(feature = "dict-juniper")]
    super::generated::juniper::ATTRIBUTES,
    #[cfg(feature = "dict-meraki")]
    super::generated::meraki::ATTRIBUTES,
    #[cfg(feature = "dict-microsoft")]
    super::generated::microsoft::ATTRIBUTES,
    #[cfg(feature = "dict-mikrotik")]
    super::generated::mikrotik::ATTRIBUTES,
    #[cfg(feature = "dict-ruckus")]
    super::generated::ruckus::ATTRIBUTES,
    #[cfg(feature = "dict-wispr")]
    super::generated::wispr::ATTRIBUTES,
];

static VENDOR_TABLES: &[&[VendorEntry]] = &[
    #[cfg(feature = "dict-rfc")]
    super::generated::rfc::VENDORS,
    #[cfg(feature = "dict-cisco")]
    super::generated::cisco::VENDORS,
    #[cfg(feature = "dict-aruba")]
    super::generated::aruba::VENDORS,
    #[cfg(feature = "dict-ascend")]
    super::generated::ascend::VENDORS,
    #[cfg(feature = "dict-fortinet")]
    super::generated::fortinet::VENDORS,
    #[cfg(feature = "dict-hp")]
    super::generated::hp::VENDORS,
    #[cfg(feature = "dict-juniper")]
    super::generated::juniper::VENDORS,
    #[cfg(feature = "dict-meraki")]
    super::generated::meraki::VENDORS,
    #[cfg(feature = "dict-microsoft")]
    super::generated::microsoft::VENDORS,
    #[cfg(feature = "dict-mikrotik")]
    super::generated::mikrotik::VENDORS,
    #[cfg(feature = "dict-ruckus")]
    super::generated::ruckus::VENDORS,
    #[cfg(feature = "dict-wispr")]
    super::generated::wispr::VENDORS,
];

static VALUE_TABLES: &[&[ValueEntry]] = &[
    #[cfg(feature = "dict-rfc")]
    super::generated::rfc::VALUES,
    #[cfg(feature = "dict-cisco")]
    super::generated::cisco::VALUES,
    #[cfg(feature = "dict-aruba")]
    super::generated::aruba::VALUES,
    #[cfg(feature = "dict-ascend")]
    super::generated::ascend::VALUES,
    #[cfg(feature = "dict-fortinet")]
    super::generated::fortinet::VALUES,
    #[cfg(feature = "dict-hp")]
    super::generated::hp::VALUES,
    #[cfg(feature = "dict-juniper")]
    super::generated::juniper::VALUES,
    #[cfg(feature = "dict-meraki")]
    super::generated::meraki::VALUES,
    #[cfg(feature = "dict-microsoft")]
    super::generated::microsoft::VALUES,
    #[cfg(feature = "dict-mikrotik")]
    super::generated::mikrotik::VALUES,
    #[cfg(feature = "dict-ruckus")]
    super::generated::ruckus::VALUES,
    #[cfg(feature = "dict-wispr")]
    super::generated::wispr::VALUES,
];

/// Look up a top-level attribute by its 1-byte type code.
///
/// Returns the first matching entry (RFC tables consulted first) whose
/// `vendor` field is `None` and whose single-component OID equals
/// `code`. TLV / extended children (multi-component OIDs) are skipped,
/// matching the current encode-side rule in the build-time codegen.
#[must_use]
pub fn attribute(code: u8) -> Option<&'static AttributeEntry> {
    let code = u32::from(code);
    for table in ATTRIBUTE_TABLES {
        for entry in *table {
            if entry.vendor.is_none() && entry.oid == [code] {
                return Some(entry);
            }
        }
    }
    None
}

/// Look up a Vendor-Specific Attribute by `(PEN, vendor-type)`.
///
/// Searches every enabled dictionary group; the first hit wins. Sub-VSA
/// (multi-component OID) entries are skipped for the same reason as in
/// [`attribute`].
#[must_use]
pub fn vsa(vendor_id: u32, vendor_type: u8) -> Option<&'static AttributeEntry> {
    let vt = u32::from(vendor_type);
    for table in ATTRIBUTE_TABLES {
        for entry in *table {
            if entry.vendor == Some(vendor_id) && entry.oid == [vt] {
                return Some(entry);
            }
        }
    }
    None
}

/// Look up a `VENDOR` directive by its IANA Private Enterprise Number.
#[must_use]
pub fn vendor(id: u32) -> Option<&'static VendorEntry> {
    for table in VENDOR_TABLES {
        for entry in *table {
            if entry.id == id {
                return Some(entry);
            }
        }
    }
    None
}

/// Resolve an enumerator name for `attribute`'s integer value `number`.
///
/// `attribute` is the dictionary name (e.g. `"Service-Type"`); it is
/// matched case-sensitively, exactly as written in the dictionary.
/// Returns `None` for unknown enumerators.
#[must_use]
pub fn value_name(attribute: &str, number: i64) -> Option<&'static str> {
    for table in VALUE_TABLES {
        for entry in *table {
            if entry.number == number && entry.attribute == attribute {
                return Some(entry.name);
            }
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
