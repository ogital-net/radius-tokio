//! Compile-time-generated dictionary tables.
//!
//! `build.rs` parses the `FreeRADIUS` dictionary tree (gated by
//! `dict-*` Cargo features) and emits a table file per group into
//! `$OUT_DIR`. Each file is `include!`-ed into a submodule below and
//! exposes three `pub static` slices: `VENDORS`, `ATTRIBUTES`,
//! `VALUES`.
//!
//! The shapes consumed by the generated code live here so the renderer
//! and the runtime stay in sync; see `radius-dict-codegen::codegen` for
//! the emitter.

use super::{Flags, Type};

/// One `VENDOR` directive — name, IANA Private Enterprise Number, and
/// per-vendor attribute framing (RFC 2865 §5.26 plus `FreeRADIUS`
/// `format=t,l[,c]` extensions).
#[derive(Debug, Clone, Copy)]
pub struct VendorEntry {
    /// Vendor name as written in the dictionary (e.g. `Cisco`).
    pub name: &'static str,
    /// IANA Private Enterprise Number.
    pub id: u32,
    /// Bytes used for the vendor-attribute type field. Default 1.
    pub type_len: u8,
    /// Bytes used for the vendor-attribute length field. Default 1.
    pub length_len: u8,
    /// `c` flag from `format=t,l,c`: continuation bit present.
    pub has_continuation: bool,
}

/// One `ATTRIBUTE` directive resolved to its full identifier path,
/// owning vendor (if inside a `BEGIN-VENDOR` block), wire type, and
/// flag bag.
#[derive(Debug, Clone, Copy)]
pub struct AttributeEntry {
    /// Attribute name as written (e.g. `User-Name`).
    pub name: &'static str,
    /// Dotted attribute identifier — single component for top-level
    /// attributes, multiple for TLV / extended children.
    pub oid: &'static [u32],
    /// Owning vendor's PEN, if any.
    pub vendor: Option<u32>,
    /// Wire data type.
    pub typ: Type,
    /// Per-attribute flags (`encrypt=N`, `has_tag`, …).
    pub flags: Flags,
}

/// One `VALUE` directive — a named enumerator for an integer-typed
/// attribute. Linked to its attribute by name; names are unique across
/// the merged dictionary tree.
#[derive(Debug, Clone, Copy)]
pub struct ValueEntry {
    /// Owning attribute name.
    pub attribute: &'static str,
    /// Enumerator name.
    pub name: &'static str,
    /// Enumerator number. Signed to accommodate `signed`-typed
    /// attributes; the on-wire encoding is determined by the type.
    pub number: i64,
}

#[cfg(feature = "dict-rfc")]
#[allow(missing_docs)]
pub mod rfc {
    //! IETF / RFC attributes vendored under `dictionaries/rfc/`.
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_rfc.rs"));
}

#[cfg(feature = "dict-cisco")]
#[allow(missing_docs)]
pub mod cisco {
    //! Cisco Systems VSAs (PEN 9).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_cisco.rs"));
}

#[cfg(feature = "dict-aruba")]
#[allow(missing_docs)]
pub mod aruba {
    //! Aruba Networks / HPE VSAs (PEN 14823).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_aruba.rs"));
}

#[cfg(feature = "dict-ascend")]
#[allow(missing_docs)]
pub mod ascend {
    //! Ascend / Lucent / Nokia VSAs (PEN 529).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_ascend.rs"));
}

#[cfg(feature = "dict-fortinet")]
#[allow(missing_docs)]
pub mod fortinet {
    //! Fortinet VSAs (PEN 12356).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_fortinet.rs"));
}

#[cfg(feature = "dict-hp")]
#[allow(missing_docs)]
pub mod hp {
    //! `HP` / `ProCurve` / Aruba-HPE VSAs (PEN 11).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_hp.rs"));
}

#[cfg(feature = "dict-juniper")]
#[allow(missing_docs)]
pub mod juniper {
    //! Juniper Networks VSAs (PEN 2636).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_juniper.rs"));
}

#[cfg(feature = "dict-meraki")]
#[allow(missing_docs)]
pub mod meraki {
    //! Meraki (Cisco) VSAs (PEN 29671).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_meraki.rs"));
}

#[cfg(feature = "dict-microsoft")]
#[allow(missing_docs)]
pub mod microsoft {
    //! Microsoft VSAs (PEN 311).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_microsoft.rs"));
}

#[cfg(feature = "dict-mikrotik")]
#[allow(missing_docs)]
pub mod mikrotik {
    //! `MikroTik` VSAs (PEN 14988).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_mikrotik.rs"));
}

#[cfg(feature = "dict-ruckus")]
#[allow(missing_docs)]
pub mod ruckus {
    //! Ruckus Wireless VSAs (PEN 25053).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_ruckus.rs"));
}

#[cfg(feature = "dict-tplink")]
#[allow(missing_docs)]
pub mod tplink {
    //! TP-Link VSAs (PEN 11863).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_tplink.rs"));
}

#[cfg(feature = "dict-wispr")]
#[allow(missing_docs)]
pub mod wispr {
    //! `WISPr` / Wireless Broadband Alliance VSAs (PEN 14122).
    use super::{AttributeEntry, ValueEntry, VendorEntry};
    include!(concat!(env!("OUT_DIR"), "/dict_wispr.rs"));
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "dict-rfc")]
    #[test]
    fn rfc_tables_populated() {
        assert!(!super::rfc::ATTRIBUTES.is_empty());
        assert!(super::rfc::ATTRIBUTES.iter().any(|a| a.name == "User-Name"));
        assert!(super::rfc::ATTRIBUTES
            .iter()
            .any(|a| a.name == "User-Password" && a.flags.encrypt == Some(1)));
        // RFC 4679 carries a vendor block (ADSL-Forum, PEN 3561).
        assert!(super::rfc::VENDORS.iter().any(|v| v.id == 3561));
    }

    #[cfg(feature = "dict-cisco")]
    #[test]
    fn cisco_tables_populated() {
        assert!(super::cisco::VENDORS.iter().any(|v| v.id == 9));
        assert!(super::cisco::ATTRIBUTES
            .iter()
            .any(|a| a.name == "Cisco-AVPair"));
    }

    /// `IPv6-6rd-Configuration` (RFC 6930) is a `tlv` parent at OID
    /// 173 with three children. The codegen must emit a `TlvAttr<T>`
    /// const for each child, with the parent type encoded as 173.
    #[cfg(feature = "dict-rfc")]
    #[test]
    fn rfc_tlv_children_have_typed_handles() {
        use crate::typed::{TlvAttr, WInteger};
        // Compile-time check: the generated const exists with the
        // right shape and is reachable from the public path.
        const _MASK: TlvAttr<WInteger> = super::rfc::attrs::IPV6_6RD_IPV4MASKLEN;
        assert_eq!(_MASK.parent, 173);
        assert_eq!(_MASK.child, 1);
    }

    /// Vendor-block TLV: Ruckus PEN 25053 vendor-type 146 is `tlv`,
    /// child `Ruckus-TC-Name-Quota` (146.1) must surface as a
    /// `VsaTlvAttr<T>`.
    #[cfg(feature = "dict-ruckus")]
    #[test]
    fn ruckus_vsa_tlv_children_have_typed_handles() {
        use crate::typed::{VsaTlvAttr, WText};
        const _NAME: VsaTlvAttr<WText> = super::ruckus::attrs::RUCKUS_TC_NAME_QUOTA;
        assert_eq!(_NAME.vendor, 25053);
        assert_eq!(_NAME.parent, 146);
        assert_eq!(_NAME.child, 1);
    }
}
