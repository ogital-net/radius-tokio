//! Compile-time-generated dictionary modules.
//!
//! `build.rs` parses the `FreeRADIUS` dictionary tree (gated by
//! `dict-*` Cargo features) and emits one source file per group into
//! `$OUT_DIR`. Each file is `include!`-ed into a submodule below and
//! exposes:
//!
//! - `pub mod attrs { … }` — typed `Attr<W*>` / `VsaAttr<W*>` /
//!   `TlvAttr<W*>` / `VsaTlvAttr<W*>` const handles plus a trio of
//!   `pub const fn lookup` / `lookup_vsa` / `lookup_vendor`
//!   dispatchers used by [`crate::registry`];
//! - `pub mod values { … }` — `#[repr(transparent)]` newtypes per
//!   integer attribute carrying `VALUE` enumerators, plus a
//!   `value_name` dispatcher.
//!
//! Earlier revisions emitted `pub static VENDORS: &[VendorEntry]` and
//! `pub static ATTRIBUTES: &[AttributeEntry]` slices, which the
//! registry scanned linearly. They have been replaced by `match`-based
//! const-fn dispatchers, which the compiler typically compiles to jump
//! tables and which carry no per-entry struct overhead in `.rodata`.

use super::{AttrInfo, AttrKind, VendorInfo};

#[cfg(feature = "dict-rfc")]
#[allow(missing_docs)]
pub mod rfc {
    //! IETF / RFC attributes vendored under `dictionaries/rfc/`.
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_rfc.rs"));
}

#[cfg(feature = "dict-cisco")]
#[allow(missing_docs)]
pub mod cisco {
    //! Cisco Systems VSAs (PEN 9).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_cisco.rs"));
}

#[cfg(feature = "dict-aruba")]
#[allow(missing_docs)]
pub mod aruba {
    //! Aruba Networks / HPE VSAs (PEN 14823).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_aruba.rs"));
}

#[cfg(feature = "dict-ascend")]
#[allow(missing_docs)]
pub mod ascend {
    //! Ascend / Lucent / Nokia VSAs (PEN 529).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_ascend.rs"));
}

#[cfg(feature = "dict-fortinet")]
#[allow(missing_docs)]
pub mod fortinet {
    //! Fortinet VSAs (PEN 12356).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_fortinet.rs"));
}

#[cfg(feature = "dict-hp")]
#[allow(missing_docs)]
pub mod hp {
    //! `HP` / `ProCurve` / Aruba-HPE VSAs (PEN 11).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_hp.rs"));
}

#[cfg(feature = "dict-juniper")]
#[allow(missing_docs)]
pub mod juniper {
    //! Juniper Networks VSAs (PEN 2636).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_juniper.rs"));
}

#[cfg(feature = "dict-meraki")]
#[allow(missing_docs)]
pub mod meraki {
    //! Meraki (Cisco) VSAs (PEN 29671).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_meraki.rs"));
}

#[cfg(feature = "dict-microsoft")]
#[allow(missing_docs)]
pub mod microsoft {
    //! Microsoft VSAs (PEN 311).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_microsoft.rs"));
}

#[cfg(feature = "dict-mikrotik")]
#[allow(missing_docs)]
pub mod mikrotik {
    //! `MikroTik` VSAs (PEN 14988).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_mikrotik.rs"));
}

#[cfg(feature = "dict-ruckus")]
#[allow(missing_docs)]
pub mod ruckus {
    //! Ruckus Wireless VSAs (PEN 25053).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_ruckus.rs"));
}

#[cfg(feature = "dict-tplink")]
#[allow(missing_docs)]
pub mod tplink {
    //! TP-Link VSAs (PEN 11863).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_tplink.rs"));
}

#[cfg(feature = "dict-wispr")]
#[allow(missing_docs)]
pub mod wispr {
    //! `WISPr` / Wireless Broadband Alliance VSAs (PEN 14122).
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_wispr.rs"));
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "dict-rfc")]
    #[test]
    fn rfc_lookups_resolve_well_known() {
        let user_name = super::rfc::attrs::lookup(1).expect("User-Name resolves");
        assert_eq!(user_name.name, "User-Name");
        let user_password = super::rfc::attrs::lookup(2).expect("User-Password resolves");
        assert_eq!(user_password.name, "User-Password");
        assert!(user_password.encrypted);
        // RFC 4679 carries a vendor block (ADSL-Forum, PEN 3561).
        let adsl = super::rfc::attrs::lookup_vendor(3561).expect("ADSL-Forum vendor");
        assert_eq!(adsl.name, "ADSL-Forum");
    }

    #[cfg(feature = "dict-cisco")]
    #[test]
    fn cisco_lookups_resolve_avpair() {
        let cisco = super::cisco::attrs::lookup_vendor(9).expect("Cisco vendor");
        assert_eq!(cisco.name, "Cisco");
        let avpair = super::cisco::attrs::lookup_vsa(9, 1).expect("Cisco-AVPair");
        assert_eq!(avpair.name, "Cisco-AVPair");
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
