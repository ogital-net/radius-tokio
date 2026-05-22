//! Compile-time-generated dictionary modules.
//!
//! `build.rs` parses the `FreeRADIUS` dictionary tree (gated by
//! `dict-*` Cargo features) and emits one source file per group into
//! `$OUT_DIR`. Each group module exposes:
//!
//! - `pub mod attrs { … }` — typed `Attr<W*>` / `VsaAttr<W*>` /
//!   `TlvAttr<W*>` / `VsaTlvAttr<W*>` const handles plus the
//!   `pub const fn lookup` / `lookup_vsa` / `lookup_vendor` /
//!   `lookup_tlv` dispatchers used by the crate-level lookup helpers;
//! - `pub mod values { … }` — `#[repr(transparent)]` newtypes per
//!   integer attribute carrying `VALUE` enumerators, plus a
//!   `value_name` dispatcher.
//!
//! ## Module layout
//!
//! - `rfc` is hand-declared here because it lives outside
//!   `dictionaries/vendor/` and we want a known-good module even when
//!   no vendor features are selected.
//! - Vendor modules (`cisco`, `aruba`, …) are auto-discovered by
//!   `build.rs` from `dictionaries/vendor/dictionary.*` and emitted
//!   into `$OUT_DIR/vendor_mods.rs`, which we `include!` below.
//!
//! Adding a new vendor therefore only requires (a) dropping the
//! FreeRADIUS dictionary file into `dictionaries/vendor/` and
//! (b) declaring `dict-<vendor> = []` in the sub-crate manifest and
//! forwarding it in the workspace-root manifest. `build.rs` panics
//! if those manifests drift out of sync with what's on disk.

use super::{AttrInfo, AttrKind, VendorInfo};

#[cfg(feature = "dict-rfc")]
#[allow(missing_docs)]
pub mod rfc {
    //! IETF / RFC attributes vendored under `dictionaries/rfc/`.
    use super::{AttrInfo, AttrKind, VendorInfo};
    include!(concat!(env!("OUT_DIR"), "/dict_rfc.rs"));
}

include!(concat!(env!("OUT_DIR"), "/vendor_mods.rs"));

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
