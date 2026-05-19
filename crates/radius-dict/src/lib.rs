//! Typed FreeRADIUS dictionary tables for RADIUS attribute encoding/decoding.
//!
//! At build time, a code-generator (see `build.rs` and the `radius-dict-codegen`
//! crate) parses the FreeRADIUS dictionary files under `dictionaries/` and emits
//! typed Rust static tables. Those tables are re-exported from the [`generated`]
//! module; the [`registry`] module provides runtime lookup helpers over them.
//!
//! The [`Type`] and [`Flags`] types describe every attribute's wire format and
//! flag bag. They appear in the public `AttributeEntry` structs emitted by the
//! generator and are re-exported here for consumers that inspect those entries.

#![warn(missing_docs)]

pub mod generated;
pub mod registry;
pub mod typed;

// ── Type ────────────────────────────────────────────────────────────────────

/// RADIUS attribute data type, as named in dictionary files.
///
/// Names mirror the `FreeRADIUS` dictionary syntax and the data-type
/// terminology in RFC 6158 / RFC 8044. The code generator turns each
/// variant into a concrete encoder/decoder selector.
///
/// These variants must stay in sync with the identically-named enum in
/// `radius-dict-codegen`. The generator emits Rust source referencing these
/// by name; a mismatch is caught at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Type {
    /// UTF-8 text without a trailing NUL (RFC 8044 §3.4).
    String,
    /// Variable-length opaque bytes.
    Octets,
    /// Fixed-length opaque bytes (`octets[N]` in dictionary syntax).
    FixedOctets(u16),
    /// IPv4 address, 4 bytes.
    Ipaddr,
    /// IPv6 address, 16 bytes.
    Ipv6addr,
    /// IPv4 prefix (RFC 6572): reserved + prefix-length + address bytes.
    Ipv4prefix,
    /// IPv6 prefix (RFC 3162): reserved + prefix-length + address bytes.
    Ipv6prefix,
    /// 8-bit unsigned integer.
    Byte,
    /// 16-bit unsigned integer.
    Short,
    /// 32-bit unsigned integer.
    Integer,
    /// 64-bit unsigned integer.
    Integer64,
    /// 32-bit signed integer.
    Signed,
    /// 32-bit seconds-since-epoch.
    Date,
    /// 8-byte interface identifier.
    Ifid,
    /// 6-byte Ethernet MAC.
    Ether,
    /// Filter-Id-style ASCII binary blob (legacy).
    Abinary,
    /// Type-Length-Value container.
    Tlv,
    /// Vendor-Specific Attribute container (attribute 26).
    Vsa,
    /// Extended-Vendor-Specific (RFC 6929 §2.4).
    Evs,
    /// RFC 6929 §2.1 extended attribute (one-byte continuation reserved).
    Extended,
    /// RFC 6929 §2.2 long-extended attribute (Flags byte includes `M` bit).
    LongExtended,
    /// Composite of fixed-layout subfields (RFC 8044 §3.13).
    Struct,
    /// Synonym for [`Type::Integer`] used in some vendor dictionaries (`uint32`).
    ///
    /// Treated identically on the wire; kept as a distinct variant so codegen
    /// can preserve the exact source spelling.
    Uint32,
}

// ── Flags ────────────────────────────────────────────────────────────────────

/// Per-attribute flags parsed from the trailing flag list of an `ATTRIBUTE`
/// line. Multiple flags may be combined with commas.
///
/// These fields must stay in sync with the identically-named struct in
/// `radius-dict-codegen`. The generator emits Rust source referencing these
/// by field name; a mismatch is caught at compile time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // mirrors the dictionary flag set
pub struct Flags {
    /// `encrypt=N` — encryption scheme (1 = User-Password, 2 = Tunnel-Password,
    /// 3 = Ascend, …). `None` means no encryption.
    pub encrypt: Option<u8>,
    /// `has_tag` — RFC 2868 §3.5 tagged attribute.
    pub has_tag: bool,
    /// `concat` — RFC 3579 §3.1 fragment concatenation (e.g. EAP-Message).
    pub concat: bool,
    /// `array` — repeats indicate an ordered list (RFC 8044 §2.5).
    pub array: bool,
    /// `virtual` — synthesised, never on the wire.
    pub virtual_: bool,
    /// `internal` — server-internal bookkeeping attribute.
    pub internal: bool,
    /// `secret` — value is sensitive and should not be logged.
    pub secret: bool,
}

// ── Integration tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use radius_dict_codegen::{Attribute, FsLoader, Parser, Type, Value};

    #[test]
    fn parses_full_vendored_rfc_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("dictionaries")
            .join("rfc")
            .join("dictionary");
        let dict = Parser::new(FsLoader).parse(&root).unwrap_or_else(|e| {
            panic!("vendored RFC dictionary failed to parse: {e}");
        });

        let by_name: HashMap<&str, &Attribute> = dict
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a))
            .collect();

        let user_name = by_name.get("User-Name").expect("User-Name present");
        assert_eq!(user_name.oid.root(), 1);
        assert_eq!(user_name.typ, Type::String);

        let user_password = by_name.get("User-Password").expect("User-Password present");
        assert_eq!(user_password.flags.encrypt, Some(1));

        let evs = by_name
            .get("Extended-Vendor-Specific-1")
            .expect("RFC 6929 extended attr present");
        assert_eq!(evs.typ, Type::Evs);
        assert_eq!(evs.oid.0, vec![241, 26]);

        let adsl = dict
            .vendors_by_name()
            .get("ADSL-Forum")
            .copied()
            .expect("ADSL-Forum vendor present");
        assert_eq!(adsl.id, 3561);
        assert!(dict
            .attributes
            .iter()
            .any(|a| a.vendor == Some(3561) && a.name == "ADSL-Agent-Circuit-Id"));
    }

    #[test]
    fn parses_full_vendored_vendor_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("dictionaries")
            .join("vendor")
            .join("dictionary");
        let dict = Parser::new(FsLoader).parse(&root).unwrap_or_else(|e| {
            panic!("vendor dictionary failed to parse: {e}");
        });

        let by_name: HashMap<&str, &Attribute> = dict
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a))
            .collect();
        let by_vendor_name = dict.vendors_by_name();

        // Cisco (PEN 9)
        let cisco = by_vendor_name.get("Cisco").expect("Cisco vendor");
        assert_eq!(cisco.id, 9);
        let avpair = by_name.get("Cisco-AVPair").expect("Cisco-AVPair");
        assert_eq!(avpair.vendor, Some(9));
        assert_eq!(avpair.typ, Type::String);

        // Aruba (PEN 14823)
        let aruba = by_vendor_name.get("Aruba").expect("Aruba vendor");
        assert_eq!(aruba.id, 14823);
        let role = by_name.get("Aruba-User-Role").expect("Aruba-User-Role");
        assert_eq!(role.vendor, Some(14823));

        // Juniper (PEN 2636) — also exercises uint32 type
        let juniper = by_vendor_name.get("Juniper").expect("Juniper vendor");
        assert_eq!(juniper.id, 2636);
        let acct_reason = by_name
            .get("Juniper-Acct-Request-Reason")
            .expect("Juniper-Acct-Request-Reason");
        assert_eq!(acct_reason.typ, Type::Uint32);

        // MikroTik (PEN 14988)
        let mikrotik = by_vendor_name.get("Mikrotik").expect("Mikrotik vendor");
        assert_eq!(mikrotik.id, 14988);

        // Ruckus (PEN 25053) — exercises TLV sub-attributes with dotted OIDs
        let ruckus = by_vendor_name.get("Ruckus").expect("Ruckus vendor");
        assert_eq!(ruckus.id, 25053);
        let tc_name = by_name
            .get("Ruckus-TC-Name-Quota")
            .expect("Ruckus-TC-Name-Quota (TLV child)");
        assert_eq!(tc_name.oid.0, vec![146, 1]);
        assert!(tc_name.oid.is_child());

        // Meraki (PEN 29671)
        let meraki = by_vendor_name.get("Meraki").expect("Meraki vendor");
        assert_eq!(meraki.id, 29671);

        // Fortinet (PEN 12356)
        let fortinet = by_vendor_name.get("Fortinet").expect("Fortinet vendor");
        assert_eq!(fortinet.id, 12356);
        let ether_attr = by_name
            .get("Fortinet-WirelessController-Device-MAC")
            .expect("Fortinet ether attribute");
        assert_eq!(ether_attr.typ, Type::Ether);

        // HP / ProCurve (PEN 11)
        let hp = by_vendor_name.get("HP").expect("HP vendor");
        assert_eq!(hp.id, 11);

        // WISPr (PEN 14122)
        let wispr = by_vendor_name.get("WISPr").expect("WISPr vendor");
        assert_eq!(wispr.id, 14122);

        // Microsoft (PEN 311) — exercises octets[N] and encrypt=2
        let microsoft = by_vendor_name.get("Microsoft").expect("Microsoft vendor");
        assert_eq!(microsoft.id, 311);
        let chap_resp = by_name.get("MS-CHAP-Response").expect("MS-CHAP-Response");
        assert_eq!(chap_resp.typ, Type::FixedOctets(50));
        assert_eq!(chap_resp.vendor, Some(311));
        let mppe_key = by_name.get("MS-MPPE-Send-Key").expect("MS-MPPE-Send-Key");
        assert_eq!(mppe_key.flags.encrypt, Some(2));
        let dns = by_name
            .get("MS-Primary-DNS-Server")
            .expect("MS-Primary-DNS-Server");
        assert_eq!(dns.typ, Type::Ipaddr);

        // Ascend (PEN 529) — exercises encrypt=3
        let ascend = by_vendor_name.get("Ascend").expect("Ascend vendor");
        assert_eq!(ascend.id, 529);
        let send_secret = by_name
            .get("Ascend-Send-Secret")
            .expect("Ascend-Send-Secret");
        assert_eq!(send_secret.flags.encrypt, Some(3));

        // Aruba encrypt=2 flag on MPSK passphrase
        let mpsk = by_name
            .get("Aruba-MPSK-Passphrase")
            .expect("Aruba-MPSK-Passphrase");
        assert_eq!(mpsk.flags.encrypt, Some(2));

        // Juniper hex VALUE (0x0004) parsed correctly
        let acct_vals: Vec<&Value> = dict
            .values
            .iter()
            .filter(|v| v.attribute == "Juniper-Acct-Request-Reason")
            .collect();
        let ipv4_active = acct_vals
            .iter()
            .find(|v| v.name == "IPv4-Active")
            .expect("IPv4-Active value");
        assert_eq!(ipv4_active.number, 0x0004);
    }
}
