//! Wireshark-style human-readable packet dissection.
//!
//! Every type in this module is a thin `Display`-only wrapper around
//! borrowed packet bytes. Constructing a wrapper is a pointer copy;
//! formatting is the only thing that costs CPU, and it is only paid
//! when the caller writes the wrapper to a `Formatter` (`{}`-print,
//! `to_string()`, `tracing::info!`, etc.). Nothing in the steady-state
//! encode / decode path touches this module.
//!
//! # Example
//!
//! ```ignore
//! use radius_tokio::PacketBuffer;
//!
//! let pkt = PacketBuffer::from_bytes(&datagram)?;
//! eprintln!("{}", pkt.dissect());
//! ```
//!
//! Output mirrors Wireshark's `RADIUS Protocol` tree:
//!
//! ```text
//! RADIUS Protocol
//!     Code: Access-Request (1)
//!     Packet identifier: 0x42 (66)
//!     Length: 84
//!     Authenticator: 0102030405060708090a0b0c0d0e0f10
//!     Attribute Value Pairs
//!         AVP: t=User-Name(1) l=7 val="alice"
//!         AVP: t=NAS-IP-Address(4) l=6 val=10.0.0.1
//!         AVP: t=Vendor-Specific(26) l=12 vnd=Cisco(9)
//!             VSA: t=Cisco-AVPair(1) l=4 val="foo"
//! ```
//!
//! # Caveats
//!
//! * Encrypted attributes (`User-Password`, `Tunnel-Password`) are
//!   shown as raw hex with an `<encrypted>` marker — the dissector
//!   does not have access to a shared secret. A future
//!   `dissect_with_secret` could decrypt; deferred.
//! * Sub-VSAs packed into a single attribute-26 slot beyond the first
//!   are not unpacked. The first per-vendor TLV is dissected; trailing
//!   bytes of that slot are reported as raw hex.
//! * The renderer is intentionally lossy on truly malformed packets:
//!   it prints the offending bytes plus a `<malformed>` marker rather
//!   than refusing to format. Diagnosing bad input is the use case.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::attributes::{AttributesIter, RawAttribute};
use super::header::{Code, Header};
use super::PacketBuffer;
use crate::dict::{self, AttrInfo, AttrKind};

/// Indent applied per Wireshark "tree" level.
const INDENT: &str = "    ";

/// Hex-dump cap on raw byte values inside an attribute. Anything
/// larger is truncated with a `…(N more)` suffix to keep log lines
/// usable. Picked to comfortably hold a Message-Authenticator (16),
/// EAP-Message fragment (≤253), and most realistic VSAs.
const MAX_HEX_BYTES: usize = 64;

// ---- public wrappers --------------------------------------------------

/// `Display` wrapper rendering a full packet (header + AVP tree).
#[derive(Clone, Copy)]
pub struct PacketDissect<'a> {
    src: PacketSource<'a>,
}

#[derive(Clone, Copy)]
enum PacketSource<'a> {
    /// Built or received via [`PacketBuffer`]; we read the header and
    /// attribute region directly from the buffer's accessors so an
    /// unsealed (length-placeholder) buffer still dissects correctly.
    Buffer(&'a PacketBuffer),
    /// Raw packet bytes; the header is parsed on demand.
    Bytes(&'a [u8]),
}

impl<'a> PacketDissect<'a> {
    /// Build a dissector view over a validated packet buffer.
    #[must_use]
    pub fn new(pkt: &'a PacketBuffer) -> Self {
        Self {
            src: PacketSource::Buffer(pkt),
        }
    }

    /// Build a dissector view directly from raw packet bytes.
    ///
    /// Useful for logging un-parsed input (e.g. on a header-validation
    /// failure path); the renderer falls back to a `<malformed
    /// header>` line if the bytes are not a valid RADIUS packet.
    #[must_use]
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            src: PacketSource::Bytes(bytes),
        }
    }
}

impl fmt::Display for PacketDissect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (header, attrs): (Header, &[u8]) = match self.src {
            PacketSource::Buffer(pkt) => (pkt.header(), pkt.attributes()),
            PacketSource::Bytes(bytes) => match Header::parse(bytes) {
                Ok(parsed) => parsed,
                Err(e) => {
                    writeln!(f, "RADIUS Protocol")?;
                    writeln!(f, "{INDENT}<malformed header: {e}>")?;
                    return write_raw_hex(f, INDENT, bytes);
                }
            },
        };
        writeln!(f, "RADIUS Protocol")?;
        write_header_lines(f, INDENT, &header)?;
        writeln!(f, "{INDENT}Attribute Value Pairs")?;
        let avp_indent = concat_indent(2);
        for slot in super::attributes::iter(attrs) {
            match slot {
                Ok(raw) => write_attribute(f, &avp_indent, raw)?,
                Err(e) => {
                    writeln!(f, "{avp_indent}<malformed attribute: {e}>")?;
                    break;
                }
            }
        }
        Ok(())
    }
}

/// `Display` wrapper for a single header (no AVPs).
#[derive(Clone, Copy)]
pub struct HeaderDissect<'a> {
    header: &'a Header,
}

impl<'a> HeaderDissect<'a> {
    /// Build a header-only dissector view.
    #[must_use]
    pub fn new(header: &'a Header) -> Self {
        Self { header }
    }
}

impl fmt::Display for HeaderDissect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RADIUS Protocol")?;
        write_header_lines(f, INDENT, self.header)
    }
}

/// `Display` wrapper for a single attribute slot (incl. nested VSA).
#[derive(Clone, Copy)]
pub struct AttrDissect<'a> {
    raw: RawAttribute<'a>,
}

impl<'a> AttrDissect<'a> {
    /// Build a single-attribute dissector view.
    #[must_use]
    pub fn new(raw: RawAttribute<'a>) -> Self {
        Self { raw }
    }
}

impl fmt::Display for AttrDissect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_attribute(f, "", self.raw)
    }
}

/// `Display` wrapper that renders an [`AttributesIter`] as a flat AVP
/// list (one per line, no surrounding `RADIUS Protocol` header).
pub struct AttributesDissect<'a> {
    iter: AttributesIter<'a>,
}

impl<'a> AttributesDissect<'a> {
    /// Build a dissector view over an attribute iterator.
    #[must_use]
    pub fn new(iter: AttributesIter<'a>) -> Self {
        Self { iter }
    }
}

impl fmt::Display for AttributesDissect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for slot in self.iter.clone() {
            match slot {
                Ok(raw) => write_attribute(f, "", raw)?,
                Err(e) => {
                    writeln!(f, "<malformed attribute: {e}>")?;
                    break;
                }
            }
        }
        Ok(())
    }
}

// ---- ergonomic accessors on existing types ----------------------------

impl PacketBuffer {
    /// Wireshark-style human-readable dissection. See [`PacketDissect`].
    #[inline]
    #[must_use]
    pub fn dissect(&self) -> PacketDissect<'_> {
        PacketDissect::new(self)
    }
}

impl Header {
    /// Wireshark-style human-readable dissection. See [`HeaderDissect`].
    #[inline]
    #[must_use]
    pub fn dissect(&self) -> HeaderDissect<'_> {
        HeaderDissect::new(self)
    }
}

impl<'a> RawAttribute<'a> {
    /// Wireshark-style human-readable dissection. See [`AttrDissect`].
    #[inline]
    #[must_use]
    pub fn dissect(self) -> AttrDissect<'a> {
        AttrDissect::new(self)
    }
}

// ---- internals --------------------------------------------------------

fn write_header_lines(f: &mut fmt::Formatter<'_>, indent: &str, h: &Header) -> fmt::Result {
    let code_name = code_name(h.code);
    match code_name {
        Some(name) => writeln!(f, "{indent}Code: {name} ({})", h.code.0)?,
        None => writeln!(f, "{indent}Code: Unknown ({})", h.code.0)?,
    }
    writeln!(
        f,
        "{indent}Packet identifier: 0x{:02x} ({})",
        h.identifier, h.identifier
    )?;
    writeln!(f, "{indent}Length: {}", h.length)?;
    write!(f, "{indent}Authenticator: ")?;
    for b in &h.authenticator {
        write!(f, "{b:02x}")?;
    }
    writeln!(f)
}

fn write_attribute(f: &mut fmt::Formatter<'_>, indent: &str, raw: RawAttribute<'_>) -> fmt::Result {
    let typ = raw.attribute_type();
    let len = raw.wire_len();
    let val = raw.value();

    // Vendor-Specific gets nested treatment.
    if typ == 26 {
        return write_vsa(f, indent, len, val);
    }

    let entry = dict::attribute(typ);
    let name = entry.map_or("Unknown", |e| e.name);
    write!(f, "{indent}AVP: t={name}({typ}) l={len}")?;
    write_value(f, indent, typ, entry, val)
}

fn write_vsa(f: &mut fmt::Formatter<'_>, indent: &str, len: u8, val: &[u8]) -> fmt::Result {
    let Some((pen_bytes, rest)) = val.split_first_chunk::<4>() else {
        writeln!(
            f,
            "{indent}AVP: t=Vendor-Specific(26) l={len} <truncated VSA>"
        )?;
        return write_raw_hex(f, indent, val);
    };
    let pen = u32::from_be_bytes(*pen_bytes);
    let vendor_entry = dict::vendor(pen);
    let vendor_name = vendor_entry.map_or("Unknown", |v| v.name);
    writeln!(
        f,
        "{indent}AVP: t=Vendor-Specific(26) l={len} vnd={vendor_name}({pen})"
    )?;

    // RFC 2865 §5.26 framing assumed (1-byte type, 1-byte length).
    // FreeRADIUS `format=t,l` overrides are not yet honoured here;
    // they are rare in the dictionaries we vendor.
    let inner_indent = format!("{indent}{INDENT}");

    // Walk every vendor TLV packed into this VSA slot. RFC 2865
    // §5.26 explicitly allows multiple sub-attributes to share one
    // Vendor-Specific attribute, and Cisco AVPair stacks do so in
    // the wild.
    let mut cursor = rest;
    while !cursor.is_empty() {
        if cursor.len() < 2 {
            writeln!(
                f,
                "{inner_indent}<trailing {} byte(s) in VSA slot>",
                cursor.len()
            )?;
            write_raw_hex(f, &inner_indent, cursor)?;
            break;
        }
        let v_type = cursor[0];
        let v_len = cursor[1] as usize;
        if v_len < 2 || v_len > cursor.len() {
            writeln!(
                f,
                "{inner_indent}<malformed vendor TLV: type={v_type} len={v_len}>"
            )?;
            write_raw_hex(f, &inner_indent, cursor)?;
            break;
        }
        let data = &cursor[2..v_len];
        let entry = dict::vsa(pen, v_type);
        let vname = entry.map_or("Unknown", |e| e.name);
        write!(f, "{inner_indent}VSA: t={vname}({v_type}) l={v_len}")?;
        // `parent_code` here is the vendor-type. The RFC-namespace
        // `tlv_child` lookup will miss for vendor TLVs (Phase B
        // territory), so a `Tlv`-kind vendor parent falls back to the
        // hex dump in `write_value`'s container arm.
        write_value(f, &inner_indent, v_type, entry, data)?;
        cursor = &cursor[v_len..];
    }
    Ok(())
}

/// Render an Extended (RFC 6929 §2.1) or Long-Extended (§2.2)
/// attribute value.
///
/// `val` is the bytes following the outer 1-byte `Type` + 1-byte
/// `Length` header — i.e. starting at the `Extended-Type` byte.
/// For Long-Extended the second byte is the `Flags` field whose
/// high bit (`M`) signals fragment continuation; we surface it so
/// operators can spot mid-stream reassembly without re-reading the
/// RFC.
///
/// When the Extended-Type byte is 26 the inner payload is itself
/// an [Extended-Vendor-Specific (EVS, §2.4)][evs] tuple and we
/// recurse into [`write_evs`] for vendor framing. Other sub-types
/// fall through to a hex dump because the dict crate does not yet
/// expose an Extended-child lookup.
///
/// [evs]: write_evs
fn write_extended(f: &mut fmt::Formatter<'_>, indent: &str, val: &[u8], long: bool) -> fmt::Result {
    let header_len = if long { 2 } else { 1 };
    let cont = format!("{indent}{INDENT}");
    if val.len() < header_len {
        writeln!(f, " <truncated Extended header>")?;
        return write_raw_hex(f, &cont, val);
    }
    let ext_type = val[0];
    let inner: &[u8] = if long {
        let flags = val[1];
        let m_bit = (flags & 0x80) != 0;
        let reserved = flags & 0x7F;
        if reserved == 0 {
            writeln!(
                f,
                " ext-type={ext_type} flags=0x{flags:02x} M={}",
                u8::from(m_bit)
            )?;
        } else {
            writeln!(
                f,
                " ext-type={ext_type} flags=0x{flags:02x} M={} reserved=0x{reserved:02x}",
                u8::from(m_bit)
            )?;
        }
        &val[2..]
    } else {
        writeln!(f, " ext-type={ext_type}")?;
        &val[1..]
    };
    if ext_type == 26 {
        return write_evs(f, &cont, inner);
    }
    write_raw_hex(f, &cont, inner)
}

/// Render the value of an Extended-Vendor-Specific (RFC 6929 §2.4)
/// attribute. `val` starts at the 4-byte Vendor-Id, followed by the
/// 1-byte Vendor-Type, followed by the vendor's value payload.
fn write_evs(f: &mut fmt::Formatter<'_>, indent: &str, val: &[u8]) -> fmt::Result {
    if val.len() < 5 {
        writeln!(f, "{indent}<EVS: truncated header, need >=5 bytes>")?;
        return write_raw_hex(f, indent, val);
    }
    let pen_bytes: [u8; 4] = val[..4].try_into().unwrap();
    let pen = u32::from_be_bytes(pen_bytes);
    let v_type = val[4];
    let inner = &val[5..];
    let vendor_entry = dict::vendor(pen);
    let vendor_name = vendor_entry.map_or("Unknown", |v| v.name);
    writeln!(f, "{indent}EVS: vnd={vendor_name}({pen}) v-type={v_type}")?;
    // No dict-side lookup for EVS children exists today; render raw.
    let cont = format!("{indent}{INDENT}");
    write_raw_hex(f, &cont, inner)
}

/// Render the value portion (` val=…\n`) of an AVP line.
///
/// `parent_code` is the surrounding attribute's 1-byte type code,
/// needed for recursive `Tlv` resolution via [`dict::tlv_child`].
/// `entry` is the dictionary lookup result for the surrounding
/// attribute; it drives type-aware formatting (decimal vs hex,
/// enumerator name vs raw integer, encrypted-marker, etc.). When
/// `entry` is `None` we fall back to a hex dump.
#[allow(clippy::too_many_lines)]
fn write_value(
    f: &mut fmt::Formatter<'_>,
    indent: &str,
    parent_code: u8,
    entry: Option<AttrInfo>,
    val: &[u8],
) -> fmt::Result {
    let Some(entry) = entry else {
        write!(f, " val=")?;
        write_hex_inline(f, val)?;
        return writeln!(f);
    };

    if entry.encrypted {
        write!(f, " val=<encrypted ")?;
        write_hex_inline(f, val)?;
        return writeln!(f, ">");
    }

    match entry.kind {
        AttrKind::String => {
            if let Ok(s) = std::str::from_utf8(val) {
                writeln!(f, " val={s:?}")
            } else {
                write!(f, " val=<non-utf8 ")?;
                write_hex_inline(f, val)?;
                writeln!(f, ">")
            }
        }
        AttrKind::Octets => {
            write!(f, " val=")?;
            write_hex_inline(f, val)?;
            writeln!(f)
        }
        AttrKind::Ipaddr => match <[u8; 4]>::try_from(val) {
            Ok(octets) => writeln!(f, " val={}", Ipv4Addr::from(octets)),
            Err(_) => writeln!(f, " val=<bad ipv4 len={}>", val.len()),
        },
        AttrKind::Ipv6addr => match <[u8; 16]>::try_from(val) {
            Ok(octets) => writeln!(f, " val={}", Ipv6Addr::from(octets)),
            Err(_) => writeln!(f, " val=<bad ipv6 len={}>", val.len()),
        },
        AttrKind::Ipv4prefix => write_ip_prefix(f, val, 4),
        AttrKind::Ipv6prefix => write_ip_prefix(f, val, 16),
        AttrKind::Byte => match val {
            [b] => write_integer(f, entry, i64::from(*b)),
            _ => writeln!(f, " val=<bad byte len={}>", val.len()),
        },
        AttrKind::Short => match <[u8; 2]>::try_from(val) {
            Ok(b) => write_integer(f, entry, i64::from(u16::from_be_bytes(b))),
            Err(_) => writeln!(f, " val=<bad short len={}>", val.len()),
        },
        AttrKind::Integer => match <[u8; 4]>::try_from(val) {
            Ok(b) => write_integer(f, entry, i64::from(u32::from_be_bytes(b))),
            Err(_) => writeln!(f, " val=<bad integer len={}>", val.len()),
        },
        AttrKind::Integer64 => match <[u8; 8]>::try_from(val) {
            Ok(b) => writeln!(f, " val={}", u64::from_be_bytes(b)),
            Err(_) => writeln!(f, " val=<bad integer64 len={}>", val.len()),
        },
        AttrKind::Signed => match <[u8; 4]>::try_from(val) {
            Ok(b) => write_integer(f, entry, i64::from(i32::from_be_bytes(b))),
            Err(_) => writeln!(f, " val=<bad signed len={}>", val.len()),
        },
        AttrKind::Date => match <[u8; 4]>::try_from(val) {
            Ok(b) => writeln!(f, " val={} (epoch seconds)", u32::from_be_bytes(b)),
            Err(_) => writeln!(f, " val=<bad date len={}>", val.len()),
        },
        AttrKind::Ether => {
            if let Ok(m) = <[u8; 6]>::try_from(val) {
                writeln!(
                    f,
                    " val={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            } else {
                writeln!(f, " val=<bad ether len={}>", val.len())
            }
        }
        AttrKind::Ifid => {
            if val.len() == 8 {
                write!(f, " val=")?;
                for (i, chunk) in val.chunks(2).enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    for b in chunk {
                        write!(f, "{b:02x}")?;
                    }
                }
                writeln!(f)
            } else {
                writeln!(f, " val=<bad ifid len={}>", val.len())
            }
        }
        AttrKind::Tlv => {
            // Walk back-to-back [type, length, value] triples and
            // dissect each child via `dict::tlv_child`. If the
            // first child fails to resolve we fall through to the
            // generic container dump so vendor TLVs (Phase B) and
            // unrecognised structures still produce useful output.
            writeln!(f)?;
            let cont = format!("{indent}{INDENT}");
            let mut cursor = val;
            let mut any_dissected = false;
            while cursor.len() >= 2 {
                let t = cursor[0];
                let l = cursor[1] as usize;
                if l < 2 || l > cursor.len() {
                    writeln!(f, "{cont}<malformed TLV: type={t} len={l}>")?;
                    break;
                }
                let child_entry = dict::tlv_child(parent_code, t);
                let child_name = child_entry.map_or("Unknown", |e| e.name);
                write!(f, "{cont}TLV: t={child_name}({t}) l={l}")?;
                write_value(f, &cont, t, child_entry, &cursor[2..l])?;
                any_dissected |= child_entry.is_some();
                cursor = &cursor[l..];
            }
            if !any_dissected && cursor.len() == val.len() {
                // Nothing parsed — show the raw payload so the
                // operator can still inspect the bytes.
                write_raw_hex(f, &cont, val)?;
            } else if !cursor.is_empty() {
                writeln!(f, "{cont}<trailing {} byte(s) in TLV>", cursor.len())?;
                write_raw_hex(f, &cont, cursor)?;
            }
            Ok(())
        }
        AttrKind::Extended => {
            // RFC 6929 §2.1 framing: 1-byte Extended-Type followed
            // by the value payload.
            write_extended(f, indent, val, false)
        }
        AttrKind::LongExtended => {
            // RFC 6929 §2.2 framing: 1-byte Extended-Type + 1-byte
            // Flags (M-bit = fragment continuation) + value.
            write_extended(f, indent, val, true)
        }
        AttrKind::Evs => {
            // RFC 6929 §2.4 framing: 4-byte Vendor-Id + 1-byte
            // Vendor-Type + value. Reached when the dictionary
            // registers an attribute directly as `evs` (rare —
            // most EVS payloads arrive nested inside an `extended`
            // parent and are unwrapped by `write_extended`).
            writeln!(f)?;
            let cont = format!("{indent}{INDENT}");
            write_evs(f, &cont, val)
        }
        AttrKind::Vsa | AttrKind::Struct => {
            // `Vsa` here only fires for nested-VSA TLV children
            // (top-level type 26 is intercepted in
            // `write_attribute`). `Struct` (RFC 6929 §3.13) has no
            // first-class renderer — both fall back to a hex dump
            // so the operator can still inspect the bytes.
            writeln!(f, " <{:?}>", entry.kind)?;
            let cont = format!("{indent}{INDENT}");
            write_raw_hex(f, &cont, val)
        }
        _ => {
            // `AttrKind` is `#[non_exhaustive]`. Unknown variants
            // fall back to a raw hex dump rather than refusing to
            // render.
            write!(f, " val=")?;
            write_hex_inline(f, val)?;
            writeln!(f)
        }
    }
}

fn write_integer(f: &mut fmt::Formatter<'_>, entry: AttrInfo, n: i64) -> fmt::Result {
    match dict::value_name(entry.name, n) {
        Some(name) => writeln!(f, " val={name}({n})"),
        None => writeln!(f, " val={n}"),
    }
}

fn write_ip_prefix(f: &mut fmt::Formatter<'_>, val: &[u8], addr_len: usize) -> fmt::Result {
    // RFC 6572 / RFC 3162: 1 reserved + 1 prefix-len + up to addr_len bytes.
    if val.len() < 2 || val.len() > 2 + addr_len {
        return writeln!(f, " val=<bad prefix len={}>", val.len());
    }
    let prefix_len = val[1];
    let mut buf = vec![0u8; addr_len];
    buf[..val.len() - 2].copy_from_slice(&val[2..]);
    if addr_len == 4 {
        let octets: [u8; 4] = buf.as_slice().try_into().unwrap();
        writeln!(f, " val={}/{prefix_len}", Ipv4Addr::from(octets))
    } else {
        let octets: [u8; 16] = buf.as_slice().try_into().unwrap();
        writeln!(f, " val={}/{prefix_len}", Ipv6Addr::from(octets))
    }
}

fn write_hex_inline(f: &mut fmt::Formatter<'_>, val: &[u8]) -> fmt::Result {
    let cap = val.len().min(MAX_HEX_BYTES);
    write!(f, "0x")?;
    for b in &val[..cap] {
        write!(f, "{b:02x}")?;
    }
    if val.len() > cap {
        write!(f, "…({} more)", val.len() - cap)?;
    }
    Ok(())
}

fn write_raw_hex(f: &mut fmt::Formatter<'_>, indent: &str, val: &[u8]) -> fmt::Result {
    if val.is_empty() {
        return Ok(());
    }
    write!(f, "{indent}")?;
    write_hex_inline(f, val)?;
    writeln!(f)
}

fn concat_indent(levels: usize) -> String {
    let mut s = String::with_capacity(INDENT.len() * levels);
    for _ in 0..levels {
        s.push_str(INDENT);
    }
    s
}

fn code_name(c: Code) -> Option<&'static str> {
    Some(match c {
        Code::ACCESS_REQUEST => "Access-Request",
        Code::ACCESS_ACCEPT => "Access-Accept",
        Code::ACCESS_REJECT => "Access-Reject",
        Code::ACCOUNTING_REQUEST => "Accounting-Request",
        Code::ACCOUNTING_RESPONSE => "Accounting-Response",
        Code::ACCESS_CHALLENGE => "Access-Challenge",
        Code::STATUS_SERVER => "Status-Server",
        Code::STATUS_CLIENT => "Status-Client",
        Code::DISCONNECT_REQUEST => "Disconnect-Request",
        Code::DISCONNECT_ACK => "Disconnect-ACK",
        Code::DISCONNECT_NAK => "Disconnect-NAK",
        Code::COA_REQUEST => "CoA-Request",
        Code::COA_ACK => "CoA-ACK",
        Code::COA_NAK => "CoA-NAK",
        _ => return None,
    })
}

#[cfg(all(test, feature = "dict-rfc"))]
mod tests {
    use super::*;
    use crate::codec::PacketBuffer;
    use crate::Code;

    #[test]
    fn dissect_minimal_access_request() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 42);
        buf.add_attribute(1, b"alice").unwrap();
        buf.add_attribute(4, &[10, 0, 0, 1]).unwrap();

        let s = format!("{}", buf.dissect());
        assert!(s.contains("RADIUS Protocol"), "{s}");
        assert!(s.contains("Code: Access-Request (1)"), "{s}");
        assert!(s.contains("Packet identifier: 0x2a (42)"), "{s}");
        assert!(s.contains("AVP: t=User-Name(1)"), "{s}");
        assert!(s.contains(r#"val="alice""#), "{s}");
        assert!(s.contains("AVP: t=NAS-IP-Address(4)"), "{s}");
        assert!(s.contains("val=10.0.0.1"), "{s}");
    }

    #[test]
    fn dissect_unknown_code_and_attribute() {
        let mut buf = PacketBuffer::new(Code(99), 7);
        buf.add_attribute(250, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("Code: Unknown (99)"), "{s}");
        assert!(s.contains("AVP: t=Unknown(250)"), "{s}");
        assert!(s.contains("0xdeadbeef"), "{s}");
    }

    #[test]
    fn dissect_enumerated_integer_uses_value_name() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Service-Type = 2 → Framed-User
        buf.add_attribute(6, &2u32.to_be_bytes()).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=Framed-User(2)"), "{s}");
    }

    #[test]
    fn dissect_encrypted_attribute_marked() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // User-Password (2) is encrypt=1.
        buf.add_attribute(2, &[0u8; 16]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<encrypted "), "{s}");
    }

    #[test]
    fn dissect_malformed_header_does_not_panic() {
        let s = format!("{}", PacketDissect::from_bytes(&[1, 2, 3]));
        assert!(s.contains("<malformed header"), "{s}");
    }

    #[cfg(feature = "dict-cisco")]
    #[test]
    fn dissect_known_vsa_resolves_vendor_and_attr() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Cisco PEN = 9, Cisco-AVPair = 1, value "shell:priv-lvl=15".
        let mut v = Vec::new();
        v.extend_from_slice(&9u32.to_be_bytes());
        let payload = b"shell:priv-lvl=15";
        v.push(1); // vendor-type
        v.push(u8::try_from(payload.len() + 2).unwrap()); // vendor-length
        v.extend_from_slice(payload);
        buf.add_attribute(26, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("vnd=Cisco(9)"), "{s}");
        assert!(s.contains("VSA: t=Cisco-AVPair(1)"), "{s}");
        assert!(s.contains("shell:priv-lvl=15"), "{s}");
    }

    #[test]
    fn dissect_ipv6_address_attribute() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // NAS-IPv6-Address (95) is Ipv6addr.
        let addr: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
        buf.add_attribute(95, &addr).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=NAS-IPv6-Address(95)"), "{s}");
        assert!(s.contains("val=::1"), "{s}");
    }

    #[test]
    fn dissect_ipv6_address_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(95, &[0u8; 8]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad ipv6 len="), "{s}");
    }

    #[test]
    fn dissect_ipv6_prefix_attribute() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Framed-IPv6-Prefix (97) is Ipv6prefix: 1-byte reserved, 1-byte
        // prefix-length, up to 16 bytes of address.
        let mut payload = vec![0u8, 64];
        payload.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
        buf.add_attribute(97, &payload).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=Framed-IPv6-Prefix(97)"), "{s}");
        assert!(s.contains("/64"), "{s}");
    }

    #[test]
    fn dissect_ipv6_prefix_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(97, &[0u8]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad prefix len="), "{s}");
    }

    #[test]
    fn dissect_date_attribute() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Event-Timestamp (55) is Date.
        buf.add_attribute(55, &1_700_000_000u32.to_be_bytes())
            .unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("(epoch seconds)"), "{s}");
    }

    #[test]
    fn dissect_date_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(55, &[0u8, 1, 2]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad date len="), "{s}");
    }

    #[test]
    fn dissect_ifid_attribute() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Framed-Interface-Id (96) is Ifid (8 bytes, colon-rendered).
        buf.add_attribute(96, &[0xfe, 0x80, 0, 0, 0, 0, 0, 1])
            .unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=Framed-Interface-Id(96)"), "{s}");
        assert!(s.contains("val=fe80:0000:0000:0001"), "{s}");
    }

    #[test]
    fn dissect_ifid_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(96, &[0u8, 1, 2, 3]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad ifid len="), "{s}");
    }

    #[test]
    fn dissect_integer64_attribute() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // MIP6-Feature-Vector (124) is Integer64.
        buf.add_attribute(124, &0xdead_beef_u64.to_be_bytes())
            .unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=3735928559"), "{s}");
    }

    #[test]
    fn dissect_integer64_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(124, &[0u8; 4]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad integer64 len="), "{s}");
    }

    #[test]
    fn dissect_ipaddr_bad_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // NAS-IP-Address (4) is Ipaddr; feed wrong length.
        buf.add_attribute(4, &[10, 0, 0]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("val=<bad ipv4 len="), "{s}");
    }

    #[test]
    fn dissect_truncated_vsa_slot_too_small_for_pen() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Vendor-Specific (26) with fewer than 4 PEN bytes.
        buf.add_attribute(26, &[1u8, 2, 3]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<truncated VSA>"), "{s}");
    }

    #[test]
    fn dissect_truncated_vsa_inner_tlv() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Valid PEN, but a single trailing byte that cannot start a TLV.
        let mut v = Vec::new();
        v.extend_from_slice(&9u32.to_be_bytes());
        v.push(1);
        buf.add_attribute(26, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<trailing 1 byte(s) in VSA slot>"), "{s}");
    }

    #[test]
    fn dissect_vsa_bad_inner_length() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // PEN + vendor-type + vendor-length claiming more than is present.
        let mut v = Vec::new();
        v.extend_from_slice(&9u32.to_be_bytes());
        v.push(1); // type
        v.push(50); // claims 48 bytes payload but provides 0
        buf.add_attribute(26, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<malformed vendor TLV: type=1 len=50>"), "{s}");
    }

    #[cfg(feature = "dict-cisco")]
    #[test]
    fn dissect_vsa_walks_multiple_inner_tlvs() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // PEN + two back-to-back vendor TLVs in one VSA slot
        // (RFC 2865 §5.26 permits this; Cisco AVPair stacks do it).
        let mut v = Vec::new();
        v.extend_from_slice(&9u32.to_be_bytes());
        v.extend_from_slice(&[1u8, 3, 0xaa]); // first TLV: type=1 len=3
        v.extend_from_slice(&[2u8, 4, 0xbe, 0xef]); // second TLV: type=2 len=4
        buf.add_attribute(26, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("t=Cisco-AVPair(1) l=3"), "{s}");
        assert!(s.contains("(2) l=4"), "{s}");
    }

    #[test]
    fn dissect_vsa_with_unparseable_trailing_byte() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // PEN + valid TLV + a single dangling byte that cannot be
        // parsed as a fresh TLV header.
        let mut v = Vec::new();
        v.extend_from_slice(&9u32.to_be_bytes());
        v.extend_from_slice(&[1u8, 3, 0xaa]);
        v.push(0xde);
        buf.add_attribute(26, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<trailing 1 byte(s) in VSA slot>"), "{s}");
    }

    #[test]
    fn dissect_extended_attribute_renders_ext_type() {
        // Extended-Type-1 (RFC 6929 §2.1, attribute 241).
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // ext-type=7 + 4-byte opaque payload
        buf.add_attribute(241, &[7u8, 0xde, 0xad, 0xbe, 0xef])
            .unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=Extended-Attribute-1(241)"), "{s}");
        assert!(s.contains("ext-type=7"), "{s}");
        assert!(s.contains("0xdeadbeef"), "{s}");
    }

    #[test]
    fn dissect_long_extended_surfaces_flag_bits() {
        // Long-Extended-Type-1 (RFC 6929 §2.2, attribute 245).
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // ext-type=3 + flags=0x80 (M=1) + 2 bytes
        buf.add_attribute(245, &[3u8, 0x80, 0xaa, 0xbb]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=Extended-Attribute-5(245)"), "{s}");
        assert!(s.contains("ext-type=3"), "{s}");
        assert!(s.contains("flags=0x80"), "{s}");
        assert!(s.contains("M=1"), "{s}");
    }

    #[cfg(feature = "dict-cisco")]
    #[test]
    fn dissect_extended_vendor_specific_renders_evs() {
        // Extended-Type-1 (241) with ext-type=26 carries EVS (RFC 6929 §2.4).
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        let mut v = vec![26u8];
        v.extend_from_slice(&9u32.to_be_bytes()); // Cisco PEN
        v.push(42); // vendor-type
        v.extend_from_slice(&[0xca, 0xfe]); // vendor value
        buf.add_attribute(241, &v).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("ext-type=26"), "{s}");
        assert!(s.contains("EVS:"), "{s}");
        assert!(s.contains("vnd=Cisco(9)"), "{s}");
        assert!(s.contains("v-type=42"), "{s}");
        assert!(s.contains("0xcafe"), "{s}");
    }

    #[test]
    fn dissect_extended_truncated_header() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Long-Extended-Type-1 needs 2 header bytes; we provide 1.
        buf.add_attribute(245, &[7u8]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<truncated Extended header>"), "{s}");
    }

    #[test]
    fn dissect_evs_truncated_header() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // Extended with ext-type=26 but EVS body shorter than 5 bytes.
        buf.add_attribute(241, &[26u8, 0, 0, 0]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<EVS: truncated header"), "{s}");
    }

    #[test]
    fn header_dissect_renders_well_known_code() {
        use crate::codec::header::Header;
        let header = Header {
            code: Code::ACCESS_ACCEPT,
            identifier: 7,
            length: 20,
            authenticator: [0x11; 16],
        };
        let s = format!("{}", header.dissect());
        assert!(s.contains("Code: Access-Accept (2)"), "{s}");
        assert!(s.contains("11111111111111111111111111111111"), "{s}");
    }

    #[test]
    fn attr_dissect_renders_single_avp() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(1, b"alice").unwrap();
        let raw = crate::codec::attributes::iter(buf.attributes())
            .next()
            .unwrap()
            .unwrap();
        let s = format!("{}", raw.dissect());
        assert!(s.contains("AVP: t=User-Name(1)"), "{s}");
        assert!(s.contains(r#"val="alice""#), "{s}");
    }

    #[test]
    fn attributes_dissect_iterates_all() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        buf.add_attribute(1, b"bob").unwrap();
        buf.add_attribute(4, &[10, 0, 0, 1]).unwrap();
        let s = format!(
            "{}",
            AttributesDissect::new(crate::codec::attributes::iter(buf.attributes()))
        );
        assert!(s.contains("User-Name"), "{s}");
        assert!(s.contains("NAS-IP-Address"), "{s}");
    }

    #[test]
    fn dissect_tlv_recurses_into_named_children() {
        // RFC 5447 §4.3: IPv6-6rd-Configuration (173) is a Tlv parent
        // with children IPv6-6rd-IPv4MaskLen(1, Integer) and
        // IPv6-6rd-BR-IPv4-Address(3, Ipaddr).
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        let mut tlv = Vec::new();
        // child 1, len 6, integer 24
        tlv.extend_from_slice(&[1, 6]);
        tlv.extend_from_slice(&24u32.to_be_bytes());
        // child 3, len 6, ipaddr 192.0.2.1
        tlv.extend_from_slice(&[3, 6]);
        tlv.extend_from_slice(&[192, 0, 2, 1]);
        buf.add_attribute(173, &tlv).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("AVP: t=IPv6-6rd-Configuration(173)"), "{s}");
        assert!(s.contains("TLV: t=IPv6-6rd-IPv4MaskLen(1) l=6"), "{s}");
        assert!(s.contains("val=24"), "{s}");
        assert!(s.contains("TLV: t=IPv6-6rd-BR-IPv4-Address(3) l=6"), "{s}");
        assert!(s.contains("val=192.0.2.1"), "{s}");
    }

    #[test]
    fn dissect_tlv_malformed_payload_does_not_panic() {
        let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        // child type 1, claimed length 99 — exceeds buffer.
        buf.add_attribute(173, &[1, 99, 0, 0]).unwrap();
        let s = format!("{}", buf.dissect());
        assert!(s.contains("<malformed TLV"), "{s}");
    }
}
