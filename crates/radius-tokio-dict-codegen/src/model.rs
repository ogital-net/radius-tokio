//! Data model produced by the [`super::parser`] and consumed by
//! [`super::codegen`]. Lives in its own file (instead of `mod.rs`) so
//! the consuming `build.rs` can pull just the model + parser + codegen
//! into a flat module tree without dragging in any `OUT_DIR`-dependent
//! generated tables.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

/// Parse error with the source location that produced it.
#[derive(Debug)]
pub struct Error {
    /// Path of the dictionary file the error came from, if known.
    pub file: Option<PathBuf>,
    /// 1-indexed line number within `file`.
    pub line: u32,
    /// Concrete cause.
    pub kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            Some(p) => write!(f, "{}:{}: {}", p.display(), self.line, self.kind),
            None => write!(f, "line {}: {}", self.line, self.kind),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Concrete cause of a [`Error`].
#[derive(Debug)]
pub enum ErrorKind {
    /// I/O failure reading or opening a dictionary file.
    Io(std::io::Error),
    /// Encountered an unknown directive keyword.
    UnknownDirective(String),
    /// A directive was given the wrong number of fields.
    BadArity {
        /// Directive name (`ATTRIBUTE`, `VALUE`, …).
        directive: &'static str,
        /// Number of fields required (minimum).
        expected: usize,
        /// Number of fields actually supplied.
        got: usize,
    },
    /// Failed to parse an integer (attribute number, vendor id, value, …).
    BadInteger(String),
    /// Failed to parse a dotted attribute OID.
    BadOid(String),
    /// Unrecognised type keyword in an `ATTRIBUTE` line.
    UnknownType(String),
    /// Unrecognised flag in an `ATTRIBUTE` line.
    UnknownFlag(String),
    /// `END-VENDOR` did not match the open `BEGIN-VENDOR`.
    VendorMismatch {
        /// Vendor name on the open `BEGIN-VENDOR`.
        opened: String,
        /// Name on the offending `END-VENDOR`.
        closed: String,
    },
    /// `END-VENDOR` with no matching `BEGIN-VENDOR`.
    UnmatchedEndVendor,
    /// `BEGIN-VENDOR` referencing an unknown vendor.
    UnknownVendor(String),
    /// `$INCLUDE` recursion exceeded the safety limit.
    IncludeTooDeep,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => write!(f, "I/O error: {e}"),
            ErrorKind::UnknownDirective(s) => write!(f, "unknown directive `{s}`"),
            ErrorKind::BadArity {
                directive,
                expected,
                got,
            } => write!(f, "{directive} needs at least {expected} fields, got {got}"),
            ErrorKind::BadInteger(s) => write!(f, "invalid integer `{s}`"),
            ErrorKind::BadOid(s) => write!(f, "invalid attribute OID `{s}`"),
            ErrorKind::UnknownType(s) => write!(f, "unknown attribute type `{s}`"),
            ErrorKind::UnknownFlag(s) => write!(f, "unknown attribute flag `{s}`"),
            ErrorKind::VendorMismatch { opened, closed } => write!(
                f,
                "END-VENDOR {closed} does not match open BEGIN-VENDOR {opened}"
            ),
            ErrorKind::UnmatchedEndVendor => write!(f, "END-VENDOR with no matching BEGIN-VENDOR"),
            ErrorKind::UnknownVendor(s) => write!(f, "unknown vendor `{s}`"),
            ErrorKind::IncludeTooDeep => write!(f, "$INCLUDE nesting too deep"),
        }
    }
}

/// RADIUS attribute data type, as named in dictionary files.
///
/// Names mirror the `FreeRADIUS` dictionary syntax and the data-type
/// terminology in RFC 6158 / RFC 8044. Codegen turns each variant into a
/// concrete encoder/decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl Type {
    /// Parse a dictionary type token. Visible to the parser (sibling
    /// module) only.
    pub(super) fn parse(token: &str) -> Result<Type, ErrorKind> {
        // `octets[N]` — fixed-length opaque field.
        if let Some(rest) = token.strip_prefix("octets[") {
            let n = rest
                .strip_suffix(']')
                .ok_or_else(|| ErrorKind::UnknownType(token.into()))?;
            let n: u16 = n.parse().map_err(|_| ErrorKind::BadInteger(n.into()))?;
            return Ok(Type::FixedOctets(n));
        }
        Ok(match token {
            "string" => Type::String,
            "octets" => Type::Octets,
            "ipaddr" => Type::Ipaddr,
            "ipv6addr" => Type::Ipv6addr,
            "ipv4prefix" => Type::Ipv4prefix,
            "ipv6prefix" => Type::Ipv6prefix,
            "byte" => Type::Byte,
            "short" => Type::Short,
            "integer" => Type::Integer,
            "integer64" => Type::Integer64,
            "signed" => Type::Signed,
            "date" => Type::Date,
            "ifid" => Type::Ifid,
            "ether" => Type::Ether,
            "abinary" => Type::Abinary,
            "tlv" => Type::Tlv,
            "vsa" => Type::Vsa,
            "evs" => Type::Evs,
            "extended" => Type::Extended,
            "long-extended" => Type::LongExtended,
            "struct" => Type::Struct,
            // `uint32` appears in some vendor dictionaries (e.g. Juniper);
            // semantically identical to `integer` (RFC 8044 §3.1).
            "uint32" => Type::Uint32,
            other => return Err(ErrorKind::UnknownType(other.into())),
        })
    }
}

/// Per-attribute flags parsed from the trailing flag list of an `ATTRIBUTE`
/// line. Multiple flags may be combined with commas.
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

/// Dotted attribute identifier such as `241.26.1`.
///
/// Top-level attributes have a single component. Sub-attributes (TLV
/// children, `extended`/`evs` children) carry the full path so codegen
/// can reconstruct the wire layout.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// First component — i.e. the top-level attribute number.
    #[must_use]
    pub fn root(&self) -> u32 {
        self.0[0]
    }

    /// `true` for nested attributes (length > 1).
    #[must_use]
    pub fn is_child(&self) -> bool {
        self.0.len() > 1
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for c in &self.0 {
            if !first {
                f.write_str(".")?;
            }
            write!(f, "{c}")?;
            first = false;
        }
        Ok(())
    }
}

/// Parsed `ATTRIBUTE` directive.
#[derive(Debug, Clone)]
pub struct Attribute {
    /// Attribute name as written (e.g. `User-Name`).
    pub name: String,
    /// Dotted attribute identifier within its namespace.
    pub oid: Oid,
    /// Vendor whose namespace this attribute lives in, if inside a
    /// `BEGIN-VENDOR` / `END-VENDOR` block.
    pub vendor: Option<u32>,
    /// Wire data type.
    pub typ: Type,
    /// Flag bag.
    pub flags: Flags,
}

/// Parsed `VALUE` directive — a named enumerator for an integer attribute.
#[derive(Debug, Clone)]
pub struct Value {
    /// Owning attribute name (e.g. `Service-Type`).
    pub attribute: String,
    /// Enumerator name (e.g. `Framed-User`).
    pub name: String,
    /// Enumerator number. Signed because `signed` attributes can hold
    /// negatives, even though the on-wire encoding is 32-bit.
    pub number: i64,
}

/// Parsed `VENDOR` directive.
#[derive(Debug, Clone)]
pub struct Vendor {
    /// Vendor name as written (e.g. `ADSL-Forum`).
    pub name: String,
    /// IANA Private Enterprise Number.
    pub id: u32,
    /// Bytes used for the vendor-attribute type field. Default 1.
    pub type_len: u8,
    /// Bytes used for the vendor-attribute length field. Default 1.
    pub length_len: u8,
    /// `c` flag from `format=t,l,c` — continuation bit present.
    pub has_continuation: bool,
}

/// Fully-parsed dictionary tree.
///
/// Structurally flat: the parser keeps source order so codegen output
/// can be deterministic. Lookup tables are built on the side for the
/// few cross-references the parser itself needs.
#[derive(Debug, Default, Clone)]
pub struct Dictionary {
    /// All `ATTRIBUTE` lines in source order across every included file.
    pub attributes: Vec<Attribute>,
    /// All `VALUE` lines in source order.
    pub values: Vec<Value>,
    /// All `VENDOR` lines in source order.
    pub vendors: Vec<Vendor>,
}

impl Dictionary {
    /// Build a vendor-name → vendor map.
    #[must_use]
    pub fn vendors_by_name(&self) -> BTreeMap<&str, &Vendor> {
        self.vendors.iter().map(|v| (v.name.as_str(), v)).collect()
    }

    /// Build a vendor-id → vendor map.
    #[must_use]
    pub fn vendors_by_id(&self) -> BTreeMap<u32, &Vendor> {
        self.vendors.iter().map(|v| (v.id, v)).collect()
    }
}
