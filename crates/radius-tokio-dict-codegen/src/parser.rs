//! Dictionary file parser.
//!
//! Stateless line-based scanner that consumes `FreeRADIUS` dictionary
//! files. The parser is reentrant for `$INCLUDE` via the [`Loader`]
//! abstraction: production callers use [`FsLoader`] (filesystem); tests
//! use an in-memory map.
//!
//! Comments (`#` to end of line) and blank lines are ignored. Each
//! non-empty line is split on whitespace; the first token selects the
//! directive handler.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::{Attribute, Dictionary, Error, ErrorKind, Flags, Oid, Type, Value, Vendor};

/// Maximum `$INCLUDE` nesting depth. Picked to be far above any plausible
/// real dictionary tree (the `FreeRADIUS` root pulls in two levels) while
/// still bounding pathological cycles.
const MAX_INCLUDE_DEPTH: usize = 16;

/// File-fetching abstraction so the parser can be exercised without I/O.
///
/// `current` is the path of the file containing the `$INCLUDE` directive
/// (or the entry-point passed to [`Parser::parse`]); `target` is the
/// path written in the directive. Implementations resolve `target`
/// relative to `current` as appropriate.
pub trait Loader {
    /// Read a dictionary file. Returns the resolved path (used for
    /// error messages and to anchor further `$INCLUDE`s) and the file
    /// contents.
    ///
    /// # Errors
    /// Implementations may return any I/O error.
    fn load(&self, current: Option<&Path>, target: &Path) -> std::io::Result<(PathBuf, String)>;
}

/// Filesystem-backed [`Loader`] used at build time and in tests.
///
/// `$INCLUDE` paths are resolved relative to the directory of the
/// including file. The entry-point is opened verbatim.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsLoader;

impl Loader for FsLoader {
    fn load(&self, current: Option<&Path>, target: &Path) -> std::io::Result<(PathBuf, String)> {
        let resolved = match current.and_then(Path::parent) {
            Some(dir) if target.is_relative() => dir.join(target),
            _ => target.to_path_buf(),
        };
        let text = fs::read_to_string(&resolved)?;
        Ok((resolved, text))
    }
}

/// In-memory loader for tests. Maps a logical path to file contents;
/// `$INCLUDE` resolution joins on `/`.
#[derive(Debug, Default, Clone)]
pub struct MapLoader {
    /// Logical-path → file-contents map.
    pub files: HashMap<PathBuf, String>,
}

impl Loader for MapLoader {
    fn load(&self, current: Option<&Path>, target: &Path) -> std::io::Result<(PathBuf, String)> {
        let resolved = match current.and_then(Path::parent) {
            Some(dir) if target.is_relative() => dir.join(target),
            _ => target.to_path_buf(),
        };
        match self.files.get(&resolved) {
            Some(s) => Ok((resolved, s.clone())),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such dictionary in MapLoader: {}", resolved.display()),
            )),
        }
    }
}

/// Driver that walks a dictionary tree using a [`Loader`].
pub struct Parser<L: Loader> {
    loader: L,
}

impl<L: Loader> Parser<L> {
    /// Construct a parser over the given loader.
    pub fn new(loader: L) -> Self {
        Self { loader }
    }

    /// Parse the dictionary rooted at `entry`, following every
    /// `$INCLUDE` directive.
    ///
    /// # Errors
    /// Returns the first parse or I/O error encountered.
    pub fn parse(&self, entry: impl AsRef<Path>) -> Result<Dictionary, Error> {
        let mut state = State::default();
        self.parse_one(None, entry.as_ref(), &mut state, 0)?;
        Ok(state.dict)
    }

    fn parse_one(
        &self,
        from: Option<&Path>,
        target: &Path,
        state: &mut State,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(Error {
                file: from.map(Path::to_path_buf),
                line: 0,
                kind: ErrorKind::IncludeTooDeep,
            });
        }
        let (path, text) = self.loader.load(from, target).map_err(|e| Error {
            file: from.map(Path::to_path_buf),
            line: 0,
            kind: ErrorKind::Io(e),
        })?;
        for (lineno, raw) in text.lines().enumerate() {
            let lineno = u32::try_from(lineno + 1).unwrap_or(u32::MAX);
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            self.handle_line(line, &path, lineno, state, depth)
                .map_err(|kind| Error {
                    file: Some(path.clone()),
                    line: lineno,
                    kind,
                })?;
        }
        Ok(())
    }

    fn handle_line(
        &self,
        line: &str,
        path: &Path,
        lineno: u32,
        state: &mut State,
        depth: usize,
    ) -> Result<(), ErrorKind> {
        let mut fields = line.split_whitespace();
        let directive = fields.next().expect("non-empty after trim");
        let rest: Vec<&str> = fields.collect();
        match directive {
            "ATTRIBUTE" => parse_attribute(&rest, state),
            "VALUE" => parse_value(&rest, state),
            "VENDOR" => parse_vendor(&rest, state),
            "BEGIN-VENDOR" => parse_begin_vendor(&rest, state),
            "END-VENDOR" => parse_end_vendor(&rest, state),
            "$INCLUDE" => {
                if rest.len() != 1 {
                    return Err(ErrorKind::BadArity {
                        directive: "$INCLUDE",
                        expected: 1,
                        got: rest.len(),
                    });
                }
                self.parse_one(Some(path), Path::new(rest[0]), state, depth + 1)
                    .map_err(|e| {
                        // Bubble through the inner kind but tag the
                        // outer location so users see the include site.
                        let _ = lineno;
                        e.kind
                    })
            }
            other => Err(ErrorKind::UnknownDirective(other.into())),
        }
    }
}

/// Mutable state threaded through every line of every included file.
#[derive(Default)]
struct State {
    dict: Dictionary,
    /// Stack of currently open `BEGIN-VENDOR` blocks. Nested blocks
    /// aren't legal in `FreeRADIUS` but using a stack keeps the close
    /// handling symmetrical and lets us produce a useful error.
    vendor_stack: Vec<(String, u32)>,
}

impl State {
    fn current_vendor(&self) -> Option<u32> {
        self.vendor_stack.last().map(|(_, id)| *id)
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn parse_attribute(fields: &[&str], state: &mut State) -> Result<(), ErrorKind> {
    // ATTRIBUTE name oid type [flags]
    if fields.len() < 3 {
        return Err(ErrorKind::BadArity {
            directive: "ATTRIBUTE",
            expected: 3,
            got: fields.len(),
        });
    }
    let name = fields[0].to_owned();
    let oid = parse_oid(fields[1])?;
    let typ = Type::parse(fields[2])?;
    let flags = if fields.len() > 3 {
        parse_flags(&fields[3..])?
    } else {
        Flags::default()
    };
    state.dict.attributes.push(Attribute {
        name,
        oid,
        vendor: state.current_vendor(),
        typ,
        flags,
    });
    Ok(())
}

fn parse_value(fields: &[&str], state: &mut State) -> Result<(), ErrorKind> {
    // VALUE attribute name number
    if fields.len() < 3 {
        return Err(ErrorKind::BadArity {
            directive: "VALUE",
            expected: 3,
            got: fields.len(),
        });
    }
    let attribute = fields[0].to_owned();
    let name = fields[1].to_owned();
    let number = parse_signed(fields[2])?;
    state.dict.values.push(Value {
        attribute,
        name,
        number,
    });
    Ok(())
}

fn parse_vendor(fields: &[&str], state: &mut State) -> Result<(), ErrorKind> {
    // VENDOR name id [format=t,l[,c]]
    if fields.len() < 2 {
        return Err(ErrorKind::BadArity {
            directive: "VENDOR",
            expected: 2,
            got: fields.len(),
        });
    }
    let name = fields[0].to_owned();
    let id = parse_unsigned(fields[1])?;
    let id = u32::try_from(id).map_err(|_| ErrorKind::BadInteger(fields[1].into()))?;

    let mut type_len = 1u8;
    let mut length_len = 1u8;
    let mut has_continuation = false;
    if let Some(fmt) = fields.get(2) {
        let payload = fmt
            .strip_prefix("format=")
            .ok_or_else(|| ErrorKind::UnknownFlag((*fmt).into()))?;
        let mut parts = payload.split(',');
        type_len = parse_small_u8(parts.next().unwrap_or(""))?;
        length_len = parse_small_u8(parts.next().unwrap_or(""))?;
        if let Some(c) = parts.next() {
            // `c` flag is the only third-position value FreeRADIUS uses.
            if c != "c" {
                return Err(ErrorKind::UnknownFlag(c.into()));
            }
            has_continuation = true;
        }
    }

    state.dict.vendors.push(Vendor {
        name,
        id,
        type_len,
        length_len,
        has_continuation,
    });
    Ok(())
}

fn parse_begin_vendor(fields: &[&str], state: &mut State) -> Result<(), ErrorKind> {
    if fields.len() != 1 {
        return Err(ErrorKind::BadArity {
            directive: "BEGIN-VENDOR",
            expected: 1,
            got: fields.len(),
        });
    }
    let name = fields[0];
    let id = state
        .dict
        .vendors
        .iter()
        .find(|v| v.name == name)
        .map(|v| v.id)
        .ok_or_else(|| ErrorKind::UnknownVendor(name.into()))?;
    state.vendor_stack.push((name.to_owned(), id));
    Ok(())
}

fn parse_end_vendor(fields: &[&str], state: &mut State) -> Result<(), ErrorKind> {
    if fields.len() != 1 {
        return Err(ErrorKind::BadArity {
            directive: "END-VENDOR",
            expected: 1,
            got: fields.len(),
        });
    }
    let (open_name, _) = state
        .vendor_stack
        .pop()
        .ok_or(ErrorKind::UnmatchedEndVendor)?;
    if open_name != fields[0] {
        return Err(ErrorKind::VendorMismatch {
            opened: open_name,
            closed: fields[0].into(),
        });
    }
    Ok(())
}

fn parse_oid(s: &str) -> Result<Oid, ErrorKind> {
    let mut parts = Vec::with_capacity(2);
    for component in s.split('.') {
        if component.is_empty() {
            return Err(ErrorKind::BadOid(s.into()));
        }
        let n: u32 = component.parse().map_err(|_| ErrorKind::BadOid(s.into()))?;
        parts.push(n);
    }
    if parts.is_empty() {
        return Err(ErrorKind::BadOid(s.into()));
    }
    Ok(Oid(parts))
}

fn parse_flags(tokens: &[&str]) -> Result<Flags, ErrorKind> {
    let mut flags = Flags::default();
    // Flags may be split across multiple whitespace-separated tokens or
    // packed into a single comma-separated token (FreeRADIUS allows
    // both, e.g. `has_tag,encrypt=2`).
    for tok in tokens {
        for piece in tok.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            apply_flag(piece, &mut flags)?;
        }
    }
    Ok(flags)
}

fn apply_flag(piece: &str, flags: &mut Flags) -> Result<(), ErrorKind> {
    if let Some(n) = piece.strip_prefix("encrypt=") {
        let n: u8 = n.parse().map_err(|_| ErrorKind::BadInteger(n.into()))?;
        flags.encrypt = Some(n);
        return Ok(());
    }
    match piece {
        "has_tag" => flags.has_tag = true,
        "concat" => flags.concat = true,
        "array" => flags.array = true,
        "virtual" => flags.virtual_ = true,
        "internal" => flags.internal = true,
        "secret" => flags.secret = true,
        other => return Err(ErrorKind::UnknownFlag(other.into())),
    }
    Ok(())
}

fn parse_unsigned(s: &str) -> Result<u64, ErrorKind> {
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    v.map_err(|_| ErrorKind::BadInteger(s.into()))
}

fn parse_signed(s: &str) -> Result<i64, ErrorKind> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let n = u64::from_str_radix(hex, 16).map_err(|_| ErrorKind::BadInteger(s.into()))?;
        return i64::try_from(n).map_err(|_| ErrorKind::BadInteger(s.into()));
    }
    s.parse::<i64>()
        .map_err(|_| ErrorKind::BadInteger(s.into()))
}

fn parse_small_u8(s: &str) -> Result<u8, ErrorKind> {
    s.parse::<u8>().map_err(|_| ErrorKind::BadInteger(s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(text: &str) -> Result<Dictionary, Error> {
        let mut files = HashMap::new();
        files.insert(PathBuf::from("dict"), text.to_owned());
        Parser::new(MapLoader { files }).parse("dict")
    }

    #[test]
    fn simple_attribute() {
        let d = parse_str("ATTRIBUTE User-Name 1 string\n").unwrap();
        assert_eq!(d.attributes.len(), 1);
        let a = &d.attributes[0];
        assert_eq!(a.name, "User-Name");
        assert_eq!(a.oid.root(), 1);
        assert_eq!(a.typ, Type::String);
        assert_eq!(a.vendor, None);
        assert!(!a.flags.has_tag);
    }

    #[test]
    fn flags_split_and_combined() {
        let d = parse_str(
            "ATTRIBUTE A 1 string encrypt=1\n\
             ATTRIBUTE B 2 string has_tag,encrypt=2\n\
             ATTRIBUTE C 3 octets secret\n",
        )
        .unwrap();
        assert_eq!(d.attributes[0].flags.encrypt, Some(1));
        assert!(d.attributes[1].flags.has_tag);
        assert_eq!(d.attributes[1].flags.encrypt, Some(2));
        assert!(d.attributes[2].flags.secret);
    }

    #[test]
    fn fixed_octets_length() {
        let d = parse_str("ATTRIBUTE Mac 1 octets[6]\n").unwrap();
        assert_eq!(d.attributes[0].typ, Type::FixedOctets(6));
    }

    #[test]
    fn comments_and_blank_lines() {
        let d = parse_str(
            "# header\n\
             \n\
             ATTRIBUTE A 1 integer  # trailing\n\
             # ATTRIBUTE B 2 string\n",
        )
        .unwrap();
        assert_eq!(d.attributes.len(), 1);
        assert_eq!(d.attributes[0].name, "A");
    }

    #[test]
    fn value_directive() {
        let d = parse_str(
            "ATTRIBUTE Service-Type 6 integer\n\
             VALUE Service-Type Login-User 1\n\
             VALUE Service-Type Framed-User 2\n",
        )
        .unwrap();
        assert_eq!(d.values.len(), 2);
        assert_eq!(d.values[0].attribute, "Service-Type");
        assert_eq!(d.values[0].name, "Login-User");
        assert_eq!(d.values[0].number, 1);
        assert_eq!(d.values[1].number, 2);
    }

    #[test]
    fn vendor_block() {
        let d = parse_str(
            "VENDOR ADSL-Forum 3561\n\
             BEGIN-VENDOR ADSL-Forum\n\
             ATTRIBUTE ADSL-Agent-Circuit-Id 1 octets\n\
             END-VENDOR ADSL-Forum\n\
             ATTRIBUTE Outside 99 string\n",
        )
        .unwrap();
        assert_eq!(d.vendors.len(), 1);
        assert_eq!(d.vendors[0].id, 3561);
        assert_eq!(d.attributes[0].vendor, Some(3561));
        assert_eq!(d.attributes[1].vendor, None);
    }

    #[test]
    fn vendor_format_directive() {
        let d = parse_str("VENDOR USR 429 format=4,0,c\n").unwrap();
        let v = &d.vendors[0];
        assert_eq!(v.type_len, 4);
        assert_eq!(v.length_len, 0);
        assert!(v.has_continuation);
    }

    #[test]
    fn dotted_oid_for_extended() {
        let d = parse_str("ATTRIBUTE Extended-Vendor-Specific-1 241.26 evs\n").unwrap();
        assert_eq!(d.attributes[0].oid.0, vec![241, 26]);
        assert!(d.attributes[0].oid.is_child());
    }

    #[test]
    fn end_vendor_mismatch_is_error() {
        let err = parse_str(
            "VENDOR A 1\n\
             VENDOR B 2\n\
             BEGIN-VENDOR A\n\
             END-VENDOR B\n",
        )
        .unwrap_err();
        assert!(matches!(err.kind, ErrorKind::VendorMismatch { .. }));
    }

    #[test]
    fn unmatched_end_vendor_is_error() {
        let err = parse_str("END-VENDOR Whatever\n").unwrap_err();
        assert!(matches!(err.kind, ErrorKind::UnmatchedEndVendor));
    }

    #[test]
    fn unknown_type_is_error() {
        let err = parse_str("ATTRIBUTE A 1 floaty\n").unwrap_err();
        assert!(matches!(err.kind, ErrorKind::UnknownType(_)));
    }

    #[test]
    fn unknown_flag_is_error() {
        let err = parse_str("ATTRIBUTE A 1 string wat\n").unwrap_err();
        assert!(matches!(err.kind, ErrorKind::UnknownFlag(_)));
    }

    #[test]
    fn include_resolves_relative() {
        let mut files = HashMap::new();
        files.insert(
            PathBuf::from("root/dict"),
            "$INCLUDE child\nATTRIBUTE Top 1 string\n".to_owned(),
        );
        files.insert(
            PathBuf::from("root/child"),
            "ATTRIBUTE Inner 2 integer\n".to_owned(),
        );
        let d = Parser::new(MapLoader { files }).parse("root/dict").unwrap();
        // Includes are processed in source order — child first.
        assert_eq!(d.attributes[0].name, "Inner");
        assert_eq!(d.attributes[1].name, "Top");
    }

    // Full-tree tests against the vendored FreeRADIUS dictionaries live in
    // `radius-tokio-dict` (which owns the `dictionaries/` directory). See
    // `crates/radius-tokio-dict/src/lib.rs` `#[cfg(test)]` section.
    //
    // NOTE: tests below this line were moved to radius-tokio-dict to avoid a
    // path-dependency on the dictionaries directory from this build-only crate.

    #[test]
    #[ignore = "dictionary files live in radius-tokio-dict; run from that crate"]
    fn parses_full_vendored_rfc_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("dictionaries")
            .join("rfc")
            .join("dictionary");
        let dict = Parser::new(FsLoader).parse(&root).unwrap_or_else(|e| {
            panic!("vendored dictionary failed to parse: {e}");
        });
        // Sanity: pull a few well-known attributes.
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

        // Vendor block from RFC 4679 should have produced a vendor and
        // tagged its attributes with vendor id 3561.
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
    #[ignore = "dictionary files live in radius-tokio-dict; run from that crate"]
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
        let recv_secret = by_name
            .get("Ascend-Receive-Secret")
            .expect("Ascend-Receive-Secret");
        assert_eq!(recv_secret.flags.encrypt, Some(3));

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
