//! EAP-AKA / EAP-AKA' attribute (AT_*) TLV codec.
//!
//! RFC 4187 §8.1 — Attribute Format:
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  | Attribute Type|    Length     |          Value...           |
//! ```
//!
//! `Length` counts the whole TLV in 4-octet units (header included),
//! so the minimum is 1 (4 octets total — degenerate, value-less),
//! and the value field is always padded with zeros to a 4-octet
//! boundary. Attribute Type ≥ 128 marks the attribute *skippable*
//! per RFC 4187 §8.1; receivers ignore unknown skippable
//! attributes and reject unknown non-skippable ones.
//!
//! Only the attributes EAP-AKA' (RFC 5448) actually uses on the
//! wire for the basic non-pseudonym / non-re-auth flow are
//! handled here:
//!
//! | Code | Name                 | Notes                                |
//! |-----:|----------------------|--------------------------------------|
//! |  1   | `AT_RAND`            | 16-byte UMTS RAND                    |
//! |  2   | `AT_AUTN`            | 16-byte UMTS AUTN                    |
//! |  3   | `AT_RES`             | Variable-length, 4..=16 bytes        |
//! |  4   | `AT_AUTS`            | 14-byte resynch token                |
//! | 10   | `AT_PERMANENT_ID_REQ`| Identity-request marker              |
//! | 11   | `AT_MAC`             | 16-byte HMAC-SHA256-128 tag          |
//! | 14   | `AT_IDENTITY`        | Variable-length peer identity        |
//! | 22   | `AT_CLIENT_ERROR_CODE`| 2-byte error code                   |
//! | 23   | `AT_KDF_INPUT`       | Access-network name                  |
//! | 24   | `AT_KDF`             | 2-byte KDF identifier (= 1)          |
//!
//! Pseudonym (`AT_NEXT_PSEUDONYM`), fast-reauth
//! (`AT_NEXT_REAUTH_ID`, `AT_COUNTER`, …) and encrypted-blob
//! (`AT_ENCR_DATA`, `AT_IV`, `AT_PADDING`) attributes are not
//! emitted today; the receive side ignores them as skippable when
//! the high bit is set and rejects them otherwise.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)] // AT_* / RFC §… mentions in attribute docs.

/// `AT_RAND` — `Length` = 5 (20 octets total). Reserved(2)|RAND(16).
pub const AT_RAND: u8 = 1;
/// `AT_AUTN` — `Length` = 5 (20 octets total). Reserved(2)|AUTN(16).
pub const AT_AUTN: u8 = 2;
/// `AT_RES` — Reserved(2 bits)|RES-Length-in-bits(14 bits)|RES|pad.
pub const AT_RES: u8 = 3;
/// `AT_AUTS` — `Length` = 4 (16 octets). AUTS(14)|Padding(0) — AUTS
/// packs directly into the value slot with no 2-byte reserved
/// sub-header, see [`encode_auts`].
pub const AT_AUTS: u8 = 4;
/// `AT_PERMANENT_ID_REQ` — `Length` = 1. Reserved(2).
pub const AT_PERMANENT_ID_REQ: u8 = 10;
/// `AT_MAC` — `Length` = 5 (20 octets). Reserved(2)|MAC(16).
pub const AT_MAC: u8 = 11;
/// `AT_NOTIFICATION` — `Length` = 1. Reserved(2 bits)|Code(14 bits).
pub const AT_NOTIFICATION: u8 = 12;
/// `AT_ANY_ID_REQ` — `Length` = 1.
pub const AT_ANY_ID_REQ: u8 = 13;
/// `AT_IDENTITY` — Actual-Identity-Length(2)|Identity|pad.
pub const AT_IDENTITY: u8 = 14;
/// `AT_FULLAUTH_ID_REQ` — `Length` = 1.
pub const AT_FULLAUTH_ID_REQ: u8 = 17;
/// `AT_CLIENT_ERROR_CODE` — `Length` = 1. ClientErrorCode(2).
pub const AT_CLIENT_ERROR_CODE: u8 = 22;
/// `AT_KDF_INPUT` — Actual-Network-Name-Length(2)|NetworkName|pad
/// (RFC 5448 §3.1).
pub const AT_KDF_INPUT: u8 = 23;
/// `AT_KDF` — `Length` = 1. KDF identifier (2 octets, 0x0001 =
/// "EAP-AKA' with CK'/IK' per TS 33.402", RFC 5448 §3.2).
pub const AT_KDF: u8 = 24;

/// HMAC-SHA-256-128 truncated tag length used by `AT_MAC` (16 bytes).
pub const MAC_LEN: usize = 16;
/// UMTS RAND length (16 bytes).
pub const RAND_LEN: usize = 16;
/// UMTS AUTN length (16 bytes).
pub const AUTN_LEN: usize = 16;
/// UMTS AUTS length (14 bytes).
pub const AUTS_LEN: usize = 14;
/// Sole KDF identifier defined by RFC 5448 §3.2 (HMAC-SHA-256 over
/// CK'/IK' per 3GPP TS 33.402 Annex A).
pub const KDF_HMAC_SHA256: u16 = 1;

/// Error type for attribute parse / decode failures.
#[derive(Debug, Clone, Copy)]
pub enum AttrError {
    /// Attribute body is shorter than the declared `Length` field.
    Truncated,
    /// Declared `Length` is zero, which is illegal (the header
    /// itself takes one 4-octet word).
    ZeroLength,
    /// Encountered an unknown non-skippable attribute
    /// (`type < 128`). Per RFC 4187 §8.1 this is a hard error.
    UnknownNonSkippable(u8),
    /// Attribute value did not match the layout required for its
    /// type (e.g. AT_RAND with a wrong inner length, AT_MAC with a
    /// non-16-byte body).
    Malformed(&'static str),
}

impl std::fmt::Display for AttrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttrError::Truncated => f.write_str("EAP-AKA' attribute truncated"),
            AttrError::ZeroLength => f.write_str("EAP-AKA' attribute Length=0"),
            AttrError::UnknownNonSkippable(t) => {
                write!(f, "EAP-AKA' unknown non-skippable attribute type={t}")
            }
            AttrError::Malformed(what) => {
                write!(f, "EAP-AKA' malformed attribute: {what}")
            }
        }
    }
}

impl std::error::Error for AttrError {}

/// A single decoded attribute.
#[derive(Debug, Clone)]
pub struct Attr<'a> {
    /// The 1-byte attribute type code (one of the `AT_*` constants).
    pub typ: u8,
    /// The value portion *with* the leading 2-byte reserved /
    /// length field that some attributes use, as it appeared on
    /// the wire (i.e. the bytes after the 2-byte `Type|Length`
    /// header, including the standard 2-byte sub-header most
    /// attributes have). Length always matches `4 * Length - 2`.
    pub body: &'a [u8],
}

/// Iterator over the attribute list in a subtype payload.
///
/// Stops at end-of-buffer; surface errors are returned as `Err`
/// items that terminate the iteration.
pub struct AttrIter<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> AttrIter<'a> {
    /// Build an iterator over the attribute region of an EAP-AKA'
    /// payload (the bytes after the 4-byte
    /// `Subtype | Reserved(2)` header — i.e. exactly what
    /// [`crate::eap_aka_prime::subtype::parse`] hands you).
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            rest: buf,
            done: false,
        }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<Attr<'a>, AttrError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 2 {
            self.done = true;
            return Some(Err(AttrError::Truncated));
        }
        let typ = self.rest[0];
        let length_words = self.rest[1] as usize;
        if length_words == 0 {
            self.done = true;
            return Some(Err(AttrError::ZeroLength));
        }
        let total = length_words * 4;
        if self.rest.len() < total {
            self.done = true;
            return Some(Err(AttrError::Truncated));
        }
        let body = &self.rest[2..total];
        self.rest = &self.rest[total..];
        Some(Ok(Attr { typ, body }))
    }
}

// ── Encoders ───────────────────────────────────────────────────────

/// Append a 20-octet AT_RAND attribute.
pub fn encode_rand(out: &mut Vec<u8>, rand: &[u8; RAND_LEN]) {
    out.extend_from_slice(&[AT_RAND, 5, 0, 0]);
    out.extend_from_slice(rand);
}

/// Append a 20-octet AT_AUTN attribute.
pub fn encode_autn(out: &mut Vec<u8>, autn: &[u8; AUTN_LEN]) {
    out.extend_from_slice(&[AT_AUTN, 5, 0, 0]);
    out.extend_from_slice(autn);
}

/// Append an AT_AUTS attribute (16 octets: Type|Length|AUTS(14)).
/// AUTS does not have the 2-byte reserved sub-header — its 14
/// bytes pack directly into the value slot. RFC 4187 §10.5.
pub fn encode_auts(out: &mut Vec<u8>, auts: &[u8; AUTS_LEN]) {
    out.extend_from_slice(&[AT_AUTS, 4]);
    out.extend_from_slice(auts);
}

/// Append AT_MAC with a 16-byte zero placeholder. Returns the
/// offset of the start of the MAC value bytes within `out`, so the
/// caller can fill it in after computing HMAC-SHA-256-128 over the
/// finalised EAP packet with these 16 bytes set to zero.
pub fn encode_mac_placeholder(out: &mut Vec<u8>) -> usize {
    out.extend_from_slice(&[AT_MAC, 5, 0, 0]);
    let mac_offset = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    mac_offset
}

/// Append AT_PERMANENT_ID_REQ (`Length` = 1).
pub fn encode_permanent_id_req(out: &mut Vec<u8>) {
    out.extend_from_slice(&[AT_PERMANENT_ID_REQ, 1, 0, 0]);
}

/// Append AT_KDF (`Length` = 1, KDF id = 1).
pub fn encode_kdf(out: &mut Vec<u8>, kdf: u16) {
    out.extend_from_slice(&[AT_KDF, 1]);
    out.extend_from_slice(&kdf.to_be_bytes());
}

/// Append AT_KDF_INPUT carrying the access-network name. RFC 5448
/// §3.1: Actual-Length(2 bytes, big-endian) | NetworkName | zero
/// padding to a 4-octet boundary. Total TLV padded to 4-octet
/// alignment via the `Length` field.
///
/// # Panics
///
/// Panics if `name.len()` exceeds 65535 bytes (the
/// Actual-Length field is 2 bytes) or if the encoded attribute
/// would exceed 255 × 4 = 1020 octets.
pub fn encode_kdf_input(out: &mut Vec<u8>, name: &[u8]) {
    let actual = u16::try_from(name.len()).expect("network name fits in u16");
    // Header(2) + Actual-Length(2) + name + pad-to-4
    let unpadded = 2 + 2 + name.len();
    let padded = unpadded.div_ceil(4) * 4;
    let length_words = padded / 4;
    let length_words_u8 = u8::try_from(length_words).expect("AT_KDF_INPUT fits in u8 length field");
    out.extend_from_slice(&[AT_KDF_INPUT, length_words_u8]);
    out.extend_from_slice(&actual.to_be_bytes());
    out.extend_from_slice(name);
    out.resize(out.len() + (padded - unpadded), 0);
}

// ── Decoders ───────────────────────────────────────────────────────

/// Extract a 16-byte RAND from an `AT_RAND` body
/// (`Reserved(2) | RAND(16)`).
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the body is not 18 bytes long.
pub fn decode_rand(body: &[u8]) -> Result<[u8; RAND_LEN], AttrError> {
    if body.len() != 2 + RAND_LEN {
        return Err(AttrError::Malformed("AT_RAND body length"));
    }
    let mut out = [0u8; RAND_LEN];
    out.copy_from_slice(&body[2..]);
    Ok(out)
}

/// Extract a 16-byte AUTN.
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the body is not 18 bytes long.
pub fn decode_autn(body: &[u8]) -> Result<[u8; AUTN_LEN], AttrError> {
    if body.len() != 2 + AUTN_LEN {
        return Err(AttrError::Malformed("AT_AUTN body length"));
    }
    let mut out = [0u8; AUTN_LEN];
    out.copy_from_slice(&body[2..]);
    Ok(out)
}

/// Extract a 16-byte MAC tag.
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the body is not 18 bytes long.
pub fn decode_mac(body: &[u8]) -> Result<[u8; MAC_LEN], AttrError> {
    if body.len() != 2 + MAC_LEN {
        return Err(AttrError::Malformed("AT_MAC body length"));
    }
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&body[2..]);
    Ok(out)
}

/// Extract a variable-length RES (32..=128 bits, in whole bytes).
///
/// Layout (RFC 4187 §10.6): `RES-Length(2 bytes, in bits) | RES |
/// padding`. The attribute's `Length` word also pads to the next
/// 4-octet boundary.
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the declared bit length is
/// not byte-aligned, falls outside 32..=128 bits, or overruns the
/// available body.
pub fn decode_res(body: &[u8]) -> Result<Vec<u8>, AttrError> {
    if body.len() < 2 {
        return Err(AttrError::Malformed("AT_RES too short"));
    }
    let bit_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if !(32..=128).contains(&bit_len) {
        return Err(AttrError::Malformed("AT_RES bit length out of range"));
    }
    if bit_len % 8 != 0 {
        return Err(AttrError::Malformed("AT_RES bit length not byte-aligned"));
    }
    let byte_len = bit_len / 8;
    if body.len() < 2 + byte_len {
        return Err(AttrError::Malformed("AT_RES body shorter than declared"));
    }
    Ok(body[2..2 + byte_len].to_vec())
}

/// Extract a variable-length AT_IDENTITY value.
///
/// Layout (RFC 4187 §10.1): `Actual-Length(2 bytes) | Identity |
/// padding`.
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the declared length
/// overruns the body.
pub fn decode_identity(body: &[u8]) -> Result<Vec<u8>, AttrError> {
    if body.len() < 2 {
        return Err(AttrError::Malformed("AT_IDENTITY too short"));
    }
    let actual = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + actual {
        return Err(AttrError::Malformed("AT_IDENTITY shorter than declared"));
    }
    Ok(body[2..2 + actual].to_vec())
}

/// Extract a 14-byte AUTS from an `AT_AUTS` body. AUTS packs
/// directly into the value (no 2-byte reserved sub-header).
///
/// # Errors
///
/// Returns [`AttrError::Malformed`] if the body is not 14 bytes long.
pub fn decode_auts(body: &[u8]) -> Result<[u8; AUTS_LEN], AttrError> {
    if body.len() != AUTS_LEN {
        return Err(AttrError::Malformed("AT_AUTS body length"));
    }
    let mut out = [0u8; AUTS_LEN];
    out.copy_from_slice(body);
    Ok(out)
}

/// Convenience: zero-out the 16-byte MAC value field inside a full
/// EAP packet so the MAC over the canonicalised packet can be
/// computed. `mac_value_offset` is what
/// [`encode_mac_placeholder`] returned, but biased by the offset
/// of the EAP-AKA' type-data region inside the surrounding EAP
/// packet (5 bytes: `Code|Identifier|Length(2)|Type`).
pub fn zero_mac_in_place(packet: &mut [u8], mac_value_offset: usize) {
    packet[mac_value_offset..mac_value_offset + MAC_LEN].fill(0);
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_rand_autn_mac() {
        let mut buf = Vec::new();
        let rand = [0x11u8; 16];
        let autn = [0x22u8; 16];
        encode_rand(&mut buf, &rand);
        encode_autn(&mut buf, &autn);
        let mac_off = encode_mac_placeholder(&mut buf);
        assert_eq!(mac_off + 16, buf.len());

        let mut iter = AttrIter::new(&buf);
        let a0 = iter.next().unwrap().unwrap();
        assert_eq!(a0.typ, AT_RAND);
        assert_eq!(decode_rand(a0.body).unwrap(), rand);
        let a1 = iter.next().unwrap().unwrap();
        assert_eq!(a1.typ, AT_AUTN);
        assert_eq!(decode_autn(a1.body).unwrap(), autn);
        let a2 = iter.next().unwrap().unwrap();
        assert_eq!(a2.typ, AT_MAC);
        assert_eq!(decode_mac(a2.body).unwrap(), [0u8; 16]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn roundtrip_kdf_input_and_kdf() {
        let mut buf = Vec::new();
        encode_kdf(&mut buf, KDF_HMAC_SHA256);
        encode_kdf_input(&mut buf, b"WLAN");
        // 4 byte KDF tlv + (header 2 + actual-len 2 + 4 byte name = 8) tlv
        assert_eq!(buf.len(), 4 + 8);

        let mut iter = AttrIter::new(&buf);
        let kdf = iter.next().unwrap().unwrap();
        assert_eq!(kdf.typ, AT_KDF);
        assert_eq!(u16::from_be_bytes([kdf.body[0], kdf.body[1]]), 1);

        let kin = iter.next().unwrap().unwrap();
        assert_eq!(kin.typ, AT_KDF_INPUT);
        let actual = u16::from_be_bytes([kin.body[0], kin.body[1]]) as usize;
        assert_eq!(actual, 4);
        assert_eq!(&kin.body[2..2 + actual], b"WLAN");
    }

    #[test]
    fn kdf_input_pads_to_four() {
        // 5-byte name → header 2 + actual 2 + name 5 = 9, padded to 12 → Length = 3
        let mut buf = Vec::new();
        encode_kdf_input(&mut buf, b"hello");
        assert_eq!(buf.len(), 12);
        assert_eq!(buf[1], 3);
        let attr = AttrIter::new(&buf).next().unwrap().unwrap();
        let actual = u16::from_be_bytes([attr.body[0], attr.body[1]]) as usize;
        assert_eq!(&attr.body[2..2 + actual], b"hello");
    }

    #[test]
    fn iter_rejects_zero_length() {
        let buf = [AT_RAND, 0, 0, 0];
        let mut iter = AttrIter::new(&buf);
        matches!(iter.next(), Some(Err(AttrError::ZeroLength)));
    }

    #[test]
    fn iter_rejects_truncated_header() {
        let buf = [AT_RAND];
        let mut iter = AttrIter::new(&buf);
        matches!(iter.next(), Some(Err(AttrError::Truncated)));
    }

    #[test]
    fn iter_rejects_truncated_body() {
        let buf = [AT_RAND, 5, 0, 0, 0xAA];
        let mut iter = AttrIter::new(&buf);
        matches!(iter.next(), Some(Err(AttrError::Truncated)));
    }

    #[test]
    fn decode_res_byte_aligned_64_bit() {
        // RES bit-length=64, value=8 bytes, header+pad = 12 octets, Length=3
        let mut buf = vec![AT_RES, 3];
        buf.extend_from_slice(&64u16.to_be_bytes());
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE]);
        let attr = AttrIter::new(&buf).next().unwrap().unwrap();
        let res = decode_res(attr.body).unwrap();
        assert_eq!(res, [0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE]);
    }

    #[test]
    fn decode_identity_roundtrip() {
        // Identity = "0123456789012345" (16 bytes, fits exactly)
        // header 2 + actual 2 + 16 = 20 → Length 5
        let mut buf = vec![AT_IDENTITY, 5];
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(b"0123456789012345");
        let attr = AttrIter::new(&buf).next().unwrap().unwrap();
        let ident = decode_identity(attr.body).unwrap();
        assert_eq!(ident, b"0123456789012345");
    }
}
