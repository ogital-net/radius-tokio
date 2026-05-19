//! RADIUS packet header parsing (RFC 2865 §3).
//!
//! The fixed header is the first 20 bytes of every RADIUS packet:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Code      |  Identifier   |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Authenticator                         |
//! |                            (16 bytes)                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Attributes ...
//! ```
//!
//! `Length` covers the full packet (header + attributes). Per RFC 2865:
//! "Octets outside the range of the Length field MUST be treated as
//! padding and ignored on reception", and packets shorter than the
//! claimed length "MUST be silently discarded".

use std::fmt;

/// Smallest legal RADIUS packet: a header with no attributes (RFC 2865 §3).
pub const MIN_PACKET_LEN: usize = 20;

/// Largest legal RADIUS packet (RFC 2865 §3). Both the wire length
/// field and any datagram we accept are bounded by this.
pub const MAX_PACKET_LEN: usize = 4096;

/// RADIUS message code (RFC 2865 §3 field "Code").
///
/// Modelled as a thin newtype around the wire byte so the parser stays
/// total: any value an NAS hands us round-trips without loss, and known
/// codes are exposed as associated constants for ergonomic matching.
///
/// ```ignore
/// match header.code {
///     Code::ACCESS_REQUEST => { /* … */ }
///     Code::ACCOUNTING_REQUEST => { /* … */ }
///     other => { /* unknown / unsupported */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Code(pub u8);

impl Code {
    /// `Access-Request` (RFC 2865 §4.1).
    pub const ACCESS_REQUEST: Code = Code(1);
    /// `Access-Accept` (RFC 2865 §4.2).
    pub const ACCESS_ACCEPT: Code = Code(2);
    /// `Access-Reject` (RFC 2865 §4.3).
    pub const ACCESS_REJECT: Code = Code(3);
    /// `Accounting-Request` (RFC 2866 §4.1).
    pub const ACCOUNTING_REQUEST: Code = Code(4);
    /// `Accounting-Response` (RFC 2866 §4.2).
    pub const ACCOUNTING_RESPONSE: Code = Code(5);
    /// `Access-Challenge` (RFC 2865 §4.4).
    pub const ACCESS_CHALLENGE: Code = Code(11);
    /// `Status-Server` (RFC 5997).
    pub const STATUS_SERVER: Code = Code(12);
    /// `Status-Client` (RFC 5997, experimental).
    pub const STATUS_CLIENT: Code = Code(13);
    /// `Disconnect-Request` (RFC 5176 §2.1).
    pub const DISCONNECT_REQUEST: Code = Code(40);
    /// `Disconnect-ACK` (RFC 5176 §2.1).
    pub const DISCONNECT_ACK: Code = Code(41);
    /// `Disconnect-NAK` (RFC 5176 §2.1).
    pub const DISCONNECT_NAK: Code = Code(42);
    /// `CoA-Request` (RFC 5176 §2.2).
    pub const COA_REQUEST: Code = Code(43);
    /// `CoA-ACK` (RFC 5176 §2.2).
    pub const COA_ACK: Code = Code(44);
    /// `CoA-NAK` (RFC 5176 §2.2).
    pub const COA_NAK: Code = Code(45);
}

impl Code {
    /// Human-readable name for known codes, e.g. `"Access-Request"`.
    /// Returns `"Unknown"` for codes the parser does not enumerate.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
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
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Code {
    /// Renders the RFC name when known, otherwise the decimal byte.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name();
        if name == "Unknown" {
            write!(f, "Code({})", self.0)
        } else {
            f.write_str(name)
        }
    }
}

/// Parsed view of the fixed 20-byte RADIUS header.
///
/// Owned (the authenticator is just 16 bytes; copying it is cheaper
/// than carrying a borrow through the call graph). Attribute payloads
/// stay in the source buffer and are walked separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Message type (RFC 2865 §3 "Code").
    pub code: Code,
    /// Request/response correlation byte (RFC 2865 §3 "Identifier").
    pub identifier: u8,
    /// Total packet length in octets — header + attributes — as carried
    /// on the wire. Guaranteed to satisfy `MIN_PACKET_LEN..=MAX_PACKET_LEN`.
    pub length: u16,
    /// 16-byte Request/Response Authenticator (RFC 2865 §3).
    pub authenticator: [u8; 16],
}

/// Reasons a candidate packet failed header validation.
///
/// Every variant corresponds to a "MUST silently discard" condition in
/// RFC 2865 §3; callers typically log + drop without a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// Fewer than [`MIN_PACKET_LEN`] bytes were received — no header
    /// could exist.
    TooShort {
        /// Number of bytes actually available.
        got: usize,
    },
    /// Length field is below the protocol minimum (20).
    LengthUnderflow {
        /// Length value as read from the wire.
        length: u16,
    },
    /// Length field is above the protocol maximum (4096).
    LengthOverflow {
        /// Length value as read from the wire.
        length: u16,
    },
    /// Length field claims more bytes than were actually received. The
    /// packet must be discarded; NAS retransmissions handle recovery.
    LengthExceedsBuffer {
        /// Length value as read from the wire.
        length: u16,
        /// Number of bytes actually available.
        got: usize,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::TooShort { got } => write!(
                f,
                "packet shorter than the {MIN_PACKET_LEN}-byte RADIUS header (got {got})",
            ),
            HeaderError::LengthUnderflow { length } => write!(
                f,
                "header length field {length} is below the {MIN_PACKET_LEN}-byte minimum",
            ),
            HeaderError::LengthOverflow { length } => write!(
                f,
                "header length field {length} exceeds the {MAX_PACKET_LEN}-byte maximum",
            ),
            HeaderError::LengthExceedsBuffer { length, got } => write!(
                f,
                "header length field {length} exceeds received bytes ({got})",
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

impl Header {
    /// Parse the fixed header out of a candidate datagram.
    ///
    /// Returns the parsed header *and* the attribute byte slice (the
    /// payload between byte 20 and the wire length, with any trailing
    /// padding already trimmed off — RFC 2865 §3 instructs us to
    /// ignore octets past the length field).
    ///
    /// # Errors
    ///
    /// See [`HeaderError`]. The function is total over input: any
    /// `bytes` slice either yields a header or a typed reason for
    /// rejection. No panics, no allocation.
    #[inline]
    #[allow(clippy::missing_panics_doc)] // cannot panic: slice is 16 bytes by construction
    pub fn parse(bytes: &[u8]) -> Result<(Header, &[u8]), HeaderError> {
        let fixed: &[u8; MIN_PACKET_LEN] = bytes
            .first_chunk::<MIN_PACKET_LEN>()
            .ok_or(HeaderError::TooShort { got: bytes.len() })?;

        let length = u16::from_be_bytes([fixed[2], fixed[3]]);
        let length_usize = length as usize;

        if length_usize < MIN_PACKET_LEN {
            return Err(HeaderError::LengthUnderflow { length });
        }
        if length_usize > MAX_PACKET_LEN {
            return Err(HeaderError::LengthOverflow { length });
        }
        if length_usize > bytes.len() {
            return Err(HeaderError::LengthExceedsBuffer {
                length,
                got: bytes.len(),
            });
        }

        // SAFETY: would-be unsafe avoided. `fixed[4..20]` is in-bounds
        // by construction of `first_chunk::<20>`.
        let authenticator: [u8; 16] = fixed[4..20].try_into().expect("slice is exactly 16 bytes");

        let header = Header {
            code: Code(fixed[0]),
            identifier: fixed[1],
            length,
            authenticator,
        };
        // Attribute bytes: header end (20) up to the declared length.
        // Anything past `length` is padding and is dropped here.
        let attrs = &bytes[MIN_PACKET_LEN..length_usize];
        Ok((header, attrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a valid header + payload of the requested total length.
    /// `len_field` lets a test override the on-wire length to provoke
    /// specific failures.
    fn build(code: u8, id: u8, len_field: u16, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total.max(MIN_PACKET_LEN)];
        v[0] = code;
        v[1] = id;
        v[2..4].copy_from_slice(&len_field.to_be_bytes());
        for (i, b) in v[4..20].iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap() + 0xa0;
        }
        v
    }

    #[test]
    fn parses_minimum_header() {
        let buf = build(1, 7, 20, 20);
        let (h, attrs) = Header::parse(&buf).unwrap();
        assert_eq!(h.code, Code::ACCESS_REQUEST);
        assert_eq!(h.identifier, 7);
        assert_eq!(h.length, 20);
        assert_eq!(h.authenticator[0], 0xa0);
        assert_eq!(h.authenticator[15], 0xaf);
        assert!(attrs.is_empty());
    }

    #[test]
    fn extracts_attribute_slice() {
        // 20-byte header + 4 bytes of attributes; length=24.
        let mut buf = build(4, 99, 24, 24);
        buf[20..24].copy_from_slice(&[1, 4, 0xde, 0xad]);
        let (h, attrs) = Header::parse(&buf).unwrap();
        assert_eq!(h.code, Code::ACCOUNTING_REQUEST);
        assert_eq!(attrs, &[1, 4, 0xde, 0xad]);
    }

    #[test]
    fn trims_trailing_padding() {
        // Wire length says 20; datagram delivered with 8 bytes of trailing
        // padding (UDP fillers, IP options, whatever). Padding is dropped.
        let buf = build(1, 1, 20, 28);
        let (h, attrs) = Header::parse(&buf).unwrap();
        assert_eq!(h.length, 20);
        assert!(attrs.is_empty());
    }

    #[test]
    fn rejects_short_datagram() {
        let buf = vec![0u8; 19];
        assert_eq!(
            Header::parse(&buf).unwrap_err(),
            HeaderError::TooShort { got: 19 },
        );
    }

    #[test]
    fn rejects_length_underflow() {
        let buf = build(1, 1, 19, 20);
        assert_eq!(
            Header::parse(&buf).unwrap_err(),
            HeaderError::LengthUnderflow { length: 19 },
        );
    }

    #[test]
    fn rejects_length_overflow() {
        let buf = build(1, 1, 4097, MAX_PACKET_LEN + 1);
        assert_eq!(
            Header::parse(&buf).unwrap_err(),
            HeaderError::LengthOverflow { length: 4097 },
        );
    }

    #[test]
    fn rejects_length_exceeding_buffer() {
        // Length field claims 100 but we only delivered 30 bytes.
        let buf = build(1, 1, 100, 30);
        assert_eq!(
            Header::parse(&buf).unwrap_err(),
            HeaderError::LengthExceedsBuffer {
                length: 100,
                got: 30
            },
        );
    }

    #[test]
    fn accepts_maximum_packet() {
        // length == 4096, datagram delivered exactly that long.
        let len = u16::try_from(MAX_PACKET_LEN).unwrap();
        let buf = build(1, 1, len, MAX_PACKET_LEN);
        let (h, attrs) = Header::parse(&buf).unwrap();
        assert_eq!(h.length as usize, MAX_PACKET_LEN);
        assert_eq!(attrs.len(), MAX_PACKET_LEN - MIN_PACKET_LEN);
    }

    #[test]
    fn unknown_code_round_trips() {
        let buf = build(0xff, 0, 20, 20);
        let (h, _) = Header::parse(&buf).unwrap();
        assert_eq!(h.code, Code(0xff));
        // No special equality with any named constant.
        assert_ne!(h.code, Code::ACCESS_REQUEST);
    }
}
