//! EAP-AKA / EAP-AKA' subtype header (RFC 4187 §8.1).
//!
//! The type-data of an EAP-AKA(') packet — i.e. everything after
//! the `Code | Identifier | Length | Type=AKA'` header parsed by
//! [`radius_tokio::eap`] — has the layout:
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |   Subtype     |           Reserved            |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |               Attribute List ...                              |
//! ```
//!
//! Reserved bytes MUST be zero on send and MUST be ignored on
//! receive (RFC 4187 §8.1).

/// AKA-Challenge — server sends `RAND|AUTN|KDF|KDF_INPUT|MAC`,
/// peer answers with `RES|MAC`.
pub const AKA_CHALLENGE: u8 = 1;
/// AKA-Authentication-Reject — peer rejects the AUTN
/// (impersonation suspected). Hard failure.
pub const AKA_AUTHENTICATION_REJECT: u8 = 2;
/// AKA-Synchronization-Failure — peer's USIM detected an SQN
/// out-of-range; AUTS carries resync info for the HSS.
pub const AKA_SYNCHRONIZATION_FAILURE: u8 = 4;
/// AKA-Identity — used for identity exchange when the outer
/// `EAP-Response/Identity` was anonymous (RFC 4187 §4.1.1).
pub const AKA_IDENTITY: u8 = 5;
/// AKA-Notification — server-to-peer notification carrying
/// `AT_NOTIFICATION` (success/failure post-hoc, RFC 4187 §9.10).
pub const AKA_NOTIFICATION: u8 = 12;
/// AKA-Reauthentication — fast re-auth path (not implemented).
pub const AKA_REAUTHENTICATION: u8 = 13;
/// AKA-Client-Error — peer-to-server error notification carrying
/// `AT_CLIENT_ERROR_CODE` (RFC 4187 §9.9).
pub const AKA_CLIENT_ERROR: u8 = 14;

/// Reason for a [`parse`] failure. Only one variant today; kept as
/// an enum so additional structured errors can be added without
/// breaking call sites.
#[derive(Debug, Clone, Copy)]
pub enum ParseError {
    /// Buffer shorter than the 3-byte subtype header.
    Truncated,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("EAP-AKA' subtype header truncated"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse the `Subtype | Reserved(2)` header from an EAP-AKA(')
/// type-data buffer, returning `(subtype, attribute_region)`.
///
/// # Errors
///
/// Returns [`ParseError::Truncated`] when the buffer is shorter
/// than the 3-byte header.
pub fn parse(buf: &[u8]) -> Result<(u8, &[u8]), ParseError> {
    if buf.len() < 3 {
        return Err(ParseError::Truncated);
    }
    Ok((buf[0], &buf[3..]))
}

/// Write the 3-byte subtype header into `out`, leaving the
/// attribute list to be appended by the caller.
pub fn write_header(out: &mut Vec<u8>, subtype: u8) {
    out.extend_from_slice(&[subtype, 0, 0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let mut buf = Vec::new();
        write_header(&mut buf, AKA_CHALLENGE);
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let (st, attrs) = parse(&buf).unwrap();
        assert_eq!(st, AKA_CHALLENGE);
        assert_eq!(attrs, &[0xAA, 0xBB]);
    }

    #[test]
    fn parse_rejects_short() {
        assert!(parse(&[1, 0]).is_err());
    }
}
