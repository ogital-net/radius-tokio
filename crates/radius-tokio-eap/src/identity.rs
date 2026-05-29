//! Helpers for the universal `EAP-Identity` exchange (RFC 3748 §5.1).
//!
//! Most NASes send an Access-Request that already contains an
//! `EAP-Response/Identity` packet (the supplicant pre-empted the
//! Identity request locally). A few — or any handler that wants to
//! force a fresh identity round — issue `EAP-Request/Identity` and
//! wait for the peer's response.
//!
//! This module is a tiny convenience layer over
//! [`radius_tokio::eap::write_request`]/[`Packet::parse`]; it does
//! not own any state and is always compiled in.
//!
//! ```ignore
//! use radius_tokio_eap::identity;
//!
//! let mut buf = Vec::new();
//! identity::write_request(&mut buf, /* id */ 1, b"")?;
//! // ↑ pair with `Reply::add_eap_message(&buf)` on an Access-Challenge.
//! ```
//!
//! [`Packet::parse`]: radius_tokio::eap::Packet::parse

use radius_tokio::eap::{self, Packet, PacketError, Type};

use crate::Error;

/// Append an `EAP-Request/Identity` packet to `out`.
///
/// `display` is the optional displayable message the spec lets the
/// server attach (RFC 3748 §5.1) — for prompting on captive portals,
/// for instance. Pass `b""` to emit a bare prompt.
///
/// Returns the total number of bytes written (always
/// `5 + display.len()`), for symmetry with
/// [`radius_tokio::eap::write_request`].
///
/// # Errors
///
/// Forwards [`PacketError::PayloadTooLong`] from the underlying
/// encoder.
pub fn write_request(out: &mut Vec<u8>, id: u8, display: &[u8]) -> Result<u16, PacketError> {
    eap::write_request(out, id, Type::IDENTITY, display)
}

/// Borrowed identity bytes extracted from an `EAP-Response/Identity`
/// packet.
///
/// The slice borrows from the original EAP packet buffer; copy out
/// with [`Vec::from`] when you need to outlive that buffer (e.g. to
/// stash on the per-session record).
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    /// Raw identity bytes as the peer asserted them — typically a
    /// UTF-8 NAI of the shape `user@realm`, but the spec does not
    /// require any particular encoding.
    pub bytes: &'a [u8],
}

impl<'a> Identity<'a> {
    /// Try to decode `bytes` as UTF-8. Returns `None` for
    /// non-UTF-8 identities (which are legal per RFC 3748 §5.1 but
    /// rare in practice).
    #[must_use]
    pub fn as_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes).ok()
    }
}

/// Parse an `EAP-Response/Identity` packet and return the borrowed
/// identity bytes.
///
/// `eap_packet` is the *reassembled* EAP payload — typically the
/// output of [`radius_tokio::AttributesView::eap_message_into`].
///
/// # Errors
///
/// - [`Error::Eap`] when the buffer is not a parseable EAP packet.
/// - [`Error::Framing`] when the packet is not a Response/Identity
///   (wrong Code or wrong Type).
pub fn parse_response(eap_packet: &[u8]) -> Result<Identity<'_>, Error> {
    let pkt = Packet::parse(eap_packet).map_err(Error::Eap)?;
    if pkt.code() != eap::Code::RESPONSE {
        return Err(Error::Framing("EAP packet is not a Response"));
    }
    if pkt.typ() != Some(Type::IDENTITY) {
        return Err(Error::Framing("EAP Response is not Type=Identity"));
    }
    Ok(Identity {
        bytes: pkt.type_data(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_identity_request_response() {
        let mut buf = Vec::new();
        write_request(&mut buf, 7, b"login: ").unwrap();
        let pkt = Packet::parse(&buf).unwrap();
        assert_eq!(pkt.code(), eap::Code::REQUEST);
        assert_eq!(pkt.identifier(), 7);
        assert_eq!(pkt.typ(), Some(Type::IDENTITY));
        assert_eq!(pkt.type_data(), b"login: ");
    }

    #[test]
    fn parses_identity_response() {
        // Code=Response(2), Id=1, Length=10, Type=Identity(1), "alice"
        let bytes = [2u8, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e'];
        let id = parse_response(&bytes).unwrap();
        assert_eq!(id.bytes, b"alice");
        assert_eq!(id.as_str(), Some("alice"));
    }

    #[test]
    fn rejects_non_identity_response() {
        // Code=Response, Type=MD5-Challenge.
        let bytes = [2u8, 1, 0, 5, 4];
        let err = parse_response(&bytes).unwrap_err();
        assert!(matches!(err, Error::Framing(_)));
    }

    #[test]
    fn rejects_request() {
        let bytes = [1u8, 1, 0, 5, 1];
        let err = parse_response(&bytes).unwrap_err();
        assert!(matches!(err, Error::Framing(_)));
    }
}
