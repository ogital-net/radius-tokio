//! Message-Authenticator (RFC 3579 §3.2; attribute type 80) helpers.
//!
//! # Wire format
//!
//! ```text
//! Type    = 80
//! Length  = 18           (2-byte TLV header + 16-byte HMAC-MD5 tag)
//! Value   = HMAC-MD5(secret,
//!                    Code || Identifier || Length || RequestAuth ||
//!                    Attributes-with-MA-zeroed)
//! ```
//!
//! `RequestAuth` is the Authenticator field of the *paired*
//! Access-Request when verifying a reply, or the Authenticator field
//! of the packet itself when verifying a request (which is what
//! callers actually see in `packet[4..20]`).
//!
//! # Why we always emit it on replies
//!
//! Historically the Message-Authenticator was only mandated for
//! Access-Request packets carrying EAP and for Status-Server
//! exchanges. This crate makes it mandatory on every reply we encode
//! (Access-Accept/Reject/Challenge, Accounting-Response, CoA-ACK/NAK,
//! Disconnect-ACK/NAK). The reasoning:
//!
//! * It binds the response to the shared secret using HMAC, not just
//!   MD5(packet || secret) — defeating the `BlastRADIUS` class of
//!   collision attacks (CVE-2024-3596).
//! * It is forward-compatible with the deprecation timeline laid out
//!   in `draft-ietf-radext-deprecating-radius`, which moves toward
//!   *requiring* Message-Authenticator everywhere.
//! * The 18-byte cost is negligible relative to a packet budget of
//!   4 096 bytes.
//!
//! Receive-side, [`verify`] always validates the attribute when
//! present, regardless of whether the request also carries an
//! EAP-Message. The server's request pipeline rejects
//! Access-Request packets that *omit* the attribute by default,
//! per [`crate::server::Client::require_message_authenticator`];
//! a per-client opt-out
//! ([`crate::server::Client::allow_missing_message_authenticator`])
//! covers legacy NAS firmware that cannot emit it.

use crate::crypto::ct_eq;
use crate::crypto::hmac_md5::HmacMd5;

use super::header::MIN_PACKET_LEN;

/// RADIUS attribute type for Message-Authenticator (RFC 3579 §3.2).
pub const TYPE: u8 = 80;

/// Wire length byte: 2-byte TLV header + 16-byte HMAC-MD5 tag.
pub const TLV_LEN: u8 = 18;

/// Length of the HMAC-MD5 tag carried in the value field.
pub const VALUE_LEN: usize = 16;

/// Outcome of an inbound Message-Authenticator check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The packet does not carry a Message-Authenticator. Whether
    /// this is acceptable is a policy decision for the caller; the
    /// server's request pipeline can reject `Absent` for codes where
    /// the operator has chosen to require the attribute.
    Absent,
    /// Attribute present and the HMAC matched.
    Valid,
    /// Attribute present and the HMAC did not match. The packet must
    /// be silently discarded (RFC 3579 §3.2).
    Invalid,
}

/// Locate the Message-Authenticator attribute in the attribute region.
///
/// Returns the byte offset of the attribute's *value* (the 16-byte
/// HMAC tag) within the original packet — i.e., suitable for indexing
/// `packet`, not the attribute region — or `None` if no
/// well-formed Message-Authenticator slot is present.
///
/// The walk halts on the first malformed slot, just like
/// [`super::attributes::iter`]; a corrupt earlier attribute hides any
/// later Message-Authenticator from view.
///
/// # Duplicates
///
/// RFC 3579 §3.2 implicitly allows only one Message-Authenticator per
/// packet. This helper returns the *first* offset and ignores any
/// duplicates; the higher-level [`verify`] uses
/// [`count_value_offsets`] to reject packets that carry more than
/// one slot, matching the fail-closed policy `FreeRADIUS` adopted in
/// response to `BlastRADIUS` (CVE-2024-3596) follow-on hardening.
#[must_use]
pub fn find_value_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < MIN_PACKET_LEN {
        return None;
    }
    let mut offset = MIN_PACKET_LEN;
    while offset < packet.len() {
        let rest = &packet[offset..];
        if rest.len() < 2 {
            return None;
        }
        let len = rest[1] as usize;
        if len < 2 || len > rest.len() {
            return None;
        }
        if rest[0] == TYPE && rest[1] == TLV_LEN {
            return Some(offset + 2);
        }
        offset += len;
    }
    None
}

/// Count the number of Message-Authenticator slots in the packet.
///
/// Used by [`verify`] to enforce the "at most one" policy. Stops
/// counting at the first malformed slot, mirroring
/// [`find_value_offset`].
#[must_use]
pub fn count_value_offsets(packet: &[u8]) -> usize {
    if packet.len() < MIN_PACKET_LEN {
        return 0;
    }
    let mut count = 0usize;
    let mut offset = MIN_PACKET_LEN;
    while offset < packet.len() {
        let rest = &packet[offset..];
        if rest.len() < 2 {
            break;
        }
        let len = rest[1] as usize;
        if len < 2 || len > rest.len() {
            break;
        }
        if rest[0] == TYPE && rest[1] == TLV_LEN {
            count += 1;
        }
        offset += len;
    }
    count
}

/// Compute the Message-Authenticator HMAC over `packet`.
///
/// The packet's Length field must already reflect its final size. Any
/// existing Message-Authenticator slot is treated as if its value were
/// zeroed; bytes `4..20` are replaced by `request_authenticator` for
/// the duration of the hash.
///
/// Returns the 16-byte tag. Callers patch it into the slot themselves
/// via [`patch`] (encode path) or compare it with [`verify`] (receive
/// path).
#[must_use]
pub fn compute(packet: &[u8], request_authenticator: &[u8; 16], secret: &[u8]) -> [u8; 16] {
    debug_assert!(packet.len() >= MIN_PACKET_LEN);
    let mut hmac = HmacMd5::new(secret);
    // Code | Identifier | Length
    hmac.update(&packet[..4]);
    // Substituted authenticator field.
    hmac.update(request_authenticator);
    // Attributes, with the M-A slot's value zeroed.
    let attrs = &packet[MIN_PACKET_LEN..];
    let zeros = [0u8; VALUE_LEN];
    let mut rest = attrs;
    while !rest.is_empty() {
        // Bail safely on a malformed tail; we feed what we have so the
        // result is still defined, but walking further would index
        // out of bounds.
        if rest.len() < 2 {
            hmac.update(rest);
            break;
        }
        let len = rest[1] as usize;
        if len < 2 || len > rest.len() {
            hmac.update(rest);
            break;
        }
        let (slot, after) = rest.split_at(len);
        if slot[0] == TYPE && slot.len() == TLV_LEN as usize {
            // type, length, then 16 zero bytes in place of the value.
            hmac.update(&slot[..2]);
            hmac.update(&zeros);
        } else {
            hmac.update(slot);
        }
        rest = after;
    }
    hmac.finalize()
}

/// Verify the Message-Authenticator on `packet`, if present.
///
/// `request_authenticator` is the value to substitute into the
/// `4..20` byte range during the hash. For inbound requests this is
/// the Authenticator field as-received (`packet[4..20]`); for inbound
/// replies it is the matching request's Authenticator.
///
/// A packet carrying more than one Message-Authenticator attribute
/// is rejected as [`Verification::Invalid`]. RFC 3579 §3.2 defines
/// the attribute as singular, and tolerating duplicates would let a
/// peer pad in a valid tag plus an arbitrary second slot whose
/// presence might confuse downstream attribute scanners.
#[must_use]
pub fn verify(packet: &[u8], request_authenticator: &[u8; 16], secret: &[u8]) -> Verification {
    match count_value_offsets(packet) {
        0 => return Verification::Absent,
        1 => {}
        _ => return Verification::Invalid,
    }
    let Some(offset) = find_value_offset(packet) else {
        return Verification::Absent;
    };
    let computed = compute(packet, request_authenticator, secret);
    if ct_eq(&packet[offset..offset + VALUE_LEN], &computed) {
        Verification::Valid
    } else {
        Verification::Invalid
    }
}

/// Append a zeroed Message-Authenticator slot to `packet` (the
/// encoder's first step). Returns the absolute offset of the value
/// field for [`patch`].
///
/// The packet's Length field is *not* updated here — the encoder does
/// that once all attributes are in place.
///
/// # Errors
///
/// Returns [`super::CodecError::PacketTooLarge`] if the slot would
/// push the packet past the 4 096-byte cap.
pub fn append_zeroed_slot(buf: &mut super::PacketBuffer) -> Result<usize, super::CodecError> {
    // Offset of the value bytes once `add_attribute` is done:
    // current end + 2 (TLV header).
    let value_offset = buf.as_bytes().len() + 2;
    buf.add_attribute(TYPE, &[0u8; VALUE_LEN])?;
    Ok(value_offset)
}

/// Overwrite the 16-byte HMAC tag at `value_offset` with `tag`.
pub fn patch(buf: &mut super::PacketBuffer, value_offset: usize, tag: &[u8; VALUE_LEN]) {
    let attrs = buf.attributes_mut();
    let local = value_offset - MIN_PACKET_LEN;
    attrs[local..local + VALUE_LEN].copy_from_slice(tag);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{header::Code, PacketBuffer};

    #[test]
    fn find_offset_locates_slot() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_attribute(1, b"x").unwrap();
        let value_off = append_zeroed_slot(&mut pkt).unwrap();
        pkt.patch_length();
        assert_eq!(find_value_offset(pkt.as_bytes()), Some(value_off));
    }

    #[test]
    fn find_offset_returns_none_when_absent() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 1);
        pkt.add_attribute(1, b"x").unwrap();
        pkt.patch_length();
        assert_eq!(find_value_offset(pkt.as_bytes()), None);
    }

    #[test]
    fn compute_then_verify_round_trip() {
        let secret = b"shared";
        let req_auth = [0x77; 16];
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 5);
        pkt.add_attribute(1, b"alice").unwrap();
        let value_off = append_zeroed_slot(&mut pkt).unwrap();
        pkt.patch_length();
        let tag = compute(pkt.as_bytes(), &req_auth, secret);
        patch(&mut pkt, value_off, &tag);
        assert_eq!(
            verify(pkt.as_bytes(), &req_auth, secret),
            Verification::Valid
        );
    }

    #[test]
    fn verify_detects_tampering() {
        let secret = b"shared";
        let req_auth = [0x77; 16];
        let mut pkt = PacketBuffer::new(Code::ACCESS_ACCEPT, 5);
        pkt.add_attribute(1, b"alice").unwrap();
        let value_off = append_zeroed_slot(&mut pkt).unwrap();
        pkt.patch_length();
        let tag = compute(pkt.as_bytes(), &req_auth, secret);
        patch(&mut pkt, value_off, &tag);
        // Flip a byte in the User-Name value.
        pkt.attributes_mut()[2] ^= 1;
        assert_eq!(
            verify(pkt.as_bytes(), &req_auth, secret),
            Verification::Invalid
        );
    }

    #[test]
    fn verify_reports_absent() {
        let mut pkt = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        pkt.add_attribute(1, b"bob").unwrap();
        pkt.patch_length();
        assert_eq!(
            verify(pkt.as_bytes(), &[0; 16], b"secret"),
            Verification::Absent,
        );
    }

    #[test]
    fn verify_rejects_duplicate_message_authenticator() {
        let secret = b"shared";
        let req_auth = [0x55; 16];
        let mut pkt = PacketBuffer::new(Code::ACCESS_REQUEST, 1);
        pkt.add_attribute(1, b"alice").unwrap();
        // Two zeroed M-A slots side by side. Even if a peer spent
        // the effort to compute a tag matching the first one, the
        // verifier must still refuse the packet.
        let value_off = append_zeroed_slot(&mut pkt).unwrap();
        let _second_off = append_zeroed_slot(&mut pkt).unwrap();
        pkt.patch_length();
        let tag = compute(pkt.as_bytes(), &req_auth, secret);
        patch(&mut pkt, value_off, &tag);
        assert_eq!(count_value_offsets(pkt.as_bytes()), 2);
        assert_eq!(
            verify(pkt.as_bytes(), &req_auth, secret),
            Verification::Invalid,
        );
    }
}
