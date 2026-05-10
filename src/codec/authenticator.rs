//! Request and Response Authenticator computation (RFC 2865 §3,
//! RFC 2866 §3, RFC 5176).
//!
//! Two formulas cover every code we care about:
//!
//! * **Random** — the Authenticator field of an outbound `Access-Request`
//!   is 16 cryptographically random bytes (RFC 2865 §3 "Request
//!   Authenticator").
//! * **`MD5(packet || secret)`** — every other authenticator (response
//!   authenticator for replies, request authenticator for
//!   Accounting-Request / CoA-Request / Disconnect-Request) is the MD5
//!   of the packet bytes (with a code-specific value substituted into
//!   the Authenticator field) concatenated with the shared secret:
//!
//!   - **Reply to a request:** substitute the request's Authenticator.
//!   - **Outbound `Accounting` / `CoA` / `Disconnect` request:** substitute
//!     16 zero bytes.
//!
//! The streaming MD5 wrapper in `crate::crypto::md5` lets us hash in
//! place without allocating a copy of the packet.

use crate::crypto::md5::Md5;
use crate::crypto::{ct_eq, rand};
use std::mem::MaybeUninit;

use super::header::MIN_PACKET_LEN;

/// 16 cryptographically random bytes for an outbound `Access-Request`.
#[must_use]
pub fn random_request_authenticator() -> [u8; 16] {
    let mut buf = [MaybeUninit::<u8>::uninit(); 16];
    rand::fill(&mut buf);
    // SAFETY: `rand::fill` initializes every byte.
    unsafe { std::mem::transmute::<[MaybeUninit<u8>; 16], [u8; 16]>(buf) }
}

/// Compute `MD5(Code || Identifier || Length || substitute || Attributes || Secret)`
/// where `substitute` is what should occupy bytes `4..20` of the
/// packet during the hash.
///
/// `packet` must already carry the final Code, Identifier, and Length
/// fields; the caller's job is to ensure those bytes are stable before
/// calling.
fn md5_with_substitute(packet: &[u8], substitute: &[u8; 16], secret: &[u8]) -> [u8; 16] {
    debug_assert!(packet.len() >= MIN_PACKET_LEN);
    let mut md5 = Md5::new();
    md5.update(&packet[..4]);
    md5.update(substitute);
    md5.update(&packet[MIN_PACKET_LEN..]);
    md5.update(secret);
    md5.finalize()
}

/// Compute the Response Authenticator for a reply (Access-Accept,
/// Access-Reject, Access-Challenge, Accounting-Response, CoA-ACK/NAK,
/// Disconnect-ACK/NAK).
///
/// The reply packet `packet` must have its Length field patched and
/// every attribute (including any zeroed `Message-Authenticator`
/// placeholder) already in place; the bytes at offset `4..20` are
/// ignored — `request_authenticator` is substituted in their place.
#[must_use]
pub fn compute_response(
    packet: &[u8],
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> [u8; 16] {
    md5_with_substitute(packet, request_authenticator, secret)
}

/// Verify the Response Authenticator on an inbound reply.
///
/// Compares the value carried in `packet[4..20]` against the freshly
/// computed authenticator using a constant-time check.
#[must_use]
pub fn verify_response(packet: &[u8], request_authenticator: &[u8; 16], secret: &[u8]) -> bool {
    if packet.len() < MIN_PACKET_LEN {
        return false;
    }
    let computed = compute_response(packet, request_authenticator, secret);
    ct_eq(&packet[4..MIN_PACKET_LEN], &computed)
}

/// Compute the request authenticator for an outbound Accounting,
/// `CoA`, or Disconnect request: `MD5(packet-with-zeros-in-4..20 || secret)`.
///
/// The same formula verifies an inbound request of these codes (the
/// authenticator field on the wire IS the result of this hash).
#[must_use]
pub fn compute_zeroed_request(packet: &[u8], secret: &[u8]) -> [u8; 16] {
    md5_with_substitute(packet, &[0; 16], secret)
}

/// Verify the Authenticator field of an inbound Accounting-Request,
/// CoA-Request, or Disconnect-Request.
///
/// `Access-Request` Authenticators are random and unverifiable on
/// their own; for those codes use a Message-Authenticator check
/// (see [`super::message_authenticator`]).
#[must_use]
pub fn verify_zeroed_request(packet: &[u8], secret: &[u8]) -> bool {
    if packet.len() < MIN_PACKET_LEN {
        return false;
    }
    let computed = compute_zeroed_request(packet, secret);
    ct_eq(&packet[4..MIN_PACKET_LEN], &computed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_packet(code: u8, id: u8, auth: [u8; 16], attrs: &[u8]) -> Vec<u8> {
        let total = MIN_PACKET_LEN + attrs.len();
        let mut v = Vec::with_capacity(total);
        v.push(code);
        v.push(id);
        v.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        v.extend_from_slice(&auth);
        v.extend_from_slice(attrs);
        v
    }

    #[test]
    fn random_authenticator_is_nonzero_and_varies() {
        let a = random_request_authenticator();
        let b = random_request_authenticator();
        assert_ne!(a, [0; 16]);
        assert_ne!(a, b, "two random calls must (almost surely) differ");
    }

    #[test]
    fn response_authenticator_verifies_round_trip() {
        let secret = b"secret";
        let req_auth = [0x42; 16];
        let mut reply = build_packet(2, 7, [0; 16], &[1, 4, 0xde, 0xad]);
        let auth = compute_response(&reply, &req_auth, secret);
        reply[4..MIN_PACKET_LEN].copy_from_slice(&auth);
        assert!(verify_response(&reply, &req_auth, secret));
    }

    #[test]
    fn response_authenticator_rejects_wrong_secret() {
        let req_auth = [0x42; 16];
        let mut reply = build_packet(2, 7, [0; 16], &[1, 4, 0xde, 0xad]);
        let auth = compute_response(&reply, &req_auth, b"correct");
        reply[4..MIN_PACKET_LEN].copy_from_slice(&auth);
        assert!(!verify_response(&reply, &req_auth, b"wrong"));
    }

    #[test]
    fn zeroed_request_round_trip_for_accounting() {
        let secret = b"shh";
        // Accounting-Request: code 4. Authenticator field on the wire
        // is the hash itself.
        let attrs = &[40, 6, 0, 0, 0, 1]; // Acct-Status-Type = Start
        let mut pkt = build_packet(4, 0, [0; 16], attrs);
        let auth = compute_zeroed_request(&pkt, secret);
        pkt[4..MIN_PACKET_LEN].copy_from_slice(&auth);
        assert!(verify_zeroed_request(&pkt, secret));
        // Tampering invalidates.
        pkt[MIN_PACKET_LEN] = 99;
        assert!(!verify_zeroed_request(&pkt, secret));
    }

    #[test]
    fn verify_handles_short_input() {
        assert!(!verify_response(&[0u8; 5], &[0; 16], b""));
        assert!(!verify_zeroed_request(&[0u8; 5], b""));
    }
}
