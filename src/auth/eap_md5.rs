//! EAP-MD5-Challenge helpers (RFC 3748 §5.4).
//!
//! EAP-MD5 reuses the PPP CHAP algorithm of RFC 1994: the response is
//! `MD5(eap_identifier || password || challenge)`, where
//! `eap_identifier` is the single-byte `Identifier` field copied from
//! the EAP-Request that carried the challenge.
//!
//! Full EAP method termination is an explicit non-goal of this
//! library (see `CLAUDE.md`); the codec relays `EAP-Message`
//! attributes and this module exposes the raw computation needed by
//! consumers that wish to terminate EAP-MD5 in their handler. The
//! state machine — issuing the request, tracking the `State`
//! attribute, etc. — is the consumer's responsibility.
//!
//! No shared-secret obfuscation: the password is hashed directly. The
//! [`Client`](crate::server::Client) shared secret is therefore
//! unused by these helpers.
//!
//! # Example
//!
//! ```
//! use radius_tokio::auth::eap_md5;
//!
//! let challenge = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
//! let response = eap_md5::challenge_response(7, b"hunter2", challenge);
//! assert!(eap_md5::verify_response(7, b"hunter2", challenge, &response));
//! assert!(!eap_md5::verify_response(7, b"wrong", challenge, &response));
//! ```

use crate::crypto::{ct_eq, md5};

/// Length, in bytes, of the EAP-MD5 response value.
pub const RESPONSE_LEN: usize = 16;

/// Compute the EAP-MD5 response value `MD5(eap_id || password || challenge)`.
///
/// `eap_id` is the EAP `Identifier` byte from the Request that carried
/// the challenge (RFC 3748 §4.1). `password` is the cleartext shared
/// secret known to both peers. `challenge` is the random value sent in
/// the EAP-Request/MD5-Challenge `Value` field; RFC 3748 §5.4
/// recommends at least 16 bytes but does not mandate a fixed length.
#[must_use]
pub fn challenge_response(eap_id: u8, password: &[u8], challenge: &[u8]) -> [u8; RESPONSE_LEN] {
    let mut ctx = md5::Md5::new();
    ctx.update(&[eap_id]);
    ctx.update(password);
    ctx.update(challenge);
    ctx.finalize()
}

/// Constant-time check that `response` equals
/// `MD5(eap_id || password || challenge)`.
///
/// Returns `false` if the response does not match. Equivalent to
/// computing [`challenge_response`] and comparing with a constant-time
/// helper, but avoids ever materialising the expected value in a
/// caller-visible buffer.
#[must_use]
pub fn verify_response(
    eap_id: u8,
    password: &[u8],
    challenge: &[u8],
    response: &[u8; RESPONSE_LEN],
) -> bool {
    let expected = challenge_response(eap_id, password, challenge);
    ct_eq(&expected, response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_response_matches_manual_md5() {
        // Cross-check against an independent MD5 of the concatenation.
        let eap_id = 0x42u8;
        let password = b"hello123";
        let challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

        let mut concat = Vec::new();
        concat.push(eap_id);
        concat.extend_from_slice(password);
        concat.extend_from_slice(challenge);
        let expected = md5::digest(&concat);

        let got = challenge_response(eap_id, password, challenge);
        assert_eq!(got, expected);
    }

    #[test]
    fn verify_response_match_and_mismatch() {
        let eap_id = 7;
        let password = b"correct horse battery staple";
        let challenge = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        let resp = challenge_response(eap_id, password, challenge);
        assert!(verify_response(eap_id, password, challenge, &resp));

        let mut bad = resp;
        bad[0] ^= 0x01;
        assert!(!verify_response(eap_id, password, challenge, &bad));
        assert!(!verify_response(
            eap_id,
            b"wrong password",
            challenge,
            &resp
        ));
        assert!(!verify_response(
            eap_id.wrapping_add(1),
            password,
            challenge,
            &resp
        ));
    }

    #[test]
    fn empty_password_and_challenge_are_handled() {
        // Degenerate but well-defined: MD5 of a single identifier byte.
        let resp = challenge_response(0, b"", b"");
        let expected = md5::digest(&[0u8]);
        assert_eq!(resp, expected);
    }
}
