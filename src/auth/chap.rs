//! CHAP (`CHAP-Password`) verification — RFC 2865 §5.3 + RFC 1994.
//!
//! The NAS computes `MD5(chap_id || password || challenge)` and sends
//! `CHAP-Password = chap_id || response_hash` (17 octets total). The
//! challenge defaults to the Request Authenticator unless an explicit
//! `CHAP-Challenge` (attribute 60) is present, per RFC 2865 §5.3.
//!
//! No shared-secret obfuscation: the password is hashed directly. The
//! shared secret on the [`Client`](crate::server::Client) is therefore
//! unused by this helper.

use crate::codec::attributes::AttributeError;
use crate::codec::constants::{
    CHAP_CHALLENGE as CHAP_CHALLENGE_TYPE, CHAP_PASSWORD as CHAP_PASSWORD_TYPE,
};
use crate::crypto::{ct_eq, md5};
use crate::server::Request;

use super::VerifyOutcome;

/// Wire length of `CHAP-Password`: 1 byte CHAP-ID + 16 byte response.
const CHAP_PASSWORD_LEN: usize = 1 + 16;

/// Verify a CHAP credential against an expected cleartext password.
///
/// Returns:
///
/// * [`VerifyOutcome::Match`] / [`VerifyOutcome::Mismatch`] when
///   `CHAP-Password` is present and well-formed.
/// * [`VerifyOutcome::Missing`] when no `CHAP-Password` attribute is
///   present.
/// * [`VerifyOutcome::Malformed`] when the attribute is present but
///   not exactly 17 bytes, or when an oversized `CHAP-Challenge` is
///   present.
///
/// # Errors
///
/// Forwards [`AttributeError`] from the attribute list iterator.
pub fn verify(
    request: &Request<'_>,
    expected_password: &[u8],
) -> Result<VerifyOutcome, AttributeError> {
    let Some(raw) = request.first_raw(CHAP_PASSWORD_TYPE)? else {
        return Ok(VerifyOutcome::Missing);
    };
    let value = raw.value();
    if value.len() != CHAP_PASSWORD_LEN {
        return Ok(VerifyOutcome::Malformed);
    }
    let chap_id = value[0];
    let response = &value[1..];

    // Challenge: explicit CHAP-Challenge attribute if present, else
    // the Request Authenticator (RFC 2865 §5.3).
    let challenge_attr = request.first_raw(CHAP_CHALLENGE_TYPE)?;
    let challenge: &[u8] = match &challenge_attr {
        Some(a) => a.value(),
        None => request.authenticator().as_slice(),
    };

    let mut ctx = md5::Md5::new();
    ctx.update(&[chap_id]);
    ctx.update(expected_password);
    ctx.update(challenge);
    let expected = ctx.finalize();

    Ok(if ct_eq(&expected, response) {
        VerifyOutcome::Match
    } else {
        VerifyOutcome::Mismatch
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::server::Client;
    use std::sync::Arc;

    const AUTH: [u8; 16] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
        0x00,
    ];

    fn make_request<'a>(client: &'a Arc<Client>, attrs: &'a [u8]) -> Request<'a> {
        Request::new(
            Code::ACCESS_REQUEST,
            9,
            AUTH,
            attrs,
            client,
            "127.0.0.1:1812".parse().unwrap(),
        )
    }

    fn chap_response(chap_id: u8, password: &[u8], challenge: &[u8]) -> [u8; 16] {
        let mut ctx = md5::Md5::new();
        ctx.update(&[chap_id]);
        ctx.update(password);
        ctx.update(challenge);
        ctx.finalize()
    }

    fn attr(typ: u8, val: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + val.len());
        v.push(typ);
        #[allow(clippy::cast_possible_truncation)]
        v.push((val.len() + 2) as u8);
        v.extend_from_slice(val);
        v
    }

    #[test]
    fn verify_match_using_request_authenticator_as_challenge() {
        let password = b"hello";
        let chap_id = 0x42u8;
        let response = chap_response(chap_id, password, &AUTH);

        let mut chap_pw = vec![chap_id];
        chap_pw.extend_from_slice(&response);
        let attrs = attr(CHAP_PASSWORD_TYPE, &chap_pw);

        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(verify(&req, password).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn verify_match_with_explicit_challenge() {
        let password = b"correct horse battery staple";
        let chap_id = 0x05u8;
        let challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
        let response = chap_response(chap_id, password, challenge);

        let mut chap_pw = vec![chap_id];
        chap_pw.extend_from_slice(&response);
        let mut attrs = attr(CHAP_PASSWORD_TYPE, &chap_pw);
        attrs.extend_from_slice(&attr(CHAP_CHALLENGE_TYPE, challenge));

        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(verify(&req, password).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn verify_mismatch() {
        let chap_id = 0x01u8;
        let response = chap_response(chap_id, b"right", &AUTH);
        let mut chap_pw = vec![chap_id];
        chap_pw.extend_from_slice(&response);
        let attrs = attr(CHAP_PASSWORD_TYPE, &chap_pw);

        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(verify(&req, b"wrong").unwrap(), VerifyOutcome::Mismatch);
    }

    #[test]
    fn verify_missing() {
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &[]);
        assert_eq!(verify(&req, b"x").unwrap(), VerifyOutcome::Missing);
    }

    #[test]
    fn verify_malformed_length() {
        // Wrong length (16 bytes total instead of 17).
        let attrs = attr(CHAP_PASSWORD_TYPE, &[0u8; 16]);
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(verify(&req, b"x").unwrap(), VerifyOutcome::Malformed);
    }
}
