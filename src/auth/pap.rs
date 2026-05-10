//! PAP (`User-Password`) verification — RFC 2865 §5.2.
//!
//! The NAS XOR-encrypts the user's cleartext password with a stream
//! derived from `MD5(secret || prev_block)`, seeded by the Request
//! Authenticator. Verification runs the same transform on the
//! *expected* password and compares the resulting ciphertexts in
//! constant time, which is faster than decrypting (one allocation
//! either way) and avoids leaking the decrypted plaintext into a
//! `Vec<u8>` we would have to scrub.

use crate::codec::attributes::AttributeError;
use crate::crypto::{ct_eq, password};
use crate::server::Request;

use super::VerifyOutcome;

/// RFC 2865 §5.2: User-Password attribute type.
const USER_PASSWORD_TYPE: u8 = 2;

/// Maximum cleartext password length the helper will encrypt for the
/// constant-time compare. Matches the RFC's 128-byte ciphertext cap.
const MAX_EXPECTED_LEN: usize = 128;

/// Verify a PAP credential against an expected cleartext password.
///
/// Returns:
///
/// * [`VerifyOutcome::Match`] / [`VerifyOutcome::Mismatch`] when the
///   `User-Password` attribute is present and well-formed.
/// * [`VerifyOutcome::Missing`] when no `User-Password` attribute is
///   present (the request is using some other auth scheme).
/// * [`VerifyOutcome::Malformed`] when the attribute is present but
///   carries an invalid length, or when the expected password exceeds
///   the 128-byte protocol limit.
///
/// The expected password is encrypted under the same secret +
/// authenticator and compared with the wire ciphertext via
/// `CRYPTO_memcmp`, so timing does not depend on which byte first
/// differs. Length-based timing is still observable: requests whose
/// ciphertext length differs from the encrypted expected length are
/// rejected before the compare. That is unavoidable without padding
/// every comparison to 128 bytes, which would obscure all length
/// information from logs as well.
///
/// # Errors
///
/// Forwards [`AttributeError`] if the attribute list is malformed
/// before the `User-Password` slot is reached.
pub fn verify(
    request: &Request<'_>,
    expected_password: &[u8],
) -> Result<VerifyOutcome, AttributeError> {
    if expected_password.len() > MAX_EXPECTED_LEN {
        return Ok(VerifyOutcome::Malformed);
    }
    let Some(raw) = request.first_raw(USER_PASSWORD_TYPE)? else {
        return Ok(VerifyOutcome::Missing);
    };
    let ciphertext = raw.value();
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || ciphertext.len() > MAX_EXPECTED_LEN {
        return Ok(VerifyOutcome::Malformed);
    }
    // Encrypt expected to match the on-wire length, then constant-time
    // compare. user_password_encrypt pads to a multiple of 16 (minimum
    // 16); if the ciphertext length differs from the expected length
    // it cannot match.
    let expected_ct = password::user_password_encrypt(
        expected_password,
        request.client().secret(),
        request.authenticator(),
    );
    if expected_ct.len() != ciphertext.len() {
        return Ok(VerifyOutcome::Mismatch);
    }
    Ok(if ct_eq(&expected_ct, ciphertext) {
        VerifyOutcome::Match
    } else {
        VerifyOutcome::Mismatch
    })
}

/// Decrypt the `User-Password` attribute and return the cleartext.
///
/// For consumers that need to forward the cleartext to an external
/// backend (LDAP simple bind, PAM, SQL `crypt(3)` compare, …) rather
/// than compare it locally. The returned [`ZeroizingBytes`] holds a
/// sensitive secret and scrubs the buffer with `OPENSSL_cleanse` on
/// drop, so callers should pass it onward without retaining copies
/// in `String`/`Vec<u8>` form that would outlive the wrapper.
///
/// [`ZeroizingBytes`]: crate::ZeroizingBytes
///
/// Returns `Ok(None)` when the request carries no `User-Password`,
/// `Ok(Some(_))` on a successful decrypt.
///
/// # Errors
///
/// * [`PapError::Attribute`] — the attribute list could not be parsed.
/// * [`PapError::Malformed`] — `User-Password` length is not a non-zero
///   multiple of 16, or exceeds 128 bytes.
pub fn decrypt_user_password(
    request: &Request<'_>,
) -> Result<Option<crate::ZeroizingBytes>, PapError> {
    let raw = request
        .first_raw(USER_PASSWORD_TYPE)
        .map_err(PapError::Attribute)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let plain = password::user_password_decrypt(
        raw.value(),
        request.client().secret(),
        request.authenticator(),
    )
    .map_err(|_| PapError::Malformed)?;
    Ok(Some(plain))
}

/// Errors returned by [`decrypt_user_password`].
#[derive(Debug)]
pub enum PapError {
    /// The attribute list could not be parsed up to the
    /// `User-Password` slot.
    Attribute(AttributeError),
    /// The `User-Password` value field is not a non-zero multiple of
    /// 16 bytes, or exceeds the 128-byte protocol cap.
    Malformed,
}

impl std::fmt::Display for PapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PapError::Attribute(e) => write!(f, "attribute parse: {e}"),
            PapError::Malformed => f.write_str("malformed User-Password ciphertext"),
        }
    }
}

impl std::error::Error for PapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PapError::Attribute(e) => Some(e),
            PapError::Malformed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::server::Client;
    use std::sync::Arc;

    // RFC 2865 §7.1 KAT.
    const SECRET: &[u8] = b"xyzzy5461";
    const AUTH: [u8; 16] = [
        0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb, 0x98, 0xf4, 0x22,
        0x7a,
    ];
    const PASSWORD: &[u8] = b"arctangent";
    const CIPHERTEXT: [u8; 16] = [
        0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a, 0x0a,
        0xee,
    ];

    fn build_request<'a>(client: &'a Arc<Client>, attrs: &'a [u8]) -> Request<'a> {
        Request::new(
            Code::ACCESS_REQUEST,
            7,
            AUTH,
            attrs,
            client,
            "127.0.0.1:1812".parse().unwrap(),
        )
    }

    fn user_password_attr(ciphertext: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + ciphertext.len());
        v.push(USER_PASSWORD_TYPE);
        // SAFETY of cast: ciphertext.len() <= 128 in tests, fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        v.push((ciphertext.len() + 2) as u8);
        v.extend_from_slice(ciphertext);
        v
    }

    #[test]
    fn verify_match() {
        let client = Arc::new(Client::new(SECRET));
        let attrs = user_password_attr(&CIPHERTEXT);
        let req = build_request(&client, &attrs);
        assert_eq!(verify(&req, PASSWORD).unwrap(), VerifyOutcome::Match);
    }

    #[test]
    fn verify_mismatch() {
        let client = Arc::new(Client::new(SECRET));
        let attrs = user_password_attr(&CIPHERTEXT);
        let req = build_request(&client, &attrs);
        assert_eq!(
            verify(&req, b"wrong-password").unwrap(),
            VerifyOutcome::Mismatch,
        );
    }

    #[test]
    fn verify_missing() {
        let client = Arc::new(Client::new(SECRET));
        let req = build_request(&client, &[]);
        assert_eq!(verify(&req, PASSWORD).unwrap(), VerifyOutcome::Missing);
    }

    #[test]
    fn verify_malformed_length() {
        let client = Arc::new(Client::new(SECRET));
        // Ciphertext that is not a multiple of 16 bytes.
        let attrs = user_password_attr(&[0u8; 8]);
        let req = build_request(&client, &attrs);
        assert_eq!(verify(&req, PASSWORD).unwrap(), VerifyOutcome::Malformed,);
    }

    #[test]
    fn verify_expected_too_long() {
        let client = Arc::new(Client::new(SECRET));
        let attrs = user_password_attr(&CIPHERTEXT);
        let req = build_request(&client, &attrs);
        assert_eq!(
            verify(&req, &[b'x'; 129]).unwrap(),
            VerifyOutcome::Malformed,
        );
    }

    #[test]
    fn decrypt_round_trip() {
        let client = Arc::new(Client::new(SECRET));
        let attrs = user_password_attr(&CIPHERTEXT);
        let req = build_request(&client, &attrs);
        let plain = decrypt_user_password(&req).unwrap().expect("present");
        assert_eq!(plain.as_bytes(), PASSWORD);
    }

    #[test]
    fn decrypt_missing_returns_none() {
        let client = Arc::new(Client::new(SECRET));
        let req = build_request(&client, &[]);
        assert!(decrypt_user_password(&req).unwrap().is_none());
    }

    #[test]
    fn decrypt_malformed_returns_error() {
        let client = Arc::new(Client::new(SECRET));
        let attrs = user_password_attr(&[0u8; 8]);
        let req = build_request(&client, &attrs);
        assert!(matches!(
            decrypt_user_password(&req),
            Err(PapError::Malformed),
        ));
    }
}
