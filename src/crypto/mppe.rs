//! `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key` attribute decryption
//! (RFC 2548 §2.4.3).
//!
//! The encryption side lives on the server reply builder
//! ([`crate::Reply::add_mppe_keys`]); this module provides the
//! authenticator-side inverse so consumers can harvest MPPE keys
//! from an Access-Accept without re-implementing the salted-MD5
//! chain.
//!
//! Wire layout of an MS-MPPE-{Send,Recv}-Key attribute *value*
//! (i.e. the bytes inside the `Vendor-Specific` attribute, after
//! `Vendor-Id || Vendor-Type || Vendor-Length`):
//!
//! ```text
//! Salt (2)  ||  Encrypted-Key (N \u00d7 16, 1 \u2264 N \u2264 15)
//! ```
//!
//! The high bit of `Salt[0]` MUST be set (RFC 2548 §2.4.3). The
//! plaintext that the chain produces is `Length (1) || Key || Pad`
//! where `Length` is the inner key length and `Pad` rounds the
//! total to a 16-byte multiple.

use super::md5;
use super::ZeroizingBytes;

/// Errors returned by [`mppe_key_decrypt`].
#[derive(Debug, PartialEq, Eq)]
pub enum MppeError {
    /// Attribute value is shorter than the 2-byte salt plus one
    /// 16-byte ciphertext block.
    TooShort(usize),
    /// The high bit of the first salt byte was clear; the value is
    /// not a valid MPPE-encrypted key per RFC 2548 §2.4.3.
    BadSalt,
    /// Ciphertext (everything after the 2-byte salt) is not a
    /// non-zero multiple of 16 bytes.
    BadLength(usize),
    /// The decrypted inner length byte is larger than the available
    /// payload (ciphertext minus the 1-byte length prefix). Typically
    /// indicates a wrong shared secret or wrong Request Authenticator.
    BadInnerLength {
        /// Inner key length as decoded from the first plaintext byte.
        inner: usize,
        /// Bytes of plaintext available after the length byte.
        payload: usize,
    },
}

impl std::fmt::Display for MppeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "MPPE key value too short: {n} bytes"),
            Self::BadSalt => write!(f, "MPPE salt top bit not set"),
            Self::BadLength(n) => write!(f, "MPPE ciphertext length {n} is not a multiple of 16"),
            Self::BadInnerLength { inner, payload } => {
                write!(f, "MPPE inner length {inner} exceeds payload {payload}")
            }
        }
    }
}

impl std::error::Error for MppeError {}

/// Decrypt an `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key` attribute
/// value (RFC 2548 §2.4.3).
///
/// `value` is the raw attribute value as carried inside the
/// enclosing `Vendor-Specific` attribute — i.e. `salt (2) ||
/// ciphertext`, with no surrounding `Vendor-Id` / `Vendor-Type` /
/// `Vendor-Length` bytes. `request_authenticator` is the
/// Authenticator field of the *original Access-Request*, **not** the
/// reply's Response Authenticator.
///
/// The returned buffer is wrapped in [`ZeroizingBytes`] so the
/// cleartext key material is scrubbed on drop.
///
/// # Errors
///
/// See [`MppeError`].
pub fn mppe_key_decrypt(
    value: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<ZeroizingBytes, MppeError> {
    if value.len() < 2 + 16 {
        return Err(MppeError::TooShort(value.len()));
    }
    let salt = [value[0], value[1]];
    if salt[0] & 0x80 == 0 {
        return Err(MppeError::BadSalt);
    }
    let ciphertext = &value[2..];
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(MppeError::BadLength(ciphertext.len()));
    }

    // Decrypt into a scratch buffer that scrubs on drop: even the
    // padding bytes still hold key-derived plaintext until cleansed.
    let mut plaintext = ZeroizingBytes::new(vec![0u8; ciphertext.len()]);

    // First block seed: MD5(secret || request_authenticator || salt)
    // — byte-for-byte the construction used by Tunnel-Password
    // (RFC 2868 §3.5) and by `Reply::add_mppe_keys`.
    let first = {
        let mut ctx = md5::Md5::new();
        ctx.update(secret);
        ctx.update(request_authenticator);
        ctx.update(&salt);
        ctx.finalize()
    };
    {
        let pt = plaintext.as_mut_bytes();
        for j in 0..16 {
            pt[j] = ciphertext[j] ^ first[j];
        }
        let mut prev = [0u8; 16];
        prev.copy_from_slice(&ciphertext[0..16]);
        for i in 1..ciphertext.len() / 16 {
            let mut ctx = md5::Md5::new();
            ctx.update(secret);
            ctx.update(&prev);
            let b = ctx.finalize();
            let base = i * 16;
            for j in 0..16 {
                pt[base + j] = ciphertext[base + j] ^ b[j];
            }
            prev.copy_from_slice(&ciphertext[base..base + 16]);
        }
    }

    let inner = plaintext.as_bytes()[0] as usize;
    let payload = plaintext.as_bytes().len() - 1;
    if inner > payload {
        return Err(MppeError::BadInnerLength { inner, payload });
    }

    let mut out = vec![0u8; inner];
    out.copy_from_slice(&plaintext.as_bytes()[1..=inner]);
    Ok(ZeroizingBytes::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a synthetic MPPE attribute value by running the same
    // salted-MD5 chain `Reply::add_mppe_keys` uses (delegated to
    // `password::tunnel_password_encrypt`), then concatenating
    // `salt || ciphertext`. This is what one Microsoft VSA carries
    // in its value field.
    fn build_mppe_value(key: &[u8], secret: &[u8], req_auth: &[u8; 16]) -> Vec<u8> {
        let (salt, ct) = crate::crypto::password::tunnel_password_encrypt(key, secret, req_auth);
        let mut v = Vec::with_capacity(2 + ct.len());
        v.extend_from_slice(&salt);
        v.extend_from_slice(&ct);
        v
    }

    #[test]
    fn roundtrip_16_byte_key() {
        let secret = b"shared";
        let req_auth = [0x11u8; 16];
        let key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let value = build_mppe_value(&key, secret, &req_auth);
        let pt = mppe_key_decrypt(&value, secret, &req_auth).expect("decrypt");
        assert_eq!(pt.as_bytes(), key.as_slice());
    }

    #[test]
    fn roundtrip_32_byte_key() {
        let secret = b"another-secret";
        let req_auth = [0xa5u8; 16];
        let key = [0x42u8; 32];
        let value = build_mppe_value(&key, secret, &req_auth);
        let pt = mppe_key_decrypt(&value, secret, &req_auth).expect("decrypt");
        assert_eq!(pt.as_bytes(), key.as_slice());
    }

    #[test]
    fn rejects_short_value() {
        let req_auth = [0u8; 16];
        let err = mppe_key_decrypt(&[0x80, 0x00], b"s", &req_auth).unwrap_err();
        assert_eq!(err, MppeError::TooShort(2));
    }

    #[test]
    fn rejects_bad_salt() {
        let req_auth = [0u8; 16];
        // Salt high bit clear -> reject regardless of ciphertext.
        let mut v = vec![0x00, 0x01];
        v.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            mppe_key_decrypt(&v, b"s", &req_auth).unwrap_err(),
            MppeError::BadSalt
        );
    }

    #[test]
    fn rejects_unaligned_ciphertext() {
        let req_auth = [0u8; 16];
        let mut v = vec![0x80, 0x00];
        v.extend_from_slice(&[0u8; 15]);
        // 2 + 15 = 17 total; that's >= 18? No, 17 < 18, so TooShort wins.
        assert_eq!(
            mppe_key_decrypt(&v, b"s", &req_auth).unwrap_err(),
            MppeError::TooShort(17),
        );

        let mut v = vec![0x80, 0x00];
        v.extend_from_slice(&[0u8; 24]);
        assert_eq!(
            mppe_key_decrypt(&v, b"s", &req_auth).unwrap_err(),
            MppeError::BadLength(24),
        );
    }

    #[test]
    fn rejects_bad_inner_length() {
        // Craft a value whose first plaintext byte decodes to a
        // length larger than the remaining payload.
        let secret = b"s";
        let req_auth = [0u8; 16];
        let salt = [0x80u8, 0x00];
        // First block seed = MD5(secret || req_auth || salt).
        let mut ctx = md5::Md5::new();
        ctx.update(secret);
        ctx.update(&req_auth);
        ctx.update(&salt);
        let seed = ctx.finalize();
        // Make plaintext byte 0 = 0xff (>= 15 remaining bytes).
        let mut ct = [0u8; 16];
        ct[0] = 0xff ^ seed[0];
        ct[1..16].copy_from_slice(&seed[1..16]); // decrypts to zero
        let mut v = Vec::with_capacity(18);
        v.extend_from_slice(&salt);
        v.extend_from_slice(&ct);
        assert_eq!(
            mppe_key_decrypt(&v, secret, &req_auth).unwrap_err(),
            MppeError::BadInnerLength {
                inner: 0xff,
                payload: 15,
            },
        );
    }

    #[test]
    fn error_display_covers_every_variant() {
        for e in [
            MppeError::TooShort(7),
            MppeError::BadSalt,
            MppeError::BadLength(24),
            MppeError::BadInnerLength {
                inner: 99,
                payload: 15,
            },
        ] {
            // Just exercise Display; format is documentary.
            assert!(!e.to_string().is_empty());
        }
    }
}
