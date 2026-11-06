//! `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key` decryption (RFC 2548).
//!
//! The matching encoder is [`crate::Reply::add_mppe_keys`]. Pass only the
//! vendor attribute's value (`salt || ciphertext`), without the surrounding
//! Vendor-Id, Vendor-Type, or Vendor-Length fields.
//!
//! Decryption does not authenticate the ciphertext or reliably detect a wrong
//! secret. Only decrypt keys from an authenticated Access-Accept response.

use super::{password, ZeroizingBytes};

/// Errors returned by [`mppe_key_decrypt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MppeError {
    /// Value is shorter than a two-byte salt and one ciphertext block.
    TooShort(usize),
    /// The salt's most significant bit is not set.
    BadSalt,
    /// Ciphertext is not a multiple of 16 bytes or exceeds 240 bytes.
    BadLength(usize),
    /// The decrypted key length exceeds the available plaintext payload.
    InvalidKeyLength,
}

impl std::fmt::Display for MppeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(length) => write!(formatter, "MPPE key value too short: {length} bytes"),
            Self::BadSalt => formatter.write_str("MPPE salt top bit not set"),
            Self::BadLength(length) => write!(
                formatter,
                "MPPE ciphertext length {length} must be a multiple of 16, at most 240 bytes"
            ),
            Self::InvalidKeyLength => {
                formatter.write_str("MPPE key length exceeds decrypted payload")
            }
        }
    }
}

impl std::error::Error for MppeError {}

/// Decrypt one `MS-MPPE-Send-Key` or `MS-MPPE-Recv-Key` value.
///
/// `value` contains the two-byte salt followed by encrypted key blocks.
/// `request_authenticator` must come from the original Access-Request, not
/// the reply header. Client consumers can obtain it from
/// `client::Response::request_authenticator()`.
///
/// Use the exchange's shared secret (`b"radsec"` for RFC 6614). Plaintext
/// scratch storage and the returned key are scrubbed on drop. A successful
/// decrypt is not an integrity check; verify the response before calling.
///
/// # Errors
/// Returns [`MppeError`] for an invalid salt, ciphertext size, or embedded
/// key length. No allocation is made for invalid ciphertext sizes.
pub fn mppe_key_decrypt(
    value: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<ZeroizingBytes, MppeError> {
    if value.len() < 18 {
        return Err(MppeError::TooShort(value.len()));
    }
    if value[0] & 0x80 == 0 {
        return Err(MppeError::BadSalt);
    }
    let ciphertext = &value[2..];
    if ciphertext.len() % 16 != 0 || ciphertext.len() > 240 {
        return Err(MppeError::BadLength(ciphertext.len()));
    }
    password::tunnel_password_decrypt(
        ciphertext,
        secret,
        request_authenticator,
        [value[0], value[1]],
    )
    .map_err(|_| MppeError::InvalidKeyLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE_16: [u8; 34] = [
        0x80, 0x01, 0x95, 0x02, 0xea, 0x09, 0x75, 0xfa, 0x86, 0xf0, 0x34, 0x7c, 0x75, 0x63, 0x47,
        0x52, 0x7f, 0xdf, 0x69, 0xa2, 0xa2, 0xb4, 0xc8, 0x88, 0xc9, 0xd9, 0x73, 0xe2, 0xfa, 0xbc,
        0xac, 0x13, 0x30, 0xab,
    ];
    const VALUE_32: [u8; 50] = [
        0x80, 0x01, 0xa5, 0x02, 0xea, 0x09, 0x75, 0xfa, 0x86, 0xf0, 0x34, 0x7c, 0x75, 0x63, 0x47,
        0x52, 0x7f, 0xdf, 0xd2, 0x38, 0x36, 0x36, 0x5e, 0x4f, 0x83, 0x5c, 0x84, 0xf7, 0x70, 0x90,
        0x77, 0xf7, 0xc8, 0xc0, 0x62, 0x2a, 0xf6, 0x28, 0x3d, 0xdd, 0x4e, 0xba, 0x4a, 0x3e, 0x2e,
        0x56, 0xf7, 0x65, 0x8a, 0x79,
    ];

    #[test]
    fn decrypts_independent_known_answer_vectors() {
        for (value, length) in [(VALUE_16.as_slice(), 16u8), (VALUE_32.as_slice(), 32u8)] {
            let key = mppe_key_decrypt(value, b"shared", &[0x11; 16]).unwrap();
            assert_eq!(key.as_bytes(), (1..=length).collect::<Vec<_>>());
        }
    }

    #[test]
    fn roundtrips_key_lengths_and_preserves_zero_bytes() {
        for length in [0, 1, 15, 16, 31, 32, 239] {
            let mut key = vec![0x42; length];
            if let Some(last) = key.last_mut() {
                *last = 0;
            }
            let (salt, ciphertext) = password::tunnel_password_encrypt(&key, b"secret", &[5; 16]);
            let value = [salt.as_slice(), ciphertext.as_slice()].concat();
            let decrypted = mppe_key_decrypt(&value, b"secret", &[5; 16]).unwrap();
            assert_eq!(decrypted.as_bytes(), key);
        }
    }

    #[test]
    fn rejects_short_values() {
        for length in 0..18 {
            assert_eq!(
                mppe_key_decrypt(&vec![0; length], b"secret", &[0; 16]).unwrap_err(),
                MppeError::TooShort(length)
            );
        }
    }

    #[test]
    fn rejects_salt_without_high_bit() {
        let mut value = VALUE_16;
        value[0] &= 0x7f;
        assert_eq!(
            mppe_key_decrypt(&value, b"shared", &[0x11; 16]).unwrap_err(),
            MppeError::BadSalt
        );
    }

    #[test]
    fn rejects_unaligned_and_oversized_ciphertext() {
        for length in [17, 31, 241, 256, 4096] {
            let mut value = vec![0; length + 2];
            value[0] = 0x80;
            assert_eq!(
                mppe_key_decrypt(&value, b"secret", &[0; 16]).unwrap_err(),
                MppeError::BadLength(length)
            );
        }
    }

    #[test]
    fn rejects_key_length_exceeding_decrypted_payload() {
        let mut value = VALUE_16;
        value[2] ^= 16 ^ 0xff;
        assert_eq!(
            mppe_key_decrypt(&value, b"shared", &[0x11; 16]).unwrap_err(),
            MppeError::InvalidKeyLength
        );
    }

    #[test]
    fn errors_implement_display_and_error() {
        for error in [
            MppeError::TooShort(2),
            MppeError::BadSalt,
            MppeError::BadLength(17),
            MppeError::InvalidKeyLength,
        ] {
            assert_ne!(error.to_string(), "");
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
