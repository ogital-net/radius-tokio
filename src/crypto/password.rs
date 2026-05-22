//! Password attribute encryption helpers (RFC 2865 §5.2, RFC 2868 §3.5).
//!
//! Both schemes use chained MD5 to XOR-encrypt 16-byte blocks. Tunnel-Password
//! differs by prepending a 1-byte length field to the plaintext and seeding
//! the first block hash with a 2-byte salt.

use super::md5;

/// Max plaintext length for User-Password (RFC 2865 §5.2).
const USER_PASSWORD_MAX: usize = 128;

/// Max ciphertext length for Tunnel-Password given a single RADIUS attribute.
/// Value field = 253 bytes max; tag(1) + salt(2) + ciphertext <= 253, so
/// ciphertext <= 250; rounded down to a multiple of 16 gives 240 bytes.
const TUNNEL_CIPHERTEXT_MAX: usize = 240;

/// Errors returned by password decryption.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// Ciphertext length is not a non-empty multiple of 16, exceeds the
    /// allowed maximum, or the embedded Tunnel-Password length byte is
    /// inconsistent with the ciphertext size.
    InvalidLength,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidLength => write!(f, "invalid ciphertext length"),
        }
    }
}

impl std::error::Error for Error {}

// MD5(secret || prev_block) -- shared chaining step for both schemes.
fn chain_hash(secret: &[u8], prev: &[u8; 16]) -> [u8; 16] {
    let mut ctx = md5::Md5::new();
    ctx.update(secret);
    ctx.update(prev);
    ctx.finalize()
}

// ---- User-Password (RFC 2865 §5.2) -----------------------------------------

/// Encrypts a User-Password attribute value.
///
/// `password` must be at most 128 bytes. Returns the ciphertext padded to a
/// multiple of 16 bytes (16-128 bytes).
pub(crate) fn user_password_encrypt(
    password: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Vec<u8> {
    assert!(
        password.len() <= USER_PASSWORD_MAX,
        "password exceeds 128 bytes"
    );

    // Pad password to a multiple of 16, minimum 16 bytes.
    let block_count = password.len().max(1).div_ceil(16);
    let padded_len = block_count * 16;
    let mut plaintext = vec![0u8; padded_len];
    plaintext[..password.len()].copy_from_slice(password);

    let mut out = vec![0u8; padded_len];
    let mut prev = *authenticator;

    for i in 0..block_count {
        let b = chain_hash(secret, &prev);
        let base = i * 16;
        for j in 0..16 {
            out[base + j] = plaintext[base + j] ^ b[j];
        }
        prev.copy_from_slice(&out[base..base + 16]);
    }

    out
}

/// Decrypts a User-Password attribute value.
///
/// Returns the cleartext wrapped in [`super::ZeroizingBytes`] so the
/// buffer is scrubbed on drop. Returns `Err(Error::InvalidLength)` if
/// `ciphertext` is not a non-empty multiple of 16 bytes or exceeds
/// 128 bytes.
///
/// # RFC 2865 trailing-null ambiguity
///
/// Per RFC 2865 §5.2 the encoder right-pads the password with NUL
/// bytes to a 16-byte boundary and the receiver MUST strip trailing
/// NULs. A password whose own bytes end in `\0` therefore cannot
/// round-trip — `b"abc\0"` decrypts to `b"abc"`. This is a property
/// of the protocol, not of this implementation; consumers that need
/// to support binary credentials should use a different attribute
/// (e.g. EAP) rather than User-Password.
pub(crate) fn user_password_decrypt(
    ciphertext: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Result<super::ZeroizingBytes, Error> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || ciphertext.len() > USER_PASSWORD_MAX {
        return Err(Error::InvalidLength);
    }

    let block_count = ciphertext.len() / 16;
    // Decrypt into a scratch buffer that scrubs on every early
    // return: the trimmed-padding bytes still hold key-derived
    // plaintext until cleansed.
    let mut plaintext = super::ZeroizingBytes::new(vec![0u8; ciphertext.len()]);
    let mut prev = *authenticator;

    {
        let pt = plaintext.as_mut_bytes();
        for i in 0..block_count {
            let b = chain_hash(secret, &prev);
            let base = i * 16;
            for j in 0..16 {
                pt[base + j] = ciphertext[base + j] ^ b[j];
            }
            prev.copy_from_slice(&ciphertext[base..base + 16]);
        }
    }

    // Strip trailing null padding (password may be shorter than the
    // padded block). Build the trimmed result in a fresh
    // `ZeroizingBytes`; the original scratch buffer drops here and
    // its full 16/32/...-byte contents (including the now-redundant
    // copy of the first n cleartext bytes) are cleansed.
    let trimmed_len = plaintext
        .as_bytes()
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |pos| pos + 1);
    let mut out = vec![0u8; trimmed_len];
    out.copy_from_slice(&plaintext.as_bytes()[..trimmed_len]);
    Ok(super::ZeroizingBytes::new(out))
}

// ---- Tunnel-Password (RFC 2868 §3.5) ----------------------------------------

/// Encrypts a Tunnel-Password attribute value, generating a fresh
/// salt internally.
///
/// `password` must be at most 239 bytes. Returns `(salt, ciphertext)`;
/// the caller writes the attribute as
/// `tag || salt || ciphertext`. The salt's MSB-set requirement
/// (RFC 2868 §3.5) and the cryptographic requirement that salts be
/// unpredictable per packet are both handled here.
pub(crate) fn tunnel_password_encrypt(
    password: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> ([u8; 2], Vec<u8>) {
    let salt = generate_salt();
    let ct = tunnel_password_encrypt_with_salt(password, secret, authenticator, salt);
    (salt, ct)
}

/// Generate a fresh 2-byte Tunnel-Password salt with the MSB of the
/// first byte set, as required by RFC 2868 §3.5. The remaining 15
/// bits come from the system CSPRNG.
fn generate_salt() -> [u8; 2] {
    use std::mem::MaybeUninit;
    let mut buf = [MaybeUninit::<u8>::uninit(); 2];
    super::rand::fill(&mut buf);
    // SAFETY: rand::fill initializes every byte.
    let mut salt = unsafe { [buf[0].assume_init(), buf[1].assume_init()] };
    salt[0] |= 0x80;
    salt
}

/// Deterministic Tunnel-Password encrypt — `salt` is supplied by the
/// caller. Private to this module so the high-bit-MSB precondition
/// stays an internal invariant; production code goes through
/// [`tunnel_password_encrypt`], which generates salts itself.
/// Tests use this entry point so they can pin known-answer vectors.
fn tunnel_password_encrypt_with_salt(
    password: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
    salt: [u8; 2],
) -> Vec<u8> {
    assert!(
        password.len() < TUNNEL_CIPHERTEXT_MAX,
        "password exceeds 239 bytes"
    );
    debug_assert!(
        salt[0] & 0x80 != 0,
        "tunnel password salt MSB must be set (RFC 2868 §3.5)"
    );

    // Plaintext = [1-byte password length] || password || zero padding,
    // rounded up to a multiple of 16 bytes.
    let plaintext_len = (1 + password.len()).div_ceil(16) * 16;
    let mut plaintext = vec![0u8; plaintext_len];
    // SAFETY: assert above ensures password.len() < TUNNEL_CIPHERTEXT_MAX (240), which fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = password.len() as u8;
    plaintext[0] = len_byte;
    plaintext[1..=password.len()].copy_from_slice(password);

    let mut out = vec![0u8; plaintext_len];

    // First block seed: MD5(secret || authenticator || salt).
    let first = {
        let mut ctx = md5::Md5::new();
        ctx.update(secret);
        ctx.update(authenticator);
        ctx.update(&salt);
        ctx.finalize()
    };
    for j in 0..16 {
        out[j] = plaintext[j] ^ first[j];
    }

    let mut prev = [0u8; 16];
    prev.copy_from_slice(&out[0..16]);

    for i in 1..plaintext_len / 16 {
        let b = chain_hash(secret, &prev);
        let base = i * 16;
        for j in 0..16 {
            out[base + j] = plaintext[base + j] ^ b[j];
        }
        prev.copy_from_slice(&out[base..base + 16]);
    }

    out
}

/// Decrypts a Tunnel-Password attribute value.
///
/// `ciphertext` is the String field of the attribute (not including the salt).
/// Returns the cleartext wrapped in [`super::ZeroizingBytes`] so the
/// buffer is scrubbed on drop. Returns `Err(Error::InvalidLength)` if
/// the ciphertext length is invalid or the embedded length byte is
/// inconsistent with the ciphertext size.
pub(crate) fn tunnel_password_decrypt(
    ciphertext: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
    salt: [u8; 2],
) -> Result<super::ZeroizingBytes, Error> {
    if ciphertext.is_empty()
        || ciphertext.len() % 16 != 0
        || ciphertext.len() > TUNNEL_CIPHERTEXT_MAX
    {
        return Err(Error::InvalidLength);
    }

    let block_count = ciphertext.len() / 16;
    let mut plaintext = super::ZeroizingBytes::new(vec![0u8; ciphertext.len()]);

    // First block seed: MD5(secret || authenticator || salt).
    let first = {
        let mut ctx = md5::Md5::new();
        ctx.update(secret);
        ctx.update(authenticator);
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

        for i in 1..block_count {
            let b = chain_hash(secret, &prev);
            let base = i * 16;
            for j in 0..16 {
                pt[base + j] = ciphertext[base + j] ^ b[j];
            }
            prev.copy_from_slice(&ciphertext[base..base + 16]);
        }
    }

    // First byte is the password length.
    let plen = plaintext.as_bytes()[0] as usize;
    if 1 + plen > plaintext.as_bytes().len() {
        return Err(Error::InvalidLength);
    }

    let mut out = vec![0u8; plen];
    out.copy_from_slice(&plaintext.as_bytes()[1..=plen]);
    Ok(super::ZeroizingBytes::new(out))
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2865 section 7.1 known-answer test for User-Password.
    //   secret        = "xyzzy5461"
    //   authenticator = 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a
    //   password      = "arctangent"
    //   ciphertext    = 0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee
    #[test]
    fn user_password_rfc2865_kat() {
        let secret = b"xyzzy5461";
        let auth: [u8; 16] = [
            0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb, 0x98, 0xf4,
            0x22, 0x7a,
        ];
        let password = b"arctangent";
        let expected: [u8; 16] = [
            0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a,
            0x0a, 0xee,
        ];

        let ct = user_password_encrypt(password, secret, &auth);
        assert_eq!(ct.as_slice(), expected.as_slice());
    }

    #[test]
    fn user_password_roundtrip() {
        let secret = b"s3cr3t";
        let auth = [0x42u8; 16];

        for password in [
            b"".as_slice(),
            b"short",
            b"exactly-16-bytez",
            b"a longer password value here!!",
        ] {
            let ct = user_password_encrypt(password, secret, &auth);
            assert_eq!(ct.len() % 16, 0);
            assert!(!ct.is_empty());
            let pt = user_password_decrypt(&ct, secret, &auth).expect("decrypt");
            assert_eq!(pt.as_bytes(), password);
        }
    }

    #[test]
    fn user_password_decrypt_bad_length() {
        let auth = [0u8; 16];
        // empty
        assert_eq!(
            user_password_decrypt(&[], b"s", &auth),
            Err(Error::InvalidLength)
        );
        // not a multiple of 16
        assert_eq!(
            user_password_decrypt(&[0u8; 17], b"s", &auth),
            Err(Error::InvalidLength)
        );
        // too long (144 > 128)
        assert_eq!(
            user_password_decrypt(&[0u8; 144], b"s", &auth),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn tunnel_password_roundtrip() {
        let secret = b"s3cr3t";
        let auth = [0x11u8; 16];
        let salt = [0x80, 0x01];

        for password in [
            b"".as_slice(),
            b"pass",
            b"exactly15bytes!",
            b"a longer tunnel password value",
        ] {
            let ct = tunnel_password_encrypt_with_salt(password, secret, &auth, salt);
            assert_eq!(ct.len() % 16, 0);
            let pt = tunnel_password_decrypt(&ct, secret, &auth, salt).expect("decrypt");
            assert_eq!(pt.as_bytes(), password);
        }
    }

    #[test]
    fn error_display_and_debug_cover_every_variant() {
        let e = Error::InvalidLength;
        assert_eq!(e.to_string(), "invalid ciphertext length");
        // Round-trip Debug and PartialEq so all derive-generated
        // arms participate in coverage.
        assert_eq!(format!("{e:?}"), "InvalidLength");
        let err_dyn: &dyn std::error::Error = &e;
        assert!(err_dyn.source().is_none());
    }

    #[test]
    fn tunnel_password_decrypt_bad_length() {
        let auth = [0u8; 16];
        let salt = [0x80, 0x00];
        // empty
        assert_eq!(
            tunnel_password_decrypt(&[], b"s", &auth, salt),
            Err(Error::InvalidLength)
        );
        // not a multiple of 16
        assert_eq!(
            tunnel_password_decrypt(&[0u8; 15], b"s", &auth, salt),
            Err(Error::InvalidLength)
        );
        // too long (256 > 240)
        assert_eq!(
            tunnel_password_decrypt(&[0u8; 256], b"s", &auth, salt),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn tunnel_password_bad_embedded_length() {
        // Encrypt with a valid password, then corrupt the first plaintext byte
        // (length field) via a crafted ciphertext where decrypted byte 0 > remaining.
        // The simplest way: pass 16 bytes that decrypt to a length byte of 255.
        // We construct ciphertext such that decrypted[0] = 0xff (> 15 remaining).
        let secret = b"s";
        let auth = [0u8; 16];
        let salt = [0x80, 0x00];

        // Encrypt a known plaintext first block all-0xff.
        // b0 = MD5("s" || auth || salt)
        // ciphertext[0..16] = 0xff XOR b0
        let mut seed = Vec::new();
        seed.extend_from_slice(secret);
        seed.extend_from_slice(&auth);
        seed.extend_from_slice(&salt);
        let b0 = md5::digest(&seed);
        let mut ct = [0xffu8; 16];
        for j in 0..16 {
            ct[j] ^= b0[j];
        }
        // Decrypted byte 0 = 0xff, but only 15 bytes remain -> invalid.
        assert_eq!(
            tunnel_password_decrypt(&ct, secret, &auth, salt),
            Err(Error::InvalidLength)
        );
    }

    // ---- Boundary cases that have historically tripped RADIUS ports --------

    /// User-Password at exactly the RFC 2865 §5.2 maximum: 128 bytes
    /// of password produce 128 bytes of ciphertext (eight 16-byte
    /// blocks), and the receiver must accept and round-trip it.
    #[test]
    fn user_password_roundtrip_at_max_length() {
        let secret = b"max-len-secret";
        let auth = [0xa5u8; 16];
        let password = vec![b'x'; 128];

        let ct = user_password_encrypt(&password, secret, &auth);
        assert_eq!(ct.len(), 128, "ciphertext is exactly the max value");
        let pt = user_password_decrypt(&ct, secret, &auth).expect("decrypt");
        assert_eq!(pt.as_bytes(), password.as_slice());
    }

    /// Documents the RFC 2865 §5.2 trailing-NUL ambiguity: a password
    /// whose own bytes end in `\0` cannot be distinguished from
    /// padding and so does not round-trip. This test exists so that
    /// any future "fix" that removes the trim breaks loudly here
    /// rather than silently changing the wire interpretation.
    #[test]
    fn user_password_trailing_null_is_rfc_ambiguous() {
        let secret = b"s3cr3t";
        let auth = [0x42u8; 16];
        let password = b"abc\0\0";
        let ct = user_password_encrypt(password, secret, &auth);
        let pt = user_password_decrypt(&ct, secret, &auth).expect("decrypt");
        // Per RFC the receiver MUST strip trailing NULs; the original
        // tail is unrecoverable.
        assert_eq!(pt.as_bytes(), b"abc");
    }

    /// User-Password whose length is an exact multiple of 16 must
    /// not get an extra block of padding appended (a classic off-
    /// by-one in `div_ceil`-free implementations).
    #[test]
    fn user_password_exact_block_multiple_no_extra_padding() {
        let secret = b"s3cr3t";
        let auth = [0x42u8; 16];
        for password in [vec![b'a'; 16], vec![b'b'; 32], vec![b'c'; 64]] {
            let ct = user_password_encrypt(&password, secret, &auth);
            assert_eq!(
                ct.len(),
                password.len(),
                "no extra block for exact-multiple plaintext"
            );
            let pt = user_password_decrypt(&ct, secret, &auth).expect("decrypt");
            assert_eq!(pt.as_bytes(), password.as_slice());
        }
    }

    /// Tunnel-Password at the RFC 2868 §3.5 maximum: 239 bytes of
    /// password (length byte + payload + zero pad fits in the 240-
    /// byte ciphertext ceiling).
    #[test]
    fn tunnel_password_roundtrip_at_max_length() {
        let secret = b"max-len-secret";
        let auth = [0x5au8; 16];
        let salt = [0x80, 0x42];
        let password = vec![b'y'; 239];

        let ct = tunnel_password_encrypt_with_salt(&password, secret, &auth, salt);
        assert_eq!(ct.len(), 240, "ciphertext is the 240-byte ceiling");
        let pt = tunnel_password_decrypt(&ct, secret, &auth, salt).expect("decrypt");
        assert_eq!(pt.as_bytes(), password.as_slice());
    }

    /// Tunnel-Password embedded length byte at the just-fits
    /// boundary (`plen == ciphertext_len - 1`) must succeed; bumping
    /// it to `ciphertext_len` must fail. This is the classic
    /// "off-by-one in the length sanity check" footgun.
    #[test]
    fn tunnel_password_embedded_length_just_fits_boundary() {
        let secret = b"s";
        let auth = [0u8; 16];
        let salt = [0x80, 0x00];

        // A 15-byte payload exactly fills a single 16-byte plaintext
        // block (1 length byte + 15 password bytes, no padding).
        let password = vec![b'q'; 15];
        let ct = tunnel_password_encrypt_with_salt(&password, secret, &auth, salt);
        assert_eq!(ct.len(), 16);
        let pt = tunnel_password_decrypt(&ct, secret, &auth, salt).expect("decrypt");
        assert_eq!(pt.as_bytes(), password.as_slice());

        // Now craft a ciphertext whose decrypted first byte is 16
        // (== ciphertext_len) — must be rejected.
        let mut seed = Vec::new();
        seed.extend_from_slice(secret);
        seed.extend_from_slice(&auth);
        seed.extend_from_slice(&salt);
        let b0 = md5::digest(&seed);
        let mut bad = [0u8; 16];
        bad[0] = 16 ^ b0[0];
        bad[1..16].copy_from_slice(&b0[1..16]); // decrypts to zeros
        assert_eq!(
            tunnel_password_decrypt(&bad, secret, &auth, salt),
            Err(Error::InvalidLength)
        );
    }

    /// Tunnel-Password whose payload is exactly 16-byte aligned (so
    /// `1 + len` rounds *up* to the next block) must produce
    /// ciphertext of `len + 1` bytes rounded up to 16, not
    /// `(len).div_ceil(16) * 16`.
    #[test]
    fn tunnel_password_block_boundary_padding() {
        let secret = b"s3cr3t";
        let auth = [0x11u8; 16];
        let salt = [0x80, 0x01];
        // 15-byte payload  -> 1+15 = 16  -> 1 block
        // 16-byte payload  -> 1+16 = 17  -> 2 blocks (extra block for the length byte)
        // 31-byte payload  -> 1+31 = 32  -> 2 blocks
        for (password, expected_ct) in [
            (vec![b'a'; 15], 16usize),
            (vec![b'b'; 16], 32),
            (vec![b'c'; 31], 32),
            (vec![b'd'; 32], 48),
        ] {
            let ct = tunnel_password_encrypt_with_salt(&password, secret, &auth, salt);
            assert_eq!(
                ct.len(),
                expected_ct,
                "padding boundary for {}-byte payload",
                password.len(),
            );
            let pt = tunnel_password_decrypt(&ct, secret, &auth, salt).expect("decrypt");
            assert_eq!(pt.as_bytes(), password.as_slice());
        }
    }

    /// The public [`tunnel_password_encrypt`] entry point must always
    /// emit a salt with the high bit of the first byte set
    /// (RFC 2868 §3.5) and the result must round-trip through
    /// `tunnel_password_decrypt`.
    #[test]
    fn tunnel_password_public_entry_round_trips_with_generated_salt() {
        let secret = b"s3cr3t";
        let auth = [0x33u8; 16];
        let password = b"hunter2";
        let (salt, ct) = tunnel_password_encrypt(password, secret, &auth);
        assert_ne!(salt[0] & 0x80, 0, "salt MSB must be set per RFC 2868");
        let pt = tunnel_password_decrypt(&ct, secret, &auth, salt).expect("decrypt");
        assert_eq!(pt.as_bytes(), password);
    }

    /// The salt generator must actually draw fresh randomness rather
    /// than returning a constant. We can't push hard on uniqueness —
    /// only 15 bits are random (the high bit is fixed) so the
    /// birthday bound is ≈ 2¹⁵ᐟ² ≈ 181 draws — but a handful of
    /// distinct values across a small sample rules out the
    /// "always returns the same byte" failure mode.
    #[test]
    fn tunnel_password_salt_is_freshly_generated() {
        let secret = b"s";
        let auth = [0u8; 16];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let (salt, _) = tunnel_password_encrypt(b"x", secret, &auth);
            assert_eq!(salt[0] & 0x80, 0x80);
            seen.insert(salt);
        }
        // 8 draws over 2^15 buckets: P(all equal) ≈ 2⁻¹⁰⁵.
        assert!(
            seen.len() > 1,
            "salt generator returned the same value 8 times in a row",
        );
    }
}
