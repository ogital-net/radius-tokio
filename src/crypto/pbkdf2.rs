//! Safe wrapper for PBKDF2 (RFC 2898 §5.2 / RFC 8018 §5.2).
//!
//! PBKDF2 is the password-stretching KDF behind the bulk of
//! pre-shared-key derivations adjacent to RADIUS deployments:
//!
//! * **WPA/WPA2-Personal (IEEE 802.11i §F.4.1)** — `PMK = PBKDF2-HMAC-SHA1(
//!   passphrase, SSID, 4096, 32)`. The same construction underpins
//!   per-user PSK schemes (PPSK / DPSK / MPSK) shipped by Aruba,
//!   Ruckus, Cisco Meraki, Extreme, and most other enterprise APs:
//!   the RADIUS server returns a vendor-specific PSK attribute and
//!   the AP derives the PMK on-device with PBKDF2.
//! * **Generic passphrase-keyed MAC derivations** in PEAP/TTLS inner
//!   methods and out-of-tree tooling that needs a stable
//!   passphrase-to-key mapping.
//!
//! Exposed here so handlers minting per-user PSKs (or comparing
//! against a vendor-supplied PMK) can use the same crypto stack the
//! rest of the library uses, rather than pulling in a second one.
//!
//! # API shape
//!
//! Two variants: [`hmac_sha1`] (RFC 6070, the WPA/PSK workhorse) and
//! [`hmac_sha256`] (newer deployments, FIPS 140-3 friendlier). Both
//! take the passphrase, salt, iteration count, and an output buffer
//! sized by the caller to the desired key length. The output buffer
//! is filled in place; PBKDF2 has no inherent maximum output size
//! beyond `(2^32 − 1) × hLen` octets and we do not impose one.
//!
//! # Iteration counts
//!
//! Choose iteration counts at the call site, not here. Reference
//! points: WPA/WPA2-Personal mandates 4096; OWASP 2023 cheat-sheet
//! recommends ≥ 600 000 for HMAC-SHA-256 password verification.
//! Passing zero panics rather than silently returning the salt.

use std::ffi::c_char;

use aws_lc_sys::{EVP_sha1, EVP_sha256, PKCS5_PBKDF2_HMAC};

/// Derive `out.len()` bytes of key material using PBKDF2-HMAC-SHA1.
///
/// This is the variant Wi-Fi PSK / PPSK / DPSK / MPSK derivations
/// use (IEEE 802.11i §F.4.1: `PMK = PBKDF2-HMAC-SHA1(passphrase,
/// SSID, 4096, 32)`).
///
/// # Panics
///
/// Panics if `iterations` is zero (zero iterations would emit raw
/// salt bytes and is always a caller bug). Also panics if the
/// underlying `PKCS5_PBKDF2_HMAC` call fails, which aws-lc only
/// reports for allocation failure on absurdly large output lengths.
pub fn hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    derive(password, salt, iterations, Digest::Sha1, out);
}

/// Derive `out.len()` bytes of key material using PBKDF2-HMAC-SHA256.
///
/// Preferred over [`hmac_sha1`] for new password-verification or
/// key-derivation work; required by some recent vendor PSK
/// derivation schemes and by FIPS-140-3-aligned deployments.
///
/// # Panics
///
/// As for [`hmac_sha1`].
pub fn hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    derive(password, salt, iterations, Digest::Sha256, out);
}

#[derive(Debug, Clone, Copy)]
enum Digest {
    Sha1,
    Sha256,
}

fn derive(password: &[u8], salt: &[u8], iterations: u32, digest: Digest, out: &mut [u8]) {
    assert!(iterations > 0, "PBKDF2 iterations must be non-zero");
    if out.is_empty() {
        return;
    }
    // SAFETY: EVP_sha1/EVP_sha256 return static, immutable EVP_MD
    // pointers and never NULL. password/salt are valid slices for
    // their lengths; out is a valid mutable slice for out.len()
    // bytes. The aws-lc C signature takes password as `c_char` but
    // treats the bytes as opaque key material — the cast is the
    // standard PBKDF2 invocation pattern.
    let md = unsafe {
        match digest {
            Digest::Sha1 => EVP_sha1(),
            Digest::Sha256 => EVP_sha256(),
        }
    };
    // SAFETY: see comment above. PKCS5_PBKDF2_HMAC returns 1 on
    // success, 0 on failure (allocation only for sane inputs).
    let ret = unsafe {
        PKCS5_PBKDF2_HMAC(
            password.as_ptr().cast::<c_char>(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            md,
            out.len(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 1, "PKCS5_PBKDF2_HMAC failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    // RFC 6070 §2 PBKDF2-HMAC-SHA-1 test vectors.
    #[test]
    fn rfc6070_iter_1() {
        let mut out = [0u8; 20];
        hmac_sha1(b"password", b"salt", 1, &mut out);
        assert_eq!(hex(&out), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    #[test]
    fn rfc6070_iter_2() {
        let mut out = [0u8; 20];
        hmac_sha1(b"password", b"salt", 2, &mut out);
        assert_eq!(hex(&out), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    #[test]
    fn rfc6070_iter_4096_with_long_salt_and_key() {
        let mut out = [0u8; 25];
        hmac_sha1(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out,
        );
        assert_eq!(
            hex(&out),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );
    }

    // IEEE 802.11i Annex F.4.1 reference WPA-PSK derivation:
    // PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32).
    #[test]
    fn wpa_psk_known_answer() {
        let mut pmk = [0u8; 32];
        hmac_sha1(b"password", b"IEEE", 4096, &mut pmk);
        assert_eq!(
            hex(&pmk),
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",
        );
    }

    // RFC 7914 §11 PBKDF2-HMAC-SHA-256 test vector
    // ("passwd"/"salt"/1/64).
    #[test]
    fn rfc7914_pbkdf2_sha256() {
        let mut out = [0u8; 64];
        hmac_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            concat!(
                "55ac046e56e3089fec1691c22544b605",
                "f94185216dde0465e68b9d57c20dacbc",
                "49ca9cccf179b645991664b39d77ef31",
                "7c71b845b1e30bd509112041d3a19783",
            ),
        );
    }

    #[test]
    fn empty_output_is_noop() {
        // No assertion on iterations==0 because we still bail before
        // calling aws-lc when output is empty — exercise the path.
        let mut out: [u8; 0] = [];
        hmac_sha1(b"pw", b"salt", 1, &mut out);
        hmac_sha256(b"pw", b"salt", 1, &mut out);
    }

    #[test]
    #[should_panic(expected = "PBKDF2 iterations must be non-zero")]
    fn zero_iterations_panics() {
        let mut out = [0u8; 16];
        hmac_sha1(b"pw", b"salt", 0, &mut out);
    }
}
