//! Safe wrappers over [`aws_lc_sys`] cryptographic primitives.
//!
//! All FFI calls are encapsulated here; no other module in this crate calls
//! `aws_lc_sys` directly.  Every `unsafe` block carries a `// SAFETY:`
//! comment that states the invariants being upheld.
//!
//! # Panic policy
//!
//! Wrappers in this module deliberately `assert!` on FFI return codes
//! that the underlying library documents as infallible for the inputs
//! we supply (`MD5_Init`, `HMAC_Init_ex`, `RAND_bytes`, …). These
//! assertions are not error handling: they catch a violation of the
//! library's contract — a memory-corruption bug, a build linked
//! against the wrong ABI, an entropy source failure, or similar. In
//! every such case continuing with a silently-degraded crypto
//! operation would be strictly worse than crashing, because the
//! result would be plumbed through to authenticator and
//! Message-Authenticator computations whose security depends on the
//! primitive returning real output. Crashes are loud and recoverable;
//! a forged authenticator that validates is neither.
//!
//! Surfaces that genuinely can fail on well-formed input — TLS
//! handshakes, PEM parsing, X.509 chain validation — return typed
//! [`tls::TlsError`] values via `Result`. Only the "the universe is
//! broken" cases panic.

pub(crate) mod des;
pub(crate) mod hmac_md5;
pub(crate) mod md4;
pub(crate) mod md5;
pub mod mppe;
pub(crate) mod password;
#[cfg(feature = "radsec")]
pub mod pki;
pub mod rand;
pub(crate) mod sha1;
#[cfg(feature = "radsec")]
pub mod tls;

pub mod aes;
pub mod hmac_sha1;
pub mod hmac_sha256;
pub mod pbkdf2;

/// Compares two byte slices in constant time.
///
/// Returns `false` immediately if the lengths differ (length is not secret).
/// Otherwise delegates to `CRYPTO_memcmp` to avoid timing side-channels.
///
/// Exposed publicly so that EAP method implementations in the
/// companion `radius-tokio-eap` crate — and any out-of-tree handler
/// that compares a peer-supplied secret against an expected value —
/// can share the same primitive instead of hand-rolling their own
/// XOR-accumulator loop.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY: a and b are valid slices of equal length for the duration of
    // this call. CRYPTO_memcmp returns 0 if the contents are equal.
    let ret = unsafe {
        aws_lc_sys::CRYPTO_memcmp(
            a.as_ptr().cast::<std::os::raw::c_void>(),
            b.as_ptr().cast::<std::os::raw::c_void>(),
            a.len(),
        )
    };
    ret == 0
}

/// Securely zero `buf` so the compiler will not optimise the write away.
///
/// Used to scrub shared secrets and other key material when the owning
/// container is dropped. Backed by `OPENSSL_cleanse`.
pub(crate) fn cleanse(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: buf is a valid mutable slice for buf.len() bytes.
    unsafe {
        aws_lc_sys::OPENSSL_cleanse(buf.as_mut_ptr().cast::<std::os::raw::c_void>(), buf.len());
    }
}

/// Owning byte buffer whose contents are scrubbed with
/// `OPENSSL_cleanse` when dropped.
///
/// Use this for any plaintext that should not linger in memory after
/// the caller is done with it — decrypted RADIUS passwords being the
/// motivating example. The wrapper deliberately does not implement
/// `Clone`: copying the secret material would defeat the purpose.
/// Borrow `&[u8]` via [`as_bytes`](Self::as_bytes) (or via the `Deref`
/// impl) to feed it into APIs that consume a slice.
#[derive(Debug)]
pub struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    /// Take ownership of `buf`. The buffer's bytes are scrubbed when
    /// the returned value is dropped.
    #[must_use]
    pub fn new(buf: Vec<u8>) -> Self {
        Self(buf)
    }

    /// Borrow the contained bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the contained bytes mutably. Crate-internal: external
    /// callers should treat the buffer as immutable, since growing /
    /// shrinking it would prevent `Drop` from cleansing the original
    /// allocation.
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl std::ops::Deref for ZeroizingBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl PartialEq<[u8]> for ZeroizingBytes {
    fn eq(&self, other: &[u8]) -> bool {
        ct_eq(self.0.as_slice(), other)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for ZeroizingBytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        ct_eq(self.0.as_slice(), other.as_slice())
    }
}

impl PartialEq for ZeroizingBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_slice(), other.0.as_slice())
    }
}

impl Eq for ZeroizingBytes {}

/// RFC 2865 §5.2 User-Password obfuscation.
///
/// Encrypts `password` under `secret` and the Access-Request's
/// Request Authenticator, producing a 16-to-128-byte ciphertext
/// (always a non-zero multiple of 16) suitable for the
/// `User-Password` attribute value.
///
/// Authenticator-side consumers (the [`crate::client`] module, and
/// any out-of-tree Access-Request originator) call this to populate
/// `User-Password`. The matching decrypt path is internal to
/// [`crate::auth::pap`], which constant-time-compares an
/// encrypted expected password against the wire ciphertext.
///
/// # Panics
///
/// Panics if `password.len() > 128` (the RFC 2865 §5.2 maximum).
#[must_use]
pub fn user_password_encrypt(
    password: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Vec<u8> {
    password::user_password_encrypt(password, secret, request_authenticator)
}

#[cfg(test)]
mod tests {
    use super::{cleanse, ct_eq, ZeroizingBytes};

    #[test]
    fn ct_eq_handles_unequal_lengths() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn ct_eq_handles_empty_slices() {
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn ct_eq_compares_contents() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
    }

    #[test]
    fn cleanse_empty_is_noop() {
        let mut empty: [u8; 0] = [];
        cleanse(&mut empty);
    }

    #[test]
    fn cleanse_zeros_buffer() {
        let mut buf = [1u8, 2, 3, 4, 5];
        cleanse(&mut buf);
        assert_eq!(buf, [0u8; 5]);
    }

    #[test]
    fn zeroizing_bytes_partial_eq_slice() {
        let z = ZeroizingBytes::new(b"abc".to_vec());
        assert_eq!(z, *b"abc".as_slice());
        // PartialEq<[u8; N]>
        assert_eq!(z, *b"abc");
        // Negative path through ct_eq.
        let other_slice: &[u8] = b"abd";
        assert_ne!(z, *other_slice);
    }

    #[test]
    fn zeroizing_bytes_partial_eq_self() {
        let a = ZeroizingBytes::new(vec![1, 2, 3]);
        let b = ZeroizingBytes::new(vec![1, 2, 3]);
        let c = ZeroizingBytes::new(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn zeroizing_bytes_deref_and_accessors() {
        let mut z = ZeroizingBytes::new(vec![9u8, 8, 7]);
        // Deref to &[u8].
        let s: &[u8] = &z;
        assert_eq!(s, &[9u8, 8, 7]);
        assert_eq!(z.as_bytes(), &[9u8, 8, 7]);
        // Crate-internal mutable accessor.
        z.as_mut_bytes()[0] = 0;
        assert_eq!(z.as_bytes(), &[0u8, 8, 7]);
        // Drop scrubs; just ensure we can drop without UB.
        drop(z);
    }
}
