//! Safe wrapper for HMAC-SHA256.
//!
//! HMAC-SHA256 is reached for by newer EAP methods (EAP-AKA' RFC 5448
//! §3.4, EAP-PWD RFC 5931 §2.7, EAP-TEAP RFC 7170 §5.3) and by the
//! RADIUS/TLS RFC 6614 exporter when deriving Message-Authenticator
//! material for tunnelled inner authentications. Exposed here so the
//! companion `radius-tokio-eap` crate and out-of-tree handlers do
//! not need to link a second crypto stack.
//!
//! Backed by `aws-lc-sys`'s `HMAC_*` interface with `EVP_sha256()`.
//! See [`super::hmac_md5`] for the rationale on incremental-only
//! API and the assertion / panic policy.

use std::mem::MaybeUninit;

use aws_lc_sys::{HMAC_CTX_cleanup, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX};

/// HMAC-SHA256 tag length in bytes (32, equal to the SHA-256 digest length).
pub const TAG_LEN: usize = aws_lc_sys::SHA256_DIGEST_LENGTH as usize;

/// Incremental HMAC-SHA256 context backed by a stack-allocated `HMAC_CTX`.
///
/// Call [`update`](HmacSha256::update) one or more times, then
/// [`finalize`](HmacSha256::finalize). `finalize` consumes `self` to
/// prevent reuse after the context is cleaned up.
pub struct HmacSha256 {
    ctx: HMAC_CTX,
}

impl HmacSha256 {
    /// Initialise a new HMAC-SHA256 context with the given `key`.
    ///
    /// `key` may be any length; the underlying implementation
    /// pre-hashes keys longer than the SHA-256 block size per
    /// RFC 2104 §2.
    ///
    /// # Panics
    ///
    /// Panics if `HMAC_Init_ex` reports failure — only possible on
    /// allocation failure in aws-lc, which we treat as unrecoverable
    /// (see [`crate::crypto`] panic policy).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        // SAFETY: HMAC_CTX is a C struct with no padding invariants;
        // zeroing it is the correct initial state, equivalent to
        // HMAC_CTX_init.
        let mut ctx = unsafe { MaybeUninit::<HMAC_CTX>::zeroed().assume_init() };
        // SAFETY: ctx is zero-initialised. key is valid for key.len()
        // bytes. EVP_sha256() returns a pointer to a static, immutable
        // EVP_MD object and never returns NULL. impl_ is NULL (use
        // the default engine).
        let ret = unsafe {
            HMAC_Init_ex(
                &raw mut ctx,
                key.as_ptr().cast(),
                key.len(),
                aws_lc_sys::EVP_sha256(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 1, "HMAC_Init_ex(EVP_sha256) failed");
        Self { ctx }
    }

    /// Feed `data` into the running HMAC. May be called any number of times.
    ///
    /// # Panics
    ///
    /// Panics if `HMAC_Update` reports failure; aws-lc only returns
    /// failure on allocation faults under absurd input sizes.
    pub fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialised and not yet finalised. data is a
        // valid slice for the duration of this call.
        let ret = unsafe { HMAC_Update(&raw mut self.ctx, data.as_ptr(), data.len()) };
        assert_eq!(ret, 1, "HMAC_Update failed");
    }

    /// Finalise the HMAC and return the 32-byte tag.
    ///
    /// # Panics
    ///
    /// Panics if `HMAC_Final` reports failure (aws-lc allocation fault).
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        let mut out_len: std::os::raw::c_uint = 0;
        // SAFETY: ctx is initialised and not previously finalised.
        // tag is exactly the SHA-256 digest size.
        let ret = unsafe { HMAC_Final(&raw mut self.ctx, tag.as_mut_ptr(), &raw mut out_len) };
        assert_eq!(ret, 1, "HMAC_Final failed");
        debug_assert_eq!(out_len as usize, TAG_LEN);
        tag
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        // SAFETY: ctx is initialised. HMAC_CTX_cleanup is idempotent
        // and safe to call even after HMAC_Final has run.
        unsafe { HMAC_CTX_cleanup(&raw mut self.ctx) };
    }
}

/// Convenience one-shot helper. Equivalent to
/// `let mut h = HmacSha256::new(key); h.update(data); h.finalize()`.
#[must_use]
pub fn compute(key: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
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

    // RFC 4231 §4 HMAC-SHA-256 test vectors.
    #[test]
    fn rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let tag = compute(&key, data);
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
    }

    #[test]
    fn rfc4231_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = compute(key, data);
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let key = b"key";
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut h = HmacSha256::new(key);
        h.update(&data[..10]);
        h.update(&data[10..]);
        assert_eq!(h.finalize(), compute(key, data));
    }
}
