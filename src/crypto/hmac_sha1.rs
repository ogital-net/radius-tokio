//! Safe wrapper for HMAC-SHA1.
//!
//! HMAC-SHA1 is not used by the bare RADIUS wire protocol — RFC 3579
//! pins Message-Authenticator to HMAC-MD5 — but it is the keyed-MAC
//! primitive several EAP methods (EAP-AKA RFC 4187 §6.3, EAP-SIM
//! RFC 4186 §10.4, EAP-FAST RFC 4851 §5.5) and the RFC 2548
//! MS-MPPE-{Send,Recv}-Key key-wrap derivation reach for, so we
//! expose it here for use by the companion `radius-tokio-eap` crate
//! and out-of-tree handlers.
//!
//! Backed by `aws-lc-sys`'s `HMAC_*` interface with `EVP_sha1()`.
//! See [`super::hmac_md5`] for the rationale on incremental-only
//! API and the assertion / panic policy.

use std::mem::MaybeUninit;

use aws_lc_sys::{HMAC_CTX_cleanup, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX};

/// HMAC-SHA1 tag length in bytes (equal to the SHA-1 digest length).
pub const TAG_LEN: usize = aws_lc_sys::SHA_DIGEST_LENGTH as usize;

/// Incremental HMAC-SHA1 context backed by a stack-allocated `HMAC_CTX`.
///
/// Call [`update`](HmacSha1::update) one or more times, then
/// [`finalize`](HmacSha1::finalize). `finalize` consumes `self` to
/// prevent reuse after the context is cleaned up.
pub struct HmacSha1 {
    ctx: HMAC_CTX,
}

impl HmacSha1 {
    /// Initialise a new HMAC-SHA1 context with the given `key`.
    ///
    /// `key` may be any length; the underlying implementation
    /// pre-hashes keys longer than the SHA-1 block size per
    /// RFC 2104 §2.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        // SAFETY: HMAC_CTX is a C struct with no padding invariants;
        // zeroing it is the correct initial state, equivalent to
        // HMAC_CTX_init.
        let mut ctx = unsafe { MaybeUninit::<HMAC_CTX>::zeroed().assume_init() };
        // SAFETY: ctx is zero-initialised. key is valid for key.len()
        // bytes. EVP_sha1() returns a pointer to a static, immutable
        // EVP_MD object and never returns NULL. impl_ is NULL (use
        // the default engine).
        let ret = unsafe {
            HMAC_Init_ex(
                &raw mut ctx,
                key.as_ptr().cast(),
                key.len(),
                aws_lc_sys::EVP_sha1(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 1, "HMAC_Init_ex(EVP_sha1) failed");
        Self { ctx }
    }

    /// Feed `data` into the running HMAC. May be called any number of times.
    pub fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialised and not yet finalised. data is a
        // valid slice for the duration of this call.
        let ret = unsafe { HMAC_Update(&raw mut self.ctx, data.as_ptr(), data.len()) };
        assert_eq!(ret, 1, "HMAC_Update failed");
    }

    /// Finalise the HMAC and return the 20-byte tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        let mut out_len: std::os::raw::c_uint = 0;
        // SAFETY: ctx is initialised and not previously finalised.
        // tag is exactly the SHA-1 digest size.
        let ret = unsafe { HMAC_Final(&raw mut self.ctx, tag.as_mut_ptr(), &raw mut out_len) };
        assert_eq!(ret, 1, "HMAC_Final failed");
        debug_assert_eq!(out_len as usize, TAG_LEN);
        tag
    }
}

impl Drop for HmacSha1 {
    fn drop(&mut self) {
        // SAFETY: ctx is initialised. HMAC_CTX_cleanup is idempotent
        // and safe to call even after HMAC_Final has run.
        unsafe { HMAC_CTX_cleanup(&raw mut self.ctx) };
    }
}

/// Convenience one-shot helper. Equivalent to
/// `let mut h = HmacSha1::new(key); h.update(data); h.finalize()`.
#[must_use]
pub fn compute(key: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let mut h = HmacSha1::new(key);
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

    // RFC 2202 §3 HMAC-SHA-1 test vectors.
    #[test]
    fn rfc2202_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let tag = compute(&key, data);
        assert_eq!(hex(&tag), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn rfc2202_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = compute(key, data);
        assert_eq!(hex(&tag), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn incremental_matches_one_shot() {
        let key = b"key";
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut h = HmacSha1::new(key);
        h.update(&data[..10]);
        h.update(&data[10..]);
        assert_eq!(h.finalize(), compute(key, data));
    }
}
