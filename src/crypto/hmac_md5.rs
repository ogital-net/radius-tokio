//! Safe wrapper for HMAC-MD5 from `aws-lc-sys`.
//!
//! HMAC-MD5 is the only HMAC variant the RADIUS wire protocol uses
//! (Message-Authenticator, RFC 3579). This module is intentionally
//! single-purpose: no digest selector enum, no one-shot helper, no
//! generic plumbing.

use std::mem::MaybeUninit;

use aws_lc_sys::{HMAC_CTX_cleanup, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX};

/// HMAC-MD5 tag length in bytes. Equal to the MD5 digest length, as
/// re-exported from `aws_lc_sys`.
pub(crate) const TAG_LEN: usize = aws_lc_sys::MD5_DIGEST_LENGTH as usize;

/// Incremental HMAC-MD5 context backed by a stack-allocated `HMAC_CTX`.
///
/// Call [`update`][HmacMd5::update] one or more times, then
/// [`finalize`][HmacMd5::finalize]. `finalize` consumes `self` to
/// prevent reuse after the context is cleaned up.
pub(crate) struct HmacMd5 {
    ctx: HMAC_CTX,
}

impl HmacMd5 {
    /// Initializes a new HMAC-MD5 context with the given `key`.
    pub(crate) fn new(key: &[u8]) -> Self {
        // SAFETY: HMAC_CTX is a C struct with no padding invariants;
        // zeroing it is the correct initial state, equivalent to
        // HMAC_CTX_init.
        let mut ctx = unsafe { MaybeUninit::<HMAC_CTX>::zeroed().assume_init() };
        // SAFETY: ctx is zero-initialized. key is a valid slice for
        // key.len() bytes. EVP_md5() returns a pointer to a static,
        // immutable EVP_MD object and never returns NULL. impl_ is
        // NULL (use the default engine).
        let ret = unsafe {
            HMAC_Init_ex(
                &mut ctx,
                key.as_ptr().cast(),
                key.len(),
                aws_lc_sys::EVP_md5(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 1, "HMAC_Init_ex failed");
        Self { ctx }
    }

    /// Feeds `data` into the running HMAC. May be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialized and not yet finalized. data is a
        // valid slice for the duration of this call.
        let ret = unsafe { HMAC_Update(&mut self.ctx, data.as_ptr(), data.len()) };
        assert_eq!(ret, 1, "HMAC_Update failed");
    }

    /// Finalizes the HMAC and returns the 16-byte tag.
    pub(crate) fn finalize(mut self) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        let mut out_len: std::os::raw::c_uint = 0;
        // SAFETY: ctx is initialized and not previously finalized. tag
        // is 16 bytes — exactly the MD5 digest size.
        let ret = unsafe { HMAC_Final(&mut self.ctx, tag.as_mut_ptr(), &mut out_len) };
        assert_eq!(ret, 1, "HMAC_Final failed");
        debug_assert_eq!(out_len as usize, TAG_LEN);
        tag
    }
}

impl Drop for HmacMd5 {
    fn drop(&mut self) {
        // SAFETY: ctx is initialized. HMAC_CTX_cleanup is idempotent and
        // safe to call even after HMAC_Final has run.
        unsafe { HMAC_CTX_cleanup(&mut self.ctx) };
    }
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

    // RFC 2202 §2 test vectors for HMAC-MD5.
    #[test]
    fn known_answers() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
                b"Hi There",
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
        ];

        for (key, data, expected) in cases {
            let mut ctx = HmacMd5::new(key);
            ctx.update(data);
            assert_eq!(hex(&ctx.finalize()), *expected);
        }
    }

    #[test]
    fn multi_update_matches_single() {
        let key = b"Jefe";
        let full = b"what do ya want for nothing?";

        let mut a = HmacMd5::new(key);
        a.update(full);
        let single = a.finalize();

        let mut b = HmacMd5::new(key);
        for byte in full {
            b.update(std::slice::from_ref(byte));
        }
        assert_eq!(b.finalize(), single);
    }

    #[test]
    fn drop_without_finalize() {
        drop(HmacMd5::new(b"key"));
    }
}
