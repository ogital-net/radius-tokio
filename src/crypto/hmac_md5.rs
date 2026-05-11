//! Safe wrapper for HMAC-MD5.
//!
//! HMAC-MD5 is the only HMAC variant the RADIUS wire protocol uses
//! (Message-Authenticator, RFC 3579). This module is intentionally
//! single-purpose: no digest selector enum, no one-shot helper, no
//! generic plumbing.
//!
//! Two backends are available:
//!
//! * `fast-md5` feature (default) — delegates directly to
//!   `fast_md5::HmacMd5`, which precomputes the ipad/opad states at
//!   construction time.
//! * Default — `aws-lc-sys`'s `HMAC_*` interface.

/// HMAC-MD5 tag length in bytes. Equal to the MD5 digest length.
#[cfg(not(feature = "fast-md5"))]
pub(crate) const TAG_LEN: usize = aws_lc_sys::MD5_DIGEST_LENGTH as usize;
#[cfg(feature = "fast-md5")]
pub(crate) const TAG_LEN: usize = super::md5::DIGEST_LENGTH;

// ---------------------------------------------------------------------------
// aws-lc-sys backend (default)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "fast-md5"))]
use std::mem::MaybeUninit;

#[cfg(not(feature = "fast-md5"))]
use aws_lc_sys::{HMAC_CTX_cleanup, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX};

/// Incremental HMAC-MD5 context backed by a stack-allocated `HMAC_CTX`.
///
/// Call [`update`][HmacMd5::update] one or more times, then
/// [`finalize`][HmacMd5::finalize]. `finalize` consumes `self` to
/// prevent reuse after the context is cleaned up.
#[cfg(not(feature = "fast-md5"))]
pub(crate) struct HmacMd5 {
    ctx: HMAC_CTX,
}

#[cfg(not(feature = "fast-md5"))]
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

#[cfg(not(feature = "fast-md5"))]
impl Drop for HmacMd5 {
    fn drop(&mut self) {
        // SAFETY: ctx is initialized. HMAC_CTX_cleanup is idempotent and
        // safe to call even after HMAC_Final has run.
        unsafe { HMAC_CTX_cleanup(&mut self.ctx) };
    }
}

// ---------------------------------------------------------------------------
// fast-md5 native backend (highest priority when feature = "fast-md5")
// ---------------------------------------------------------------------------

/// Incremental HMAC-MD5 context backed by `fast_md5::HmacMd5`.
///
/// Precomputes the ipad/opad MD5 states at construction time (two
/// 64-byte block compressions, done once per key), so `update` and
/// `finalize` carry no key-schedule overhead.
#[cfg(feature = "fast-md5")]
pub(crate) struct HmacMd5 {
    inner: fast_md5::HmacMd5,
}

#[cfg(feature = "fast-md5")]
impl HmacMd5 {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            inner: fast_md5::HmacMd5::new(key),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finalize(self) -> [u8; TAG_LEN] {
        self.inner.finalize()
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
            (&[0xaa; 16], &[0xdd; 50], "56be34521d144c88dbb8c733f0e8b3f6"),
            (
                &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                ],
                &[0xcd; 50],
                "697eaf0aca3a3aea3a75164746ffaa79",
            ),
            (
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            ),
            (
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger \
                  Than One Block-Size Data",
                "6f630fad67cda0ee1fb1f562db3aa53e",
            ),
        ];

        for (key, data, expected) in cases {
            let mut ctx = HmacMd5::new(key);
            ctx.update(data);
            assert_eq!(hex(&ctx.finalize()), *expected, "key.len() = {}", key.len());
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
        let _ctx = HmacMd5::new(b"key");
    }
}
