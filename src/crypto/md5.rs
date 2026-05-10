//! Safe wrappers for the MD5 functions in `aws-lc-sys`.
//!
//! MD5 is cryptographically broken. Its use here is limited to the RADIUS
//! wire format (RFC 2865 authenticators, User-Password obfuscation) where
//! the protocol mandates it.

use std::mem::MaybeUninit;

use aws_lc_sys::{MD5_Final, MD5_Init, MD5_Transform, MD5_Update, MD5, MD5_CTX};

/// MD5 block size in bytes (re-exported from `aws_lc_sys`).
pub(crate) const BLOCK_SIZE: usize = aws_lc_sys::MD5_CBLOCK as usize;

/// MD5 digest length in bytes (re-exported from `aws_lc_sys`).
pub(crate) const DIGEST_LENGTH: usize = aws_lc_sys::MD5_DIGEST_LENGTH as usize;

/// Hashes `data` and returns the 16-byte MD5 digest.
pub(crate) fn digest(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut out = [0u8; DIGEST_LENGTH];
    // SAFETY: data is a valid slice for data.len() bytes. out is exactly
    // DIGEST_LENGTH bytes. MD5() returns a pointer to out on success; it
    // only returns NULL if out is NULL, which cannot happen here.
    let ret = unsafe { MD5(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!ret.is_null(), "MD5 failed");
    out
}

/// Incremental MD5 digest context.
///
/// Call [`update`][Md5::update] one or more times, then [`finalize`][Md5::finalize].
/// `finalize` consumes `self` to prevent reuse.
pub(crate) struct Md5 {
    ctx: MD5_CTX,
}

impl Md5 {
    /// Initializes a new MD5 context.
    pub(crate) fn new() -> Self {
        // SAFETY: MD5_Init writes every field of md5_state_st before we call
        // assume_init. MaybeUninit gives a properly aligned allocation without
        // reading uninitialized memory.
        let mut ctx = MaybeUninit::<MD5_CTX>::uninit();
        let ret = unsafe { MD5_Init(ctx.as_mut_ptr()) };
        // aws-lc returns 1 unconditionally for a valid (non-null) pointer.
        assert_eq!(ret, 1, "MD5_Init failed");
        // SAFETY: MD5_Init returned 1, all fields are initialized.
        Self {
            ctx: unsafe { ctx.assume_init() },
        }
    }

    /// Feeds `data` into the digest. May be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialized and not yet finalized. data is a valid
        // slice for the duration of this call.
        let ret = unsafe {
            MD5_Update(
                &mut self.ctx,
                data.as_ptr().cast::<std::os::raw::c_void>(),
                data.len(),
            )
        };
        assert_eq!(ret, 1, "MD5_Update failed");
    }

    /// Finalizes the digest and returns the 16-byte output.
    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LENGTH] {
        let mut out = [0u8; DIGEST_LENGTH];
        // SAFETY: out is exactly DIGEST_LENGTH bytes. ctx is initialized and
        // not previously finalized.
        let ret = unsafe { MD5_Final(out.as_mut_ptr(), &mut self.ctx) };
        assert_eq!(ret, 1, "MD5_Final failed");
        out
    }

    /// Applies a single MD5 block transformation to `self` using `block`.
    ///
    /// Low-level primitive; prefer [`update`][Md5::update] for normal use.
    pub(crate) fn transform(&mut self, block: &[u8; BLOCK_SIZE]) {
        // SAFETY: ctx is initialized. block is exactly BLOCK_SIZE (64) bytes
        // as enforced by the array reference type.
        unsafe {
            MD5_Transform(&mut self.ctx, block.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 Appendix A.5 known-answer vectors.
    const VECTORS: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    #[test]
    fn oneshot_known_answers() {
        for (input, expected) in VECTORS {
            let got = digest(input);
            assert_eq!(hex(&got), *expected, "input = {input:?}");
        }
    }

    #[test]
    fn incremental_single_update() {
        for (input, expected) in VECTORS {
            let mut ctx = Md5::new();
            ctx.update(input);
            let got = ctx.finalize();
            assert_eq!(hex(&got), *expected, "input = {input:?}");
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = digest(data);

        let mut ctx = Md5::new();
        for byte in data {
            ctx.update(std::slice::from_ref(byte));
        }
        assert_eq!(ctx.finalize(), expected);
    }

    #[test]
    fn incremental_multi_update() {
        let mut ctx = Md5::new();
        ctx.update(b"a");
        ctx.update(b"b");
        ctx.update(b"c");
        assert_eq!(hex(&ctx.finalize()), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn drop_without_finalize() {
        // MD5_CTX has no heap resources; drop without finalize must not panic.
        let _ctx = Md5::new();
    }

    #[test]
    fn transform_smoke() {
        let mut ctx = Md5::new();
        ctx.transform(&[0u8; BLOCK_SIZE]);
    }
}
