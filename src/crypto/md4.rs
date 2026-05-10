//! Safe wrappers for the MD4 functions in `aws-lc-sys`.
//!
//! MD4 is cryptographically broken. Its use here is limited to the
//! MS-CHAP wire format (RFC 2433 / RFC 2759) where the protocol
//! mandates it for the NT hash (`NtPasswordHash`).

use std::mem::MaybeUninit;

use aws_lc_sys::{MD4_Final, MD4_Init, MD4_Transform, MD4_Update, MD4, MD4_CTX};

/// MD4 block size in bytes.
pub(crate) const BLOCK_SIZE: usize = aws_lc_sys::MD4_CBLOCK as usize;

/// MD4 digest length in bytes.
pub(crate) const DIGEST_LENGTH: usize = aws_lc_sys::MD4_DIGEST_LENGTH as usize;

/// Hashes `data` and returns the 16-byte MD4 digest.
pub(crate) fn digest(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut out = [0u8; DIGEST_LENGTH];
    // SAFETY: data is a valid slice for data.len() bytes. out is exactly
    // DIGEST_LENGTH bytes. MD4() returns a pointer to out on success; it
    // only returns NULL if out is NULL, which cannot happen here.
    let ret = unsafe { MD4(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!ret.is_null(), "MD4 failed");
    out
}

/// Incremental MD4 digest context.
///
/// Call [`update`][Md4::update] one or more times, then
/// [`finalize`][Md4::finalize]. `finalize` consumes `self` to prevent
/// reuse of a finished context.
pub(crate) struct Md4 {
    ctx: MD4_CTX,
}

impl Md4 {
    /// Initializes a new MD4 context.
    pub(crate) fn new() -> Self {
        // SAFETY: MD4_Init writes every field of md4_state_st before we call
        // assume_init. MaybeUninit gives a properly aligned allocation without
        // reading uninitialized memory.
        let mut ctx = MaybeUninit::<MD4_CTX>::uninit();
        let ret = unsafe { MD4_Init(ctx.as_mut_ptr()) };
        // aws-lc returns 1 unconditionally for a valid (non-null) pointer.
        assert_eq!(ret, 1, "MD4_Init failed");
        // SAFETY: MD4_Init returned 1, all fields are initialized.
        Self {
            ctx: unsafe { ctx.assume_init() },
        }
    }

    /// Feeds `data` into the digest. May be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialized and not yet finalized. data is a valid
        // slice for the duration of this call.
        let ret = unsafe {
            MD4_Update(
                &mut self.ctx,
                data.as_ptr().cast::<std::os::raw::c_void>(),
                data.len(),
            )
        };
        assert_eq!(ret, 1, "MD4_Update failed");
    }

    /// Finalizes the digest and returns the 16-byte output.
    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LENGTH] {
        let mut out = [0u8; DIGEST_LENGTH];
        // SAFETY: out is exactly DIGEST_LENGTH bytes. ctx is initialized and
        // not previously finalized.
        let ret = unsafe { MD4_Final(out.as_mut_ptr(), &mut self.ctx) };
        assert_eq!(ret, 1, "MD4_Final failed");
        out
    }

    /// Applies a single MD4 block transformation to `self` using `block`.
    ///
    /// Low-level primitive; prefer [`update`][Md4::update] for normal use.
    pub(crate) fn transform(&mut self, block: &[u8; BLOCK_SIZE]) {
        // SAFETY: ctx is initialized. block is exactly BLOCK_SIZE (64) bytes
        // as enforced by the array reference type.
        unsafe {
            MD4_Transform(&mut self.ctx, block.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1320 Appendix A.5 known-answer vectors.
    const VECTORS: &[(&[u8], &str)] = &[
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
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
            let mut ctx = Md4::new();
            ctx.update(input);
            let got = ctx.finalize();
            assert_eq!(hex(&got), *expected, "input = {input:?}");
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = digest(data);

        let mut ctx = Md4::new();
        for byte in data {
            ctx.update(std::slice::from_ref(byte));
        }
        assert_eq!(ctx.finalize(), expected);
    }

    #[test]
    fn incremental_multi_update() {
        let mut ctx = Md4::new();
        ctx.update(b"a");
        ctx.update(b"b");
        ctx.update(b"c");
        assert_eq!(hex(&ctx.finalize()), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn drop_without_finalize() {
        // MD4_CTX has no heap resources; drop without finalize must not panic.
        let _ctx = Md4::new();
    }

    #[test]
    fn transform_smoke() {
        let mut ctx = Md4::new();
        ctx.transform(&[0u8; BLOCK_SIZE]);
    }
}
