//! Safe wrappers for the MD5 functions in `aws-lc-sys`.
//!
//! MD5 is cryptographically broken. Its use here is limited to the RADIUS
//! wire format (RFC 2865 authenticators, User-Password obfuscation) where
//! the protocol mandates it.
//!
//! When the optional `md5-asm` Cargo feature is enabled the per-block
//! compressor is sourced from the [`md5-asm`] workspace crate (a C++
//! shim around the vendored
//! [`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
//! inline-asm headers) instead of `aws-lc-sys`. The public surface of
//! this module is identical either way.

#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
use std::mem::MaybeUninit;

#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
use aws_lc_sys::{MD5_Final, MD5_Init, MD5_Transform, MD5_Update, MD5, MD5_CTX};

/// MD5 block size in bytes.
#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
pub(crate) const BLOCK_SIZE: usize = aws_lc_sys::MD5_CBLOCK as usize;
#[cfg(all(feature = "md5-asm", not(target_env = "msvc")))]
pub(crate) const BLOCK_SIZE: usize = md5_asm::BLOCK_SIZE;

/// MD5 digest length in bytes.
#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
pub(crate) const DIGEST_LENGTH: usize = aws_lc_sys::MD5_DIGEST_LENGTH as usize;
#[cfg(all(feature = "md5-asm", not(target_env = "msvc")))]
pub(crate) const DIGEST_LENGTH: usize = 16;

/// Hashes `data` and returns the 16-byte MD5 digest.
#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
pub(crate) fn digest(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut out = [0u8; DIGEST_LENGTH];
    // SAFETY: data is a valid slice for data.len() bytes. out is exactly
    // DIGEST_LENGTH bytes. MD5() returns a pointer to out on success; it
    // only returns NULL if out is NULL, which cannot happen here.
    let ret = unsafe { MD5(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!ret.is_null(), "MD5 failed");
    out
}

/// Hashes `data` and returns the 16-byte MD5 digest (asm backend).
#[cfg(all(feature = "md5-asm", not(target_env = "msvc")))]
pub(crate) fn digest(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// aws-lc-sys backend (default)
// ---------------------------------------------------------------------------

/// Incremental MD5 digest context.
///
/// Call [`update`][Md5::update] one or more times, then [`finalize`][Md5::finalize].
/// `finalize` consumes `self` to prevent reuse.
#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
pub(crate) struct Md5 {
    ctx: MD5_CTX,
}

#[cfg(any(not(feature = "md5-asm"), target_env = "msvc"))]
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

// ---------------------------------------------------------------------------
// md5-asm backend (experimental, opt-in via `md5-asm` feature)
// ---------------------------------------------------------------------------

/// Incremental MD5 digest context, backed by the vendored
/// `animetosho/md5-optimisation` inline-asm block compressor.
///
/// The compressor is FFI; the rest of the state machine (padding,
/// length encoding, buffering) is plain Rust. No allocation on
/// the steady-state path.
#[cfg(all(feature = "md5-asm", not(target_env = "msvc")))]
pub(crate) struct Md5 {
    state: [u32; 4],
    buf: [u8; BLOCK_SIZE],
    /// Number of bytes currently held in `buf` (`0..BLOCK_SIZE`).
    buf_len: usize,
    /// Total bytes consumed via `update`.
    total_len: u64,
}

#[cfg(all(feature = "md5-asm", not(target_env = "msvc")))]
impl Md5 {
    pub(crate) fn new() -> Self {
        Self {
            state: md5_asm::IV,
            buf: [0u8; BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// One-time runtime backend selection. With the
    /// `md5-asm-avx512` feature enabled and an AVX512-capable CPU,
    /// returns `true`; otherwise the scalar `block_std` path is
    /// used. Plain `md5-asm` always returns `false`.
    #[cfg(all(feature = "md5-asm-avx512", not(target_env = "msvc")))]
    #[inline]
    fn use_avx512() -> bool {
        use std::sync::OnceLock;
        static CACHED: OnceLock<bool> = OnceLock::new();
        *CACHED.get_or_init(md5_asm::is_avx512_supported)
    }
    #[cfg(any(not(feature = "md5-asm-avx512"), target_env = "msvc"))]
    #[inline]
    fn use_avx512() -> bool {
        false
    }

    #[inline]
    fn compress_block(state: &mut [u32; 4], block: &[u8; BLOCK_SIZE]) {
        #[cfg(all(
            feature = "md5-asm-avx512",
            target_arch = "x86_64",
            not(target_env = "msvc")
        ))]
        if Self::use_avx512() {
            // SAFETY: `use_avx512` only returns true if
            // `is_avx512_supported()` was true.
            unsafe { md5_asm::block_avx512(state, block) };
            return;
        }
        md5_asm::block(state, block);
    }

    #[inline]
    fn compress_blocks(state: &mut [u32; 4], blocks: &[u8]) {
        #[cfg(all(
            feature = "md5-asm-avx512",
            target_arch = "x86_64",
            not(target_env = "msvc")
        ))]
        if Self::use_avx512() {
            // SAFETY: as above.
            unsafe { md5_asm::blocks_avx512(state, blocks) };
            return;
        }
        md5_asm::blocks(state, blocks);
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self
            .total_len
            .checked_add(data.len() as u64)
            .expect("MD5 input length overflowed u64");

        // Top up a partially-filled buffer first.
        if self.buf_len > 0 {
            let need = BLOCK_SIZE - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_SIZE {
                Self::compress_block(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }

        // Compress full blocks directly out of `data` (zero-copy).
        let full = data.len() / BLOCK_SIZE * BLOCK_SIZE;
        if full > 0 {
            Self::compress_blocks(&mut self.state, &data[..full]);
            data = &data[full..];
        }

        // Stash the remainder.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LENGTH] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Append 0x80, then zero-pad so the length field falls in the
        // last 8 bytes of a 64-byte block. RFC 1321 §3.1.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > BLOCK_SIZE - 8 {
            // Not enough room for the length; flush this block first.
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            Self::compress_block(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..BLOCK_SIZE - 8] {
            *b = 0;
        }
        self.buf[BLOCK_SIZE - 8..].copy_from_slice(&bit_len.to_le_bytes());
        Self::compress_block(&mut self.state, &self.buf);

        let mut out = [0u8; DIGEST_LENGTH];
        out[0..4].copy_from_slice(&self.state[0].to_le_bytes());
        out[4..8].copy_from_slice(&self.state[1].to_le_bytes());
        out[8..12].copy_from_slice(&self.state[2].to_le_bytes());
        out[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        out
    }

    /// Applies a single 64-byte block transformation. Mirrors the
    /// `aws-lc-sys` backend's `MD5_Transform`-shaped escape hatch:
    /// callers that use this **must not** mix it with `update` /
    /// `finalize` on the same instance; it bypasses the buffered
    /// streaming state.
    pub(crate) fn transform(&mut self, block: &[u8; BLOCK_SIZE]) {
        Self::compress_block(&mut self.state, block);
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
