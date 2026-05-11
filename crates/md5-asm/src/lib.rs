//! Experimental MD5 block compressor backed by the vendored
//! [`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
//! inline-assembly headers, built in-tree through a thin C++ shim.
//!
//! This crate exposes **only** the per-block MD5 compression step:
//! given a 4×u32 state (initialized by the caller to the standard
//! MD5 IV or a partial result) and a 64-byte block, it produces
//! the updated state. Buffering, length encoding, and final
//! padding are the caller's responsibility — see the
//! `radius_tokio::crypto::md5` integration which wraps this in a
//! streaming hasher.
//!
//! This crate is intentionally minimal and `#![no_std]`-compatible
//! (apart from `extern "C"` declarations). It performs no
//! allocation.

#![no_std]
#![allow(unsafe_code)]

/// MD5 block size in bytes.
pub const BLOCK_SIZE: usize = 64;

/// MD5 state size in 32-bit words (A, B, C, D).
pub const STATE_WORDS: usize = 4;

unsafe extern "C" {
    fn md5_asm_block_std(state: *mut u32, block: *const u8);
    fn md5_asm_blocks_std(state: *mut u32, data: *const u8, nblocks: usize);

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn md5_asm_block_gopt(state: *mut u32, block: *const u8);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn md5_asm_block_noleag(state: *mut u32, block: *const u8);
}

/// Compress one 64-byte block into `state` using the upstream
/// "Standard" variant (the 0% baseline in the published benchmarks).
///
/// The caller must initialize `state` to the MD5 IV
/// `[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]` before the
/// first call, then keep feeding 64-byte blocks. The final block
/// must already contain the `0x80` terminator and the 64-bit
/// length trailer per RFC 1321 §3.
#[inline]
pub fn block_std(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    // SAFETY: `state` is a valid pointer to exactly 4 contiguous
    // u32s (16 bytes), and `block` is a valid pointer to exactly
    // 64 bytes. The C++ shim's `MD5_STATE<uint32_t>` has identical
    // size, alignment, and field order to `[u32; 4]` (asserted by
    // `static_assert` in the shim). No aliasing: the shim does
    // not retain either pointer past return.
    unsafe { md5_asm_block_std(state.as_mut_ptr(), block.as_ptr()) }
}

/// Compress `blocks.len() / 64` consecutive blocks into `state`.
///
/// # Panics
///
/// Panics if `blocks.len()` is not a multiple of [`BLOCK_SIZE`].
#[inline]
pub fn blocks_std(state: &mut [u32; STATE_WORDS], blocks: &[u8]) {
    assert!(
        blocks.len() % BLOCK_SIZE == 0,
        "blocks_std: input must be a multiple of 64 bytes"
    );
    let n = blocks.len() / BLOCK_SIZE;
    if n == 0 {
        return;
    }
    // SAFETY: see `block_std`. `data` points to `n * 64` contiguous
    // bytes of `blocks`; the loop body inside the shim only reads
    // 64 bytes per iteration.
    unsafe { md5_asm_blocks_std(state.as_mut_ptr(), blocks.as_ptr(), n) }
}

/// x86/x86_64 "GOpt" variant — Standard with the G-function
/// dependency shortcut applied.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub fn block_gopt(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    // SAFETY: see `block_std`.
    unsafe { md5_asm_block_gopt(state.as_mut_ptr(), block.as_ptr()) }
}

/// x86/x86_64 "NoLEA-G" variant — GOpt with `LEA` replaced by two
/// `ADD`s. Typically the fastest non-AVX512 variant in the upstream
/// benchmarks.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
pub fn block_noleag(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    // SAFETY: see `block_std`.
    unsafe { md5_asm_block_noleag(state.as_mut_ptr(), block.as_ptr()) }
}

/// Standard MD5 initialization vector (RFC 1321 §3.3).
pub const IV: [u32; STATE_WORDS] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

// ---------------------------------------------------------------------------
// AVX512 single-buffer compressor (x86_64-only, opt-in via `avx512` feature).
// ---------------------------------------------------------------------------
//
// Upstream-reported speedup over the "Standard" variant: +23.11% on
// Skylake-X (the only x86 entry in the published benchmark table to
// clear +10%). Hot caveat: AMD Zen ≤ 3 has 2-cycle vector rotate
// latency, which makes this *slower* than `block_std` on those
// uarchs even though `avx512vl` is reported as supported. Use the
// `is_avx512_supported` helper to gate calls; consider an
// additional vendor check for Zen workloads.

#[cfg(all(feature = "avx512", target_arch = "x86_64"))]
unsafe extern "C" {
    fn md5_asm_block_avx512(state: *mut u32, block: *const u8);
    fn md5_asm_blocks_avx512(state: *mut u32, data: *const u8, nblocks: usize);
}

/// Returns `true` if the running CPU supports the AVX512 variant
/// of [`block_avx512`] / [`blocks_avx512`].
///
/// Performs the standard `is_x86_feature_detected!("avx512vl")`
/// check on x86_64; returns `false` on every other architecture
/// or when the `avx512` Cargo feature is not enabled.
#[must_use]
#[inline]
pub fn is_avx512_supported() -> bool {
    #[cfg(all(feature = "avx512", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("avx512vl")
            && std::arch::is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(all(feature = "avx512", target_arch = "x86_64")))]
    {
        false
    }
}

/// AVX512 single-block compressor.
///
/// # Safety
///
/// The caller must verify [`is_avx512_supported`] returned `true`
/// before invoking. Running this on a CPU without `avx512vl` +
/// `avx512f` will raise `SIGILL`.
#[cfg(all(feature = "avx512", target_arch = "x86_64"))]
#[inline]
pub unsafe fn block_avx512(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    // SAFETY: caller has asserted AVX512VL availability; pointer
    // layout matches the shim's `static_assert`s.
    unsafe { md5_asm_block_avx512(state.as_mut_ptr(), block.as_ptr()) }
}

/// AVX512 multi-block compressor.
///
/// Holds the MD5 state in vector registers across the loop, so the
/// per-call `__m128i` ↔ `[u32; 4]` bridge cost is paid once
/// regardless of input size.
///
/// # Safety
///
/// Same as [`block_avx512`].
///
/// # Panics
///
/// Panics if `blocks.len()` is not a multiple of [`BLOCK_SIZE`].
#[cfg(all(feature = "avx512", target_arch = "x86_64"))]
#[inline]
pub unsafe fn blocks_avx512(state: &mut [u32; STATE_WORDS], blocks: &[u8]) {
    assert!(
        blocks.len() % BLOCK_SIZE == 0,
        "blocks_avx512: input must be a multiple of 64 bytes"
    );
    let n = blocks.len() / BLOCK_SIZE;
    if n == 0 {
        return;
    }
    // SAFETY: caller has asserted AVX512VL availability.
    unsafe { md5_asm_blocks_avx512(state.as_mut_ptr(), blocks.as_ptr(), n) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer: empty message.
    // The standard MD5 padding for an empty input is:
    //   0x80, 63 zero bytes (but the last 8 of those are the 64-bit
    //   length = 0). So a single block of [0x80, 0, ..., 0].
    #[test]
    fn empty_message() {
        let mut state = IV;
        let mut block = [0u8; 64];
        block[0] = 0x80;
        // length in bits = 0; trailer already zeroed.
        block_std(&mut state, &block);
        // d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(state[0].to_le_bytes(), [0xd4, 0x1d, 0x8c, 0xd9]);
        assert_eq!(state[1].to_le_bytes(), [0x8f, 0x00, 0xb2, 0x04]);
        assert_eq!(state[2].to_le_bytes(), [0xe9, 0x80, 0x09, 0x98]);
        assert_eq!(state[3].to_le_bytes(), [0xec, 0xf8, 0x42, 0x7e]);
    }

    // Known-answer: "abc" (RFC 1321 Appendix A.5).
    #[test]
    fn abc_message() {
        let mut state = IV;
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        // length in bits = 24 = 0x18, little-endian, last 8 bytes.
        let bits: u64 = 24;
        block[56..64].copy_from_slice(&bits.to_le_bytes());
        block_std(&mut state, &block);
        // 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(state[0].to_le_bytes(), [0x90, 0x01, 0x50, 0x98]);
        assert_eq!(state[1].to_le_bytes(), [0x3c, 0xd2, 0x4f, 0xb0]);
        assert_eq!(state[2].to_le_bytes(), [0xd6, 0x96, 0x3f, 0x7d]);
        assert_eq!(state[3].to_le_bytes(), [0x28, 0xe1, 0x7f, 0x72]);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn variants_agree_with_std() {
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        let bits: u64 = 24;
        block[56..64].copy_from_slice(&bits.to_le_bytes());

        let mut s0 = IV;
        block_std(&mut s0, &block);
        let mut s1 = IV;
        block_gopt(&mut s1, &block);
        let mut s2 = IV;
        block_noleag(&mut s2, &block);
        assert_eq!(s0, s1);
        assert_eq!(s0, s2);
    }

    #[test]
    fn blocks_driver_matches_per_block() {
        // Two blocks of arbitrary data.
        let mut buf = [0u8; 128];
        for (i, b) in buf.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u8;
            *b = v.wrapping_mul(31).wrapping_add(7);
        }
        let mut s_loop = IV;
        let mut s_drv = IV;
        for chunk in buf.chunks_exact(64) {
            let arr: &[u8; 64] = chunk.try_into().unwrap();
            block_std(&mut s_loop, arr);
        }
        blocks_std(&mut s_drv, &buf);
        assert_eq!(s_loop, s_drv);
    }

    #[cfg(all(feature = "avx512", target_arch = "x86_64"))]
    #[test]
    fn avx512_matches_std_when_supported() {
        if !is_avx512_supported() {
            eprintln!("avx512 not available on this CPU; skipping");
            return;
        }
        // "abc" padded block.
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        let bits: u64 = 24;
        block[56..64].copy_from_slice(&bits.to_le_bytes());

        let mut s_std = IV;
        block_std(&mut s_std, &block);
        let mut s_avx = IV;
        // SAFETY: gated by is_avx512_supported().
        unsafe { block_avx512(&mut s_avx, &block) };
        assert_eq!(s_std, s_avx);

        // Multi-block: two synthetic blocks.
        let mut buf = [0u8; 128];
        for (i, b) in buf.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u8;
            *b = v.wrapping_mul(31).wrapping_add(7);
        }
        let mut a = IV;
        blocks_std(&mut a, &buf);
        let mut b = IV;
        // SAFETY: gated by is_avx512_supported().
        unsafe { blocks_avx512(&mut b, &buf) };
        assert_eq!(a, b);
    }
}
