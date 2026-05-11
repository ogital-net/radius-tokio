//! MD5 block compressor backed by the vendored
//! [`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
//! inline-assembly headers, exposed to Rust through a thin C++
//! shim built with [`cc`](https://crates.io/crates/cc).
//!
//! This crate exposes **only** the per-block MD5 compression step:
//! given a 4×u32 state (initialized by the caller to the standard
//! MD5 IV or a partial result) and a 64-byte block, it produces
//! the updated state. Buffering, length encoding, and final
//! padding are the caller's responsibility — see the crate
//! [README](https://github.com/example/radius-tokio/tree/main/crates/md5-asm)
//! for a worked example, or
//! [`radius_tokio::crypto::md5`](https://docs.rs/radius-tokio) for
//! a full streaming hasher built on top of this primitive.
//!
//! `#![no_std]`. No allocation. No transitive runtime
//! dependencies.
//!
//! # MSVC
//!
//! The vendored upstream headers use GCC inline asm and
//! `__attribute__((always_inline))`, neither of which `cl.exe`
//! understands. On `target_env = "msvc"` the build script skips
//! the C++ shim entirely and every block-compressor function
//! transparently dispatches to a pure-Rust RFC 1321 reference
//! implementation. The asm-grade speedup is **not** delivered on
//! that target, so the MSVC entry points are marked
//! `#[deprecated]` to nudge callers — the crate still builds and
//! produces correct digests, but you'll likely get better
//! performance from a different MD5 backend (e.g. `aws-lc-sys`'s
//! `MD5`). For the real asm speedup on
//! Windows, build with `x86_64-pc-windows-gnu` or `clang-cl`.

#![no_std]
#![allow(unsafe_code)]

/// MD5 block size in bytes.
pub const BLOCK_SIZE: usize = 64;

/// MD5 state size in 32-bit words (A, B, C, D).
pub const STATE_WORDS: usize = 4;

// On MSVC the upstream vendored headers can't be compiled (they
// use GCC inline asm and `__attribute__((always_inline))`), so
// the build script skips the C++ shim entirely and the FFI block
// below is excluded. The public block-compressor functions stay
// available on MSVC — they dispatch to the pure-Rust
// [`rust_fallback`] module instead and are marked `#[deprecated]`
// so callers get a compile-time nudge that the asm speedup is
// not being delivered on that target. For asm-grade performance
// on Windows, build with `x86_64-pc-windows-gnu` or `clang-cl`.
#[cfg(not(target_env = "msvc"))]
unsafe extern "C" {
    fn md5_asm_block_std(state: *mut u32, block: *const u8);
    fn md5_asm_blocks_std(state: *mut u32, data: *const u8, nblocks: usize);

    fn md5_asm_block(state: *mut u32, block: *const u8);
    fn md5_asm_blocks(state: *mut u32, data: *const u8, nblocks: usize);

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn md5_asm_block_gopt(state: *mut u32, block: *const u8);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn md5_asm_block_noleag(state: *mut u32, block: *const u8);
}

// Pure-Rust MD5 block compressor used as the MSVC fallback. RFC
// 1321 §3.4 reference construction. Slow compared to the vendored
// asm variants; meant only to keep this crate buildable on MSVC,
// not to compete on speed. Consumers that care about MD5
// performance on MSVC should pick a different backend (e.g.
// `aws-lc-sys`'s MD5).
#[cfg(target_env = "msvc")]
mod rust_fallback {
    use super::{BLOCK_SIZE, STATE_WORDS};

    // Per-round constants (RFC 1321 §3.4).
    const T: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    // Per-round shift amounts.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    #[inline(always)]
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    #[inline(always)]
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }
    #[inline(always)]
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    #[inline(always)]
    fn i(x: u32, y: u32, z: u32) -> u32 {
        y ^ (x | !z)
    }

    pub(super) fn block(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
        let mut m = [0u32; 16];
        for (j, chunk) in block.chunks_exact(4).enumerate() {
            m[j] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

        for j in 0..64 {
            let (fval, k) = if j < 16 {
                (f(b, c, d), j)
            } else if j < 32 {
                (g(b, c, d), (5 * j + 1) % 16)
            } else if j < 48 {
                (h(b, c, d), (3 * j + 5) % 16)
            } else {
                (i(b, c, d), (7 * j) % 16)
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(fval)
                    .wrapping_add(T[j])
                    .wrapping_add(m[k])
                    .rotate_left(S[j]),
            );
            a = temp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

/// Compress one 64-byte block into `state` using the upstream
/// "Standard" variant (the 0% baseline in the published benchmarks).
///
/// The caller must initialize `state` to the MD5 IV
/// `[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]` before the
/// first call, then keep feeding 64-byte blocks. The final block
/// must already contain the `0x80` terminator and the 64-bit
/// length trailer per RFC 1321 §3.
///
/// On `target_env = "msvc"` this dispatches to a pure-Rust fallback
/// (the vendored asm headers can't be compiled by `cl.exe`) and is
/// marked `#[deprecated]` so callers get a compile-time nudge.
#[cfg_attr(
    target_env = "msvc",
    deprecated(note = "md5-asm on MSVC falls back to a pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl")
)]
#[inline]
pub fn block_std(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    #[cfg(target_env = "msvc")]
    {
        rust_fallback::block(state, block);
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: `state` is a valid pointer to exactly 4 contiguous
    // u32s (16 bytes), and `block` is a valid pointer to exactly
    // 64 bytes. The C++ shim's `MD5_STATE<uint32_t>` has identical
    // size, alignment, and field order to `[u32; 4]` (asserted by
    // `static_assert` in the shim). No aliasing: the shim does
    // not retain either pointer past return.
    unsafe {
        md5_asm_block_std(state.as_mut_ptr(), block.as_ptr());
    }
}

/// Compress `blocks.len() / 64` consecutive blocks into `state`.
///
/// On `target_env = "msvc"` this dispatches to a pure-Rust fallback
/// (the vendored asm headers can't be compiled by `cl.exe`) and is
/// marked `#[deprecated]` so callers get a compile-time nudge.
///
/// # Panics
///
/// Panics if `blocks.len()` is not a multiple of [`BLOCK_SIZE`].
#[cfg_attr(
    target_env = "msvc",
    deprecated(
        note = "md5-asm on MSVC falls back to a slow pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl"
    )
)]
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
    #[cfg(target_env = "msvc")]
    {
        for chunk in blocks.chunks_exact(BLOCK_SIZE) {
            let arr: &[u8; BLOCK_SIZE] = chunk.try_into().expect("chunk is 64 bytes");
            rust_fallback::block(state, arr);
        }
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: see `block_std`. `data` points to `n * 64` contiguous
    // bytes of `blocks`; the loop body inside the shim only reads
    // 64 bytes per iteration.
    unsafe {
        md5_asm_blocks_std(state.as_mut_ptr(), blocks.as_ptr(), n);
    }
}

/// x86/x86_64 "GOpt" variant — Standard with the G-function
/// dependency shortcut applied.
///
/// On `target_env = "msvc"` this dispatches to the same pure-Rust
/// fallback as [`block_std`] and is marked `#[deprecated]`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(
    target_env = "msvc",
    deprecated(note = "md5-asm on MSVC falls back to a pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl")
)]
#[inline]
pub fn block_gopt(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    #[cfg(target_env = "msvc")]
    {
        rust_fallback::block(state, block);
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: see `block_std`.
    unsafe {
        md5_asm_block_gopt(state.as_mut_ptr(), block.as_ptr());
    }
}

/// x86/x86_64 "NoLEA-G" variant — GOpt with `LEA` replaced by two
/// `ADD`s. Typically the fastest non-AVX512 variant in the upstream
/// benchmarks.
///
/// On `target_env = "msvc"` this dispatches to the same pure-Rust
/// fallback as [`block_std`] and is marked `#[deprecated]`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(
    target_env = "msvc",
    deprecated(note = "md5-asm on MSVC falls back to a pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl")
)]
#[inline]
pub fn block_noleag(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    #[cfg(target_env = "msvc")]
    {
        rust_fallback::block(state, block);
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: see `block_std`.
    unsafe {
        md5_asm_block_noleag(state.as_mut_ptr(), block.as_ptr());
    }
}

/// Compress one 64-byte block using the **architecture-best**
/// upstream variant for sequential single-buffer hashing:
///
/// * `x86` / `x86_64` → "NoLEA-G" (fastest non-AVX512 variant in
///   the published benchmarks).
/// * `aarch64` → "Standard" (the only ARM64 variant upstream
///   ships).
///
/// This is the entry point most callers should use. The named
/// per-variant functions ([`block_std`], [`block_gopt`],
/// [`block_noleag`]) remain available for benchmarking and for
/// callers that need a specific tuning.
///
/// AVX512 is **not** selected here: it requires runtime CPU
/// detection and its multi-buffer / wide-SIMD layout is not a
/// win for short single-stream inputs. Gate it behind the
/// `is_avx512_supported` helper and call [`block_avx512`]
/// directly when appropriate.
///
/// On `target_env = "msvc"` this dispatches to a pure-Rust
/// fallback (the vendored asm headers can't be compiled by
/// `cl.exe`) and is marked `#[deprecated]`.
#[cfg_attr(
    target_env = "msvc",
    deprecated(note = "md5-asm on MSVC falls back to a pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl")
)]
#[inline]
pub fn block(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    #[cfg(target_env = "msvc")]
    {
        rust_fallback::block(state, block);
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: see `block_std`. The C++ shim picks the best
    // upstream variant at compile time via `#ifdef`; ABI is
    // identical to every other entry point.
    unsafe {
        md5_asm_block(state.as_mut_ptr(), block.as_ptr());
    }
}

/// Compress `blocks.len() / 64` consecutive blocks using the
/// architecture-best variant. See [`block`] for the variant
/// selection rationale.
///
/// On `target_env = "msvc"` this dispatches to a pure-Rust
/// fallback and is marked `#[deprecated]`.
///
/// # Panics
///
/// Panics if `blocks.len()` is not a multiple of [`BLOCK_SIZE`].
#[cfg_attr(
    target_env = "msvc",
    deprecated(note = "md5-asm on MSVC falls back to a pure-Rust block compressor; \
                use a different MD5 backend or build with x86_64-pc-windows-gnu / clang-cl")
)]
#[inline]
pub fn blocks(state: &mut [u32; STATE_WORDS], blocks: &[u8]) {
    assert!(
        blocks.len() % BLOCK_SIZE == 0,
        "blocks: input must be a multiple of 64 bytes"
    );
    let n = blocks.len() / BLOCK_SIZE;
    if n == 0 {
        return;
    }
    #[cfg(target_env = "msvc")]
    {
        for chunk in blocks.chunks_exact(BLOCK_SIZE) {
            let arr: &[u8; BLOCK_SIZE] = chunk.try_into().expect("chunk is 64 bytes");
            rust_fallback::block(state, arr);
        }
    }
    #[cfg(not(target_env = "msvc"))]
    // SAFETY: see `blocks_std`.
    unsafe {
        md5_asm_blocks(state.as_mut_ptr(), blocks.as_ptr(), n);
    }
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

#[cfg(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc")))]
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
    #[cfg(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc")))]
    {
        std::arch::is_x86_feature_detected!("avx512vl")
            && std::arch::is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc"))))]
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
#[cfg(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc")))]
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
#[cfg(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc")))]
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
    // The fallback path on MSVC triggers the deprecation warnings
    // on every call; this is intentional for downstream callers
    // but noisy inside the crate's own tests.
    #![allow(deprecated)]
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

    // The architecture-best `block` / `blocks` entry points must
    // agree with `block_std` for every input — they only differ in
    // which upstream variant the C++ shim picks at compile time.
    #[test]
    fn arch_best_matches_std() {
        let mut buf = [0u8; 128];
        for (i, b) in buf.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let v = i as u8;
            *b = v.wrapping_mul(31).wrapping_add(7);
        }
        // Single-block.
        let single: &[u8; 64] = buf[..64].try_into().unwrap();
        let mut s_std = IV;
        block_std(&mut s_std, single);
        let mut s_best = IV;
        block(&mut s_best, single);
        assert_eq!(s_std, s_best);

        // Multi-block driver.
        let mut s_std_m = IV;
        blocks_std(&mut s_std_m, &buf);
        let mut s_best_m = IV;
        blocks(&mut s_best_m, &buf);
        assert_eq!(s_std_m, s_best_m);
    }

    #[cfg(all(feature = "avx512", target_arch = "x86_64", not(target_env = "msvc")))]
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
