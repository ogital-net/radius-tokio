// Thin C shim around the vendored animetosho/md5-optimisation block
// compressor. The upstream headers expose `md5_block_*` as
// `static inline __attribute__((always_inline))` functions operating
// on a POD `md5_state_u32` struct (locally patched from the upstream
// `MD5_STATE<uint32_t>` template; see the header notes). We
// re-export the appropriate variant for the target architecture
// through a stable C ABI so Rust can call it via FFI.
//
// `md5_state_u32` is `{ uint32_t A, B, C, D; }` with standard
// layout, so it is ABI-compatible with a `uint32_t[4]` from the
// Rust side.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Select the appropriate vendored header. Each header defines its
// own `md5_state_u32` typedef inside an `#ifdef` guard for its
// target arch, so we only include the one that matches.
#if defined(__aarch64__)
#   include "md5-arm64-asm.h"
#elif defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#   include "md5-x86-asm.h"
#else
#   error "md5-asm: unsupported target architecture (need aarch64 or x86/x86_64)"
#endif

// Sanity: the layout we promise to Rust.
_Static_assert(sizeof(md5_state_u32) == 16, "md5_state_u32 must be 16 bytes");
_Static_assert(offsetof(md5_state_u32, A) == 0,  "A @ 0");
_Static_assert(offsetof(md5_state_u32, B) == 4,  "B @ 4");
_Static_assert(offsetof(md5_state_u32, C) == 8,  "C @ 8");
_Static_assert(offsetof(md5_state_u32, D) == 12, "D @ 12");

// Compress one 64-byte block into `state` (4x u32, little-endian:
// A, B, C, D). `block` must be a 64-byte buffer; `state` must be
// pre-initialised by the caller (the standard MD5 IV or a partial
// result from a previous call). This is the "Standard" reference
// variant — the one used as the 0% baseline in the upstream README.
void md5_asm_block_std(uint32_t state[4], const uint8_t block[64]) {
    md5_block_std((md5_state_u32*)state, block);
}

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
// x86-only: G-function dependency shortcut. Upstream "GOpt".
void md5_asm_block_gopt(uint32_t state[4], const uint8_t block[64]) {
    md5_block_gopt((md5_state_u32*)state, block);
}
// x86-only: GOpt + LEA-removed. Upstream "NoLEA-G", typically the
// fastest non-AVX512 variant in the published benchmarks.
void md5_asm_block_noleag(uint32_t state[4], const uint8_t block[64]) {
    md5_block_noleag((md5_state_u32*)state, block);
}
#endif

// Multi-block driver. Hashes `nblocks` consecutive 64-byte blocks
// starting at `data` into `state`. Kept as a single C function so
// the compiler can inline the per-block compressor across the loop
// — important because the upstream block functions are marked
// `always_inline`.
void md5_asm_blocks_std(uint32_t state[4], const uint8_t* data, size_t nblocks) {
    md5_state_u32* s = (md5_state_u32*)state;
    for (size_t i = 0; i < nblocks; ++i) {
        md5_block_std(s, data + (i * 64));
    }
}

// Architecture-best single-buffer block compressor. Resolves at
// compile time to the upstream variant that wins the published
// benchmarks for sequential (non-multi-buffer) hashing on the
// target ISA:
//
//   * x86 / x86_64 → "NoLEA-G" (fastest non-AVX512 variant).
//   * aarch64       → "Standard" (the only ARM64 variant upstream
//                     ships; the other tunings are x86-specific).
//
// AVX512 is intentionally **not** chosen here. It's runtime-gated
// (CPUID) and the multi-buffer / wide-SIMD layout is a poor fit
// for short, single-stream inputs like RADIUS authenticators; the
// caller dispatches to `md5_asm_block_avx512` separately when both
// the `md5-asm-avx512` Cargo feature and the running CPU support
// it.
void md5_asm_block(uint32_t state[4], const uint8_t block[64]) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
    md5_block_noleag((md5_state_u32*)state, block);
#elif defined(__aarch64__)
    md5_block_std((md5_state_u32*)state, block);
#else
#   error "md5-asm: no preferred variant selected for this architecture"
#endif
}

// Architecture-best multi-block driver. See `md5_asm_block` for
// the variant selection rationale. Same loop-and-inline pattern as
// `md5_asm_blocks_std` so the per-block compressor inlines across
// the loop body.
void md5_asm_blocks(uint32_t state[4], const uint8_t* data, size_t nblocks) {
    md5_state_u32* s = (md5_state_u32*)state;
    for (size_t i = 0; i < nblocks; ++i) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
        md5_block_noleag(s, data + (i * 64));
#elif defined(__aarch64__)
        md5_block_std(s, data + (i * 64));
#else
#   error "md5-asm: no preferred variant selected for this architecture"
#endif
    }
}
