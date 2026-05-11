// Thin C++ shim around the vendored animetosho/md5-optimisation
// block compressor. The upstream headers expose `md5_block_*` as
// `static inline __attribute__((always_inline))` C++ functions
// operating on a templated `MD5_STATE<uint32_t>` POD struct. We
// re-export the appropriate variant for the target architecture
// through an `extern "C"` boundary so Rust can call it via FFI.
//
// `MD5_STATE<uint32_t>` is `{ uint32_t A, B, C, D; }` with standard
// layout, so it is ABI-compatible with a `uint32_t[4]` from the
// Rust side.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Select the appropriate vendored header. Each header defines its
// own `MD5_STATE<HT>` template inside an `#ifdef` guard for its
// target arch, so we only include the one that matches.
#if defined(__aarch64__)
#   include "md5-arm64-asm.h"
#elif defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#   include "md5-x86-asm.h"
#else
#   error "md5-asm: unsupported target architecture (need aarch64 or x86/x86_64)"
#endif

// Sanity: the layout we promise to Rust.
typedef MD5_STATE<uint32_t> Md5State32;
static_assert(sizeof(Md5State32) == 16, "MD5_STATE<uint32_t> must be 16 bytes");
static_assert(offsetof(Md5State32, A) == 0,  "A @ 0");
static_assert(offsetof(Md5State32, B) == 4,  "B @ 4");
static_assert(offsetof(Md5State32, C) == 8,  "C @ 8");
static_assert(offsetof(Md5State32, D) == 12, "D @ 12");

extern "C" {

// Compress one 64-byte block into `state` (4x u32, little-endian:
// A, B, C, D). `block` must be a 64-byte buffer; `state` must be
// pre-initialised by the caller (the standard MD5 IV or a partial
// result from a previous call). This is the "Standard" reference
// variant — the one used as the 0% baseline in the upstream README.
void md5_asm_block_std(uint32_t state[4], const uint8_t block[64]) {
    md5_block_std(reinterpret_cast<MD5_STATE<uint32_t>*>(state), block);
}

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
// x86-only: G-function dependency shortcut. Upstream "GOpt".
void md5_asm_block_gopt(uint32_t state[4], const uint8_t block[64]) {
    md5_block_gopt(reinterpret_cast<MD5_STATE<uint32_t>*>(state), block);
}
// x86-only: GOpt + LEA-removed. Upstream "NoLEA-G", typically the
// fastest non-AVX512 variant in the published benchmarks.
void md5_asm_block_noleag(uint32_t state[4], const uint8_t block[64]) {
    md5_block_noleag(reinterpret_cast<MD5_STATE<uint32_t>*>(state), block);
}
#endif

// Multi-block driver. Hashes `nblocks` consecutive 64-byte blocks
// starting at `data` into `state`. Kept as a single C++ function so
// the compiler can inline the per-block compressor across the loop
// — important because the upstream block functions are marked
// `always_inline`.
void md5_asm_blocks_std(uint32_t state[4], const uint8_t* data, size_t nblocks) {
    auto* s = reinterpret_cast<MD5_STATE<uint32_t>*>(state);
    for (size_t i = 0; i < nblocks; ++i) {
        md5_block_std(s, data + (i * 64));
    }
}

} // extern "C"
