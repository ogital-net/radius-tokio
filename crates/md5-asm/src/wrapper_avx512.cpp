// AVX512 entry points for the md5-asm shim. Compiled into a
// separate translation unit so the `-mavx512f -mavx512vl` build
// flags don't contaminate the rest of the wrapper (and so this
// file can be skipped entirely on non-x86_64 targets or when the
// `avx512` Cargo feature is off).
//
// Bridges between the upstream `MD5_STATE<__m128i>` layout (one
// 32-bit word per `__m128i`, low lane only) and the plain
// `uint32_t[4]` ABI the rest of the crate uses.

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

#include "md5-x86-asm.h"

extern "C" {

void md5_asm_block_avx512(uint32_t state[4], const uint8_t block[64]) {
    MD5_STATE<__m128i> s;
    s.A = _mm_cvtsi32_si128(static_cast<int>(state[0]));
    s.B = _mm_cvtsi32_si128(static_cast<int>(state[1]));
    s.C = _mm_cvtsi32_si128(static_cast<int>(state[2]));
    s.D = _mm_cvtsi32_si128(static_cast<int>(state[3]));
    md5_block_avx512(&s, block);
    state[0] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.A));
    state[1] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.B));
    state[2] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.C));
    state[3] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.D));
}

// Multi-block driver: holds the __m128i state in vector registers
// across the whole sequence so the per-block bridge cost is paid
// once. This is the version the streaming `Md5` wrapper should
// prefer for any input >= 64 bytes.
void md5_asm_blocks_avx512(uint32_t state[4], const uint8_t* data, size_t nblocks) {
    MD5_STATE<__m128i> s;
    s.A = _mm_cvtsi32_si128(static_cast<int>(state[0]));
    s.B = _mm_cvtsi32_si128(static_cast<int>(state[1]));
    s.C = _mm_cvtsi32_si128(static_cast<int>(state[2]));
    s.D = _mm_cvtsi32_si128(static_cast<int>(state[3]));
    for (size_t i = 0; i < nblocks; ++i) {
        md5_block_avx512(&s, data + (i * 64));
    }
    state[0] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.A));
    state[1] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.B));
    state[2] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.C));
    state[3] = static_cast<uint32_t>(_mm_cvtsi128_si32(s.D));
}

} // extern "C"
