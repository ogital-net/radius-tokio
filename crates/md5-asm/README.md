# md5-asm

A minimal MD5 **block compressor** backed by the vendored
[`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
inline-assembly headers, exposed to Rust through a thin C++ shim
built with [`cc`](https://crates.io/crates/cc).

This crate exposes only the per-block compression primitive — given
a 4×u32 MD5 state and a 64-byte block, it produces the updated
state. **Buffering, padding, and length encoding are the caller's
responsibility.** It is intended as a building block for higher-
level MD5 implementations that want the upstream's hand-tuned
single-buffer assembly without writing their own state machine.

`#![no_std]`. Zero allocation. No transitive dependencies beyond a
build-time `cc`.

## Variants

| Function           | Arch        | Notes                                                |
| ------------------ | ----------- | ---------------------------------------------------- |
| `block_std`        | any         | Upstream "Standard" — 0% baseline.                   |
| `blocks_std`       | any         | Multi-block driver around `block_std`.               |
| `block_gopt`       | x86 / x64   | "GOpt" — G-function dependency shortcut.             |
| `block_noleag`     | x86 / x64   | "NoLEA-G" — typically the fastest non-AVX512 path.   |
| `block_avx512`     | x86_64      | AVX512VL single-block. Opt-in via `avx512` feature.  |
| `blocks_avx512`    | x86_64      | AVX512VL multi-block.                                |

Use `is_avx512_supported()` to runtime-gate the AVX512 entry points.

## Platform support

| Target                          | Status                                                |
| ------------------------------- | ----------------------------------------------------- |
| `*-unknown-linux-gnu`           | Built and tested.                                     |
| `*-apple-darwin` (x86_64, arm64)| Built and tested.                                     |
| `x86_64-pc-windows-gnu`         | Should build (untested upstream).                     |
| `x86_64-pc-windows-msvc`        | Builds via pure-Rust fallback; see below.             |
| Other arches (riscv, ppc, …)    | Build script errors out — vendored headers are x86 / aarch64 only. |

### MSVC

The vendored upstream headers use GCC inline assembly and
`__attribute__((always_inline))`, neither of which `cl.exe`
understands. On `target_env = "msvc"` the build script skips the
C++ shim entirely and every block-compressor function transparently
dispatches to a **tuned pure-Rust NoLEA-G implementation**.

The fallback is fast — LLVM emits a tight rotate/add loop — but
still slower than the hand-written asm variants. The MSVC entry
points are marked `#[deprecated]` so callers get a compile-time
nudge that they're not getting peak performance. The deprecation
only fires under `target_env = "msvc"`; non-MSVC builds are
unaffected.

For the asm-grade speedup on Windows, build with
`x86_64-pc-windows-gnu` or `clang-cl`.

## Example

```rust
use md5_asm::{block_std, BLOCK_SIZE, IV, STATE_WORDS};

// Hash "abc" — the RFC 1321 Appendix A.5 test vector.
let mut state: [u32; STATE_WORDS] = IV;
let mut block = [0u8; BLOCK_SIZE];
block[..3].copy_from_slice(b"abc");
block[3] = 0x80;                          // RFC 1321 §3.1 padding marker
let bits: u64 = 24;                       // length in bits, little-endian
block[BLOCK_SIZE - 8..].copy_from_slice(&bits.to_le_bytes());
block_std(&mut state, &block);

// Final digest = concat(A, B, C, D) little-endian.
let mut digest = [0u8; 16];
digest[0..4].copy_from_slice(&state[0].to_le_bytes());
digest[4..8].copy_from_slice(&state[1].to_le_bytes());
digest[8..12].copy_from_slice(&state[2].to_le_bytes());
digest[12..16].copy_from_slice(&state[3].to_le_bytes());

assert_eq!(
    digest,
    [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
     0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]
);
```

## Safety

MD5 is **cryptographically broken**. Do not use it for password
hashing, signatures, or anything where collision resistance
matters. Legitimate uses today are limited to legacy interop
(RADIUS authenticators, RTP, etc.) where the protocol mandates it.

## Licence

Wrapper code (`src/`, `build.rs`) is BSD-2-Clause. Vendored
upstream headers in `vendor/` are public-domain / CC0-1.0
per the upstream
[discussion](https://github.com/animetosho/md5-optimisation/discussions/4).

The combined SPDX expression is `BSD-2-Clause AND CC0-1.0`.
