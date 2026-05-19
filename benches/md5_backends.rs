//! Head-to-head benchmark of the MD5 block compressors available to this crate:
//!
//! * `aws-lc-sys`'s `MD5_Transform` — the fallback used when the
//!   `fast-md5` feature is off.
//! * `fast_md5::transform` — the architecture-dispatch entry point from the
//!   [`fast-md5`](https://crates.io/crates/fast-md5) crate (hand-written
//!   `x86_64`/`aarch64` assembly, portable Rust fallback). On by default.
//!
//! Both benches drive the raw block-compression function directly —
//! no init/finalize overhead — so the numbers reflect pure compression work.
//!
//! Run with:
//!
//! ```text
//! # fast-md5 + aws-lc baseline (default)
//! cargo bench --bench md5_backends
//!
//! # aws-lc baseline only
//! cargo bench --bench md5_backends --no-default-features --features dict-rfc
//! ```
//!
//! Throughput is reported in bytes/sec; each iteration drives
//! `n` consecutive 64-byte block compressions over the same
//! buffer so the per-call overhead is amortized exactly the way
//! the streaming `Md5::update` path amortizes it.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

const SIZES: &[usize] = &[64, 256, 1024, 4096];

const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

#[allow(clippy::cast_possible_truncation)]
fn make_buf(len: usize) -> Vec<u8> {
    assert!(len % 64 == 0, "block compressor inputs must be 64B-aligned");
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

// ---------------------------------------------------------------------------
// aws-lc-sys baseline: MD5_Transform per 64-byte block.
// ---------------------------------------------------------------------------

#[allow(clippy::many_single_char_names)]
fn bench_awslc(c: &mut Criterion) {
    use std::mem::MaybeUninit;
    let mut g = c.benchmark_group("md5_block/aws_lc_sys");
    for &len in SIZES {
        let buf = make_buf(len);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("{len}B"), |b| {
            b.iter(|| {
                // Fresh context per iteration so we measure pure
                // block work, not Init/Final overhead.
                let mut ctx = MaybeUninit::<aws_lc_sys::MD5_CTX>::uninit();
                // SAFETY: MD5_Init writes every field before we
                // read; pointer is non-null.
                let r = unsafe { aws_lc_sys::MD5_Init(ctx.as_mut_ptr()) };
                assert_eq!(r, 1);
                // SAFETY: MD5_Init returned 1.
                let mut ctx = unsafe { ctx.assume_init() };
                let p = black_box(buf.as_ptr());
                let n = black_box(len / 64);
                for i in 0..n {
                    // SAFETY: `p.add(i*64)` points to a 64-byte
                    // block inside `buf`; `ctx` is initialized.
                    unsafe { aws_lc_sys::MD5_Transform(&raw mut ctx, p.add(i * 64)) };
                }
                black_box(&ctx);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// fast-md5: raw block compressor via `fast_md5::transform`.
// ---------------------------------------------------------------------------

#[cfg(feature = "fast-md5")]
fn bench_fast_md5(c: &mut Criterion) {
    let mut g = c.benchmark_group("md5_block/fast_md5");
    for &len in SIZES {
        let buf = make_buf(len);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("{len}B"), |b| {
            b.iter(|| {
                let mut state = IV;
                let p = black_box(buf.as_ptr());
                let n = black_box(len / 64);
                for i in 0..n {
                    // SAFETY: `p.add(i*64)` points to a 64-byte block
                    // inside `buf`.
                    let block: &[u8; 64] = unsafe { &*(p.add(i * 64).cast()) };
                    fast_md5::transform(&mut state, black_box(block));
                }
                black_box(state);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Group registration.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "fast-md5"))]
criterion_group!(benches, bench_awslc);

#[cfg(feature = "fast-md5")]
criterion_group!(benches, bench_awslc, bench_fast_md5);

criterion_main!(benches);
