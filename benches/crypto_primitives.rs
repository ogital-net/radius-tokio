//! Microbenchmarks for the crypto primitives the hot path actually
//! exercises, accessed through their public RADIUS wrappers.
//!
//! * `Message-Authenticator` HMAC-MD5 over a typical packet.
//! * Response Authenticator MD5(packet || secret).
//! * Inbound Accounting-Request authenticator verify (zeroed-request
//!   MD5 with constant-time compare).
//!
//! The crypto module itself is crate-private, so these benches go
//! through `codec::message_authenticator::compute` and
//! `codec::authenticator::*` — the same entry points the runtime uses.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use radius_tokio::{authenticator, message_authenticator};

const SECRET: &[u8] = b"benchmark-shared-secret";
const AUTH: [u8; 16] = [0xab; 16];

/// Build a packet of `total_len` bytes (header + filler attribute).
fn make_packet(code: u8, total_len: usize) -> Vec<u8> {
    assert!((20..=4096).contains(&total_len));
    let mut pkt = vec![0u8; total_len];
    pkt[0] = code;
    pkt[1] = 7;
    let len_bytes = u16::try_from(total_len).unwrap().to_be_bytes();
    pkt[2..4].copy_from_slice(&len_bytes);
    pkt[4..20].copy_from_slice(&AUTH);
    // Fill the attribute region with a single oversized "padding"
    // attribute composed of 253-byte chunks so the iter walk is sane.
    let mut off = 20;
    while off < total_len {
        let remaining = total_len - off;
        let take = remaining.clamp(2, 255);
        pkt[off] = 99; // arbitrary unknown type
        pkt[off + 1] = u8::try_from(take).unwrap();
        off += take;
    }
    pkt
}

fn bench_hmac_md5(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/message_authenticator_compute");
    for &len in &[64usize, 256, 1024, 4096] {
        let pkt = make_packet(1, len);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("{len}B"), |b| {
            b.iter(|| {
                let tag = message_authenticator::compute(
                    black_box(&pkt),
                    black_box(&AUTH),
                    black_box(SECRET),
                );
                black_box(tag);
            });
        });
    }
    g.finish();
}

fn bench_response_authenticator(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/response_authenticator");
    for &len in &[64usize, 256, 1024, 4096] {
        let pkt = make_packet(2, len);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("{len}B"), |b| {
            b.iter(|| {
                let tag = authenticator::compute_response(
                    black_box(&pkt),
                    black_box(&AUTH),
                    black_box(SECRET),
                );
                black_box(tag);
            });
        });
    }
    g.finish();
}

fn bench_zeroed_request_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("crypto/zeroed_request_verify");
    for &len in &[64usize, 256, 1024] {
        let mut pkt = make_packet(4, len); // Accounting-Request
        pkt[4..20].copy_from_slice(&[0u8; 16]);
        let tag = authenticator::compute_zeroed_request(&pkt, SECRET);
        pkt[4..20].copy_from_slice(&tag);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("{len}B"), |b| {
            b.iter(|| {
                let ok = authenticator::verify_zeroed_request(black_box(&pkt), black_box(SECRET));
                black_box(ok);
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_hmac_md5,
    bench_response_authenticator,
    bench_zeroed_request_verify,
);
criterion_main!(benches);
