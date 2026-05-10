//! Encode-side microbenchmarks: build an Access-Accept reply and seal
//! it (Length patch + Message-Authenticator HMAC + Response
//! Authenticator MD5) against a synthetic shared secret.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use radius_tokio::header::Code;
use radius_tokio::Reply;

const SECRET: &[u8] = b"benchmark-shared-secret";
const REQ_AUTH: [u8; 16] = [0xab; 16];

fn build_typical_accept() -> Reply {
    let mut reply = Reply::new(Code::ACCESS_ACCEPT, 7);
    // A modest set of attributes representative of an enterprise
    // Wi-Fi auth: VLAN assignment, session timeout, idle timeout.
    reply
        .add_attribute(8, &[10, 0, 0, 5]) // Framed-IP-Address
        .unwrap()
        .add_attribute(27, &3600u32.to_be_bytes()) // Session-Timeout
        .unwrap()
        .add_attribute(28, &600u32.to_be_bytes()) // Idle-Timeout
        .unwrap()
        .add_attribute(64, &13u32.to_be_bytes()) // Tunnel-Type = VLAN
        .unwrap()
        .add_attribute(65, &6u32.to_be_bytes()) // Tunnel-Medium-Type = 802
        .unwrap()
        .add_attribute(81, b"42") // Tunnel-Private-Group-Id
        .unwrap();
    reply
}

fn bench_encode(c: &mut Criterion) {
    c.bench_function("encode/access_accept_build", |b| {
        b.iter(|| {
            let r = build_typical_accept();
            black_box(r);
        });
    });

    c.bench_function("encode/access_accept_seal", |b| {
        b.iter(|| {
            let r = build_typical_accept();
            let sealed = r.seal_for(black_box(&REQ_AUTH), black_box(SECRET));
            black_box(sealed.as_bytes().len());
        });
    });

    c.bench_function("encode/access_reject_minimal", |b| {
        b.iter(|| {
            let r = Reply::new(Code::ACCESS_REJECT, 7);
            let sealed = r.seal_for(black_box(&REQ_AUTH), black_box(SECRET));
            black_box(sealed.as_bytes().len());
        });
    });
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
