//! Synchronous in-process roundtrip: decode an inbound Access-Request,
//! verify its Message-Authenticator, build an Access-Accept reply, and
//! seal it. This is the codec / crypto portion of the UDP hot path,
//! without sockets or task spawn — useful as a noise-free baseline for
//! the per-packet steady-state cost the runtime adds on top.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use radius_tokio::header::{Code, Header};
use radius_tokio::message_authenticator::{self, Verification};
use radius_tokio::{authenticator, Reply};

const SECRET: &[u8] = b"benchmark-shared-secret";

fn build_access_request() -> Vec<u8> {
    fn tlv(typ: u8, val: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + val.len());
        v.push(typ);
        v.push(u8::try_from(val.len() + 2).unwrap());
        v.extend_from_slice(val);
        v
    }

    let mut attrs = Vec::new();
    attrs.extend(tlv(1, b"alice@example.com")); // User-Name
    attrs.extend(tlv(4, &[10, 0, 0, 5])); // NAS-IP-Address
    attrs.extend(tlv(5, &0u32.to_be_bytes())); // NAS-Port
    attrs.extend(tlv(6, &2u32.to_be_bytes())); // Service-Type
    attrs.extend(tlv(31, b"00-11-22-33-44-55")); // Calling-Station-Id
    attrs.extend(tlv(32, b"ap-edge-12")); // NAS-Identifier

    // Random Request Authenticator (fixed for the bench).
    let req_auth = [0xab; 16];

    // Header + attributes + a Message-Authenticator TLV with zeroed
    // value, then patch length and compute / write the real tag.
    let total = 20 + attrs.len() + 2 + 16;
    let mut pkt = Vec::with_capacity(total);
    pkt.push(Code::ACCESS_REQUEST.0);
    pkt.push(7);
    pkt.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    pkt.extend_from_slice(&req_auth);
    pkt.extend_from_slice(&attrs);
    pkt.push(message_authenticator::TYPE);
    pkt.push(message_authenticator::TLV_LEN);
    let value_off = pkt.len();
    pkt.extend_from_slice(&[0u8; message_authenticator::VALUE_LEN]);

    let tag = message_authenticator::compute(&pkt, &req_auth, SECRET);
    pkt[value_off..value_off + message_authenticator::VALUE_LEN].copy_from_slice(&tag);
    pkt
}

fn build_reply(ident: u8) -> Reply {
    let mut r = Reply::new(Code::ACCESS_ACCEPT, ident);
    r.add_attribute(8, &[10, 0, 0, 5]) // Framed-IP-Address
        .unwrap()
        .add_attribute(27, &3600u32.to_be_bytes()) // Session-Timeout
        .unwrap();
    r
}

fn bench_roundtrip(c: &mut Criterion) {
    let datagram = build_access_request();

    c.bench_function("roundtrip/decode_and_verify", |b| {
        b.iter(|| {
            let (h, _attrs) = Header::parse(black_box(&datagram)).unwrap();
            let v = message_authenticator::verify(
                black_box(&datagram),
                &h.authenticator,
                black_box(SECRET),
            );
            assert_eq!(v, Verification::Valid);
            black_box(v);
        });
    });

    c.bench_function("roundtrip/full_request_response", |b| {
        b.iter(|| {
            // Inbound: parse + M-A verify.
            let (h, _attrs) = Header::parse(black_box(&datagram)).expect("parse");
            let v = message_authenticator::verify(&datagram, &h.authenticator, SECRET);
            debug_assert_eq!(v, Verification::Valid);

            // Outbound: build + seal (M-A + Response Authenticator).
            let reply = build_reply(h.identifier);
            let sealed = reply.seal_for(&h.authenticator, SECRET);

            // Sanity check folded into the bench so the optimiser can't
            // delete the work.
            debug_assert!(authenticator::verify_response(
                sealed.as_bytes(),
                &h.authenticator,
                SECRET,
            ));
            black_box(sealed.as_bytes().len());
        });
    });
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
