//! Decode-side microbenchmarks: header parse + attribute walk + typed
//! attribute lookup against a representative Access-Request payload.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use radius_tokio::attributes;
use radius_tokio::header::Header;
use radius_tokio::message_authenticator;

/// Build a typical Access-Request datagram: User-Name, NAS-IP-Address,
/// NAS-Port, Calling-Station-Id, Called-Station-Id, NAS-Identifier,
/// Service-Type, Framed-Protocol, plus a Message-Authenticator slot.
/// 16-byte authenticator is fixed; this is a static fixture, not a
/// security-bearing artifact.
fn build_access_request() -> Vec<u8> {
    // Attributes (RFC 2865 §5).
    const USER_NAME: u8 = 1;
    const NAS_IP_ADDRESS: u8 = 4;
    const NAS_PORT: u8 = 5;
    const SERVICE_TYPE: u8 = 6;
    const FRAMED_PROTOCOL: u8 = 7;
    const CALLED_STATION_ID: u8 = 30;
    const CALLING_STATION_ID: u8 = 31;
    const NAS_IDENTIFIER: u8 = 32;

    fn tlv(typ: u8, val: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + val.len());
        v.push(typ);
        v.push(u8::try_from(val.len() + 2).unwrap());
        v.extend_from_slice(val);
        v
    }

    let mut attrs = Vec::new();
    attrs.extend(tlv(USER_NAME, b"alice@example.com"));
    attrs.extend(tlv(NAS_IP_ADDRESS, &[10, 0, 0, 5]));
    attrs.extend(tlv(NAS_PORT, &0u32.to_be_bytes()));
    attrs.extend(tlv(SERVICE_TYPE, &2u32.to_be_bytes()));
    attrs.extend(tlv(FRAMED_PROTOCOL, &1u32.to_be_bytes()));
    attrs.extend(tlv(CALLING_STATION_ID, b"00-11-22-33-44-55"));
    attrs.extend(tlv(CALLED_STATION_ID, b"AA-BB-CC-DD-EE-FF:MyWiFi"));
    attrs.extend(tlv(NAS_IDENTIFIER, b"ap-edge-12"));
    // Message-Authenticator slot (zeroed; we don't verify in this bench).
    attrs.push(message_authenticator::TYPE);
    attrs.push(message_authenticator::TLV_LEN);
    attrs.extend_from_slice(&[0u8; message_authenticator::VALUE_LEN]);

    let total = 20 + attrs.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.push(1); // Access-Request
    pkt.push(42); // Identifier
    pkt.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    pkt.extend_from_slice(&[0xab; 16]); // Request Authenticator
    pkt.extend_from_slice(&attrs);
    pkt
}

fn bench_decode(c: &mut Criterion) {
    let pkt = build_access_request();

    c.bench_function("decode/header", |b| {
        b.iter(|| {
            let (h, attrs) = Header::parse(black_box(&pkt)).unwrap();
            black_box((h.code, h.identifier, h.length, attrs.len()));
        });
    });

    c.bench_function("decode/attribute_walk", |b| {
        let (_h, attrs) = Header::parse(&pkt).unwrap();
        b.iter(|| {
            let mut count = 0usize;
            for slot in attributes::iter(black_box(attrs)) {
                let raw = slot.unwrap();
                count += raw.value().len();
            }
            black_box(count)
        });
    });

    c.bench_function("decode/find_first_typed", |b| {
        let (_h, attrs) = Header::parse(&pkt).unwrap();
        b.iter(|| {
            // Walk to find User-Name (type 1) — first attribute.
            for slot in attributes::iter(black_box(attrs)) {
                let raw = slot.unwrap();
                if raw.attribute_type() == 1 {
                    black_box(raw.value());
                    break;
                }
            }
        });
    });

    c.bench_function("decode/find_last_typed", |b| {
        let (_h, attrs) = Header::parse(&pkt).unwrap();
        b.iter(|| {
            // Walk to find NAS-Identifier (type 32) — last RFC attr.
            for slot in attributes::iter(black_box(attrs)) {
                let raw = slot.unwrap();
                if raw.attribute_type() == 32 {
                    black_box(raw.value());
                    break;
                }
            }
        });
    });

    c.bench_function("decode/message_authenticator_locate", |b| {
        b.iter(|| black_box(message_authenticator::find_value_offset(black_box(&pkt))));
    });
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
