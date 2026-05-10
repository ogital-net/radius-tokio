//! Heap-allocation profile of the per-packet hot path.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example dhat_hot_path
//! ```
//!
//! Produces `dhat-heap.json` in the current directory. Load it in the
//! dhat viewer (`https://nnethercote.github.io/dh_view/dh_view.html`)
//! to inspect every allocation made during the steady-state loop.
//!
//! The goal is *zero* per-iteration allocations on the
//! decode → verify → build → seal path. Anything that scales with
//! `ITERS` is a regression worth investigating.
#![allow(clippy::cast_possible_truncation)]
use radius_tokio::header::{Code, Header};
use radius_tokio::message_authenticator::{self, Verification};
use radius_tokio::{authenticator, PacketBuffer, Reply};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const SECRET: &[u8] = b"benchmark-shared-secret";
const ITERS: usize = 10_000;

fn build_access_request() -> Vec<u8> {
    fn tlv(typ: u8, val: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + val.len());
        v.push(typ);
        v.push(u8::try_from(val.len() + 2).unwrap());
        v.extend_from_slice(val);
        v
    }

    let mut attrs = Vec::new();
    attrs.extend(tlv(1, b"alice@example.com"));
    attrs.extend(tlv(4, &[10, 0, 0, 5]));
    attrs.extend(tlv(5, &0u32.to_be_bytes()));
    attrs.extend(tlv(6, &2u32.to_be_bytes()));
    attrs.extend(tlv(31, b"00-11-22-33-44-55"));
    attrs.extend(tlv(32, b"ap-edge-12"));

    let req_auth = [0xab; 16];
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
    r.add_attribute(8, &[10, 0, 0, 5])
        .unwrap()
        .add_attribute(27, &3600u32.to_be_bytes())
        .unwrap();
    r
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "owned".into());

    // Build the test datagram outside the profiled region — we only
    // care about per-packet allocations on the hot path itself.
    let datagram = build_access_request();

    // Start the profiler. Drop on exit writes `dhat-heap.json`.
    let _profiler = dhat::Profiler::new_heap();

    let mut sink: usize = 0;
    match mode.as_str() {
        // Default loop: each iteration builds a fresh `Reply`,
        // which owns its own `PacketBuffer`. One allocation per
        // iteration (the buffer's `Vec`).
        "owned" => {
            for i in 0..ITERS {
                let (h, _attrs) = Header::parse(&datagram).expect("parse");
                let v = message_authenticator::verify(&datagram, &h.authenticator, SECRET);
                debug_assert_eq!(v, Verification::Valid);

                let reply = build_reply(h.identifier.wrapping_add((i & 0xff) as u8));
                let sealed = reply.seal_for(&h.authenticator, SECRET);
                debug_assert!(authenticator::verify_response(
                    sealed.as_bytes(),
                    &h.authenticator,
                    SECRET,
                ));
                sink = sink.wrapping_add(sealed.as_bytes().len());
            }
        }
        // Recycle a single `PacketBuffer` across every iteration via
        // `Reply::from_buffer`. Steady state should show *zero*
        // per-iteration allocations on the codec layer.
        "recycled" => {
            let mut buf = PacketBuffer::with_capacity(Code::ACCESS_ACCEPT, 0, 512);
            for i in 0..ITERS {
                let (h, _attrs) = Header::parse(&datagram).expect("parse");
                let v = message_authenticator::verify(&datagram, &h.authenticator, SECRET);
                debug_assert_eq!(v, Verification::Valid);

                buf.reset(
                    Code::ACCESS_ACCEPT,
                    h.identifier.wrapping_add((i & 0xff) as u8),
                );
                let mut reply = Reply::from_buffer(buf);
                reply
                    .add_attribute(8, &[10, 0, 0, 5])
                    .unwrap()
                    .add_attribute(27, &3600u32.to_be_bytes())
                    .unwrap();
                buf = reply.seal_for(&h.authenticator, SECRET);
                debug_assert!(authenticator::verify_response(
                    buf.as_bytes(),
                    &h.authenticator,
                    SECRET,
                ));
                sink = sink.wrapping_add(buf.as_bytes().len());
            }
        }
        other => {
            eprintln!("unknown mode {other:?}; expected `owned` or `recycled`");
            std::process::exit(2);
        }
    }

    // Touch `sink` so the optimiser can't delete the loop body.
    println!("mode: {mode}, iterations: {ITERS}, byte-sum sink: {sink}");
}
