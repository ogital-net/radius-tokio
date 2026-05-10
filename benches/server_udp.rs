//! End-to-end UDP throughput + latency measurement against a running
//! [`Server`] with a no-op handler.
//!
//! This is the bench that backs the CLAUDE.md "Performance budget"
//! verification: everything in
//! `benches/{codec_decode,codec_encode,roundtrip}.rs` measures the
//! synchronous codec/crypto floor; this binary folds in the actual
//! UDP socket loop, the dedup cache, the spawn boundary, and the
//! per-packet allocations on the dispatch path.
//!
//! Two measurements are reported:
//!
//! 1. **Sequential roundtrip latency.** A single test client fires
//!    one Access-Request at a time and waits for the reply before
//!    sending the next. Reports min / p50 / p90 / p99 / p999 / max
//!    over `LATENCY_SAMPLES` iterations. Approximates the per-packet
//!    added latency a real NAS observes.
//!
//! 2. **Concurrent throughput.** `THROUGHPUT_CLIENTS` test sockets
//!    each fire `THROUGHPUT_PER_CLIENT` requests back-to-back; total
//!    wall-clock time across all clients yields a sustained req/s
//!    figure. The clients use distinct identifiers to avoid the
//!    dedup cache.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --bench server_udp -- --nocapture
//! ```
//!
//! (The `--nocapture` is needed because this is a `harness = false`
//! bench — it prints its results to stdout instead of going through
//! libtest.)

#![allow(
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::{authenticator, message_authenticator, Code};
use tokio::net::UdpSocket;

/// How many sequential roundtrips to time.
const LATENCY_SAMPLES: usize = 10_000;
/// Concurrent test clients during the throughput phase.
const THROUGHPUT_CLIENTS: usize = 16;
/// Requests each throughput client sends back-to-back.
const THROUGHPUT_PER_CLIENT: usize = 5_000;

const SECRET: &[u8] = b"benchmark-shared-secret";

/// Trivial handler: always reply Access-Accept with no extra
/// attributes. Establishes the absolute lower bound on consumer
/// cost.
struct NoopHandler;

impl Handler for NoopHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
    }
}

/// Build an Access-Request datagram with a stable Message-Authenticator.
///
/// We hand-pack the wire bytes rather than going through
/// `PacketBuffer::seal_*` because Access-Request's Authenticator is
/// the random Request Authenticator the NAS chose, not a value
/// derived from the packet body.
fn build_access_request(identifier: u8, request_authenticator: &[u8; 16]) -> Vec<u8> {
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

    let total = 20 + attrs.len() + 2 + message_authenticator::VALUE_LEN;
    let mut pkt = Vec::with_capacity(total);
    pkt.push(Code::ACCESS_REQUEST.0);
    pkt.push(identifier);
    pkt.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    pkt.extend_from_slice(request_authenticator);
    pkt.extend_from_slice(&attrs);
    pkt.push(message_authenticator::TYPE);
    pkt.push(message_authenticator::TLV_LEN);
    let value_off = pkt.len();
    pkt.extend_from_slice(&[0u8; message_authenticator::VALUE_LEN]);
    let tag = message_authenticator::compute(&pkt, request_authenticator, SECRET);
    pkt[value_off..value_off + message_authenticator::VALUE_LEN].copy_from_slice(&tag);
    pkt
}

async fn spin_up_server() -> SocketAddr {
    // Pick a free port up front.
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let bind_addr = probe.local_addr().unwrap();
    drop(probe);

    let client = Arc::new(Client::new(SECRET));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let server = Server::builder()
        .clients(store)
        .handler(NoopHandler)
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    tokio::spawn(server.run());

    // Give the listener a moment to actually bind before the bench
    // starts firing traffic at it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    bind_addr
}

async fn measure_latency(bind_addr: SocketAddr) -> Vec<Duration> {
    let nas = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut samples = Vec::with_capacity(LATENCY_SAMPLES);
    let mut recv_buf = vec![0u8; 4096];

    // Stable request-auth per identifier so each iteration's dedup
    // key is unique (we cycle the identifier through 256 values).
    let mut req_auths = [[0u8; 16]; 256];
    for (i, ra) in req_auths.iter_mut().enumerate() {
        ra[0] = i as u8;
        ra[15] = 0xa5;
    }

    // Warm-up to amortise first-time JIT/page-fault costs.
    for i in 0..256 {
        let pkt = build_access_request(i as u8, &req_auths[i]);
        nas.send_to(&pkt, bind_addr).await.unwrap();
        nas.recv_from(&mut recv_buf).await.unwrap();
    }

    for n in 0..LATENCY_SAMPLES {
        // Bump a counter into the request-auth so every iteration is
        // a unique dedup key (otherwise the first 256 iterations
        // would all hit the cache after wrap).
        let id = (n & 0xff) as u8;
        let mut ra = req_auths[id as usize];
        ra[1..9].copy_from_slice(&(n as u64).to_be_bytes());
        let pkt = build_access_request(id, &ra);

        let t0 = Instant::now();
        nas.send_to(&pkt, bind_addr).await.unwrap();
        let (len, _) = nas.recv_from(&mut recv_buf).await.unwrap();
        let dt = t0.elapsed();
        debug_assert_eq!(recv_buf[0], Code::ACCESS_ACCEPT.0);
        debug_assert_eq!(recv_buf[1], id);
        debug_assert!(authenticator::verify_response(
            &recv_buf[..len],
            &ra,
            SECRET,
        ));
        samples.push(dt);
    }
    samples
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx]
}

fn report_latency(mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let n = samples.len();
    let total: Duration = samples.iter().sum();
    let mean = total / n as u32;
    println!("\nSequential roundtrip latency over {n} samples:");
    println!("  min   = {:?}", samples[0]);
    println!("  p50   = {:?}", percentile(&samples, 0.50));
    println!("  mean  = {mean:?}");
    println!("  p90   = {:?}", percentile(&samples, 0.90));
    println!("  p99   = {:?}", percentile(&samples, 0.99));
    println!("  p999  = {:?}", percentile(&samples, 0.999));
    println!("  max   = {:?}", samples[n - 1]);

    // CLAUDE.md performance budget: <50 µs added latency (excluding handler).
    let p99 = percentile(&samples, 0.99);
    let budget = Duration::from_micros(50);
    let verdict = if p99 <= budget { "PASS" } else { "FAIL" };
    println!("  CLAUDE.md p99 budget = {budget:?}: {verdict}");
}

async fn measure_throughput(bind_addr: SocketAddr) -> (usize, Duration) {
    let total = THROUGHPUT_CLIENTS * THROUGHPUT_PER_CLIENT;
    let started = Arc::new(tokio::sync::Barrier::new(THROUGHPUT_CLIENTS + 1));
    let mut tasks = Vec::with_capacity(THROUGHPUT_CLIENTS);

    for client_idx in 0..THROUGHPUT_CLIENTS {
        let started = Arc::clone(&started);
        tasks.push(tokio::spawn(async move {
            let nas = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            // Pre-build all packets so the timed region is purely
            // network + server cost.
            let mut packets = Vec::with_capacity(THROUGHPUT_PER_CLIENT);
            for n in 0..THROUGHPUT_PER_CLIENT {
                let id = (n & 0xff) as u8;
                let mut ra = [0u8; 16];
                ra[0] = client_idx as u8;
                ra[1..9].copy_from_slice(&(n as u64).to_be_bytes());
                ra[15] = 0xa5;
                packets.push((id, ra, build_access_request(id, &ra)));
            }
            let mut recv_buf = vec![0u8; 4096];
            started.wait().await;
            for (id, ra, pkt) in &packets {
                nas.send_to(pkt, bind_addr).await.unwrap();
                let (len, _) = nas.recv_from(&mut recv_buf).await.unwrap();
                debug_assert_eq!(recv_buf[1], *id);
                debug_assert!(authenticator::verify_response(&recv_buf[..len], ra, SECRET,));
            }
        }));
    }

    started.wait().await;
    let t0 = Instant::now();
    for t in tasks {
        t.await.unwrap();
    }
    let elapsed = t0.elapsed();
    (total, elapsed)
}

fn report_throughput(packets: usize, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let rate = packets as f64 / secs;
    println!("\nConcurrent throughput:");
    println!("  clients         = {THROUGHPUT_CLIENTS}");
    println!("  per client      = {THROUGHPUT_PER_CLIENT}");
    println!("  total packets   = {packets}");
    println!("  wall clock      = {elapsed:?}");
    println!("  throughput      = {rate:.0} req/s");

    // CLAUDE.md performance budget: >200k req/s on a modern x86 core.
    let budget = 200_000.0;
    let verdict = if rate >= budget { "PASS" } else { "FAIL" };
    println!("  CLAUDE.md req/s budget = {budget:.0}: {verdict}");
}

fn main() {
    // Multi-threaded runtime: the server's listener task and the
    // throughput-test clients all want to make progress in parallel.
    // Cap to a small worker count so the numbers don't depend on
    // the host's full CPU complement; bench reports the count.
    let worker_threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(4));
    println!("server_udp bench: tokio worker threads = {worker_threads}");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let bind_addr = spin_up_server().await;

        let samples = measure_latency(bind_addr).await;
        report_latency(samples);

        let (packets, elapsed) = measure_throughput(bind_addr).await;
        report_throughput(packets, elapsed);
    });
}
