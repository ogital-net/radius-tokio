//! Example: a synchronous worker-thread RADIUS responder that
//! reuses a thread-local, max-size [`PacketBuffer`] for every reply.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example threadlocal_responder
//! ```
//!
//! ## When this pattern is the right tool
//!
//! The library's [`Server`](radius_tokio::server::Server) is built
//! on Tokio and spawns a fresh task per request, so its per-reply
//! `PacketBuffer` allocation is structural — a task may be polled
//! on a different worker thread between awaits, which makes
//! `thread_local!` unsafe to hold across `.await`.
//!
//! Some deployments don't want or need the async machinery:
//!
//! * High-PPS, low-jitter responders where every microsecond of
//!   scheduler overhead matters (RADIUS test rigs, Status-Server
//!   probers, monitoring-style "always-Accept" stubs).
//! * Threadpool-style architectures already in place from a
//!   non-Rust component being ported.
//! * Embedded or single-purpose appliances where a Tokio runtime is
//!   excessive.
//!
//! For those cases a plain `std::net::UdpSocket` + a worker thread
//! per core is a perfectly reasonable shape — and `thread_local!`
//! is then the natural place to park a reusable max-size buffer.
//!
//! ## What this example demonstrates
//!
//! 1. A worker thread owns a `RefCell<Option<PacketBuffer>>` in
//!    thread-local storage. The slot starts empty; the first reply
//!    materializes a 4 096-byte buffer and parks it back in the
//!    cell on every subsequent send. After the first packet,
//!    **steady-state allocation count is zero** for the codec layer.
//! 2. The buffer flows through the round trip:
//!    `take → reset → from_buffer → add_attribute → seal_for →
//!    send_to → put back`. The `seal_for` API hands the buffer
//!    back, so we never lose ownership.
//! 3. A small load-generator thread fires `REQUESTS` Access-Requests
//!    at the responder, asserts each Access-Accept is well-formed
//!    (correct identifier, valid Response Authenticator, valid
//!    Message-Authenticator), and prints a sustained req/s rate.
//!
//! ## Single-thread vs many
//!
//! `thread_local!` gives each worker thread its own private buffer,
//! so this pattern scales fan-out by spawning more worker threads
//! against the same `UdpSocket` (Linux supports `SO_REUSEPORT` for
//! true kernel-side load balancing; this example uses a single
//! worker for clarity).

#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use radius_tokio::dict::rfc::attrs;
use radius_tokio::header::{Code, Header, MAX_PACKET_LEN};
use radius_tokio::message_authenticator::{self, Verification};
use radius_tokio::{authenticator, PacketBuffer, Reply};

const SECRET: &[u8] = b"threadlocal-responder-secret";
const REQUESTS: usize = 50_000;

thread_local! {
    /// Per-worker scratch buffer for outbound replies.
    ///
    /// `RefCell` so we can `take()` the buffer for the duration of a
    /// reply and `set` it back when done; `Option` so the very first
    /// invocation can materialize a max-size allocation lazily
    /// instead of paying for it at thread spawn.
    static REPLY_BUF: RefCell<Option<PacketBuffer>> = const { RefCell::new(None) };
}

/// Build, seal, and send an Access-Accept for `request_bytes`.
///
/// Reuses the thread-local `REPLY_BUF` for the underlying
/// `PacketBuffer`; allocation count for this function is
/// `0` in steady state once the slot has been primed on the first
/// call.
///
/// Returns `Ok(())` on send, `Err` on socket failure or malformed
/// request. Drops malformed inputs silently per RFC 2865 §3 — the
/// caller can ignore the error and keep serving.
fn respond(socket: &UdpSocket, request_bytes: &[u8], src: SocketAddr) -> std::io::Result<()> {
    // Validate the request enough to extract identifier + auth. Real
    // code would also verify the M-A here against the client's
    // secret; omitted for brevity.
    let Ok((header, _attrs)) = Header::parse(request_bytes) else {
        return Ok(());
    };
    let req_auth = header.authenticator;
    let identifier = header.identifier;

    REPLY_BUF.with(|cell| {
        // Take the buffer (or allocate the first time).
        let mut buf = cell.borrow_mut().take().unwrap_or_else(|| {
            // Pre-size to the protocol maximum so the buffer never
            // reallocates on a large reply. ~4 KiB per worker
            // thread is a trivial cost for a process-lifetime
            // allocation.
            PacketBuffer::with_capacity(Code::ACCESS_ACCEPT, identifier, MAX_PACKET_LEN)
        });
        // Recycle the existing allocation: rewrite the header and
        // clear the attribute region in place.
        buf.reset(Code::ACCESS_ACCEPT, identifier);

        // Build the reply through the typed API. `Reply::from_buffer`
        // takes ownership for the duration of building + sealing.
        let mut reply = Reply::from_buffer(buf);
        reply
            .add(attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 5))
            .expect("fits")
            .add(attrs::SESSION_TIMEOUT, 3600u32)
            .expect("fits");

        // Seal hands the buffer back. Send the wire bytes
        // synchronously — we are on a dedicated worker thread, so
        // blocking here is fine and avoids a copy out of the
        // buffer.
        let sealed = reply.seal_for(&req_auth, SECRET);
        let send_result = socket.send_to(sealed.as_bytes(), src);

        // Park the buffer back in the thread-local for the next
        // request, regardless of whether the send succeeded — the
        // allocation is reusable either way.
        *cell.borrow_mut() = Some(sealed);

        send_result.map(|_| ())
    })
}

/// Worker thread: read a datagram, build + send the reply, repeat.
#[allow(clippy::needless_pass_by_value)] // worker owns its socket + stop handle
fn run_worker(socket: UdpSocket, stop: Arc<AtomicBool>) {
    // The receive buffer is also reused — but it's a `Vec<u8>` on
    // the worker's stack frame, not in thread-local storage, since
    // it never escapes this function.
    let mut recv = vec![0u8; MAX_PACKET_LEN];
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set timeout");

    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut recv) {
            Ok((len, src)) => {
                // Errors on send are logged-and-continue; a real
                // responder would surface them via metrics.
                let _ = respond(&socket, &recv[..len], src);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("worker recv error: {e}");
                return;
            }
        }
    }
}

/// Hand-pack an Access-Request with a stable Message-Authenticator.
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

fn main() -> std::io::Result<()> {
    // Bind the responder up front so the load generator knows where
    // to send.
    let server_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let server_addr = server_sock.local_addr()?;

    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || run_worker(server_sock, worker_stop));

    // Load generator: fire requests sequentially, validating every
    // reply. Sequential keeps the math simple and exercises the
    // "one in flight" path the worker is optimized for.
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut recv_buf = vec![0u8; MAX_PACKET_LEN];
    println!("threadlocal_responder: warming up (256 packets)");
    for n in 0..256u32 {
        let mut ra = [0u8; 16];
        ra[0] = 0xa5;
        ra[1..9].copy_from_slice(&u64::from(n).to_be_bytes());
        let pkt = build_access_request((n & 0xff) as u8, &ra);
        client.send_to(&pkt, server_addr)?;
        client.recv_from(&mut recv_buf)?;
    }

    println!("threadlocal_responder: timing {REQUESTS} round-trips");
    let t0 = Instant::now();
    for n in 0..REQUESTS {
        let id = (n & 0xff) as u8;
        let mut ra = [0u8; 16];
        ra[0] = 0xa5;
        ra[1..9].copy_from_slice(&(n as u64).to_be_bytes());
        let pkt = build_access_request(id, &ra);

        client.send_to(&pkt, server_addr)?;
        let (len, _) = client.recv_from(&mut recv_buf)?;

        // Sanity-check the reply.
        assert_eq!(recv_buf[0], Code::ACCESS_ACCEPT.0, "wrong code");
        assert_eq!(recv_buf[1], id, "wrong identifier");
        assert!(
            authenticator::verify_response(&recv_buf[..len], &ra, SECRET),
            "bad Response Authenticator at iter {n}",
        );
        assert_eq!(
            message_authenticator::verify(&recv_buf[..len], &ra, SECRET),
            Verification::Valid,
            "bad Message-Authenticator at iter {n}",
        );
    }
    let elapsed = t0.elapsed();

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();

    let rate = REQUESTS as f64 / elapsed.as_secs_f64();
    println!("completed {REQUESTS} round-trips in {elapsed:?} ({rate:.0} req/s)");
    println!("each reply built into the same thread-local PacketBuffer");
    Ok(())
}
