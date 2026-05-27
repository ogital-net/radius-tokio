//! End-to-end accounting flow against a real `Server` over UDP.
//!
//! Drives the full RFC 2866 lifecycle (Start → Interim-Update →
//! Stop) plus a NAS retransmit of the Stop, and asserts:
//!
//! * the server replies with Accounting-Response for every step;
//! * the handler sees the right `Acct-Status-Type` for each step;
//! * the server's Response Authenticator (RFC 2866 §3) and
//!   reply-side Message-Authenticator (RFC 3579 §3.2) are valid;
//! * a NAS retransmit of the Stop with the same identifier and
//!   request-authenticator is satisfied from the dedup cache (RFC
//!   5080 §2.2.2) — the handler does *not* run a second time.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::dict::rfc::attrs;
use radius_tokio::server::{
    AcctStatusType, Client, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server,
    StaticClients,
};
use radius_tokio::{authenticator, message_authenticator, Code, PacketBuffer};

/// Counts each Acct-Status-Type the handler observes.
#[derive(Debug, Default)]
struct AcctCounts {
    start: AtomicUsize,
    interim: AtomicUsize,
    stop: AtomicUsize,
    other: AtomicUsize,
}

struct AcctHandler {
    counts: Arc<AcctCounts>,
}

impl Handler for AcctHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        // This fixture only enumerates Accounting-Request handling;
        // reject any other code so a bug surfaces clearly.
        assert_eq!(request.code(), Code::ACCOUNTING_REQUEST);
        match request.acct_status_type() {
            Some(AcctStatusType::Start) => {
                self.counts.start.fetch_add(1, Ordering::Relaxed);
            }
            Some(AcctStatusType::InterimUpdate) => {
                self.counts.interim.fetch_add(1, Ordering::Relaxed);
            }
            Some(AcctStatusType::Stop) => {
                self.counts.stop.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.counts.other.fetch_add(1, Ordering::Relaxed);
            }
        }
        HandlerResult::Reply(request.reply(Code::ACCOUNTING_RESPONSE))
    }
}

/// Build an Accounting-Request datagram for the supplied
/// Acct-Status-Type. Returns `(request_authenticator, datagram)`.
///
/// The Authenticator field of an Accounting-Request is `MD5(packet
/// with the auth field zeroed || secret)` (RFC 2866 §3); we delegate
/// that math to the library's own helper so the test stays
/// independent of any second MD5 implementation.
fn build_accounting_request(
    identifier: u8,
    status: AcctStatusType,
    session_id: &str,
    secret: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let mut buf = PacketBuffer::new(Code::ACCOUNTING_REQUEST, identifier);
    buf.add(attrs::ACCT_STATUS_TYPE, status.to_u32())
        .expect("fits");
    buf.add(attrs::ACCT_SESSION_ID, session_id).expect("fits");
    buf.add(attrs::USER_NAME, "alice").expect("fits");

    let sealed = buf.seal_as_zeroed_request(secret);
    let auth = sealed.header().authenticator;
    (auth, sealed.as_bytes().to_vec())
}

/// Wait for one reply on `sock` with a short timeout.
async fn recv_one(sock: &tokio::net::UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf))
        .await
        .expect("server replied within timeout")
        .unwrap();
    buf.truncate(len);
    buf
}

#[tokio::test(flavor = "current_thread")]
async fn full_accounting_lifecycle() {
    let secret = b"shared".to_vec();
    let counts = Arc::new(AcctCounts::default());

    let client = Arc::new(Client::new(secret.as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    // Pick a free port up front so the test client knows where to
    // send. (`Server::run` does its own bind on the same address.)
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(AcctHandler {
            counts: Arc::clone(&counts),
        })
        .listen_udp_with(bind_addr, ListenerRole::Acct)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    // Let the listener bind before firing test traffic.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let nas = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // ---------- Start ----------
    let (start_auth, start_pkt) =
        build_accounting_request(1, AcctStatusType::Start, "sess-1", &secret);
    nas.send_to(&start_pkt, bind_addr).await.unwrap();
    let reply = recv_one(&nas).await;
    assert_eq!(reply[0], Code::ACCOUNTING_RESPONSE.0);
    assert_eq!(reply[1], 1);
    assert!(authenticator::verify_response(&reply, &start_auth, &secret));
    assert_eq!(
        message_authenticator::verify(&reply, &start_auth, &secret),
        message_authenticator::Verification::Valid,
    );

    // ---------- Interim-Update ----------
    let (interim_auth, interim_pkt) =
        build_accounting_request(2, AcctStatusType::InterimUpdate, "sess-1", &secret);
    nas.send_to(&interim_pkt, bind_addr).await.unwrap();
    let reply = recv_one(&nas).await;
    assert_eq!(reply[0], Code::ACCOUNTING_RESPONSE.0);
    assert_eq!(reply[1], 2);
    assert!(authenticator::verify_response(
        &reply,
        &interim_auth,
        &secret
    ));

    // ---------- Stop ----------
    let (stop_auth, stop_pkt) =
        build_accounting_request(3, AcctStatusType::Stop, "sess-1", &secret);
    nas.send_to(&stop_pkt, bind_addr).await.unwrap();
    let reply = recv_one(&nas).await;
    assert_eq!(reply[0], Code::ACCOUNTING_RESPONSE.0);
    assert_eq!(reply[1], 3);
    assert!(authenticator::verify_response(&reply, &stop_auth, &secret));

    // ---------- NAS retransmit of the Stop ----------
    // Same identifier + same request-authenticator → dedup cache hit;
    // the handler must NOT run a second time, but we must still see a
    // valid reply on the wire.
    nas.send_to(&stop_pkt, bind_addr).await.unwrap();
    let cached = recv_one(&nas).await;
    assert_eq!(cached[0], Code::ACCOUNTING_RESPONSE.0);
    assert_eq!(cached[1], 3);
    assert!(authenticator::verify_response(&cached, &stop_auth, &secret));

    shutdown.shutdown();
    let _ = server_task.await;

    // The dedup cache must have absorbed the retransmit: exactly
    // three handler invocations for Start / Interim / Stop.
    assert_eq!(counts.start.load(Ordering::Relaxed), 1, "Start once");
    assert_eq!(counts.interim.load(Ordering::Relaxed), 1, "Interim once");
    assert_eq!(
        counts.stop.load(Ordering::Relaxed),
        1,
        "Stop runs once; the retransmit is served from the dedup cache",
    );
    assert_eq!(counts.other.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bad_secret_drops_accounting_request() {
    let secret = b"shared".to_vec();
    let counts = Arc::new(AcctCounts::default());

    let client = Arc::new(Client::new(secret.as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(AcctHandler {
            counts: Arc::clone(&counts),
        })
        .listen_udp_with(bind_addr, ListenerRole::Acct)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Compute the authenticator with the wrong secret on purpose.
    let nas = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_, pkt) = build_accounting_request(7, AcctStatusType::Start, "sess-x", b"WRONG");
    nas.send_to(&pkt, bind_addr).await.unwrap();

    // No reply expected — the server silently drops on auth failure.
    let mut buf = vec![0u8; 4096];
    let res = tokio::time::timeout(Duration::from_millis(150), nas.recv_from(&mut buf)).await;
    assert!(res.is_err(), "no reply expected for bad authenticator");

    shutdown.shutdown();
    let _ = server_task.await;
    assert_eq!(counts.start.load(Ordering::Relaxed), 0);
}
