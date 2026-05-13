//! End-to-end Status-Server (RFC 5997) coverage against a real
//! `Server` over UDP.
//!
//! Asserts:
//!
//! * an auth-role listener answers a valid Status-Server probe with
//!   Access-Accept + valid Response Authenticator + valid
//!   Message-Authenticator (RFC 5997 §6);
//! * an acct-role listener answers with Accounting-Response;
//! * a probe missing Message-Authenticator is silently dropped
//!   (RFC 5997 §6);
//! * a probe with a bad Message-Authenticator is silently dropped;
//! * `StatusServerPolicy::Disabled` silences every probe;
//! * `Client::disable_status_server` silences a single peer;
//! * a `StatusResponder` callback can inject a `Reply-Message`;
//! * the consumer's `Handler` is **never** invoked for Status-Server
//!   regardless of policy.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server, StaticClients,
    StatusAction, StatusContext, StatusResponder, StatusServerPolicy,
};
use radius_tokio::{authenticator, message_authenticator, Code, PacketBuffer};

/// Handler that records every invocation. Status-Server must short-
/// circuit *before* the handler runs, so the count must stay zero
/// for every Status-Server-only test.
struct CountHandler {
    calls: Arc<AtomicUsize>,
}

impl Handler for CountHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.calls.fetch_add(1, Ordering::Relaxed);
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
    }
}

/// Build a valid Status-Server datagram: random Request
/// Authenticator + a correct Message-Authenticator. Returns
/// `(request_authenticator, datagram)`.
fn build_status_server(identifier: u8, secret: &[u8]) -> ([u8; 16], Vec<u8>) {
    let req_auth = authenticator::random_request_authenticator();
    let buf = PacketBuffer::new(Code::STATUS_SERVER, identifier);
    let sealed = buf
        .seal_as_random_authenticator_request(&req_auth, secret)
        .expect("seal");
    (req_auth, sealed.as_bytes().to_vec())
}

/// Same shape, but **without** a Message-Authenticator attribute.
/// RFC 5997 §6 says this MUST be silently dropped.
fn build_status_server_no_ma(identifier: u8) -> Vec<u8> {
    let req_auth = authenticator::random_request_authenticator();
    let mut pkt = vec![Code::STATUS_SERVER.0, identifier, 0, 0];
    pkt.extend_from_slice(&req_auth);
    let len = u16::try_from(pkt.len()).unwrap();
    pkt[2..4].copy_from_slice(&len.to_be_bytes());
    pkt
}

/// Build a Status-Server with a deliberately corrupted M-A tag.
fn build_status_server_bad_ma(identifier: u8, secret: &[u8]) -> Vec<u8> {
    let (_auth, mut bytes) = build_status_server(identifier, secret);
    // Flip the last byte — guaranteed to land in the M-A value
    // since we appended it as the only attribute.
    *bytes.last_mut().unwrap() ^= 0xFF;
    bytes
}

/// Pick a free loopback UDP port up front and hand it back so the
/// server can re-bind the same address. Mirrors the pattern used in
/// `tests/accounting.rs`.
async fn pick_port() -> SocketAddr {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

async fn recv_one(sock: &tokio::net::UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf))
        .await
        .expect("server replied within timeout")
        .unwrap();
    buf.truncate(len);
    buf
}

/// Returns `Ok(())` if no datagram arrives within the window.
async fn expect_silence(sock: &tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 4096];
    let res = tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut buf)).await;
    assert!(res.is_err(), "expected silence, got reply: {res:?}");
}

fn make_store(secret: &[u8], status_enabled: bool) -> StaticClients {
    let mut client = Client::new(secret);
    if !status_enabled {
        client = client.disable_status_server();
    }
    StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), Arc::new(client))
        .build()
}

#[tokio::test(flavor = "current_thread")]
async fn auth_listener_replies_access_accept() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::clone(&calls),
        })
        .listen_udp(bind)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (req_auth, datagram) = build_status_server(7, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    let reply = recv_one(&probe).await;

    assert_eq!(
        reply[0],
        Code::ACCESS_ACCEPT.0,
        "auth role => Access-Accept"
    );
    assert_eq!(reply[1], 7, "identifier echoed");
    assert!(authenticator::verify_response(&reply, &req_auth, &secret));
    assert_eq!(
        message_authenticator::verify(&reply, &req_auth, &secret),
        message_authenticator::Verification::Valid,
    );

    shutdown.shutdown();
    let _ = task.await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "handler must not see Status-Server",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn acct_listener_replies_accounting_response() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::clone(&calls),
        })
        .listen_udp_with(bind, ListenerRole::Acct)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (req_auth, datagram) = build_status_server(8, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    let reply = recv_one(&probe).await;

    assert_eq!(reply[0], Code::ACCOUNTING_RESPONSE.0);
    assert_eq!(reply[1], 8);
    assert!(authenticator::verify_response(&reply, &req_auth, &secret));

    shutdown.shutdown();
    let _ = task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_message_authenticator_is_silently_dropped() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::clone(&calls),
        })
        .listen_udp(bind)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe
        .send_to(&build_status_server_no_ma(1), bind)
        .await
        .unwrap();
    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bad_message_authenticator_is_silently_dropped() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::clone(&calls),
        })
        .listen_udp(bind)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe
        .send_to(&build_status_server_bad_ma(2, &secret), bind)
        .await
        .unwrap();
    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn disabled_policy_silences_every_probe() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .listen_udp(bind)
        .status_server_policy(StatusServerPolicy::Disabled)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_auth, datagram) = build_status_server(3, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn per_client_disable_silences_one_peer() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;

    let server = Server::builder()
        .clients(make_store(&secret, false))
        .handler(CountHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .listen_udp(bind)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_auth, datagram) = build_status_server(4, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
}

struct StatusString(&'static str);
impl StatusResponder for StatusString {
    fn respond(&self, _ctx: StatusContext<'_>, reply: &mut radius_tokio::Reply) -> StatusAction {
        radius_tokio::server::status::append_reply_message(reply, self.0.as_bytes()).unwrap();
        StatusAction::Send
    }
}

#[tokio::test(flavor = "current_thread")]
async fn custom_responder_injects_reply_message() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .listen_udp(bind)
        .status_server_policy(StatusServerPolicy::Custom(Arc::new(StatusString(
            "queue=0",
        ))))
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (req_auth, datagram) = build_status_server(5, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    let reply = recv_one(&probe).await;

    assert_eq!(reply[0], Code::ACCESS_ACCEPT.0);
    assert!(authenticator::verify_response(&reply, &req_auth, &secret));

    // Walk the attribute list looking for Reply-Message (type 18)
    // == "queue=0".
    let attrs = &reply[20..];
    let mut found = false;
    let mut idx = 0;
    while idx + 2 <= attrs.len() {
        let typ = attrs[idx];
        let len = attrs[idx + 1] as usize;
        if len < 2 || idx + len > attrs.len() {
            break;
        }
        if typ == 18 && &attrs[idx + 2..idx + len] == b"queue=0" {
            found = true;
        }
        idx += len;
    }
    assert!(found, "Reply-Message not found in {reply:02x?}");

    shutdown.shutdown();
    let _ = task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn retransmit_replays_cached_reply_byte_for_byte() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;

    let server = Server::builder()
        .clients(make_store(&secret, true))
        .handler(CountHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .listen_udp(bind)
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_auth, datagram) = build_status_server(6, &secret);
    probe.send_to(&datagram, bind).await.unwrap();
    let first = recv_one(&probe).await;
    probe.send_to(&datagram, bind).await.unwrap();
    let second = recv_one(&probe).await;
    assert_eq!(first, second, "retransmit must replay the cached reply");

    shutdown.shutdown();
    let _ = task.await;
}
