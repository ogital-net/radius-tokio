//! End-to-end coverage for the per-listener-role code filter.
//!
//! Every production RADIUS implementation (FreeRADIUS' per-socket
//! `type` filter, radsecproxy's split `listenUDP` /
//! `listenAccountingUDP` accept paths, Microsoft NPS's separate
//! 1812/1813 services) drops packets whose RADIUS code does not
//! match the role of the listener that received them. This crate
//! does the same — see [`radius_tokio::server::ListenerRole::accepts`].
//!
//! Asserts:
//!
//! * Access-Request to an `Acct` listener is silently dropped and
//!   the handler is never invoked.
//! * Accounting-Request to an `Auth` listener is silently dropped
//!   and the handler is never invoked.
//! * Status-Server (RFC 5997) is still answered on both roles
//!   (regression guard for the filter).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server, StaticClients,
};
use radius_tokio::{authenticator, Code, PacketBuffer};

struct CountHandler {
    calls: Arc<AtomicUsize>,
}

impl Handler for CountHandler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        self.calls.fetch_add(1, Ordering::Relaxed);
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
    }
}

async fn pick_port() -> SocketAddr {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

async fn expect_silence(sock: &tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 4096];
    let res = tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
    assert!(res.is_err(), "expected silence, got reply: {res:?}");
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

fn make_store(secret: &[u8]) -> StaticClients {
    StaticClients::builder()
        .add(
            IpCidr::host(Ipv4Addr::LOCALHOST.into()),
            Arc::new(Client::new(secret)),
        )
        .build()
}

fn build_access_request(identifier: u8, secret: &[u8]) -> Vec<u8> {
    let req_auth = authenticator::random_request_authenticator();
    let mut buf = PacketBuffer::new(Code::ACCESS_REQUEST, identifier);
    buf.add_attribute(1, b"alice").expect("user-name");
    buf.seal_as_random_authenticator_request(&req_auth, secret)
        .expect("seal")
        .as_bytes()
        .to_vec()
}

fn build_accounting_request(identifier: u8, secret: &[u8]) -> Vec<u8> {
    let mut buf = PacketBuffer::new(Code::ACCOUNTING_REQUEST, identifier);
    // Acct-Status-Type = Start.
    buf.add_attribute(40, &1u32.to_be_bytes()).expect("type");
    buf.add_attribute(44, b"sess-1").expect("session-id");
    buf.add_attribute(1, b"alice").expect("user-name");
    buf.seal_as_zeroed_request(secret).as_bytes().to_vec()
}

fn build_status_server(identifier: u8, secret: &[u8]) -> ([u8; 16], Vec<u8>) {
    let req_auth = authenticator::random_request_authenticator();
    let sealed = PacketBuffer::new(Code::STATUS_SERVER, identifier)
        .seal_as_random_authenticator_request(&req_auth, secret)
        .expect("seal");
    (req_auth, sealed.as_bytes().to_vec())
}

#[tokio::test(flavor = "current_thread")]
async fn access_request_on_acct_listener_is_dropped() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret))
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
    probe
        .send_to(&build_access_request(1, &secret), bind)
        .await
        .unwrap();

    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "handler must not see a mismatched-code packet",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn accounting_request_on_auth_listener_is_dropped() {
    let secret = b"shh".to_vec();
    let bind = pick_port().await;
    let calls = Arc::new(AtomicUsize::new(0));

    let server = Server::builder()
        .clients(make_store(&secret))
        .handler(CountHandler {
            calls: Arc::clone(&calls),
        })
        .listen_udp(bind) // default = Auth
        .build()
        .expect("build");
    let shutdown = server.shutdown_handle();
    let task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe
        .send_to(&build_accounting_request(2, &secret), bind)
        .await
        .unwrap();

    expect_silence(&probe).await;

    shutdown.shutdown();
    let _ = task.await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

/// Regression guard: Status-Server (RFC 5997, code 12) is the one
/// code that must traverse the filter on every role.
#[tokio::test(flavor = "current_thread")]
async fn status_server_traverses_filter_on_both_roles() {
    let secret = b"shh".to_vec();

    for (role, expected) in [
        (ListenerRole::Auth, Code::ACCESS_ACCEPT),
        (ListenerRole::Acct, Code::ACCOUNTING_RESPONSE),
    ] {
        let bind = pick_port().await;
        let calls = Arc::new(AtomicUsize::new(0));

        let server = Server::builder()
            .clients(make_store(&secret))
            .handler(CountHandler {
                calls: Arc::clone(&calls),
            })
            .listen_udp_with(bind, role)
            .build()
            .expect("build");
        let shutdown = server.shutdown_handle();
        let task = tokio::spawn(server.run());
        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_auth, datagram) = build_status_server(9, &secret);
        probe.send_to(&datagram, bind).await.unwrap();
        let reply = recv_one(&probe).await;

        assert_eq!(
            reply[0], expected.0,
            "{role:?} should reply with {expected:?}"
        );

        shutdown.shutdown();
        let _ = task.await;
    }
}
