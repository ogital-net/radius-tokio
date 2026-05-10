//! End-to-end `RadSec` **cert-keyed** integration test.
//!
//! Sister to `radsec_e2e_ip.rs`, which exercises the IP-gated mode
//! against a single client cert. This test verifies the default
//! cert-keyed mode (RFC 6614 §2.5):
//!
//! ```text
//!   radclient ──UDP──▶ radsecproxy ──TLS(alice cert)──▶ │ server's
//!   radclient ──UDP──▶ radsecproxy ──TLS(bob   cert)──▶ │ ClientStore
//!                       (one process, two tls blocks)   │ maps the
//!                                                       │ peer cert
//!                                                       │ to the
//!                                                       │ matching
//!                                                       │ Client
//! ```
//!
//! Two separate clients ("alice" and "bob") share the same CA but
//! present distinct leaf certs and are registered with **distinct
//! shared secrets**. A wrong cert→client mapping in our server
//! would cause radsecproxy to reject the reply's
//! Message-Authenticator and the upstream radclient flow to time
//! out. Both flows passing means cert-keyed dispatch is correct.
//!
//! The test is skipped (with a printed notice) on hosts missing
//! either `radclient` or `radsecproxy` from `PATH`, so the suite
//! stays green in slim containers.

#![cfg(feature = "radsec")]
#![allow(
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::needless_raw_string_hashes
)]

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{Client, ClientStore, Handler, HandlerResult, Request, Server};
use radius_tokio::tls::{PeerCertificate, TlsContext};
use radius_tokio::Code;

struct AcceptAll;

impl Handler for AcceptAll {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
    }
}

/// Cert-keyed `ClientStore`: maps a peer's hostname to a
/// pre-registered [`Client`] via
/// [`PeerCertificate::matches_hostname`], which implements RFC
/// 6125 §6.4.3 (SAN dNSName preferred, leftmost-label wildcards,
/// IP-literal expectations matched against iPAddress SANs). RFC
/// 6614 §2.3 mandates a SAN on RadSec leaves and RFC 6125 §6.4.4
/// deprecates Common Name matching, so we pass
/// `allow_common_name = false`. Real deployments would back this
/// with a database; the test uses a frozen in-memory map.
struct SanStore {
    clients_by_name: HashMap<String, Arc<Client>>,
}

impl ClientStore for SanStore {
    #[allow(clippy::manual_async_fn)]
    fn lookup_udp(&self, _src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // No UDP listeners in this test; default to None.
        async { None }
    }

    // Pre-handshake admission defaults to `false` (deny). The
    // test runs everything on loopback against an ephemeral CA,
    // so opening the gate to any source is safe — the mTLS
    // handshake against the listener's trust store rejects
    // anyone without the test client cert.
    async fn admit_radsec(&self, _src: SocketAddr) -> bool {
        true
    }

    fn lookup_radsec_by_cert(
        &self,
        _src: SocketAddr,
        peer: &PeerCertificate,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // Iterate the registry and let `matches_hostname` do the
        // RFC 6125 §6.4.3 SAN walk for us; CN fallback disabled.
        let hit = self
            .clients_by_name
            .iter()
            .find(|(name, _)| peer.matches_hostname(name, false))
            .map(|(_, client)| Arc::clone(client));
        async move { hit }
    }
}

fn radclient_available() -> bool {
    Command::new("radclient")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn radsecproxy_path() -> Option<String> {
    for candidate in [
        "radsecproxy",
        "/usr/sbin/radsecproxy",
        "/usr/local/sbin/radsecproxy",
    ] {
        if Command::new(candidate)
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Two-client PKI: one CA, one server cert (with loopback SAN), and
/// two distinct leaf certs sharing the CA but issued to different
/// CNs.
struct Pki {
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    alice_chain_pem: Vec<u8>,
    alice_key_pem: Vec<u8>,
    bob_chain_pem: Vec<u8>,
    bob_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
    use std::net::IpAddr;

    let ca = CertificateAuthority::new("radsec-ck-ca").unwrap();
    let server = ca
        .issue_server(
            "radsec.test",
            &[
                SubjectAltName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                SubjectAltName::Dns("localhost".into()),
                SubjectAltName::Dns("radsec.test".into()),
            ],
        )
        .unwrap();
    let alice = ca
        .issue_client("alice", &[SubjectAltName::Dns("alice".into())])
        .unwrap();
    let bob = ca
        .issue_client("bob", &[SubjectAltName::Dns("bob".into())])
        .unwrap();

    Pki {
        server_chain_pem: server.chain_pem,
        server_key_pem: server.key_pem,
        alice_chain_pem: alice.chain_pem,
        alice_key_pem: alice.key_pem,
        bob_chain_pem: bob.chain_pem,
        bob_key_pem: bob.key_pem,
        ca_pem: ca.cert_pem().unwrap(),
    }
}

fn write_file(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write pki file");
    path
}

#[tokio::test(flavor = "current_thread")]
async fn radsec_cert_keyed_dispatches_to_correct_client() {
    if !radclient_available() {
        eprintln!("radclient not on PATH; skipping cert-keyed RadSec end-to-end test");
        return;
    }
    let Some(rsp) = radsecproxy_path() else {
        eprintln!("radsecproxy not on PATH; skipping cert-keyed RadSec end-to-end test");
        return;
    };

    let pki = build_pki();

    // Each client has its own RadSec-leg shared secret. If the
    // server mis-dispatches and uses the wrong secret to seal the
    // reply, radsecproxy will reject the Message-Authenticator and
    // the radclient call below will fail. RFC 6614 §2.6 says the
    // literal string "radsec" SHOULD be used; we deliberately use
    // *different* strings here to make a mis-dispatch detectable.
    let alice_secret = "secret-for-alice";
    let bob_secret = "secret-for-bob";
    // UDP secret between radclient and radsecproxy — not on the
    // RadSec leg, identical for both flows.
    let client_secret = "testing123";

    let tmp = tempdir_unique("radsec-ck-e2e").expect("create tempdir");
    let ca_path = write_file(&tmp, "ca.pem", &pki.ca_pem);
    let alice_cert_path = write_file(&tmp, "alice.pem", &pki.alice_chain_pem);
    let alice_key_path = write_file(&tmp, "alice.key", &pki.alice_key_pem);
    let bob_cert_path = write_file(&tmp, "bob.pem", &pki.bob_chain_pem);
    let bob_key_path = write_file(&tmp, "bob.key", &pki.bob_key_pem);

    let radsec_addr = ephemeral_tcp().await;
    let proxy_udp_addr = ephemeral_udp().await;

    // ---- spawn our Server (cert-keyed) ---------------------------
    let tls_ctx = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem)
        .expect("build server tls ctx");

    let alice_client = Arc::new(Client::new(alice_secret.as_bytes()));
    let bob_client = Arc::new(Client::new(bob_secret.as_bytes()));
    let alice_id = alice_client.id();
    let bob_id = bob_client.id();
    let mut clients_by_name = HashMap::new();
    clients_by_name.insert("alice".to_string(), Arc::clone(&alice_client));
    clients_by_name.insert("bob".to_string(), Arc::clone(&bob_client));
    let store = SanStore { clients_by_name };

    let server = Server::builder()
        .clients(store)
        .handler(AcceptAll)
        .listen_radsec(radsec_addr, tls_ctx) // cert-keyed by default
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ---- spawn radsecproxy with two TLS profiles -----------------
    //
    // Realm-based routing:
    //   User-Name "u@alice" → realm "alice" → server srv_alice
    //   User-Name "u@bob"   → realm "bob"   → server srv_bob
    //
    // Each upstream uses its own TLS leg (own client cert + own
    // RadSec shared secret) but points at the same RadSec listener
    // on our server.
    let cfg_path = tmp.join("radsecproxy.conf");
    let config = format!(
        r#"# Auto-generated by radsec_e2e (cert-keyed) integration test.
LogLevel 1
LogDestination stderr

tls tls_alice {{
    CACertificateFile {ca}
    CertificateFile   {alice_cert}
    CertificateKeyFile {alice_key}
}}

tls tls_bob {{
    CACertificateFile {ca}
    CertificateFile   {bob_cert}
    CertificateKeyFile {bob_key}
}}

ListenUDP {proxy_listen}

client 127.0.0.1 {{
    type udp
    secret {client_secret}
}}

server srv_alice {{
    host {radsec_host}
    port {radsec_port}
    type tls
    secret {alice_secret}
    tls tls_alice
    CertificateNameCheck off
    StatusServer off
}}

server srv_bob {{
    host {radsec_host}
    port {radsec_port}
    type tls
    secret {bob_secret}
    tls tls_bob
    CertificateNameCheck off
    StatusServer off
}}

realm /@alice$/ {{
    server srv_alice
}}

realm /@bob$/ {{
    server srv_bob
}}
"#,
        ca = ca_path.display(),
        alice_cert = alice_cert_path.display(),
        alice_key = alice_key_path.display(),
        bob_cert = bob_cert_path.display(),
        bob_key = bob_key_path.display(),
        proxy_listen = proxy_udp_addr,
        radsec_host = radsec_addr.ip(),
        radsec_port = radsec_addr.port(),
        client_secret = client_secret,
        alice_secret = alice_secret,
        bob_secret = bob_secret,
    );
    std::fs::write(&cfg_path, config).expect("write radsecproxy.conf");

    let mut proxy = Command::new(&rsp)
        .args(["-f", "-d", "2", "-c", cfg_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn radsecproxy");

    // Give radsecproxy time to load + bind.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ---- run radclient twice -------------------------------------
    let alice_out = run_radclient(proxy_udp_addr, client_secret, "alice@alice")
        .await
        .expect("alice radclient");
    let bob_out = run_radclient(proxy_udp_addr, client_secret, "bob@bob")
        .await
        .expect("bob radclient");

    // ---- teardown ------------------------------------------------
    let _ = proxy.kill();
    let proxy_out = proxy.wait_with_output().ok();
    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

    let proxy_stderr = proxy_out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();

    for (label, out) in [("alice", &alice_out), ("bob", &bob_out)] {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{label} radclient exited with {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- proxy stderr ---\n{proxy_stderr}",
            out.status.code(),
        );
        assert!(
            stdout.contains("Access-Accept"),
            "{label}: expected Access-Accept through cert-keyed RadSec\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- proxy stderr ---\n{proxy_stderr}",
        );
    }

    // Sanity: alice and bob really are distinct client records.
    // (Catches accidental same-Arc construction in this test
    // setup; without it a mapping bug would still pass above.)
    assert_ne!(alice_id, bob_id);

    let _ = std::fs::remove_dir_all(&tmp);
}

async fn run_radclient(
    proxy: SocketAddr,
    secret: &str,
    user: &str,
) -> std::io::Result<std::process::Output> {
    let target = format!("{}:{}", proxy.ip(), proxy.port());
    let secret = secret.to_string();
    let user = user.to_string();
    tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        let mut child = Command::new("radclient")
            .args(["-x", "-r", "1", "-t", "5", &target, "auth", &secret])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        {
            let stdin = child.stdin.as_mut().expect("piped stdin");
            writeln!(stdin, "User-Name = \"{user}\"")?;
            writeln!(stdin, "User-Password = \"pw\"")?;
        }
        child.wait_with_output()
    })
    .await
    .expect("blocking task joined")
}

async fn ephemeral_udp() -> SocketAddr {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

async fn ephemeral_tcp() -> SocketAddr {
    let s = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

fn tempdir_unique(prefix: &str) -> std::io::Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
