//! End-to-end `RadSec` integration test.
//!
//! Wires three independent processes through our server:
//!
//! ```text
//!   radclient (UDP) ─▶ radsecproxy (UDP→TLS) ─▶ this crate's Server (RadSec)
//! ```
//!
//! `radsecproxy` is a battle-tested third-party `RadSec` implementation
//! (<https://github.com/radsecproxy/radsecproxy>) used in production at
//! eduroam scale. By forwarding through it we get external
//! verification that this server's `RadSec` implementation:
//!
//! * Performs a TLS 1.2/1.3 handshake interoperably with another
//!   stack (a different libssl flavour, different config knobs).
//! * Frames RADIUS messages over TLS exactly per RFC 6614 §2.6.4
//!   (header length field, no extra envelope).
//! * Seals the reply correctly so a downstream UDP RADIUS verifier
//!   accepts it (Response-Authenticator + Message-Authenticator).
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

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::tls::TlsContext;
use radius_tokio::Code;

struct AcceptAll;

impl Handler for AcceptAll {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
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

/// Minimal PKI built fresh per test run.
struct Pki {
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
    use std::net::IpAddr;

    let ca = CertificateAuthority::new("radsec-test-ca").unwrap();
    // Server cert: SAN includes 127.0.0.1 + localhost so radsecproxy
    // accepts the cert without `CertificateNameCheck off` gymnastics.
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
    let client = ca
        .issue_client(
            "radsecproxy-client",
            &[SubjectAltName::Dns("radsecproxy-client".into())],
        )
        .unwrap();

    Pki {
        server_chain_pem: server.chain_pem,
        server_key_pem: server.key_pem,
        client_chain_pem: client.chain_pem,
        client_key_pem: client.key_pem,
        ca_pem: ca.cert_pem().unwrap(),
    }
}

fn write_file(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write pki file");
    path
}

#[tokio::test(flavor = "current_thread")]
async fn radsec_through_radsecproxy_to_server() {
    if !radclient_available() {
        eprintln!("radclient not on PATH; skipping RadSec end-to-end test");
        return;
    }
    let Some(rsp) = radsecproxy_path() else {
        eprintln!("radsecproxy not on PATH; skipping RadSec end-to-end test");
        return;
    };

    let pki = build_pki();
    // Two distinct secrets:
    // * `client_secret` between radclient ↔ radsecproxy (UDP).
    // * `radsec_secret` between radsecproxy ↔ our server. RFC 6614
    //   §2.6 mandates the literal string "radsec" on the TLS leg
    //   regardless of what the upstream client used.
    let client_secret = "testing123";
    let radsec_secret = "radsec";

    // Per-test temp dir for cert / key / config files.
    let tmp = tempdir_unique("radsec-e2e").expect("create tempdir");
    let ca_path = write_file(&tmp, "ca.pem", &pki.ca_pem);
    let cli_cert_path = write_file(&tmp, "client.pem", &pki.client_chain_pem);
    let cli_key_path = write_file(&tmp, "client.key", &pki.client_key_pem);

    // Probe ephemeral ports. The radsecproxy listener and our RadSec
    // listener both bind only after the probe sockets are dropped;
    // collisions in this window are vanishingly unlikely on a CI box.
    let radsec_addr = ephemeral_tcp().await;
    let proxy_udp_addr = ephemeral_udp().await;

    // ---- spawn our Server ----------------------------------------
    let tls_ctx = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem)
        .expect("build server tls ctx");

    let client_record = Arc::new(Client::new(radsec_secret.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client_record)
        .build();
    let server = Server::builder()
        .clients(store)
        .handler(AcceptAll)
        .listen_radsec_ip_gated(radsec_addr, tls_ctx)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ---- spawn radsecproxy ---------------------------------------
    let cfg_path = tmp.join("radsecproxy.conf");
    let config = format!(
        r#"# Auto-generated by radsec_e2e integration test.
LogLevel 1
LogDestination stderr

tls default {{
    CACertificateFile {ca}
    CertificateFile   {cli_cert}
    CertificateKeyFile {cli_key}
}}

ListenUDP {proxy_listen}

client 127.0.0.1 {{
    type udp
    secret {client_secret}
}}

server radsec_upstream {{
    host {radsec_host}
    port {radsec_port}
    type tls
    secret {radsec_secret}
    tls default
    CertificateNameCheck off
    StatusServer off
}}

realm * {{
    server radsec_upstream
}}
"#,
        ca = ca_path.display(),
        cli_cert = cli_cert_path.display(),
        cli_key = cli_key_path.display(),
        proxy_listen = proxy_udp_addr,
        radsec_host = radsec_addr.ip(),
        radsec_port = radsec_addr.port(),
        client_secret = client_secret,
        radsec_secret = radsec_secret,
    );
    std::fs::write(&cfg_path, config).expect("write radsecproxy.conf");

    let mut proxy = Command::new(&rsp)
        .args([
            "-f", // foreground (don't fork)
            "-d",
            "2", // 1=errors only, 2=+warnings, 5=trace
            "-c",
            cfg_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn radsecproxy");

    // Give radsecproxy time to load the config, open its UDP listener,
    // and (lazily) prepare the upstream TLS server entry.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ---- run radclient -------------------------------------------
    let target = format!("{}:{}", proxy_udp_addr.ip(), proxy_udp_addr.port());
    let secret_owned = client_secret.to_string();
    let radclient =
        tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
            let mut child = Command::new("radclient")
                // -x: verbose output for CI diagnostics on failure.
                // -r 1, -t 5: one try, five-second timeout — gives the
                // proxy time to bring up the upstream TLS connection
                // on its first request, which can be a few hundred ms.
                .args(["-x", "-r", "1", "-t", "5", &target, "auth", &secret_owned])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            {
                let stdin = child.stdin.as_mut().expect("piped stdin");
                stdin.write_all(b"User-Name = \"alice\"\nUser-Password = \"bob\"\n")?;
            }
            child.wait_with_output()
        })
        .await
        .expect("blocking task joined")
        .expect("radclient spawned");

    // ---- teardown ------------------------------------------------
    let _ = proxy.kill();
    let proxy_out = proxy.wait_with_output().ok();
    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;

    let stdout = String::from_utf8_lossy(&radclient.stdout);
    let stderr = String::from_utf8_lossy(&radclient.stderr);
    let proxy_stderr = proxy_out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();

    assert!(
        radclient.status.success(),
        "radclient exited with {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- proxy stderr ---\n{proxy_stderr}",
        radclient.status.code(),
    );
    assert!(
        stdout.contains("Access-Accept"),
        "expected Access-Accept through RadSec\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- proxy stderr ---\n{proxy_stderr}",
    );

    // Tempdir cleanup is best-effort; if a panic above leaves it
    // around CI's host cleanup catches it.
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Bind a probe UDP socket on the loopback to learn an unused port,
/// then drop it so the caller can re-bind.
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

/// Create a unique temp directory under `std::env::temp_dir()`.
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
