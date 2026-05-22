//! End-to-end EAP-TLS check driven by hostap's `eapol_test`.
//!
//! Sister to [`eapol_test_md5`](../../../../tests/eapol_test_md5.rs)
//! and [`eapol_test_mschapv2`](../../../../tests/eapol_test_mschapv2.rs)
//! in the core crate, but the method state machine under test is
//! the [`radius_tokio_eap::eap_tls::EapTls`] driver wired through
//! [`radius_tokio_eap::EapHandler`].
//!
//! What we assert:
//!
//! * A real TLS 1.2 / 1.3 handshake completes between `eapol_test`'s
//!   wpa_supplicant frontend and our in-process `TlsConnection`,
//!   carried over EAP-Message fragments inside RADIUS.
//! * The server's reply chain (`Access-Challenge × N → Access-Accept`)
//!   round-trips `State` (RFC 2865 §5.24) and `Message-Authenticator`
//!   (RFC 3579 / RFC 9716).
//! * The final `Access-Accept` carries usable `MS-MPPE-Send-Key` /
//!   `MS-MPPE-Recv-Key` VSAs derived from the RFC 5216 / RFC 9190
//!   keying-material export.
//! * The supplicant signals
//!   `EAP authentication completed successfully` — i.e. it accepted
//!   our server certificate (signed by the test CA) and we accepted
//!   its client certificate (signed by the same CA).
//!
//! Skipped with a printed notice on hosts that don't have
//! `eapol_test` on `PATH` so the test stays green in minimal CI
//! containers.

#![cfg(feature = "eap-tls")]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::tls::TlsContext;
use radius_tokio_eap::eap_tls::EapTlsFactory;
use radius_tokio_eap::EapHandler;

const SHARED_SECRET: &str = "testing123";
const IDENTITY: &str = "alice";

struct Pki {
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    use std::net::IpAddr;
    let ca = CertificateAuthority::new("radius-tokio-eap-test-ca").unwrap();
    let server = ca
        .issue_server(
            "radius.test",
            &[
                SubjectAltName::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                SubjectAltName::Dns("localhost".into()),
                SubjectAltName::Dns("radius.test".into()),
            ],
        )
        .unwrap();
    let client = ca
        .issue_client(IDENTITY, &[SubjectAltName::Dns(IDENTITY.into())])
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

fn eapol_test_available() -> bool {
    Command::new("eapol_test")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[tokio::test(flavor = "current_thread")]
async fn eapol_test_eap_tls_succeeds() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end EAP-TLS test");
        return;
    }

    let pki = build_pki();

    // mTLS context: server presents its cert, validates the peer
    // against the test CA. This is the default `TlsContext::server`
    // path (not the `server_without_client_auth` variant) since
    // EAP-TLS authentication *is* the client certificate.
    let tls_ctx = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem)
        .expect("build server tls ctx");

    let factory = EapTlsFactory::new(Arc::new(tls_ctx));
    let handler = EapHandler::new(factory);

    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    // Pick an ephemeral port by binding-then-dropping a probe socket.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(handler)
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    // Give the listener a beat to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let port = bind_addr.port();
    let tmp_dir = {
        let mut p = std::env::temp_dir();
        p.push(format!("radius-tokio-eap-tls-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create tmpdir");
        p
    };
    let ca_path = write_file(&tmp_dir, "ca.pem", &pki.ca_pem);
    let cert_path = write_file(&tmp_dir, "client.pem", &pki.client_chain_pem);
    let key_path = write_file(&tmp_dir, "client.key", &pki.client_key_pem);
    let conf_path = tmp_dir.join("eapol_test.conf");
    {
        let mut f = std::fs::File::create(&conf_path).expect("write conf");
        // wpa_supplicant config: 802.1X / EAP-TLS with the test PKI.
        // `key_mgmt=IEEE8021X` selects the wired/EAPOL flow.
        writeln!(
            f,
            "network={{\n\
             \tkey_mgmt=IEEE8021X\n\
             \teap=TLS\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tca_cert=\"{ca}\"\n\
             \tclient_cert=\"{cert}\"\n\
             \tprivate_key=\"{key}\"\n\
             }}",
            ca = ca_path.display(),
            cert = cert_path.display(),
            key = key_path.display(),
        )
        .expect("write conf");
    }

    let conf_str = conf_path.to_str().expect("utf-8 conf path").to_owned();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        Command::new("eapol_test")
            // -c: supplicant config
            // -a: AS IP, -p: AS port, -s: shared secret
            // -t 10: timeout (EAP-TLS handshake is heavier than MD5)
            // -r 0: don't re-authenticate.
            // (No -n: EAP-TLS *does* yield MPPE keys; let eapol_test
            // validate they're present.)
            .args([
                "-c",
                &conf_str,
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-s",
                SHARED_SECRET,
                "-t",
                "10",
                "-r",
                "0",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
    })
    .await
    .expect("blocking task joined")
    .expect("eapol_test spawned");

    shutdown.shutdown();
    let _ = server_task.await;
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    assert!(
        result.status.success(),
        "eapol_test exited with {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        result.status.code(),
    );
    let success =
        stdout.contains("SUCCESS") || stdout.contains("EAP authentication completed successfully");
    assert!(
        success,
        "expected EAP success in eapol_test output\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}
