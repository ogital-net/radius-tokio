//! End-to-end EAP-TTLS + PAP check driven by hostap's `eapol_test`.
//!
//! Mirrors [`eapol_test_peap_mschapv2`](./eapol_test_peap_mschapv2.rs)
//! but exercises the EAP-TTLS outer + PAP inner pipeline:
//! [`radius_tokio_eap::eap_ttls::EapTtlsFactory`] wrapping
//! [`radius_tokio_eap::eap_ttls::PapInnerFactory`].
//!
//! What we assert:
//!
//! * A server-only TLS handshake (no client cert) completes
//!   between `wpa_supplicant` and our in-process `TlsConnection`,
//!   carried over EAP-Message fragments inside RADIUS.
//! * After phase-1 completes, the peer ships a single
//!   `User-Name` + `User-Password` AVP pair over the TLS tunnel
//!   which the [`PapInner`] verifies.
//! * The final `Access-Accept` carries `MS-MPPE-Send-Key` /
//!   `MS-MPPE-Recv-Key` derived from the EAP-TTLS keying-material
//!   export (`"ttls keying material"`).
//! * Supplicant prints
//!   `EAP authentication completed successfully`.
//!
//! Skipped with a printed notice on hosts that don't have
//! `eapol_test` on `PATH`.

#![cfg(feature = "eap-ttls")]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::tls::TlsContext;
use radius_tokio_eap::eap_ttls::{EapTtlsFactory, PapInnerFactory, StaticPapCredentials};
use radius_tokio_eap::EapHandler;

const SHARED_SECRET: &str = "testing123";
const IDENTITY: &str = "alice";
const PASSWORD: &str = "hello123";

struct Pki {
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    use std::net::IpAddr;
    let ca = CertificateAuthority::new("radius-tokio-ttls-test-ca").unwrap();
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
    Pki {
        server_chain_pem: server.chain_pem,
        server_key_pem: server.key_pem,
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
async fn eapol_test_ttls_pap_succeeds() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end EAP-TTLS/PAP test");
        return;
    }

    let pki = build_pki();

    let tls_ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem)
            .expect("build server tls ctx");

    let creds = Arc::new(StaticPapCredentials::cleartext(
        IDENTITY.as_bytes(),
        PASSWORD,
    ));
    let inner_factory = Arc::new(PapInnerFactory::new(creds));
    let factory = EapTtlsFactory::new(Arc::new(tls_ctx), inner_factory);
    let handler = EapHandler::new(factory);

    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let port = bind_addr.port();
    let tmp_dir = {
        let mut p = std::env::temp_dir();
        p.push(format!("radius-tokio-ttls-pap-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create tmpdir");
        p
    };
    let ca_path = write_file(&tmp_dir, "ca.pem", &pki.ca_pem);
    let conf_path = tmp_dir.join("eapol_test.conf");
    {
        let mut f = std::fs::File::create(&conf_path).expect("write conf");
        // 802.1X / TTLS, phase2 PAP. The `anonymous` outer
        // identity hides the real username before TLS is up; the
        // inner User-Name AVP carries the real identity.
        writeln!(
            f,
            "network={{\n\
             \tkey_mgmt=IEEE8021X\n\
             \teap=TTLS\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tanonymous_identity=\"anonymous\"\n\
             \tpassword=\"{PASSWORD}\"\n\
             \tca_cert=\"{ca}\"\n\
             \tphase2=\"auth=PAP\"\n\
             }}",
            ca = ca_path.display(),
        )
        .expect("write conf");
    }

    let conf_str = conf_path.to_str().expect("utf-8 conf path").to_owned();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        Command::new("eapol_test")
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
