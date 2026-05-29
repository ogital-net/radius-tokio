//! End-to-end check that a single [`MultiEapHandler`] can serve
//! two different EAP methods to two different supplicants —
//! exercising both the "preferred type wins" path and the
//! `EAP-Response/Nak` fallback path against the same listener.
//!
//! Routing table:
//!
//! * Preferred:  `PEAP` (type 25) — backed by `PeapFactory<MSCHAPv2>`
//! * Alternate:  `MD5` (type 4)   — backed by `EapMd5Factory`
//!
//! We run `eapol_test` twice against the same in-process server:
//!
//! 1. Config `eap=PEAP`: supplicant accepts the server's offered
//!    type. The PEAP outer + inner MSCHAPv2 exchange runs to
//!    completion, the reply carries MS-MPPE keys, supplicant
//!    prints SUCCESS.
//! 2. Config `eap=MD5`: server still offers PEAP first; the
//!    supplicant responds with `EAP-Response/Nak` listing type 4.
//!    [`MultiEapHandler`] pivots to the EAP-MD5 factory, replays
//!    the captured peer identity, and the MD5 exchange runs to
//!    completion. (`-n` because EAP-MD5 derives no MSK.)
//!
//! Skipped with a printed notice on hosts that don't have
//! `eapol_test` on `PATH`.

#![cfg(all(feature = "peap", feature = "eap-md5"))]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::eap::Type as EapType;
use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::tls::TlsContext;
use radius_tokio_eap::eap_md5::{EapMd5Factory, StaticCredentials as Md5StaticCredentials};
use radius_tokio_eap::mschapv2::{MsChapV2Factory, StaticCredentials as MsChapStaticCredentials};
use radius_tokio_eap::peap::PeapFactory;
use radius_tokio_eap::{EapRouter, MultiEapHandler};

mod common;
use common::{IDENTITY, PASSWORD, SHARED_SECRET};

fn eapol_test_available() -> bool {
    Command::new("eapol_test")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn build_pki() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca = CertificateAuthority::new("radius-tokio-multi-test-ca").unwrap();
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
    (server.chain_pem, server.key_pem, ca.cert_pem().unwrap())
}

/// Spawn `eapol_test` against `port` using `conf_path`. `expect_mppe`
/// controls the `-n` flag (which suppresses the MPPE-key check for
/// methods that derive none, like EAP-MD5).
#[allow(clippy::needless_pass_by_value)] // owned PathBuf reads more naturally at the test call sites
fn run_eapol_test(
    conf_path: std::path::PathBuf,
    port: u16,
    expect_mppe: bool,
) -> std::io::Result<std::process::Output> {
    let conf_str = conf_path.to_str().expect("utf-8 conf path").to_owned();
    let mut cmd = Command::new("eapol_test");
    cmd.args([
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
    ]);
    if !expect_mppe {
        cmd.arg("-n");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()
}

fn assert_eap_success(label: &str, out: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "[{label}] eapol_test exited with {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code(),
    );
    let success =
        stdout.contains("SUCCESS") || stdout.contains("EAP authentication completed successfully");
    assert!(
        success,
        "[{label}] expected EAP success in eapol_test output\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn eapol_test_multi_method_peap_and_md5() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end multi-method test");
        return;
    }

    // ── EAP stack ────────────────────────────────────────────────
    let (chain_pem, key_pem, ca_pem) = build_pki();
    let tls_ctx =
        TlsContext::server_without_client_auth(&chain_pem, &key_pem).expect("build server tls ctx");

    // Both factories share the same logical user (same identity +
    // password) so the test exercises method dispatch, not credential
    // routing.
    let mschap_creds = Arc::new(MsChapStaticCredentials::cleartext(
        IDENTITY.as_bytes(),
        PASSWORD,
    ));
    let inner_factory = Arc::new(MsChapV2Factory::new(mschap_creds));
    let peap_factory = PeapFactory::new(Arc::new(tls_ctx), inner_factory);

    let md5_creds = Arc::new(Md5StaticCredentials::cleartext(
        IDENTITY.as_bytes().to_vec(),
        PASSWORD.as_bytes().to_vec(),
    ));
    let md5_factory = EapMd5Factory::new(md5_creds);

    let router = EapRouter::builder()
        .preferred(EapType::PEAP)
        .register_typed(EapType::PEAP, peap_factory)
        .register_typed(EapType::MD5_CHALLENGE, md5_factory)
        .build()
        .expect("router builds");
    let handler = MultiEapHandler::new(router);

    // ── RADIUS plumbing ──────────────────────────────────────────
    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);
    let port = bind_addr.port();

    let server = Server::builder()
        .clients(store)
        .handler(handler)
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Per-run scratch dir ──────────────────────────────────────
    let tmp_dir = {
        let mut p = std::env::temp_dir();
        p.push(format!("radius-tokio-multi-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create tmpdir");
        p
    };
    let ca_path = tmp_dir.join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).expect("write ca pem");

    let peap_conf = tmp_dir.join("peap.conf");
    {
        let mut f = std::fs::File::create(&peap_conf).expect("write peap conf");
        writeln!(
            f,
            "network={{\n\
             \tkey_mgmt=WPA-EAP\n\
             \teap=PEAP\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tanonymous_identity=\"anonymous\"\n\
             \tpassword=\"{PASSWORD}\"\n\
             \tca_cert=\"{ca}\"\n\
             \tphase2=\"auth=MSCHAPV2\"\n\
             }}",
            ca = ca_path.display(),
        )
        .expect("write peap conf");
    }

    let md5_conf = tmp_dir.join("md5.conf");
    {
        let mut f = std::fs::File::create(&md5_conf).expect("write md5 conf");
        // Supplicant only does MD5 — when the router opens with
        // PEAP, wpa_supplicant will Nak with [4].
        writeln!(
            f,
            "network={{\n\
             \tkey_mgmt=IEEE8021X\n\
             \teap=MD5\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tpassword=\"{PASSWORD}\"\n\
             }}"
        )
        .expect("write md5 conf");
    }

    // ── Run 1: PEAP (preferred path, supplicant accepts) ─────────
    let peap_out = tokio::task::spawn_blocking(move || run_eapol_test(peap_conf, port, true))
        .await
        .expect("blocking task joined (peap)")
        .expect("eapol_test spawned (peap)");
    assert_eap_success("PEAP preferred path", &peap_out);

    // ── Run 2: MD5 (Nak fallback path) ───────────────────────────
    let md5_out = tokio::task::spawn_blocking(move || run_eapol_test(md5_conf, port, false))
        .await
        .expect("blocking task joined (md5)")
        .expect("eapol_test spawned (md5)");
    assert_eap_success("MD5 Nak fallback path", &md5_out);

    shutdown.shutdown();
    let _ = server_task.await;
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
