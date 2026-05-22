//! End-to-end EAP-MD5-Challenge check driven by hostap's `eapol_test`.
//!
//! Companion to [`eapol_test_peap_mschapv2`](./eapol_test_peap_mschapv2.rs)
//! but exercises the simplest method this crate ships:
//! [`radius_tokio_eap::eap_md5::EapMd5Factory`] driven by
//! [`radius_tokio_eap::EapHandler`].
//!
//! What we assert:
//!
//! * The handler's auto-allocated 16-byte `State` cookie
//!   (RFC 2865 §5.24) round-trips between Access-Challenge and the
//!   follow-up Access-Request.
//! * `EAP-Message` reassembly (RFC 3579 §3.1) carries the
//!   MD5-Challenge / MD5-Response across the exchange.
//! * Every reply carries a correctly-keyed `Message-Authenticator`
//!   that `eapol_test` validates per RFC 3579 / RFC 9716.
//! * `eapol_test` prints
//!   `EAP authentication completed successfully`.
//!
//! Skipped with a printed notice on hosts that don't have
//! `eapol_test` on `PATH`.
//!
//! Compared to the hand-rolled state machine that used to live in
//! `radius-tokio`'s test suite, this version is intentionally
//! tiny: the factory + handler do all the EAP plumbing, so the
//! test only wires the listener and shells out to the supplicant.

#![cfg(feature = "eap-md5")]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio_eap::eap_md5::{EapMd5Factory, StaticCredentials};
use radius_tokio_eap::EapHandler;

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

#[tokio::test(flavor = "current_thread")]
async fn eapol_test_md5_succeeds() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end EAP-MD5 test");
        return;
    }

    let creds = Arc::new(StaticCredentials::cleartext(
        IDENTITY.as_bytes().to_vec(),
        PASSWORD.as_bytes().to_vec(),
    ));
    let handler = EapHandler::new(EapMd5Factory::new(creds));

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
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        let mut conf_path = std::env::temp_dir();
        conf_path.push(format!("radius-tokio-eap-md5-{}.conf", std::process::id()));
        {
            let mut f = std::fs::File::create(&conf_path)?;
            // wpa_supplicant config: wired/EAPOL 802.1X with bare
            // EAP-MD5 and our static credentials.
            writeln!(
                f,
                "network={{\n\
                 \tkey_mgmt=IEEE8021X\n\
                 \teap=MD5\n\
                 \tidentity=\"{IDENTITY}\"\n\
                 \tpassword=\"{PASSWORD}\"\n\
                 }}"
            )?;
        }

        let output = Command::new("eapol_test")
            // -n: don't expect MPPE keys (EAP-MD5 derives none)
            // -t 5: short timeout — the conversation is local
            // -r 0: don't re-authenticate
            .args([
                "-c",
                conf_path.to_str().expect("utf-8 temp path"),
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-s",
                SHARED_SECRET,
                "-n",
                "-t",
                "5",
                "-r",
                "0",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        let _ = std::fs::remove_file(&conf_path);
        Ok(output)
    })
    .await
    .expect("blocking task joined")
    .expect("eapol_test spawned");

    shutdown.shutdown();
    let _ = server_task.await;

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
