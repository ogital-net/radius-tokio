//! End-to-end native (bare) EAP-MSCHAPv2 check driven by hostap's
//! `eapol_test`.
//!
//! Exercises [`radius_tokio_eap::mschapv2::EapMsChapV2Factory`]
//! driven by [`radius_tokio_eap::EapHandler`] over a real UDP
//! socket. Companion to `eapol_test_md5.rs`; the structural
//! sibling for the legacy wired 802.1X profile that ships
//! EAP-MSCHAPv2 (EAP type 26) without an outer TLS tunnel.
//!
//! What we assert:
//!
//! * The handler-allocated `State` cookie round-trips between
//!   Access-Challenge and follow-up Access-Request.
//! * `EAP-Message` reassembly carries the MSCHAPv2 Challenge /
//!   Response / Success exchange end to end.
//! * Every reply carries a correctly-keyed `Message-Authenticator`
//!   that `eapol_test` validates per RFC 3579 / RFC 9716.
//! * `eapol_test` prints
//!   `EAP authentication completed successfully`.
//!
//! Bare EAP-MSCHAPv2 derives no MSK (RFC 3079 `GetMasterKey` is not
//! wired in), so the supplicant config uses
//! `key_mgmt=IEEE8021X` and `eapol_test -n` so the test does not
//! expect MPPE keys back.
//!
//! Skipped with a printed notice on hosts without `eapol_test` on
//! `PATH`.

#![cfg(feature = "eap-mschapv2")]

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio_eap::mschapv2::{EapMsChapV2Factory, StaticCredentials};
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
async fn eapol_test_mschapv2_native_succeeds() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end native EAP-MSCHAPv2 test");
        return;
    }

    let creds = Arc::new(StaticCredentials::cleartext(
        IDENTITY.as_bytes().to_vec(),
        PASSWORD,
    ));
    let handler = EapHandler::new(EapMsChapV2Factory::new(creds));

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
        conf_path.push(format!(
            "radius-tokio-eap-mschapv2-native-{}.conf",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&conf_path)?;
            // wpa_supplicant config: wired/EAPOL 802.1X with bare
            // EAP-MSCHAPv2 and our static credentials. WPA-EAP
            // would require MPPE keys we do not derive.
            writeln!(
                f,
                "network={{\n\
                 \tkey_mgmt=IEEE8021X\n\
                 \teap=MSCHAPV2\n\
                 \tidentity=\"{IDENTITY}\"\n\
                 \tpassword=\"{PASSWORD}\"\n\
                 }}"
            )?;
        }

        let output = Command::new("eapol_test")
            // -n: don't expect MPPE keys (bare EAP-MSCHAPv2 derives none)
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
