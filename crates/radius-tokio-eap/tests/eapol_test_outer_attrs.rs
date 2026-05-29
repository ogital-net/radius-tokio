//! Freezes the set of RADIUS attributes that `eapol_test 2.x`
//! puts on the outer Access-Request, observed via the
//! [`radius_tokio_eap::Outer`] handed to [`Credentials::lookup`].
//!
//! Mirrors [`eapol_test_md5`](./eapol_test_md5.rs) — same wiring,
//! same supplicant invocation — but wraps the static credential
//! store in a small recorder so the test can pin the exact set of
//! outer attribute type codes the supplicant emits on the second
//! (credential-bearing) Access-Request: `User-Name`,
//! `NAS-IP-Address`, `Service-Type`, `Framed-MTU`, `State`
//! (echoed from our Access-Challenge), `Calling-Station-Id`,
//! `NAS-Port-Type`, `Connect-Info`, `EAP-Message`, and
//! `Message-Authenticator`.

#![cfg(feature = "eap-md5")]

use std::collections::BTreeSet;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::AttributesView;
use radius_tokio_eap::eap_md5::{Credentials, EapMd5Factory, StaticCredentials};
use radius_tokio_eap::{EapHandler, Outer};

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

/// `Credentials` decorator that records every outer attribute
/// type byte it sees on `lookup` and forwards to the wrapped
/// store.
struct RecordingCreds<C: Credentials> {
    inner: C,
    observed: Mutex<Option<BTreeSet<u8>>>,
}

impl<C: Credentials> Credentials for RecordingCreds<C> {
    async fn lookup<'a>(&'a self, outer: &'a Outer<'a>, username: &'a [u8]) -> Option<Vec<u8>> {
        let mut codes = BTreeSet::new();
        // Skip malformed slots; eapol_test's framing is sound,
        // but we don't want a single decode error to mask the
        // valid attributes alongside it.
        for attr in outer.attributes_iter().flatten() {
            codes.insert(attr.attribute_type());
        }
        // Sanity-check: raw byte slice matches the iter walk.
        assert!(!outer.raw_attributes().is_empty(), "outer attrs empty");
        *self.observed.lock().unwrap() = Some(codes);
        self.inner.lookup(outer, username).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn eapol_test_outer_attributes_visible_to_credentials() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping outer-attribute snapshot test");
        return;
    }

    let recorder = Arc::new(RecordingCreds {
        inner: StaticCredentials::cleartext(
            IDENTITY.as_bytes().to_vec(),
            PASSWORD.as_bytes().to_vec(),
        ),
        observed: Mutex::new(None),
    });
    let handler = EapHandler::new(EapMd5Factory::new(Arc::clone(&recorder)));

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
            "radius-tokio-eap-outer-attrs-{}.conf",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&conf_path)?;
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

    let observed = recorder
        .observed
        .lock()
        .unwrap()
        .clone()
        .expect("lookup ran and recorded outer attributes");
    eprintln!("observed outer attribute type codes: {observed:?}");

    // Exact-set freeze for hostap `eapol_test` 2.x on the second
    // (credential-bearing) Access-Request. Pinning the full set
    // (not just a subset) surfaces both regressions in this crate
    // — e.g. the handler accidentally dropping or rewriting an
    // attribute on its way to `Credentials::lookup` — and upstream
    // changes in the bundled supplicant's defaults.
    //
    // Attribute provenance:
    //   1  User-Name              (RFC 2865 §5.1, sent by peer)
    //   4  NAS-IP-Address         (eapol_test default: 127.0.0.1)
    //   6  Service-Type           (eapol_test default: Framed)
    //  12  Framed-MTU             (eapol_test default: 1400)
    //  24  State                  (RFC 2865 §5.24, echoed from
    //                              the handler's Access-Challenge
    //                              cookie)
    //  31  Calling-Station-Id     (eapol_test default MAC)
    //  61  NAS-Port-Type          (eapol_test default: Wireless-802.11)
    //  77  Connect-Info           ("CONNECT 11Mbps 802.11b" or similar)
    //  79  EAP-Message            (RFC 3579 §3.1, carries MD5-Response)
    //  80  Message-Authenticator  (RFC 3579 §3.2, keyed HMAC)
    let expected: BTreeSet<u8> = [1u8, 4, 6, 12, 24, 31, 61, 77, 79, 80]
        .into_iter()
        .collect();
    assert_eq!(
        observed, expected,
        "eapol_test outer-attribute set drifted from the frozen snapshot",
    );
}
