//! End-to-end integration test driving the server with `FreeRADIUS`'s
//! `radclient` utility.
//!
//! `radclient -b` mandates a Message-Authenticator on the reply
//! ("Blast RADIUS" mitigation, RFC 9716 / `draft-ietf-radext-deprecating-radius`).
//! By exercising that flag we get an external, third-party check that
//! every Access-Accept this server emits carries a correctly-keyed
//! Message-Authenticator attribute.
//!
//! The test is skipped (with a printed notice) on hosts that don't
//! have `radclient` on `PATH`, so the suite remains green in
//! containers without `FreeRADIUS` installed.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::typed::{VsaAttr, WText};
use radius_tokio::Code;

/// Cisco's IANA Private Enterprise Number plus the per-vendor type
/// for `Cisco-AVPair` (`dictionary.cisco`, type=string).
///
/// Built by hand here so the test stays free of the `dict-cisco`
/// Cargo feature; the codegen emits the equivalent
/// `dict::generated::cisco::attrs::CISCO_AVPAIR` const when that
/// feature is on.
const CISCO_AVPAIR: VsaAttr<WText> = VsaAttr::new(9, 1);

/// The shell-priv-lvl AV pair we hand back. Decoded by radclient as
/// `Cisco-AVPair = "shell:priv-lvl=15"` when its dictionary tree is
/// loaded (the default `/usr/share/freeradius` includes
/// `dictionary.cisco`).
const SHELL_PRIV_LVL_15: &str = "shell:priv-lvl=15";

/// Always returns Access-Accept carrying a Cisco-AVPair VSA. The
/// pairing of `radclient -b` with a vendor attribute the verifier
/// must dictionary-decode gives us a third-party check that:
///
/// * the reply's Message-Authenticator and Response-Authenticator are
///   correctly keyed (Blast RADIUS mitigation, RFC 9716);
/// * the VSA framing (`26 | len | vendor | vsa-type | vsa-len | val`)
///   is well-formed enough that a real client decodes it back to its
///   dictionary name.
struct AcceptWithCiscoAvPair;

impl Handler for AcceptWithCiscoAvPair {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        let mut reply = request.reply(Code::ACCESS_ACCEPT);
        reply
            .add_vsa(CISCO_AVPAIR, SHELL_PRIV_LVL_15)
            .expect("Cisco-AVPair fits in one attribute");
        HandlerResult::Reply(reply)
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

#[tokio::test(flavor = "current_thread")]
async fn radclient_blast_radius_check_passes() {
    if !radclient_available() {
        eprintln!("radclient not on PATH; skipping end-to-end test");
        return;
    }

    let secret = "testing123";

    let client = Arc::new(Client::new(secret.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    // Bind on an ephemeral port so concurrent test runs don't collide.
    // We need to know the chosen port before starting the server, so
    // grab it from a throwaway socket and re-bind inside the server.
    // (`Server::run` performs the bind itself.)
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(AcceptWithCiscoAvPair)
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    // Give the server a moment to bind before radclient fires.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Run radclient on a blocking thread so the current-thread
    // runtime stays responsive for the server task.
    let target = format!("{}:{}", bind_addr.ip(), bind_addr.port());
    let secret_owned = secret.to_string();
    let radclient =
        tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
            let mut child = Command::new("radclient")
                // -b: mandate Blast RADIUS / Message-Authenticator checks
                //     on the reply. This is the whole point of the test.
                // -x: verbose; surfaces decode failures in CI logs.
                // -r 1, -t 2: one try, two-second timeout — keep the
                //     suite snappy if the server misbehaves.
                .args([
                    "-b",
                    "-x",
                    "-r",
                    "1",
                    "-t",
                    "2",
                    &target,
                    "auth",
                    &secret_owned,
                ])
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

    shutdown.shutdown();
    let _ = server_task.await;

    let stdout = String::from_utf8_lossy(&radclient.stdout);
    let stderr = String::from_utf8_lossy(&radclient.stderr);

    assert!(
        radclient.status.success(),
        "radclient exited with {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        radclient.status.code(),
    );
    assert!(
        stdout.contains("Access-Accept"),
        "expected an Access-Accept reply\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    // radclient prints decoded reply attributes one-per-line; with
    // `dictionary.cisco` loaded (FreeRADIUS's default dict tree) the
    // VSA is rendered by name. If the dictionary isn't on this host,
    // the line will be `Vendor-9-Attr-1 = ...` instead — accept
    // either spelling so the test stays portable.
    let avpair_named = stdout.contains("Cisco-AVPair = \"shell:priv-lvl=15\"");
    let avpair_raw = stdout.contains("shell:priv-lvl=15");
    assert!(
        avpair_named || avpair_raw,
        "expected Cisco-AVPair shell:priv-lvl=15 in radclient output\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}
