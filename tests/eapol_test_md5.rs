//! End-to-end integration test driving the server with hostap's
//! `eapol_test` utility against an in-process EAP-MD5-Challenge
//! handler.
//!
//! Sister test to [`eapol_test_mschapv2`]. Full EAP-method
//! termination is an explicit non-goal of the library: the codec
//! relays `EAP-Message` and exposes
//! `auth::eap_md5::challenge_response` /
//! `auth::eap_md5::verify_response`, but the state machine that
//! wires them together is the consumer's responsibility. This test
//! doubles as a worked example of that shape and as an external
//! check that the codec handles the full Access-Request →
//! Access-Challenge → Access-Request → Access-Accept flow correctly:
//!
//! * `State` (RFC 2865 §5.24) is round-tripped on the
//!   Access-Challenge / Access-Request exchange.
//! * `EAP-Message` (RFC 3579 §3.1) is encoded, transported, and
//!   accepted by a third-party verifier.
//! * Every reply carries a correctly-keyed `Message-Authenticator`,
//!   which `eapol_test` validates per RFC 3579 / RFC 9716.
//!
//! The test is skipped (with a printed notice) on hosts that don't
//! have `eapol_test` on `PATH`, so the suite stays green in
//! containers without the hostap tools installed.

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use radius_tokio::auth::eap_md5;
use radius_tokio::eap;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;

mod common;
use common::{nanos_now, IDENTITY, PASSWORD, SHARED_SECRET};

/// Per-EAP-conversation state, keyed by the 16-byte `State` attribute
/// the server hands out on its first Access-Challenge.
#[derive(Clone)]
struct Session {
    /// EAP `Identifier` we used in the MD5-Challenge request, which
    /// the peer must mix into its response per RFC 3748 §5.4.
    challenge_eap_id: u8,
    challenge: [u8; 16],
}

/// EAP-MD5-Challenge handler with an in-memory session map.
struct EapMd5Handler {
    sessions: Mutex<HashMap<[u8; 16], Session>>,
    state_counter: AtomicU64,
}

impl EapMd5Handler {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            state_counter: AtomicU64::new(1),
        }
    }

    fn fresh_state(&self) -> [u8; 16] {
        let n = self.state_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = nanos_now();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out[8..].copy_from_slice(&nanos.to_be_bytes());
        out
    }

    fn fresh_challenge(&self) -> [u8; 16] {
        let nanos = nanos_now();
        let n = self.state_counter.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&nanos.to_be_bytes());
        out[8..].copy_from_slice(&(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_be_bytes());
        out
    }
}

impl Handler for EapMd5Handler {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }

        // Reassemble the EAP-Message attribute(s) and parse the EAP
        // header. `request.eap_message()` walks the attribute region
        // for us and returns an empty `Vec` when no EAP-Message is
        // present.
        let eap_buf = request.eap_message();
        if eap_buf.is_empty() {
            return HandlerResult::Drop;
        }

        let Ok(eap_pkt) = eap::Packet::parse(&eap_buf) else {
            return HandlerResult::Drop;
        };

        let state_attr = request.state().map(<[u8]>::to_vec);

        match (eap_pkt.code(), eap_pkt.typ()) {
            // ── Round 1: EAP-Response/Identity ──────────────────────
            (eap::Code::RESPONSE, Some(eap::Type::IDENTITY)) => {
                if state_attr.is_some() {
                    return HandlerResult::Drop;
                }
                let challenge = self.fresh_challenge();
                let state_value = self.fresh_state();
                let next_eap_id = eap_pkt.identifier().wrapping_add(1);

                self.sessions.lock().unwrap().insert(
                    state_value,
                    Session {
                        challenge_eap_id: next_eap_id,
                        challenge,
                    },
                );

                let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                reply.add_state(&state_value).expect("state fits");
                let mut eap_req = Vec::new();
                let md5_type_data = md5_challenge_type_data(&challenge);
                eap::write_request(
                    &mut eap_req,
                    next_eap_id,
                    eap::Type::MD5_CHALLENGE,
                    &md5_type_data,
                )
                .expect("EAP packet length fits");
                reply.add_eap_message(&eap_req).expect("fragments fit");
                HandlerResult::Reply(reply)
            }

            // ── Round 2: EAP-Response/MD5-Challenge ─────────────────
            (eap::Code::RESPONSE, Some(eap::Type::MD5_CHALLENGE)) => {
                let Some(state_bytes) = state_attr else {
                    return HandlerResult::Drop;
                };
                let Ok(state_key): Result<[u8; 16], _> = state_bytes.as_slice().try_into() else {
                    return HandlerResult::Drop;
                };

                let session = {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.remove(&state_key)
                };
                let Some(session) = session else {
                    return HandlerResult::Drop;
                };

                let Some(response) = parse_md5_response(eap_pkt.type_data()) else {
                    return HandlerResult::Drop;
                };

                if eap_md5::verify_response(
                    session.challenge_eap_id,
                    PASSWORD.as_bytes(),
                    &session.challenge,
                    &response,
                ) {
                    let mut reply = request.reply(Code::ACCESS_ACCEPT);
                    if let Some(name) = request.user_name() {
                        let _ = reply.add_attribute(1, name);
                    }
                    reply
                        .add_eap_success(eap_pkt.identifier())
                        .expect("success fits");
                    HandlerResult::Reply(reply)
                } else {
                    let mut reply = request.reply(Code::ACCESS_REJECT);
                    reply
                        .add_eap_failure(eap_pkt.identifier())
                        .expect("failure fits");
                    HandlerResult::Reply(reply)
                }
            }
            _ => HandlerResult::Drop,
        }
    }
}

// ── EAP method-specific helpers ──────────────────────────────────────

/// Parse the EAP-Response/MD5-Challenge Type-Data:
/// `Value-Size(1) || Value(16) || Name(*)` (RFC 3748 §5.4).
fn parse_md5_response(body: &[u8]) -> Option<[u8; 16]> {
    if body.len() < 1 + 16 {
        return None;
    }
    if body[0] != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&body[1..17]);
    Some(out)
}

/// Build the EAP-Request/MD5-Challenge Type-Data:
/// `Value-Size(1)=16 || Value(16)` (RFC 3748 §5.4). No Name.
fn md5_challenge_type_data(challenge: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16);
    out.push(16);
    out.extend_from_slice(challenge);
    out
}

// ── Test harness ─────────────────────────────────────────────────────

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
        eprintln!("eapol_test not on PATH; skipping end-to-end test");
        return;
    }

    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(EapMd5Handler::new())
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    tokio::time::sleep(Duration::from_millis(50)).await;

    let port = bind_addr.port();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        let mut conf_path = std::env::temp_dir();
        conf_path.push(format!("eapol_test_md5_{}.conf", std::process::id()));
        {
            let mut f = std::fs::File::create(&conf_path)?;
            // wpa_supplicant config: 802.1X with EAP-MD5 and our
            // static credentials. `key_mgmt=IEEE8021X` selects the
            // wired/EAPOL flow.
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
            // -c: supplicant config
            // -a: AS IP, -p: AS port, -s: shared secret
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
    let success_line =
        stdout.contains("SUCCESS") || stdout.contains("EAP authentication completed successfully");
    assert!(
        success_line,
        "expected EAP success in eapol_test output\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}
