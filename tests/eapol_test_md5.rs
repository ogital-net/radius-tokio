//! End-to-end integration test driving the server with hostap's
//! `eapol_test` utility against an in-process EAP-MD5-Challenge
//! handler.
//!
//! Sister test to [`eapol_test_mschapv2`]. Full EAP-method
//! termination is an explicit non-goal of the library (see
//! `CLAUDE.md`): the codec relays `EAP-Message` and exposes
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use radius_tokio::auth::eap_md5;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;

const SHARED_SECRET: &str = "testing123";
const IDENTITY: &str = "alice";
const PASSWORD: &str = "hello123";

// RADIUS attribute types we touch directly. Spelled out here so the
// test does not depend on the `dict-rfc` codegen surface for these
// well-known constants — it's a transport-level test, not a
// dictionary test.
const ATTR_USER_NAME: u8 = 1;
const ATTR_STATE: u8 = 24;
const ATTR_EAP_MESSAGE: u8 = 79;

// EAP codes (RFC 3748 §4).
const EAP_CODE_REQUEST: u8 = 1;
const EAP_CODE_RESPONSE: u8 = 2;
const EAP_CODE_SUCCESS: u8 = 3;
// EAP types (RFC 3748 §5).
const EAP_TYPE_IDENTITY: u8 = 1;
const EAP_TYPE_MD5: u8 = 4;

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

        // Reassemble the EAP-Message attribute(s) into a contiguous
        // buffer.
        let mut eap = Vec::new();
        for raw in request.attributes_iter() {
            let Ok(raw) = raw else {
                return HandlerResult::Drop;
            };
            if raw.attribute_type() == ATTR_EAP_MESSAGE {
                eap.extend_from_slice(raw.value());
            }
        }
        if eap.is_empty() {
            return HandlerResult::Drop;
        }

        let Some(eap_pkt) = parse_eap(&eap) else {
            return HandlerResult::Drop;
        };

        let state_attr = match request.first_raw(ATTR_STATE) {
            Ok(Some(raw)) => Some(raw.value().to_vec()),
            Ok(None) => None,
            Err(_) => return HandlerResult::Drop,
        };

        match (eap_pkt.code, eap_pkt.kind) {
            // ── Round 1: EAP-Response/Identity ──────────────────────
            (EAP_CODE_RESPONSE, EapKind::Identity) => {
                if state_attr.is_some() {
                    return HandlerResult::Drop;
                }
                let challenge = self.fresh_challenge();
                let state_value = self.fresh_state();
                let next_eap_id = eap_pkt.id.wrapping_add(1);

                self.sessions.lock().unwrap().insert(
                    state_value,
                    Session {
                        challenge_eap_id: next_eap_id,
                        challenge,
                    },
                );

                let eap_req = build_md5_challenge(next_eap_id, &challenge);
                let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                reply
                    .add_attribute(ATTR_STATE, &state_value)
                    .expect("state fits");
                add_eap_message(&mut reply, &eap_req);
                HandlerResult::Reply(reply)
            }

            // ── Round 2: EAP-Response/MD5-Challenge ─────────────────
            (EAP_CODE_RESPONSE, EapKind::Md5Challenge) => {
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

                let Some(response) = parse_md5_response(eap_pkt.body) else {
                    return HandlerResult::Drop;
                };

                if eap_md5::verify_response(
                    session.challenge_eap_id,
                    PASSWORD.as_bytes(),
                    &session.challenge,
                    &response,
                ) {
                    let mut reply = request.reply(Code::ACCESS_ACCEPT);
                    if let Ok(Some(un)) = request.first_raw(ATTR_USER_NAME) {
                        let _ = reply.add_attribute(ATTR_USER_NAME, un.value());
                    }
                    let success = build_eap_success(eap_pkt.id);
                    add_eap_message(&mut reply, &success);
                    HandlerResult::Reply(reply)
                } else {
                    let mut reply = request.reply(Code::ACCESS_REJECT);
                    let fail = build_eap_failure(eap_pkt.id);
                    add_eap_message(&mut reply, &fail);
                    HandlerResult::Reply(reply)
                }
            }
            _ => HandlerResult::Drop,
        }
    }
}

// ── EAP codec helpers ────────────────────────────────────────────────

fn nanos_now() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0)
}

struct EapPacket<'a> {
    code: u8,
    id: u8,
    kind: EapKind,
    /// Type-Data following the 1-byte Type field.
    body: &'a [u8],
}

enum EapKind {
    Identity,
    Md5Challenge,
}

fn parse_eap(buf: &[u8]) -> Option<EapPacket<'_>> {
    if buf.len() < 4 {
        return None;
    }
    let code = buf[0];
    let id = buf[1];
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if length < 5 || length > buf.len() {
        return None;
    }
    let typ = buf[4];
    let body = &buf[5..length];
    let kind = match typ {
        EAP_TYPE_IDENTITY => EapKind::Identity,
        EAP_TYPE_MD5 => EapKind::Md5Challenge,
        _ => return None,
    };
    Some(EapPacket {
        code,
        id,
        kind,
        body,
    })
}

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

fn build_md5_challenge(eap_id: u8, challenge: &[u8; 16]) -> Vec<u8> {
    // EAP header(4) + Type(1) + Value-Size(1) + Value(16). No Name.
    let eap_len = 4 + 1 + 1 + 16;
    let mut out = Vec::with_capacity(eap_len);
    out.push(EAP_CODE_REQUEST);
    out.push(eap_id);
    out.extend_from_slice(&u16::try_from(eap_len).unwrap().to_be_bytes());
    out.push(EAP_TYPE_MD5);
    out.push(16);
    out.extend_from_slice(challenge);
    out
}

fn build_eap_success(id: u8) -> Vec<u8> {
    vec![EAP_CODE_SUCCESS, id, 0, 4]
}

fn build_eap_failure(id: u8) -> Vec<u8> {
    // EAP code 4 = Failure (RFC 3748).
    vec![4, id, 0, 4]
}

/// Append an EAP packet to a reply, fragmenting into ≤253-byte
/// `EAP-Message` attributes per RFC 3579 §3.1.
fn add_eap_message(reply: &mut radius_tokio::Reply, eap: &[u8]) {
    for chunk in eap.chunks(253) {
        reply
            .add_attribute(ATTR_EAP_MESSAGE, chunk)
            .expect("EAP-Message fragment fits");
    }
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
