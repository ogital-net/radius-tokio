//! End-to-end integration test driving the server with hostap's
//! `eapol_test` utility against an in-process EAP-MSCHAPv2 handler.
//!
//! Full EAP-method termination is an explicit non-goal of the
//! library (see CLAUDE.md): the codec exposes the `EAP-Message`
//! reassembly view and `auth::mschap::v2_nt_response` /
//! `auth::mschap::v2_authenticator_response`, but the state machine
//! that wires them together is the consumer's responsibility. This
//! test doubles as a worked example of that shape and as an external
//! check that the codec handles the full Access-Request →
//! Access-Challenge → … → Access-Accept flow correctly:
//!
//! * `State` (RFC 2865 §5.24) is round-tripped on the
//!   Access-Challenge / Access-Request exchange.
//! * `EAP-Message` (RFC 3579 §3.1) is encoded, transported, and
//!   accepted by a third-party verifier.
//! * Every reply carries a correctly-keyed `Message-Authenticator`,
//!   which `eapol_test` validates per RFC 3579 / RFC 9716.
//! * The dedup / retransmit cache is exercised by the underlying
//!   server runtime across the multi-round-trip exchange.
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

use radius_tokio::auth::mschap::{self, MsChapSecret};
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;

mod common;
use common::{
    add_eap_message, build_eap_failure, build_eap_success, nanos_now, ATTR_EAP_MESSAGE, ATTR_STATE,
    ATTR_USER_NAME, EAP_CODE_REQUEST, EAP_CODE_RESPONSE, EAP_TYPE_IDENTITY, IDENTITY, PASSWORD,
    SHARED_SECRET,
};

// EAP type specific to MSCHAPv2 (draft-kamath-pppext-eap-mschapv2).
const EAP_TYPE_MSCHAPV2: u8 = 26;

// MSCHAPv2 opcodes (RFC 2759 §6 + draft-kamath-pppext-eap-mschapv2).
const MS_OP_CHALLENGE: u8 = 1;
const MS_OP_RESPONSE: u8 = 2;
const MS_OP_SUCCESS: u8 = 3;

const SERVER_NAME: &[u8] = b"radius-tokio-test";

/// Per-EAP-conversation state, keyed by the 16-byte `State` attribute
/// the server hands out on its first Access-Challenge.
#[derive(Clone)]
struct Session {
    stage: Stage,
    auth_challenge: [u8; 16],
    last_eap_id: u8,
    mschap_id: u8,
}

#[derive(Clone, Copy)]
enum Stage {
    /// Sent the `MSCHAPv2` Challenge; waiting for the peer's Response.
    AwaitingChallengeResponse,
    /// Verified the Response; waiting for the peer's Success ack.
    AwaitingSuccessAck,
}

/// EAP-MSCHAPv2 handler with an in-memory session map.
struct EapMschapV2Handler {
    sessions: Mutex<HashMap<[u8; 16], Session>>,
    state_counter: AtomicU64,
}

impl EapMschapV2Handler {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            state_counter: AtomicU64::new(1),
        }
    }

    /// Mint a fresh 16-byte `State` value. The actual contents only
    /// need to be unguessable across concurrent sessions; we mix a
    /// monotonic counter with a process-start nanosecond so two
    /// instances of the test in the same process don't collide.
    fn fresh_state(&self) -> [u8; 16] {
        let n = self.state_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = nanos_now();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out[8..].copy_from_slice(&nanos.to_be_bytes());
        out
    }

    /// Likewise for the 16-byte authenticator challenge fed to
    /// `MSCHAPv2`'s `ChallengeHash`.
    fn fresh_auth_challenge(&self) -> [u8; 16] {
        let nanos = nanos_now();
        let n = self.state_counter.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&nanos.to_be_bytes());
        out[8..].copy_from_slice(&(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_be_bytes());
        out
    }
}

impl Handler for EapMschapV2Handler {
    #[allow(clippy::too_many_lines)]
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }

        // Reassemble the EAP-Message attribute(s) into a contiguous
        // buffer. The library exposes the iterator/concat helpers in
        // `codec::eap`; we use the raw attribute iterator here so
        // the test stays self-contained and visible.
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

        // Locate any State attribute the peer is echoing.
        let state_attr = match request.first_raw(ATTR_STATE) {
            Ok(Some(raw)) => Some(raw.value()),
            Ok(None) => None,
            Err(_) => return HandlerResult::Drop,
        };

        match (eap_pkt.code, eap_pkt.kind) {
            // ── Round 1: EAP-Response/Identity ───────────────────────────
            (EAP_CODE_RESPONSE, EapKind::Identity) => {
                if state_attr.is_some() {
                    // Identity should be the first message; bail.
                    return HandlerResult::Drop;
                }
                let auth_challenge = self.fresh_auth_challenge();
                let state_value = self.fresh_state();
                let next_eap_id = eap_pkt.id.wrapping_add(1);
                let mschap_id = next_eap_id;

                self.sessions.lock().unwrap().insert(
                    state_value,
                    Session {
                        stage: Stage::AwaitingChallengeResponse,
                        auth_challenge,
                        last_eap_id: next_eap_id,
                        mschap_id,
                    },
                );

                let eap_req =
                    build_mschap_challenge(next_eap_id, mschap_id, &auth_challenge, SERVER_NAME);
                let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                reply
                    .add_attribute(ATTR_STATE, &state_value)
                    .expect("state fits");
                add_eap_message(&mut reply, &eap_req);
                HandlerResult::Reply(reply)
            }

            // ── Round 2 or 3: EAP-Response/MSCHAPv2 ─────────────────────
            (EAP_CODE_RESPONSE, EapKind::MsChapV2(op)) => {
                let Some(state_bytes) = state_attr else {
                    return HandlerResult::Drop;
                };
                let Ok(state_key): Result<[u8; 16], _> = state_bytes.try_into() else {
                    return HandlerResult::Drop;
                };

                let session = {
                    let sessions = self.sessions.lock().unwrap();
                    sessions.get(&state_key).cloned()
                };
                let Some(session) = session else {
                    return HandlerResult::Drop;
                };

                match (session.stage, op) {
                    (Stage::AwaitingChallengeResponse, MS_OP_RESPONSE) => {
                        let Some(resp) = parse_mschap_response(eap_pkt.body) else {
                            return HandlerResult::Drop;
                        };
                        let expected = mschap::v2_nt_response(
                            &session.auth_challenge,
                            &resp.peer_challenge,
                            IDENTITY.as_bytes(),
                            MsChapSecret::Cleartext(PASSWORD),
                        );
                        if expected != resp.nt_response {
                            // Bad password — reject. The test path
                            // doesn't exercise this branch but the
                            // library API is the same.
                            let mut reply = request.reply(Code::ACCESS_REJECT);
                            let fail = build_eap_failure(eap_pkt.id);
                            add_eap_message(&mut reply, &fail);
                            return HandlerResult::Reply(reply);
                        }

                        let auth_resp = mschap::v2_authenticator_response(
                            &session.auth_challenge,
                            &resp.peer_challenge,
                            &resp.nt_response,
                            IDENTITY.as_bytes(),
                            MsChapSecret::Cleartext(PASSWORD),
                        );

                        // Update session: now waiting for the peer's
                        // Success ack. State value is reused — we
                        // could rotate it but RFC 5080 §2.1.1 only
                        // requires uniqueness across active
                        // conversations.
                        {
                            let mut sessions = self.sessions.lock().unwrap();
                            if let Some(s) = sessions.get_mut(&state_key) {
                                s.stage = Stage::AwaitingSuccessAck;
                                s.last_eap_id = eap_pkt.id.wrapping_add(1);
                            }
                        }

                        let success_req = build_mschap_success_request(
                            eap_pkt.id.wrapping_add(1),
                            session.mschap_id,
                            &auth_resp,
                        );
                        let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                        reply
                            .add_attribute(ATTR_STATE, &state_key)
                            .expect("state fits");
                        add_eap_message(&mut reply, &success_req);
                        HandlerResult::Reply(reply)
                    }
                    (Stage::AwaitingSuccessAck, MS_OP_SUCCESS) => {
                        // Success ack from peer. Fire EAP-Success and
                        // forget the session.
                        self.sessions.lock().unwrap().remove(&state_key);

                        let mut reply = request.reply(Code::ACCESS_ACCEPT);
                        // Echo the User-Name back; some NAS gear
                        // expects it on Access-Accept (RFC 2865 §5.1).
                        if let Ok(Some(un)) = request.first_raw(ATTR_USER_NAME) {
                            let _ = reply.add_attribute(ATTR_USER_NAME, un.value());
                        }
                        let success = build_eap_success(eap_pkt.id);
                        add_eap_message(&mut reply, &success);
                        HandlerResult::Reply(reply)
                    }
                    _ => HandlerResult::Drop,
                }
            }
            _ => HandlerResult::Drop,
        }
    }
}

// ── EAP / MSCHAPv2 codec helpers ─────────────────────────────────────────

struct EapPacket<'a> {
    code: u8,
    id: u8,
    kind: EapKind,
    /// `MSCHAPv2` body: bytes following the `MSCHAPv2` 4-byte header
    /// (i.e. starting at value-size for Challenge / Response, or at
    /// the message string for Success).
    body: &'a [u8],
}

enum EapKind {
    Identity,
    /// Carries the `MSCHAPv2` opcode.
    MsChapV2(u8),
}

fn parse_eap(buf: &[u8]) -> Option<EapPacket<'_>> {
    if buf.len() < 4 {
        return None;
    }
    let code = buf[0];
    let id = buf[1];
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if length < 4 || length > buf.len() {
        return None;
    }
    if length == 4 {
        // Bare EAP-Success / -Failure; not expected on the request side.
        return Some(EapPacket {
            code,
            id,
            kind: EapKind::Identity,
            body: &[],
        });
    }
    let typ = buf[4];
    match typ {
        EAP_TYPE_IDENTITY => Some(EapPacket {
            code,
            id,
            kind: EapKind::Identity,
            body: &buf[5..length],
        }),
        EAP_TYPE_MSCHAPV2 => {
            // MSCHAPv2 type-data is at least one byte (the opcode).
            // Challenge / Response carry the full RFC 2759 header
            // (opcode + mschap-id + ms-length); Success / Failure
            // *responses from the peer* are bare opcodes — wpa_supplicant
            // sends a 1-byte body containing only the Success opcode
            // when ack'ing the server's Success request.
            if length < 6 {
                return None;
            }
            let op = buf[5];
            // Body offset depends on whether the full header is present.
            let body_start = if length >= 9 { 9 } else { 6 };
            Some(EapPacket {
                code,
                id,
                kind: EapKind::MsChapV2(op),
                body: &buf[body_start..length],
            })
        }
        _ => None,
    }
}

struct MsChapResponseFields {
    peer_challenge: [u8; 16],
    nt_response: [u8; 24],
}

fn parse_mschap_response(body: &[u8]) -> Option<MsChapResponseFields> {
    // body starts at value-size for Response.
    // value-size(1)=49, peer-challenge(16), reserved(8), NT-resp(24), flags(1), name(...)
    if body.len() < 1 + 49 {
        return None;
    }
    if body[0] != 49 {
        return None;
    }
    let mut peer = [0u8; 16];
    peer.copy_from_slice(&body[1..17]);
    let mut nt = [0u8; 24];
    nt.copy_from_slice(&body[25..49]);
    Some(MsChapResponseFields {
        peer_challenge: peer,
        nt_response: nt,
    })
}

fn build_mschap_challenge(eap_id: u8, mschap_id: u8, challenge: &[u8; 16], name: &[u8]) -> Vec<u8> {
    // EAP header(5) + MSCHAPv2 header(4) + value-size(1) + challenge(16) + name
    let ms_len = 4 + 1 + 16 + name.len();
    let eap_len = 5 + ms_len;
    let mut out = Vec::with_capacity(eap_len);
    out.push(EAP_CODE_REQUEST);
    out.push(eap_id);
    out.extend_from_slice(&u16::try_from(eap_len).unwrap().to_be_bytes());
    out.push(EAP_TYPE_MSCHAPV2);
    out.push(MS_OP_CHALLENGE);
    out.push(mschap_id);
    out.extend_from_slice(&u16::try_from(ms_len).unwrap().to_be_bytes());
    out.push(16);
    out.extend_from_slice(challenge);
    out.extend_from_slice(name);
    out
}

fn build_mschap_success_request(eap_id: u8, mschap_id: u8, auth_resp: &[u8; 42]) -> Vec<u8> {
    // Body is the ASCII "S=<40 hex>" string; no M= message.
    let body_len = auth_resp.len();
    let ms_len = 4 + body_len;
    let eap_len = 5 + ms_len;
    let mut out = Vec::with_capacity(eap_len);
    out.push(EAP_CODE_REQUEST);
    out.push(eap_id);
    out.extend_from_slice(&u16::try_from(eap_len).unwrap().to_be_bytes());
    out.push(EAP_TYPE_MSCHAPV2);
    out.push(MS_OP_SUCCESS);
    out.push(mschap_id);
    out.extend_from_slice(&u16::try_from(ms_len).unwrap().to_be_bytes());
    out.extend_from_slice(auth_resp);
    out
}

// ── Test harness ─────────────────────────────────────────────────────────

fn eapol_test_available() -> bool {
    // `eapol_test -v` exits non-zero on this build but prints version
    // information. Probe for it by inspecting whether the binary can
    // be spawned at all.
    Command::new("eapol_test")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[tokio::test(flavor = "current_thread")]
async fn eapol_test_mschapv2_succeeds() {
    if !eapol_test_available() {
        eprintln!("eapol_test not on PATH; skipping end-to-end test");
        return;
    }

    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    // Reserve an ephemeral port, then drop the probe so the server
    // can bind it. (The probe / re-bind race is benign in a test.)
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let server = Server::builder()
        .clients(store)
        .handler(EapMschapV2Handler::new())
        .listen_udp(bind_addr)
        .build()
        .expect("server builds");
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    // Give the server a moment to bind before eapol_test fires.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let port = bind_addr.port();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<std::process::Output> {
        // eapol_test reads its supplicant config from a file; pipe
        // one in via /proc/self/fd-style stdin → tempfile, but
        // simpler: write a temp file alongside the test.
        let mut conf_path = std::env::temp_dir();
        conf_path.push(format!("eapol_test_mschapv2_{}.conf", std::process::id()));
        {
            let mut f = std::fs::File::create(&conf_path)?;
            // Minimal wpa_supplicant config: 802.1X with EAP-MSCHAPv2
            // and our static credentials. `key_mgmt=IEEE8021X` is what
            // selects the wired/EAPOL flow.
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
            // -c: supplicant config
            // -a: AS IP, -p: AS port, -s: shared secret
            // -n: don't expect MPPE keys (we don't ship them)
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
    // eapol_test prints "SUCCESS" (and "EAP authentication completed
    // successfully") on a happy run. Either marker is enough — match
    // both spellings the program has used historically.
    let success_line =
        stdout.contains("SUCCESS") || stdout.contains("EAP authentication completed successfully");
    assert!(
        success_line,
        "expected EAP success in eapol_test output\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}
