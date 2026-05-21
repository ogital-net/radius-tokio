//! End-to-end integration test driving the server with hostap's
//! `eapol_test` utility against an in-process EAP-MSCHAPv2 handler.
//!
//! Full EAP-method termination is an explicit non-goal of the
//! library: the codec exposes the `EAP-Message`
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
use radius_tokio::eap;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;

mod common;
use common::{nanos_now, IDENTITY, PASSWORD, SHARED_SECRET};

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

        // Any State attribute the peer is echoing.
        let state_attr = request.state();

        match (eap_pkt.code(), eap_pkt.typ()) {
            // ── Round 1: EAP-Response/Identity ───────────────────────────
            (eap::Code::RESPONSE, Some(eap::Type::IDENTITY)) => {
                if state_attr.is_some() {
                    // Identity should be the first message; bail.
                    return HandlerResult::Drop;
                }
                let auth_challenge = self.fresh_auth_challenge();
                let state_value = self.fresh_state();
                let next_eap_id = eap_pkt.identifier().wrapping_add(1);
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
                reply.add_state(&state_value).expect("state fits");
                reply.add_eap_message(&eap_req).expect("fragments fit");
                HandlerResult::Reply(reply)
            }

            // ── Round 2 or 3: EAP-Response/MSCHAPv2 ─────────────────────
            (eap::Code::RESPONSE, Some(eap::Type::MSCHAPV2)) => {
                // Type-Data layout (RFC 2759 §6 + draft):
                //   opcode(1) || mschap-id(1) || ms-length(2) || body(*)
                // Peer acks (Success/Failure) carry only the bare
                // opcode byte and omit the rest.
                let type_data = eap_pkt.type_data();
                let Some(&op) = type_data.first() else {
                    return HandlerResult::Drop;
                };
                let body: &[u8] = if type_data.len() >= 4 {
                    &type_data[4..]
                } else {
                    &[]
                };

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
                        let Some(resp) = parse_mschap_response(body) else {
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
                            reply
                                .add_eap_failure(eap_pkt.identifier())
                                .expect("failure fits");
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
                                s.last_eap_id = eap_pkt.identifier().wrapping_add(1);
                            }
                        }

                        let success_req = build_mschap_success_request(
                            eap_pkt.identifier().wrapping_add(1),
                            session.mschap_id,
                            &auth_resp,
                        );
                        let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                        reply.add_state(&state_key).expect("state fits");
                        reply.add_eap_message(&success_req).expect("fragments fit");
                        HandlerResult::Reply(reply)
                    }
                    (Stage::AwaitingSuccessAck, MS_OP_SUCCESS) => {
                        // Success ack from peer. Fire EAP-Success and
                        // forget the session.
                        self.sessions.lock().unwrap().remove(&state_key);

                        let mut reply = request.reply(Code::ACCESS_ACCEPT);
                        // Echo the User-Name back; some NAS gear
                        // expects it on Access-Accept (RFC 2865 §5.1).
                        if let Some(name) = request.user_name() {
                            let _ = reply.add_attribute(1, name);
                        }
                        reply
                            .add_eap_success(eap_pkt.identifier())
                            .expect("success fits");
                        HandlerResult::Reply(reply)
                    }
                    _ => HandlerResult::Drop,
                }
            }
            _ => HandlerResult::Drop,
        }
    }
}

// ── MSCHAPv2 codec helpers ───────────────────────────────────────────────

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
    // MSCHAPv2 Challenge inner layout (RFC 2759 §6 + draft):
    //   opcode(1) || mschap-id(1) || ms-length(2) || value-size(1)=16
    //     || challenge(16) || name(*)
    let ms_len = 4 + 1 + 16 + name.len();
    let mut type_data = Vec::with_capacity(ms_len);
    type_data.push(MS_OP_CHALLENGE);
    type_data.push(mschap_id);
    type_data.extend_from_slice(&u16::try_from(ms_len).unwrap().to_be_bytes());
    type_data.push(16);
    type_data.extend_from_slice(challenge);
    type_data.extend_from_slice(name);

    let mut out = Vec::with_capacity(5 + ms_len);
    eap::write_request(&mut out, eap_id, eap::Type::MSCHAPV2, &type_data)
        .expect("EAP packet length fits");
    out
}

fn build_mschap_success_request(eap_id: u8, mschap_id: u8, auth_resp: &[u8; 42]) -> Vec<u8> {
    // MSCHAPv2 Success inner layout: opcode || mschap-id || ms-length
    //   || body. Body is the ASCII "S=<40 hex>" string; no M= message.
    let body_len = auth_resp.len();
    let ms_len = 4 + body_len;
    let mut type_data = Vec::with_capacity(ms_len);
    type_data.push(MS_OP_SUCCESS);
    type_data.push(mschap_id);
    type_data.extend_from_slice(&u16::try_from(ms_len).unwrap().to_be_bytes());
    type_data.extend_from_slice(auth_resp);

    let mut out = Vec::with_capacity(5 + ms_len);
    eap::write_request(&mut out, eap_id, eap::Type::MSCHAPV2, &type_data)
        .expect("EAP packet length fits");
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
