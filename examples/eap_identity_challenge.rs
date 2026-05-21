//! Example: EAP-MD5-Challenge over RADIUS — the smallest end-to-end
//! `Access-Request` → `Access-Challenge` → `Access-Request` →
//! `Access-Accept` flow that exercises every EAP-over-RADIUS
//! primitive the library ships (`EAP-Message` reassembly +
//! fragmentation, `State` round-trip, typed `eap::Packet` view,
//! `eap::write_request` / `Reply::add_eap_success`).
//!
//! Run with:
//!
//! ```text
//! cargo run --example eap_identity_challenge
//! ```
//!
//! Then drive it from another shell with hostap's `eapol_test`:
//!
//! ```text
//! cat > /tmp/md5.conf <<EOF
//! network={
//!     key_mgmt=IEEE8021X
//!     eap=MD5
//!     identity="alice"
//!     password="hello123"
//! }
//! EOF
//! eapol_test -c /tmp/md5.conf -a 127.0.0.1 -p 1812 -s shared-secret -n -t 5 -r 0
//! ```
//!
//! ## Pattern
//!
//! Method-specific bytes (the MD5 `Value-Size || Value` blob in
//! `Type-Data`) stay in the consumer. Everything that's RFC 3748 /
//! RFC 3579 framing — EAP header, `EAP-Message` 253-byte
//! fragmentation, `State` echo — is one library call. The
//! sister integration test [`tests/eapol_test_md5.rs`] runs the
//! same shape end-to-end against `eapol_test`.
//!
//! ## Non-goal
//!
//! Full EAP-method termination (PEAP, EAP-TLS, EAP-TTLS,
//! EAP-MSCHAPv2 state machinery) is a permanent non-goal of the
//! library; consumers plug in whatever method engine they already
//! use. EAP-MD5 is the smallest method that exercises the
//! Challenge / Response round-trip without dragging in TLS, which
//! is why it's the worked example.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use radius_tokio::auth::eap_md5;
use radius_tokio::eap;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;

/// Cleartext password the simulated user knows. A real handler
/// keys into a credential store off `Request::user_name()`.
const PASSWORD: &[u8] = b"hello123";

/// Per-session row: `(EAP Identifier the server used in the
/// MD5-Challenge, 16-byte challenge)`. Stashed under the 16-byte
/// `State` value so the second-round `Access-Request` can resolve
/// to the right context.
type Session = (u8, [u8; 16]);

/// EAP-MD5 handler with an in-memory session map keyed by the
/// 16-byte `State` value the server hands out on its first
/// `Access-Challenge`. A real deployment plugs whatever session
/// store it already maintains in here — the library makes no
/// assumption about the shape.
struct EapMd5 {
    sessions: Mutex<HashMap<[u8; 16], Session>>,
    seed: AtomicU64,
}

impl EapMd5 {
    /// Mint a 16-byte token. Production handlers should use
    /// `crypto::rand` for unguessable values; the counter mix here
    /// keeps the example deterministic enough to follow in a debugger.
    fn token(&self, mix: u64) -> [u8; 16] {
        let n = self.seed.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out[8..].copy_from_slice(&(n.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ mix).to_be_bytes());
        out
    }
}

impl Handler for EapMd5 {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }
        let eap_buf = request.eap_message();
        let Ok(eap_pkt) = eap::Packet::parse(&eap_buf) else {
            return HandlerResult::Drop;
        };
        match (eap_pkt.code(), eap_pkt.typ(), request.state()) {
            // Round 1: Response/Identity → Challenge.
            (eap::Code::RESPONSE, Some(eap::Type::IDENTITY), None) => {
                let state = self.token(1);
                let challenge = self.token(2);
                let next_id = eap_pkt.identifier().wrapping_add(1);
                self.sessions.lock().unwrap().insert(state, (next_id, challenge));
                let mut type_data = vec![16u8];
                type_data.extend_from_slice(&challenge);
                let mut eap_req = Vec::new();
                eap::write_request(&mut eap_req, next_id, eap::Type::MD5_CHALLENGE, &type_data)
                    .expect("EAP packet length fits");
                let mut reply = request.reply(Code::ACCESS_CHALLENGE);
                reply.add_state(&state).expect("state fits");
                reply.add_eap_message(&eap_req).expect("fragments fit");
                HandlerResult::Reply(reply)
            }
            // Round 2: Response/MD5-Challenge → Accept or Reject.
            (eap::Code::RESPONSE, Some(eap::Type::MD5_CHALLENGE), Some(state)) => {
                let Ok(key): Result<[u8; 16], _> = state.try_into() else {
                    return HandlerResult::Drop;
                };
                let Some((id, challenge)) = self.sessions.lock().unwrap().remove(&key) else {
                    return HandlerResult::Drop;
                };
                let body = eap_pkt.type_data();
                if body.len() < 17 || body[0] != 16 {
                    return HandlerResult::Drop;
                }
                let mut response = [0u8; 16];
                response.copy_from_slice(&body[1..17]);
                if eap_md5::verify_response(id, PASSWORD, &challenge, &response) {
                    let mut reply = request.reply(Code::ACCESS_ACCEPT);
                    if let Some(name) = request.user_name() {
                        reply.add_attribute(1, name).expect("user-name fits");
                    }
                    reply.add_eap_success(eap_pkt.identifier()).expect("success fits");
                    HandlerResult::Reply(reply)
                } else {
                    let mut reply = request.reply(Code::ACCESS_REJECT);
                    reply.add_eap_failure(eap_pkt.identifier()).expect("failure fits");
                    HandlerResult::Reply(reply)
                }
            }
            _ => HandlerResult::Drop,
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let client = Arc::new(Client::new(b"shared-secret".as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let handler = EapMd5 {
        sessions: Mutex::new(HashMap::new()),
        seed: AtomicU64::new(1),
    };

    let server = Server::builder()
        .clients(store)
        .handler(handler)
        .listen_udp("127.0.0.1:1812".parse().unwrap())
        .build()?;

    println!("eap-md5 listener on 127.0.0.1:1812 — drive it with:");
    println!("  eapol_test -c /tmp/md5.conf -a 127.0.0.1 -p 1812 -s shared-secret -n -t 5 -r 0");
    server.run().await
}
