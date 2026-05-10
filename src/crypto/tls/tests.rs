//! In-process TLS wrapper tests.
//!
//! Each test builds an ephemeral CA + server cert + client cert via
//! the in-tree [`crate::crypto::pki`] module, instantiates a
//! [`TlsConnection`] paired with a
//! test-only client wired through their own memory BIOs, and pumps
//! bytes between them until the handshake resolves (or fails the
//! way the test expects).

#![allow(
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::unnecessary_wraps,
    clippy::missing_panics_doc
)]

use super::test_client::{build_pki, client_side};
use super::{ClientTrust, HandshakeState, TlsConnection, TlsContext, TlsError};

fn drive(server: &mut TlsConnection, client: &mut client_side::ClientSsl) -> Result<(), TlsError> {
    let mut buf = [0u8; 16 * 1024];
    for _ in 0..64 {
        let s_state = server.process()?;
        let c_state = client.process()?;
        loop {
            let n = server.take_output(&mut buf)?;
            if n == 0 {
                break;
            }
            client.feed_input(&buf[..n])?;
        }
        loop {
            let n = client.take_output(&mut buf)?;
            if n == 0 {
                break;
            }
            server.feed_input(&buf[..n])?;
        }
        if matches!(s_state, HandshakeState::Established)
            && matches!(c_state, HandshakeState::Established)
        {
            return Ok(());
        }
    }
    Err(TlsError::Handshake("driver: too many rounds".into()))
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

#[test]
fn handshake_succeeds_with_valid_chain() {
    let pki = build_pki();
    let server_ctx = TlsContext::server(
        &pki.server_chain_pem,
        &pki.server_key_pem,
        Some(&pki.ca_pem),
    )
    .expect("build server ctx");
    let mut server = TlsConnection::accept(&server_ctx).expect("accept");
    let mut client = client_side::builder(&pki.ca_pem)
        .unwrap()
        .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut server, &mut client).expect("handshake");
    assert!(!server.is_handshaking());
}

#[test]
fn peer_certificate_exposes_subject_der_and_spki() {
    let pki = build_pki();
    let server_ctx = TlsContext::server(
        &pki.server_chain_pem,
        &pki.server_key_pem,
        Some(&pki.ca_pem),
    )
    .unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    let mut client = client_side::builder(&pki.ca_pem)
        .unwrap()
        .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut server, &mut client).unwrap();
    // Cert-keyed authorization path: the consumer inspects the peer
    // leaf and decides what to do.
    let peer = server.peer_certificate().expect("peer cert present");
    assert!(peer.subject().contains("nas-1"), "got: {}", peer.subject());
    let der = peer.to_der().unwrap();
    assert!(!der.is_empty());
    let spki = peer.spki_sha256().unwrap();
    assert_ne!(spki, [0u8; 32]);
}

#[test]
fn handshake_fails_without_client_cert() {
    let pki = build_pki();
    let server_ctx = TlsContext::server(
        &pki.server_chain_pem,
        &pki.server_key_pem,
        Some(&pki.ca_pem),
    )
    .unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    let mut client = client_side::builder(&pki.ca_pem).unwrap().build().unwrap();
    let result = drive(&mut server, &mut client);
    assert!(matches!(result, Err(TlsError::Handshake(_))));
}

#[test]
fn handshake_fails_for_untrusted_client_chain() {
    // Server trusts CA-A; client presents a cert chained to CA-B.
    let trusted = build_pki();
    let untrusted = build_pki();
    let server_ctx = TlsContext::server(
        &trusted.server_chain_pem,
        &trusted.server_key_pem,
        Some(&trusted.ca_pem),
    )
    .unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    // The client trusts the *server* CA fine, but its own client
    // cert is signed by a CA the server has never heard of.
    let mut client = client_side::builder(&trusted.ca_pem)
        .unwrap()
        .with_client_cert(&untrusted.client_chain_pem, &untrusted.client_key_pem)
        .unwrap()
        .build()
        .unwrap();
    let result = drive(&mut server, &mut client);
    assert!(matches!(result, Err(TlsError::Handshake(_))));
}

#[test]
fn cert_key_mismatch_is_detected() {
    let pki = build_pki();
    // Pair the server cert with the *client*'s key — must mismatch.
    let result = TlsContext::server(
        &pki.server_chain_pem,
        &pki.client_key_pem,
        Some(&pki.ca_pem),
    );
    // Detected either by `SSL_CTX_use_PrivateKey` directly (Ssl)
    // or by the explicit follow-up check (KeyMismatch). Either is
    // correct behaviour.
    assert!(matches!(
        result,
        Err(TlsError::KeyMismatch | TlsError::Ssl(_))
    ));
}

#[test]
fn malformed_cert_pem_surfaces_error() {
    let pki = build_pki();
    let result = TlsContext::server(b"not a pem block", &pki.server_key_pem, Some(&pki.ca_pem));
    assert!(matches!(result, Err(TlsError::Pem(_))));
}

#[test]
fn drop_cleanliness_smoke() {
    // Exercises every owning newtype's Drop. Run a few dozen
    // build/accept cycles; if any handle is leaked, sanitizer / OOM
    // would catch it in CI.
    let pki = build_pki();
    for _ in 0..32 {
        let ctx = TlsContext::server(
            &pki.server_chain_pem,
            &pki.server_key_pem,
            Some(&pki.ca_pem),
        )
        .unwrap();
        let _ = TlsConnection::accept(&ctx).unwrap();
    }
}

#[test]
fn per_connection_trust_accepts_matching_client_cert() {
    // Listener-wide trust covers BOTH CAs; per-connection trust
    // narrows to CA-A. Client presents a CA-A cert -> handshake.
    let pki_a = build_pki();
    let pki_b = build_pki();
    let combined_ca: Vec<u8> = [pki_a.ca_pem.as_slice(), pki_b.ca_pem.as_slice()].concat();
    let server_ctx = TlsContext::server(
        &pki_a.server_chain_pem,
        &pki_a.server_key_pem,
        Some(&combined_ca),
    )
    .unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    let trust_a = ClientTrust::from_pem(&pki_a.ca_pem).unwrap();
    server.set_client_trust(&trust_a).unwrap();

    let mut client = client_side::builder(&pki_a.ca_pem)
        .unwrap()
        .with_client_cert(&pki_a.client_chain_pem, &pki_a.client_key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut server, &mut client).expect("handshake under narrowed trust");
}

#[test]
fn per_connection_trust_rejects_other_ca_client_cert() {
    // Listener-wide trust covers BOTH CAs; per-connection trust
    // narrows to CA-A. Client presents a CA-B cert -> rejected.
    // This is the IP-gated authorization model: a successful
    // handshake means the peer presented the cert their `Client`
    // record was narrowed to.
    let pki_a = build_pki();
    let pki_b = build_pki();
    let combined_ca: Vec<u8> = [pki_a.ca_pem.as_slice(), pki_b.ca_pem.as_slice()].concat();
    let server_ctx = TlsContext::server(
        &pki_a.server_chain_pem,
        &pki_a.server_key_pem,
        Some(&combined_ca),
    )
    .unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    let trust_a = ClientTrust::from_pem(&pki_a.ca_pem).unwrap();
    server.set_client_trust(&trust_a).unwrap();

    // Client presents a cert chained to CA-B; the server's
    // listener-wide store would accept it but the per-connection
    // narrowing must not.
    let mut client = client_side::builder(&pki_a.ca_pem)
        .unwrap()
        .with_client_cert(&pki_b.client_chain_pem, &pki_b.client_key_pem)
        .unwrap()
        .build()
        .unwrap();
    let result = drive(&mut server, &mut client);
    assert!(matches!(result, Err(TlsError::Handshake(_))));
}

#[test]
fn client_trust_from_empty_pem_is_an_error() {
    let result = ClientTrust::from_pem(b"not a pem");
    assert!(matches!(result, Err(TlsError::Pem(_))));
}
