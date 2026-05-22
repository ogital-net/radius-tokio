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
use super::{HandshakeState, TlsConnection, TlsContext, TlsError};

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
    let server_ctx = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem)
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
    let server_ctx =
        TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
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
    assert!(
        peer.subject_display().contains("nas-1"),
        "got: {}",
        peer.subject_display()
    );
    let der = peer.to_der().unwrap();
    assert!(!der.is_empty());
    let spki = peer.spki_sha256().unwrap();
    assert_ne!(spki, [0u8; 32]);
    let sans = peer.subject_alt_names().unwrap();
    assert!(
        sans.iter()
            .any(|s| matches!(s, super::SubjectAltName::Dns(d) if d == "nas-1")),
        "expected DNS SAN nas-1, got: {sans:?}"
    );
}

#[test]
fn handshake_fails_without_client_cert() {
    let pki = build_pki();
    let server_ctx =
        TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
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
        &trusted.ca_pem,
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
    let result = TlsContext::server(&pki.server_chain_pem, &pki.client_key_pem, &pki.ca_pem);
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
    let result = TlsContext::server(b"not a pem block", &pki.server_key_pem, &pki.ca_pem);
    assert!(matches!(result, Err(TlsError::Pem(_))));
}

#[test]
fn drop_cleanliness_smoke() {
    // Exercises every owning newtype's Drop. Run a few dozen
    // build/accept cycles; if any handle is leaked, sanitizer / OOM
    // would catch it in CI.
    let pki = build_pki();
    for _ in 0..32 {
        let ctx =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let _ = TlsConnection::accept(&ctx).unwrap();
    }
}

#[test]
fn peer_certificate_per_field_san_accessors() {
    // Build a custom client cert carrying every GeneralName choice
    // that the in-tree PKI helper can issue (DNS, IP, URI, rID),
    // and verify each per-field accessor returns just its slice.
    use crate::crypto::pki::{CertificateAuthority, SubjectAltName};
    use std::net::IpAddr;

    let ca = CertificateAuthority::new("test-ca").unwrap();
    let server = ca
        .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
        .unwrap();
    let client = ca
        .issue_client(
            "nas-multi",
            &[
                SubjectAltName::Dns("nas-multi.example.com".into()),
                SubjectAltName::Ip("10.0.0.5".parse::<IpAddr>().unwrap()),
                SubjectAltName::Uri("urn:nas:multi".into()),
                SubjectAltName::RegisteredId("1.3.6.1.4.1.99999.1".into()),
            ],
        )
        .unwrap();
    let ca_pem = ca.cert_pem().unwrap();

    let server_ctx = TlsContext::server(&server.chain_pem, &server.key_pem, &ca_pem).unwrap();
    let mut srv = TlsConnection::accept(&server_ctx).unwrap();
    let mut cli = client_side::builder(&ca_pem)
        .unwrap()
        .with_client_cert(&client.chain_pem, &client.key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut srv, &mut cli).expect("handshake");

    let peer = srv.peer_certificate().expect("peer cert present");

    // CN is taken from the Subject DN, not the SAN.
    let cns = peer.common_names().unwrap();
    assert_eq!(cns, vec!["nas-multi"], "CNs: {cns:?}");

    let dns = peer.dns_names().unwrap();
    assert_eq!(dns, vec!["nas-multi.example.com"]);

    let ips = peer.ip_addresses().unwrap();
    assert_eq!(ips, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);

    let uris = peer.uris().unwrap();
    assert_eq!(uris, vec!["urn:nas:multi"]);

    let rids = peer.registered_ids().unwrap();
    assert_eq!(rids, vec!["1.3.6.1.4.1.99999.1"]);

    // No otherName SAN issued, so the accessor returns empty.
    let others = peer.other_names().unwrap();
    assert!(others.is_empty(), "unexpected otherName: {others:?}");

    // The aggregate accessor surfaces every entry exactly once.
    let all = peer.subject_alt_names().unwrap();
    assert_eq!(all.len(), 4, "all SANs: {all:?}");
}

// -----------------------------------------------------------------
// dns_name_matches — RFC 6125 §6.4.3 unit tests. These don't need
// a live handshake; they exercise the helper directly.
// -----------------------------------------------------------------

#[test]
fn dns_match_exact_case_insensitive() {
    assert!(super::dns_name_matches(
        "host.example.com",
        "host.example.com"
    ));
    assert!(super::dns_name_matches(
        "HOST.example.com",
        "host.EXAMPLE.com"
    ));
    assert!(!super::dns_name_matches(
        "host.example.com",
        "other.example.com"
    ));
}

#[test]
fn dns_match_trailing_dot() {
    assert!(super::dns_name_matches(
        "host.example.com.",
        "host.example.com"
    ));
    assert!(super::dns_name_matches(
        "host.example.com",
        "host.example.com."
    ));
}

#[test]
fn dns_match_wildcard_left_label_only() {
    assert!(super::dns_name_matches("*.example.com", "host.example.com"));
    assert!(super::dns_name_matches("*.example.com", "HOST.example.com"));
    // Wildcard matches exactly one label.
    assert!(!super::dns_name_matches(
        "*.example.com",
        "deep.host.example.com"
    ));
    // Wildcard not in leftmost position is treated as a literal
    // and rejected (no '*' allowed in non-leftmost labels).
    assert!(!super::dns_name_matches("host.*.com", "host.example.com"));
    // Partial-label wildcards rejected.
    assert!(!super::dns_name_matches(
        "f*o.example.com",
        "foo.example.com"
    ));
    assert!(!super::dns_name_matches(
        "*foo.example.com",
        "myfoo.example.com"
    ));
}

#[test]
fn dns_match_wildcard_requires_three_labels() {
    // RFC 6125 §6.4.3: wildcard certs covering top-level zones
    // (*.com, *.local) are rejected.
    assert!(!super::dns_name_matches("*.com", "example.com"));
    assert!(!super::dns_name_matches("*.local", "host.local"));
    assert!(super::dns_name_matches("*.example.com", "host.example.com"));
}

#[test]
fn dns_match_rejects_malformed() {
    assert!(!super::dns_name_matches("", "host.example.com"));
    assert!(!super::dns_name_matches("host.example.com", ""));
    assert!(!super::dns_name_matches(".example.com", ".example.com"));
    assert!(!super::dns_name_matches(
        "host..example.com",
        "host..example.com"
    ));
    // Embedded NUL — one historical X.509 SAN smuggling vector.
    assert!(!super::dns_name_matches(
        "good.example.com\0evil.example.com",
        "good.example.com",
    ));
}

// -----------------------------------------------------------------
// matches_hostname — end-to-end check using a peer cert from a
// real handshake.
// -----------------------------------------------------------------

#[test]
fn matches_hostname_san_dns_hit() {
    use crate::crypto::pki::{CertificateAuthority, SubjectAltName};
    use std::net::IpAddr;
    let ca = CertificateAuthority::new("ca").unwrap();
    let ca_pem = ca.cert_pem().unwrap();
    let server = ca
        .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
        .unwrap();
    let client = ca
        .issue_client(
            "nas-1",
            &[
                SubjectAltName::Dns("nas-1.example.com".into()),
                SubjectAltName::Ip("10.0.0.5".parse::<IpAddr>().unwrap()),
            ],
        )
        .unwrap();

    let server_ctx = TlsContext::server(&server.chain_pem, &server.key_pem, &ca_pem).unwrap();
    let mut srv = TlsConnection::accept(&server_ctx).unwrap();
    let mut cli = client_side::builder(&ca_pem)
        .unwrap()
        .with_client_cert(&client.chain_pem, &client.key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut srv, &mut cli).expect("handshake");
    let peer = srv.peer_certificate().expect("peer cert");

    // SAN DNS exact + case-insensitive.
    assert!(peer.matches_hostname("nas-1.example.com", false));
    assert!(peer.matches_hostname("NAS-1.example.com", false));
    assert!(!peer.matches_hostname("other.example.com", false));

    // SAN IP literal.
    assert!(peer.matches_hostname("10.0.0.5", false));
    assert!(!peer.matches_hostname("10.0.0.6", false));

    // CN-only "nas-1" must NOT match when SAN dNSName is present
    // (RFC 6125 §6.4.4), even with the legacy CN flag enabled.
    assert!(!peer.matches_hostname("nas-1", true));
    assert!(!peer.matches_hostname("nas-1", false));
}

#[test]
fn matches_hostname_cn_fallback_only_without_san_dns() {
    use crate::crypto::pki::{CertificateAuthority, SubjectAltName};
    use std::net::IpAddr;
    let ca = CertificateAuthority::new("ca").unwrap();
    let ca_pem = ca.cert_pem().unwrap();
    let server = ca
        .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
        .unwrap();
    // Client cert with CN=nas-1 and only an IP SAN — no DNS SAN,
    // so the CN-fallback path applies for DNS hostname matching.
    // (Empty-SAN issuance is rejected by `pki` on purpose.)
    let client = ca
        .issue_client(
            "nas-1",
            &[SubjectAltName::Ip("10.0.0.5".parse::<IpAddr>().unwrap())],
        )
        .unwrap();

    let server_ctx = TlsContext::server(&server.chain_pem, &server.key_pem, &ca_pem).unwrap();
    let mut srv = TlsConnection::accept(&server_ctx).unwrap();
    let mut cli = client_side::builder(&ca_pem)
        .unwrap()
        .with_client_cert(&client.chain_pem, &client.key_pem)
        .unwrap()
        .build()
        .unwrap();
    drive(&mut srv, &mut cli).expect("handshake");
    let peer = srv.peer_certificate().expect("peer cert");

    // Legacy mode: CN match permitted, exact case-insensitive only.
    assert!(peer.matches_hostname("nas-1", true));
    assert!(peer.matches_hostname("NAS-1", true));
    assert!(!peer.matches_hostname("nas-2", true));
    // No wildcard support in CN fallback.
    assert!(!peer.matches_hostname("*", true));
    // Strict mode: CN never consulted.
    assert!(!peer.matches_hostname("nas-1", false));
    // IP SAN still works regardless of CN-fallback flag.
    assert!(peer.matches_hostname("10.0.0.5", false));
}

#[test]
fn server_without_client_auth_accepts_cert_less_client() {
    // EAP-PEAP / TTLS / FAST shape: the server presents a cert but
    // does NOT request one back. A client that omits its cert must
    // still complete the handshake.
    let pki = build_pki();
    let server_ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem)
            .expect("build cert-optional server ctx");
    let mut server = TlsConnection::accept(&server_ctx).expect("accept");
    // Client trusts the server CA but does NOT install a client cert.
    let mut client = client_side::builder(&pki.ca_pem).unwrap().build().unwrap();
    drive(&mut server, &mut client).expect("handshake");
    assert!(!server.is_handshaking());
    // No client cert was presented.
    assert!(server.peer_certificate().is_none());
}

#[test]
fn export_keying_material_matches_between_peers_and_differs_per_label() {
    // RFC 5705 / RFC 8446 §7.5: both ends of a TLS session derive
    // identical exporter output for the same (label, context, len).
    // Different labels must yield independent material.
    let pki = build_pki();
    let server_ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut server = TlsConnection::accept(&server_ctx).unwrap();
    let mut client = client_side::builder(&pki.ca_pem).unwrap().build().unwrap();
    drive(&mut server, &mut client).expect("handshake");

    let mut srv_msk = [0u8; 64];
    let mut cli_msk = [0u8; 64];
    server
        .export_keying_material("client EAP encryption", None, &mut srv_msk)
        .expect("server export");
    client
        .export_keying_material("client EAP encryption", None, &mut cli_msk)
        .expect("client export");
    assert_eq!(srv_msk, cli_msk, "exporters must agree across peers");

    // A different label must produce different output (with
    // overwhelming probability under any sane TLS exporter).
    let mut srv_other = [0u8; 64];
    server
        .export_keying_material("client PEAP encryption", None, &mut srv_other)
        .expect("server export (other label)");
    assert_ne!(srv_msk, srv_other, "labels must namespace exporter output");
}

#[test]
fn export_keying_material_before_handshake_is_error() {
    let pki = build_pki();
    let server_ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let server = TlsConnection::accept(&server_ctx).unwrap();
    let mut out = [0u8; 16];
    let err = server
        .export_keying_material("client EAP encryption", None, &mut out)
        .expect_err("must reject pre-handshake export");
    assert!(matches!(err, TlsError::Handshake(_)), "got {err:?}");
}

// =====================================================================
// Defensive-input tests
// ---------------------------------------------------------------------
// The wrapper is the only place in the crate that hands bytes from
// the network to libssl. Every public entry point that takes
// untrusted input must:
//
//   * refuse the input cleanly with a typed `TlsError`,
//   * never panic, never abort, never UB,
//   * never advance the state machine into an inconsistent state.
//
// These tests intentionally feed garbage, truncated, oversized, and
// out-of-order bytes through `TlsContext` / `TlsConnection` and
// assert the wrapper survives.
// =====================================================================

#[test]
fn server_ctx_rejects_garbage_cert_pem() {
    let pki = build_pki();
    let err = TlsContext::server(b"not a pem", &pki.server_key_pem, &pki.ca_pem)
        .expect_err("garbage cert must be rejected");
    assert!(matches!(err, TlsError::Pem("certificate")), "got {err:?}");
}

#[test]
fn server_ctx_rejects_garbage_key_pem() {
    let pki = build_pki();
    let err = TlsContext::server(&pki.server_chain_pem, b"not a key", &pki.ca_pem)
        .expect_err("garbage key must be rejected");
    assert!(matches!(err, TlsError::Pem("private key")), "got {err:?}");
}

#[test]
fn server_ctx_rejects_garbage_ca_pem() {
    let pki = build_pki();
    let err = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, b"not a ca")
        .expect_err("garbage CA must be rejected");
    // Empty / unparseable CA bundle surfaces as a Pem error from
    // `install_client_cas`.
    assert!(
        matches!(err, TlsError::Pem(_) | TlsError::Ssl(_)),
        "got {err:?}",
    );
}

#[test]
fn server_ctx_rejects_mismatched_key() {
    // Build two independent PKIs; pair the server cert from one
    // with the server key from the other. `SSL_CTX_check_private_key`
    // must refuse the combination.
    let a = build_pki();
    let b = build_pki();
    let err = TlsContext::server(&a.server_chain_pem, &b.server_key_pem, &a.ca_pem)
        .expect_err("mismatched key must be rejected");
    assert!(matches!(err, TlsError::KeyMismatch), "got {err:?}");
}

#[test]
fn server_ctx_rejects_empty_inputs() {
    let pki = build_pki();
    // Empty cert.
    assert!(matches!(
        TlsContext::server(b"", &pki.server_key_pem, &pki.ca_pem)
            .expect_err("empty cert must be rejected"),
        TlsError::Pem(_),
    ));
    // Empty key.
    assert!(matches!(
        TlsContext::server(&pki.server_chain_pem, b"", &pki.ca_pem)
            .expect_err("empty key must be rejected"),
        TlsError::Pem(_),
    ));
    // Empty CA bundle.
    assert!(matches!(
        TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, b"")
            .expect_err("empty CA must be rejected"),
        TlsError::Pem(_) | TlsError::Ssl(_),
    ));
}

#[test]
fn feed_input_with_empty_buffer_is_noop() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    assert_eq!(conn.feed_input(&[]).unwrap(), 0);
}

#[test]
fn take_output_with_empty_buffer_is_noop() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    let mut empty: [u8; 0] = [];
    assert_eq!(conn.take_output(&mut empty).unwrap(), 0);
}

#[test]
fn pending_output_is_empty_before_handshake() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    assert!(conn.pending_output().is_empty());
}

#[test]
fn read_before_handshake_does_not_panic() {
    // SSL_read on a fresh server with no pending plaintext must
    // return `Ok(0)` (mapped from WANT_READ), not panic and not
    // surface a spurious I/O error.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(conn.read(&mut buf).unwrap(), 0);
    // Empty plaintext buffer is also a no-op.
    let mut empty: [u8; 0] = [];
    assert_eq!(conn.read(&mut empty).unwrap(), 0);
}

#[test]
fn write_before_handshake_does_not_panic() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    // Pre-handshake plaintext write returns 0 (WANT_READ) rather
    // than smuggling cleartext onto the wire.
    let n = conn.write(b"PAYLOAD").unwrap();
    assert_eq!(n, 0);
    // Empty plaintext is a no-op.
    assert_eq!(conn.write(b"").unwrap(), 0);
}

#[test]
fn peer_certificate_is_none_before_handshake() {
    let pki = build_pki();
    let ctx = TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
    let conn = TlsConnection::accept(&ctx).unwrap();
    assert!(conn.peer_certificate().is_none());
}

#[test]
fn is_tls13_is_false_before_handshake() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let conn = TlsConnection::accept(&ctx).unwrap();
    // Pre-negotiation `SSL_version` reports the placeholder, which
    // must compare *below* the TLS 1.3 constant.
    assert!(!conn.is_tls13());
}

#[test]
fn request_key_update_noop_before_tls13() {
    // Pre-handshake the negotiated version is unknown; the helper
    // must safely return `Ok(false)` rather than poke libssl.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    assert!(!conn.request_key_update().unwrap());
}

#[test]
fn shutdown_before_handshake_is_safe() {
    // Calling shutdown on a brand-new connection must not panic
    // and must return a boolean (the exact value is libssl-defined
    // and not part of our contract).
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    let _ = conn.shutdown();
}

#[test]
fn consume_output_is_safe_when_buffer_is_empty() {
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    // No queued ciphertext yet; reset must still succeed.
    conn.consume_output().expect("BIO_reset on empty BIO");
    // Idempotent.
    conn.consume_output().expect("second BIO_reset");
}

#[test]
fn process_rejects_non_tls_traffic_cleanly() {
    // A non-TLS payload (e.g. an HTTP/1.1 request mistakenly
    // pointed at the RadSec listener) must terminate the handshake
    // with `TlsError::Handshake`, not propagate as an I/O error or
    // crash.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    conn.feed_input(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    // Pump the state machine until it either fails or returns
    // NeedsRead; never let it spin indefinitely.
    let mut failed = false;
    for _ in 0..8 {
        match conn.process() {
            Ok(HandshakeState::NeedsRead | HandshakeState::NeedsWrite) => {
                // Keep pumping; libssl may demand multiple ticks
                // before it surfaces the protocol error.
            }
            Ok(HandshakeState::Established) => {
                panic!("non-TLS bytes must not yield Established");
            }
            Err(TlsError::Handshake(_)) => {
                failed = true;
                break;
            }
            Err(other) => panic!("expected Handshake error, got {other:?}"),
        }
    }
    assert!(failed, "process() must reject non-TLS traffic");
    assert!(conn.is_handshaking());
}

#[test]
fn process_handles_truncated_record_header_as_want_read() {
    // Feeding a single byte (way short of even the 5-byte TLS
    // record header) must leave the state machine in WantRead, not
    // crash and not error.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    conn.feed_input(&[0x16]).unwrap();
    match conn
        .process()
        .expect("process must not error on partial record")
    {
        HandshakeState::NeedsRead | HandshakeState::NeedsWrite => {}
        HandshakeState::Established => panic!("must not establish on partial input"),
    }
}

#[test]
fn process_handles_zero_length_record_as_want_read() {
    // A TLS 1.2 record header claiming length 0 is well-formed
    // but carries no payload — must not crash and must not be
    // mistaken for a real handshake message.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    // type=handshake(22), version=0x0303, length=0x0000
    conn.feed_input(&[0x16, 0x03, 0x03, 0x00, 0x00]).unwrap();
    // Whatever the SSL state machine decides (WantRead or
    // Handshake error), the call must return without panicking.
    let _ = conn.process();
    // And feed_input is still usable afterwards (no poisoning).
    assert_eq!(conn.feed_input(&[]).unwrap(), 0);
}

#[test]
fn feed_input_accepts_large_buffer_without_panicking() {
    // 256 KiB of arbitrary bytes — well above the 16 KiB TLS
    // record cap. The wrapper must accept it (BIOs grow on demand)
    // and process() must terminate the handshake cleanly rather
    // than panic on the oversized garbage.
    let pki = build_pki();
    let ctx =
        TlsContext::server_without_client_auth(&pki.server_chain_pem, &pki.server_key_pem).unwrap();
    let mut conn = TlsConnection::accept(&ctx).unwrap();
    let big = vec![0xa5u8; 256 * 1024];
    let written = conn.feed_input(&big).expect("feed_input large");
    assert_eq!(written, big.len());
    // The state machine must reject the bogus content cleanly:
    // either NeedsRead ("waiting for more") or a typed Handshake
    // error. Established or any other error variant is forbidden.
    // We only need a single pump — libssl decides on the first
    // record header it parses.
    match conn.process() {
        Ok(HandshakeState::NeedsRead | HandshakeState::NeedsWrite) => {}
        Ok(HandshakeState::Established) => panic!("garbage must not establish"),
        Err(TlsError::Handshake(_)) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}
