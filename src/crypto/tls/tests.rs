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
