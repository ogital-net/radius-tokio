//! Example: PEAPv0 + EAP-MSCHAPv2 RADIUS server.
//!
//! Spins up a self-signed PKI in a tmpdir, wires
//! [`PeapFactory`] around an [`MsChapV2Factory`] with a single
//! cleartext credential, and runs a UDP RADIUS listener on
//! `127.0.0.1:1812`. The supplicant authenticates the server via
//! the generated CA; the inner MSCHAPv2 exchange authenticates the
//! user.
//!
//! Run with the `peap` feature:
//!
//! ```text
//! cargo run -p radius-tokio-eap --features peap --example peap_mschapv2
//! ```
//!
//! On startup the example prints a ready-to-use `eapol_test`
//! invocation plus the `wpa_supplicant` config block it expects.
//! Drive it from another shell with hostap's `eapol_test`:
//!
//! ```text
//! eapol_test -c <printed-conf> -a 127.0.0.1 -p 1812 \
//!     -s testing123 -t 10 -r 0
//! ```
//!
//! Expected output ends with
//! `EAP authentication completed successfully` and an
//! `Access-Accept` carrying `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key`
//! derived from the PEAP keying-material export.
//!
//! # What this is not
//!
//! A production credential store. [`StaticCredentials`] holds one
//! username/password pair in memory; real deployments implement
//! the [`radius_tokio_eap::mschapv2::Credentials`] trait against
//! whatever directory / database they already run.
//!
//! # Dynamic VLAN assignment
//!
//! The example also shows the [`AcceptDecorator`] hook: a closure
//! that runs at `Access-Accept` time, sees the **authenticated
//! inner identity** (the MSCHAPv2 username, not the outer
//! `anonymous`), and stamps the RFC 3580 §3.31 tunnel triplet
//! (`Tunnel-Type=VLAN`, `Tunnel-Medium-Type=IEEE-802`,
//! `Tunnel-Private-Group-Id=<vlan>`) onto the reply. The NAS then
//! puts the supplicant in that VLAN.
//!
//! The triplet is encoded through the typed handles emitted by
//! the dictionary codegen
//! ([`radius_tokio::dict::rfc::attrs`]) rather than
//! raw `(type, bytes)` pairs — the codegen marks the tunnel
//! attributes with their `WTaggedInteger` / `WTaggedText` wire
//! shapes so `Reply::add` knows to lay out the 4-byte tagged
//! integer for `Tunnel-Type` / `Tunnel-Medium-Type` and the
//! 1-byte tag prefix for `Tunnel-Private-Group-Id`. No hand-rolled
//! byte arrays, no risk of getting the tag byte in the wrong slot.

use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::dict::rfc::{attrs, values};
use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::tls::TlsContext;
use radius_tokio::{CodecError, Reply};
use radius_tokio_eap::mschapv2::{MsChapV2Factory, StaticCredentials};
use radius_tokio_eap::peap::PeapFactory;
use radius_tokio_eap::{AcceptContext, EapHandler};

const SHARED_SECRET: &str = "testing123";
const IDENTITY: &str = "alice";
const PASSWORD: &str = "hello123";

/// RFC 2868 §3.1 tag. Zero disables tag grouping, which is fine
/// when only one tunnel entry is in flight. The enumerators for
/// `Tunnel-Type` / `Tunnel-Medium-Type` themselves come from the
/// dictionary codegen as typed newtypes
/// ([`values::TunnelType::VLAN`], [`values::TunnelMediumType::IEEE_802`]).
const TUNNEL_TAG: u8 = 0;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    // ---- PKI ----------------------------------------------------
    // Generate an ephemeral CA + server certificate. The CA PEM is
    // what the supplicant pins via `ca_cert=` in its config; the
    // chain + key go into the server's TlsContext.
    let ca = CertificateAuthority::new("radius-tokio-peap-example-ca").expect("generate CA");
    let server_cert = ca
        .issue_server(
            "radius.local",
            &[
                SubjectAltName::Ip(Ipv4Addr::LOCALHOST.into()),
                SubjectAltName::Dns("localhost".into()),
                SubjectAltName::Dns("radius.local".into()),
            ],
        )
        .expect("issue server cert");
    let ca_pem = ca.cert_pem().expect("encode CA PEM");

    // Drop the PKI material in a tmpdir keyed by PID so repeated
    // runs don't fight over the same path.
    let mut tmp_dir = std::env::temp_dir();
    tmp_dir.push(format!("radius-tokio-peap-example-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let ca_path = tmp_dir.join("ca.pem");
    let conf_path = tmp_dir.join("eapol_test.conf");
    std::fs::write(&ca_path, &ca_pem)?;
    std::fs::write(
        &conf_path,
        format!(
            "network={{\n\
             \tkey_mgmt=IEEE8021X\n\
             \teap=PEAP\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tanonymous_identity=\"anonymous\"\n\
             \tpassword=\"{PASSWORD}\"\n\
             \tca_cert=\"{ca}\"\n\
             \tphase2=\"auth=MSCHAPV2\"\n\
             }}\n",
            ca = ca_path.display(),
        ),
    )?;

    // ---- EAP stack ----------------------------------------------
    // Server-only TLS: PEAP doesn't ask for a client certificate —
    // the inner MSCHAPv2 exchange proves who the user is.
    let tls_ctx =
        TlsContext::server_without_client_auth(&server_cert.chain_pem, &server_cert.key_pem)
            .expect("build TLS context");

    let creds = Arc::new(StaticCredentials::cleartext(IDENTITY.as_bytes(), PASSWORD));
    let inner_factory = Arc::new(MsChapV2Factory::new(creds));
    let factory = PeapFactory::new(Arc::new(tls_ctx), inner_factory);

    // Accept-time hook: pick a VLAN from the authenticated inner
    // identity and stamp the RFC 3580 tunnel triplet. The typed
    // `Attr<WTaggedInteger>` / `Attr<WTaggedText>` handles from
    // the dictionary codegen know the wire shape (4-byte tagged
    // integer; 1-byte tag prefix on the text value), so the
    // decorator hands them `(tag, value)` tuples instead of
    // hand-rolled byte arrays.
    let handler = EapHandler::new(factory).with_accept_decorator(
        |ctx: &AcceptContext<'_>, reply: &mut Reply| -> Result<(), CodecError> {
            let vlan = match ctx.peer_identity {
                Some(id) if id == IDENTITY.as_bytes() => Some("42"),
                _ => None,
            };
            if let Some(vlan) = vlan {
                reply
                    .add(attrs::TUNNEL_TYPE, (TUNNEL_TAG, values::TunnelType::VLAN))?
                    .add(
                        attrs::TUNNEL_MEDIUM_TYPE,
                        (TUNNEL_TAG, values::TunnelMediumType::IEEE_802),
                    )?
                    .add(attrs::TUNNEL_PRIVATE_GROUP_ID, (TUNNEL_TAG, vlan))?;
            }
            Ok(())
        },
    );

    // ---- RADIUS plumbing ----------------------------------------
    let client = Arc::new(Client::new(SHARED_SECRET.as_bytes()));
    let clients = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let server = Server::builder()
        .clients(clients)
        .handler(handler)
        .listen_udp("127.0.0.1:1812".parse().unwrap())
        .build()?;

    println!("PEAP/MSCHAPv2 RADIUS listener on 127.0.0.1:1812");
    println!("  identity        : {IDENTITY}");
    println!("  password        : {PASSWORD}");
    println!("  shared secret   : {SHARED_SECRET}");
    println!("  CA certificate  : {}", ca_path.display());
    println!("  supplicant conf : {}", conf_path.display());
    println!();
    println!("Drive it from another shell with hostap's eapol_test:");
    println!(
        "  eapol_test -c {} -a 127.0.0.1 -p 1812 -s {SHARED_SECRET} -t 10 -r 0",
        conf_path.display(),
    );

    server.run().await
}
