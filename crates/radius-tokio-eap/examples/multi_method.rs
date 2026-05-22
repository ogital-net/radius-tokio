//! Example: multi-method RADIUS server (PEAP/MSCHAPv2 preferred,
//! EAP-MD5 fallback via `EAP-Response/Nak`).
//!
//! Demonstrates the [`MultiEapHandler`] + [`EapRouter`] pair: one
//! listener handles supplicants that speak either method, sharing
//! the same outer credentials. Peers that don't want PEAP can
//! Nak down to EAP-MD5 and authenticate against the same
//! `(identity, password)` pair.
//!
//! Run with the `peap` + `eap-md5` features:
//!
//! ```text
//! cargo run -p radius-tokio-eap \
//!     --features peap,eap-md5 \
//!     --example multi_method
//! ```
//!
//! On startup the example writes two `eapol_test` config files and
//! prints both invocations — one for the PEAP path, one for the
//! EAP-MD5 (Nak) path. Drive them from another shell:
//!
//! ```text
//! eapol_test -c <peap.conf>  -a 127.0.0.1 -p 1812 -s testing123
//! eapol_test -c <md5.conf>   -a 127.0.0.1 -p 1812 -s testing123 -n
//! ```
//!
//! Both should end with `EAP authentication completed
//! successfully`. The PEAP exchange returns MPPE keys; EAP-MD5
//! doesn't derive keying material, hence the `-n` flag on the
//! second invocation.

use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::eap::Type as EapType;
use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
use radius_tokio::server::{Client, IpCidr, Server, StaticClients};
use radius_tokio::tls::TlsContext;
use radius_tokio_eap::eap_md5::{EapMd5Factory, StaticCredentials as Md5StaticCredentials};
use radius_tokio_eap::mschapv2::{MsChapV2Factory, StaticCredentials as MsChapStaticCredentials};
use radius_tokio_eap::peap::PeapFactory;
use radius_tokio_eap::{EapRouter, MultiEapHandler};

const SHARED_SECRET: &str = "testing123";
const IDENTITY: &str = "alice";
const PASSWORD: &str = "hello123";

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    // ---- PKI (only PEAP needs it) -------------------------------
    let ca = CertificateAuthority::new("radius-tokio-multi-example-ca").expect("generate CA");
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

    let mut tmp_dir = std::env::temp_dir();
    tmp_dir.push(format!("radius-tokio-multi-example-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let ca_path = tmp_dir.join("ca.pem");
    let peap_conf = tmp_dir.join("peap.conf");
    let md5_conf = tmp_dir.join("md5.conf");
    std::fs::write(&ca_path, &ca_pem)?;
    std::fs::write(
        &peap_conf,
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
    std::fs::write(
        &md5_conf,
        format!(
            "network={{\n\
             \tkey_mgmt=IEEE8021X\n\
             \teap=MD5\n\
             \tidentity=\"{IDENTITY}\"\n\
             \tpassword=\"{PASSWORD}\"\n\
             }}\n"
        ),
    )?;

    // ---- EAP methods --------------------------------------------
    // PEAP: outer-only TLS, MSCHAPv2 inside.
    let tls_ctx =
        TlsContext::server_without_client_auth(&server_cert.chain_pem, &server_cert.key_pem)
            .expect("build TLS context");
    let mschap_creds = Arc::new(MsChapStaticCredentials::cleartext(
        IDENTITY.as_bytes(),
        PASSWORD,
    ));
    let inner = Arc::new(MsChapV2Factory::new(mschap_creds));
    let peap = PeapFactory::new(Arc::new(tls_ctx), inner);

    // EAP-MD5: same identity / password, plain challenge-response.
    let md5_creds = Arc::new(Md5StaticCredentials::cleartext(
        IDENTITY.as_bytes().to_vec(),
        PASSWORD.as_bytes(),
    ));
    let md5 = EapMd5Factory::new(md5_creds);

    // ---- Router + handler ---------------------------------------
    // PEAP is offered on the first round; EAP-MD5 only kicks in
    // when the peer Naks to it.
    let router = EapRouter::builder()
        .preferred(EapType::PEAP)
        .register_typed(EapType::PEAP, peap)
        .register_typed(EapType::MD5_CHALLENGE, md5)
        .build()
        .expect("router config valid");

    let handler = MultiEapHandler::new(router);

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

    println!("Multi-method RADIUS listener on 127.0.0.1:1812");
    println!("  identity       : {IDENTITY}");
    println!("  password       : {PASSWORD}");
    println!("  shared secret  : {SHARED_SECRET}");
    println!("  CA certificate : {}", ca_path.display());
    println!();
    println!("Drive PEAP (preferred path):");
    println!(
        "  eapol_test -c {} -a 127.0.0.1 -p 1812 -s {SHARED_SECRET} -t 10 -r 0",
        peap_conf.display(),
    );
    println!();
    println!("Drive EAP-MD5 (Nak fallback path; -n suppresses MPPE expectation):");
    println!(
        "  eapol_test -c {} -a 127.0.0.1 -p 1812 -s {SHARED_SECRET} -t 10 -r 0 -n",
        md5_conf.display(),
    );

    server.run().await
}
