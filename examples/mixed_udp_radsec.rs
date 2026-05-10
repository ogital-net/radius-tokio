//! Example: a server that listens on UDP **and** RadSec at the same time.
//!
//! Run with:
//!
//! ```text
//! cargo run --example mixed_udp_radsec --features radsec
//! ```
//!
//! Requires the `radsec` Cargo feature (it's the only thing that
//! brings in the `tls` module + the RadSec listener wiring).
//!
//! ## What this shows
//!
//! A single [`Server`](radius_tokio::server::Server) can accept any
//! mix of UDP and RadSec listeners; they all fan into the same
//! [`Handler`](radius_tokio::server::Handler) and the same
//! [`ClientStore`](radius_tokio::server::ClientStore). The store is
//! consulted differently per transport:
//!
//! * **UDP** \u2014 [`ClientStore::lookup_udp`](
//!   radius_tokio::server::ClientStore::lookup_udp) is called once
//!   per inbound packet, before any cryptographic work.
//! * **RadSec (cert-keyed, the default)** \u2014
//!   [`ClientStore::lookup_radsec_by_cert`](
//!   radius_tokio::server::ClientStore::lookup_radsec_by_cert) is
//!   called from the TLS verify callback once the peer presents a
//!   chain. Unknown chains fail the handshake.
//!
//! ## PEM material
//!
//! For brevity this example reads three PEM blobs from disk:
//!
//! * `server.pem` \u2014 the server's RadSec certificate chain.
//! * `server.key` \u2014 the matching private key.
//! * `clients-ca.pem` \u2014 the CA that issued every authorised
//!   RadSec client cert.
//!
//! In a real deployment the consumer supplies these from whatever
//! key-management story they already use (Vault, sealed secrets, KMS,
//! ...). The library intentionally never reads files itself.
//!
//! ## The store
//!
//! `MixedStore` is the smallest interesting `ClientStore`: a static
//! IP map for UDP, and a Common-Name map for RadSec. A real
//! deployment would back this with whatever identity database it
//! already runs (see `examples/sqlite_clients.rs` for a backend
//! pattern).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{
    Client, ClientStore, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::tls::{PeerCertificate, TlsContext};
use radius_tokio::Code;

// ─── handler ──────────────────────────────────────────────────────

struct AcceptAll;

impl Handler for AcceptAll {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }
        let mut reply = request.reply(Code::ACCESS_ACCEPT);
        reply.add(attrs::SESSION_TIMEOUT, 3600u32).unwrap();
        HandlerResult::Reply(reply)
    }
}

// ─── store ────────────────────────────────────────────────────────

/// Small union store: delegate UDP lookups to a [`StaticClients`]
/// table, and resolve RadSec peers by the `CN` of their leaf cert.
struct MixedStore {
    udp: StaticClients,
    by_cn: HashMap<String, Arc<Client>>,
}

impl ClientStore for MixedStore {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        self.udp.lookup_udp(src)
    }

    fn lookup_radsec_by_cert(
        &self,
        peer: &PeerCertificate,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // `PeerCertificate::subject()` returns the OpenSSL one-line
        // form (e.g. `/CN=ap-edge-01.example.com`). Pull the CN out
        // and look it up in our table.
        let subject = peer.subject();
        let cn = subject
            .split('/')
            .find_map(|part| part.strip_prefix("CN="))
            .unwrap_or("")
            .to_string();
        let hit = self.by_cn.get(&cn).cloned();
        async move { hit }
    }
}

// ─── main ─────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load TLS material. In production these come from whatever
    // secret-management story the operator runs.
    let cert_chain_pem = std::fs::read("server.pem")?;
    let key_pem = std::fs::read("server.key")?;
    let client_ca_pem = std::fs::read("clients-ca.pem")?;

    let tls = TlsContext::server(&cert_chain_pem, &key_pem, Some(&client_ca_pem))?;

    // UDP table: one /24 of NASes sharing one secret.
    let udp = StaticClients::builder()
        .add(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)?,
            Arc::new(Client::new(b"udp-shared-secret".as_slice())),
        )
        .build();

    // RadSec table: two known peers, keyed by the CN their cert
    // presents.
    let mut by_cn = HashMap::new();
    by_cn.insert(
        "ap-edge-01.example.com".to_string(),
        Arc::new(Client::new(b"radsec-secret-edge-01".as_slice())),
    );
    by_cn.insert(
        "ap-edge-02.example.com".to_string(),
        Arc::new(Client::new(b"radsec-secret-edge-02".as_slice())),
    );

    let store = MixedStore { udp, by_cn };

    // Build the server with three listeners: UDP auth + UDP acct +
    // RadSec (TCP/TLS). RadSec defaults to cert-keyed mode; switch
    // to `.listen_radsec_ip_gated(...)` for IP-keyed deployments.
    let server = Server::builder()
        .clients(store)
        .handler(AcceptAll)
        .listen_udp("0.0.0.0:1812".parse().unwrap()) // auth
        .listen_udp("0.0.0.0:1813".parse().unwrap()) // acct
        .listen_radsec("0.0.0.0:2083".parse().unwrap(), tls)
        .build()?;

    println!("radius-tokio listening on UDP/1812, UDP/1813, TLS/2083");
    server.run().await?;
    Ok(())
}
