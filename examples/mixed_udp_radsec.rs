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
//! IP map for UDP, and a name-keyed map for RadSec. Per RFC 6614
//! §2.3 every RadSec leaf carries a `dNSName` SAN identifying the
//! peer, and per RFC 6125 §6.4.4 the Common Name is deprecated for
//! identity matching — so we delegate matching to
//! [`PeerCertificate::matches_hostname`], which prefers SAN
//! `dNSName` (and `iPAddress` for IP-literal expectations), supports
//! RFC 6125 §6.4.3 leftmost-label wildcards, and never falls back
//! to CN here (`allow_common_name = false`). A real deployment
//! would back this with whatever identity database it already runs
//! (see `examples/sqlite_clients.rs` for a backend pattern).

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
/// table, and resolve RadSec peers by hostname against their leaf
/// cert (RFC 6614 §2.3 / RFC 6125 §6.4.3 / §6.4.4).
struct MixedStore {
    udp: StaticClients,
    radsec_clients_by_name: HashMap<String, Arc<Client>>,
}

impl ClientStore for MixedStore {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        self.udp.lookup_udp(src)
    }

    // Admit any source IP for the pre-handshake gate; the mTLS
    // handshake against the listener trust store + the
    // hostname-based `lookup_radsec_by_cert` below provide the
    // real authorization. Production deployments should narrow
    // this to a CIDR allow-list or wire it to a per-IP rate
    // limiter — the default returns `false` precisely so consumers
    // are forced to make this call deliberately.
    async fn admit_radsec(&self, _src: SocketAddr) -> bool {
        true
    }

    fn lookup_radsec_by_cert(
        &self,
        _src: SocketAddr,
        peer: &PeerCertificate,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // Walk the registry and ask the peer cert if it matches
        // each registered hostname. `matches_hostname` implements
        // RFC 6125 §6.4.3 (SAN dNSName preferred, leftmost-label
        // wildcards, IP-literal expectations matched against
        // iPAddress SANs) and we pass `allow_common_name = false`
        // because RFC 6125 §6.4.4 deprecates CN matching and
        // RadSec leaves are required to carry a SAN anyway.
        let hit = self
            .radsec_clients_by_name
            .iter()
            .find(|(name, _)| peer.matches_hostname(name, false))
            .map(|(_, client)| Arc::clone(client));
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

    let tls = TlsContext::server(&cert_chain_pem, &key_pem, &client_ca_pem)?;

    // UDP table: one /24 of NASes sharing one secret.
    let udp = StaticClients::builder()
        .add(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)?,
            Arc::new(Client::new(b"udp-shared-secret".as_slice())),
        )
        .build();

    // RadSec table: two known peers, keyed by the hostname their
    // cert presents (matched against the leaf's SAN dNSName via
    // `PeerCertificate::matches_hostname`).
    let mut radsec_clients_by_name = HashMap::new();
    radsec_clients_by_name.insert(
        "ap-edge-01.example.com".to_string(),
        Arc::new(Client::new(b"radsec-secret-edge-01".as_slice())),
    );
    radsec_clients_by_name.insert(
        "ap-edge-02.example.com".to_string(),
        Arc::new(Client::new(b"radsec-secret-edge-02".as_slice())),
    );

    let store = MixedStore {
        udp,
        radsec_clients_by_name,
    };

    // Build the server with three listeners: UDP auth + UDP acct +
    // RadSec (TCP/TLS). The store overrides
    // `lookup_radsec_by_cert` to map the peer's leaf certificate
    // (matched by hostname via `matches_hostname`) to a registered
    // client; `admit_radsec` keeps the
    // default (admit all source IPs).
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
