//! [`Server`] driver: owns the UDP listener tasks and the shutdown
//! channel.
//!
//! Built via [`Server::builder`]: register a [`ClientStore`] and a
//! [`Handler`], list the addresses to bind, then call [`Server::run`]
//! to drive the accept loops to completion. A separate
//! [`ShutdownHandle`] (cloneable, `Send + Sync`) lets external code
//! signal a graceful drain.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

#[cfg(feature = "radsec")]
use tokio::net::TcpListener;

use super::dedup::DedupCache;
use super::handler::Handler;
#[cfg(feature = "radsec")]
use super::radsec::{serve_radsec, ConnectionRegistry, RadSecMode};
use super::store::ClientStore;
use super::udp::{serve_udp, DEFAULT_DEDUP_TTL};

#[cfg(feature = "radsec")]
use crate::tls::TlsContext;

/// Cloneable handle to request a graceful shutdown of a running
/// [`Server`].
///
/// Dropping every clone does *not* trigger shutdown — the server is
/// owned by whoever called [`Server::run`]; callers who want
/// drop-to-shutdown semantics can wrap it in their own RAII type.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal every listener task to drain and exit. Idempotent.
    pub fn shutdown(&self) {
        // Ignored error means there are no receivers left, which
        // implies the server has already returned.
        let _ = self.tx.send(true);
    }
}

/// Cloneable handle for tearing down `RadSec` connections bound to
/// a specific client. Created via [`Server::radsec_revoker`].
#[cfg(feature = "radsec")]
#[derive(Clone)]
pub struct RadSecRevoker {
    connections: Arc<ConnectionRegistry>,
}

#[cfg(feature = "radsec")]
impl std::fmt::Debug for RadSecRevoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadSecRevoker").finish_non_exhaustive()
    }
}

#[cfg(feature = "radsec")]
impl RadSecRevoker {
    /// Tear down every active `RadSec` connection bound to
    /// `client_id`. Returns the number of connections signalled.
    #[must_use]
    pub fn revoke(&self, client_id: super::client::ClientId) -> usize {
        self.connections.close_for(client_id)
    }
}

/// Active RADIUS server. Construct via [`Server::builder`].
#[derive(Debug)]
pub struct Server<S, H> {
    store: Arc<S>,
    handler: Arc<H>,
    udp_binds: Vec<SocketAddr>,
    #[cfg(feature = "radsec")]
    radsec_binds: Vec<(SocketAddr, TlsContext, RadSecMode)>,
    #[cfg(feature = "radsec")]
    connections: Arc<ConnectionRegistry>,
    dedup_ttl: Duration,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl<S: ClientStore, H: Handler> Server<S, H> {
    /// Begin assembling a server.
    #[must_use]
    pub fn builder() -> ServerBuilder<S, H> {
        ServerBuilder::default()
    }

    /// Cloneable handle for requesting shutdown from outside the
    /// task driving [`run`](Self::run).
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            tx: self.shutdown_tx.clone(),
        }
    }

    /// Tear down every active `RadSec` connection currently bound
    /// to `client_id`. UDP traffic is unaffected (the dedup cache
    /// will simply expire its entries on its normal schedule).
    ///
    /// Use this hook when revoking a client at runtime — without
    /// it, an already-established TLS session would continue to
    /// authenticate as the old client until the peer disconnects.
    /// Returns the number of connections that were signalled.
    ///
    /// Idempotent: connections that have already exited are simply
    /// skipped.
    #[cfg(feature = "radsec")]
    #[must_use]
    pub fn close_connections_for(&self, client_id: super::client::ClientId) -> usize {
        self.connections.close_for(client_id)
    }

    /// Cloneable handle for revoking active `RadSec` connections
    /// from outside the task driving [`run`](Self::run). Pairs
    /// with [`shutdown_handle`](Self::shutdown_handle) for
    /// out-of-band server control.
    #[cfg(feature = "radsec")]
    #[must_use]
    pub fn radsec_revoker(&self) -> RadSecRevoker {
        RadSecRevoker {
            connections: Arc::clone(&self.connections),
        }
    }

    /// Bind every configured address and drive the accept loops
    /// until either an unrecoverable I/O error occurs or the
    /// [`ShutdownHandle`] flips.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error encountered while binding any
    /// listener, or any error propagated from a listener task. On
    /// shutdown, returns `Ok(())`.
    pub async fn run(self) -> io::Result<()> {
        #[cfg(feature = "radsec")]
        let no_listeners = self.udp_binds.is_empty() && self.radsec_binds.is_empty();
        #[cfg(not(feature = "radsec"))]
        let no_listeners = self.udp_binds.is_empty();
        if no_listeners {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Server::run called with no listeners configured",
            ));
        }

        let cache = Arc::new(DedupCache::new(self.dedup_ttl));

        let mut tasks = JoinSet::new();
        for addr in &self.udp_binds {
            let socket = UdpSocket::bind(addr).await?;
            info!(event = "udp_bind", %addr);
            tasks.spawn(serve_udp(
                socket,
                Arc::clone(&self.store),
                Arc::clone(&self.handler),
                Arc::clone(&cache),
                self.shutdown_rx.clone(),
            ));
        }

        #[cfg(feature = "radsec")]
        for (addr, ctx, mode) in &self.radsec_binds {
            let listener = TcpListener::bind(addr).await?;
            info!(event = "radsec_bind", %addr, mode = ?mode);
            tasks.spawn(serve_radsec(
                listener,
                ctx.clone(),
                *mode,
                Arc::clone(&self.store),
                Arc::clone(&self.handler),
                Arc::clone(&cache),
                Arc::clone(&self.connections),
                self.shutdown_rx.clone(),
            ));
        }

        // Drop our own copy of the receiver so a future-proof
        // `Sender::closed` would actually fire if every task exited.
        drop(self.shutdown_rx);

        // Drive the join set; first error wins.
        let mut first_err: Option<io::Error> = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                    // Propagate shutdown so the remaining tasks drain.
                    let _ = self.shutdown_tx.send(true);
                }
                Err(join) => {
                    if first_err.is_none() {
                        first_err = Some(io::Error::other(join.to_string()));
                    }
                    let _ = self.shutdown_tx.send(true);
                }
            }
        }

        if let Some(e) = first_err {
            warn_!(event = "server_exit", error = %e);
            Err(e)
        } else {
            info!(event = "server_exit");
            Ok(())
        }
    }
}

/// Fluent builder for [`Server`].
#[derive(Debug)]
pub struct ServerBuilder<S, H> {
    store: Option<Arc<S>>,
    handler: Option<Arc<H>>,
    udp_binds: Vec<SocketAddr>,
    #[cfg(feature = "radsec")]
    radsec_binds: Vec<(SocketAddr, TlsContext, RadSecMode)>,
    dedup_ttl: Duration,
}

impl<S, H> Default for ServerBuilder<S, H> {
    fn default() -> Self {
        Self {
            store: None,
            handler: None,
            udp_binds: Vec::new(),
            #[cfg(feature = "radsec")]
            radsec_binds: Vec::new(),
            dedup_ttl: DEFAULT_DEDUP_TTL,
        }
    }
}

impl<S: ClientStore, H: Handler> ServerBuilder<S, H> {
    /// Set the client store (required).
    #[must_use]
    pub fn clients(mut self, store: S) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    /// Set the request handler (required).
    #[must_use]
    pub fn handler(mut self, handler: H) -> Self {
        self.handler = Some(Arc::new(handler));
        self
    }

    /// Add a UDP listen address. May be called multiple times for
    /// auth + accounting, dual-stack, etc.
    #[must_use]
    pub fn listen_udp(mut self, addr: SocketAddr) -> Self {
        self.udp_binds.push(addr);
        self
    }

    /// Add a `RadSec` (RFC 6614) TCP listen address with the
    /// per-listener [`TlsContext`] used to terminate mTLS for every
    /// connection accepted on that address. Defaults to
    /// [`RadSecMode::CertKeyed`]: the listener-wide trust store
    /// validates every chain that reaches it, and
    /// [`ClientStore::lookup_radsec_by_cert`] runs after the
    /// handshake to map the leaf cert to a registered client. This
    /// is the RFC 6614 §2.5 model and works for NAT'd, shared-IP,
    /// and RFC 7585 dynamic-discovery deployments alike.
    ///
    /// Consumers using the IP-gated subset (every NAS source IP is
    /// known up front, peers are pinned to a per-IP CA / SPKI)
    /// should call [`listen_radsec_ip_gated`](Self::listen_radsec_ip_gated)
    /// instead.
    ///
    /// May be called multiple times to bind several addresses
    /// (dual-stack, multiple ports). Only available with the
    /// `radsec` cargo feature.
    ///
    /// [`ClientStore::lookup_radsec_by_cert`]:
    ///     super::store::ClientStore::lookup_radsec_by_cert
    #[cfg(feature = "radsec")]
    #[must_use]
    pub fn listen_radsec(mut self, addr: SocketAddr, tls: TlsContext) -> Self {
        self.radsec_binds.push((addr, tls, RadSecMode::CertKeyed));
        self
    }

    /// Add a `RadSec` listen address running in
    /// [`RadSecMode::IpGated`] mode: the source IP is the admission
    /// key (consulted *before* any TLS state is allocated) and the
    /// admitted client's per-record [`ClientTrust`] narrows libssl's
    /// chain validation, so a successful mTLS handshake *is* the
    /// authorization decision.
    ///
    /// Use this for enterprise / SP edges where every NAS source
    /// IP is provisioned, you want a cheap pre-handshake `DoS`
    /// filter, and "this peer at this IP must present the cert it
    /// was issued" is the policy. Cannot express NAT'd or
    /// dynamic-discovery deployments — use [`listen_radsec`] for
    /// those.
    ///
    /// [`ClientTrust`]: crate::tls::ClientTrust
    /// [`listen_radsec`]: Self::listen_radsec
    #[cfg(feature = "radsec")]
    #[must_use]
    pub fn listen_radsec_ip_gated(mut self, addr: SocketAddr, tls: TlsContext) -> Self {
        self.radsec_binds.push((addr, tls, RadSecMode::IpGated));
        self
    }

    /// Override the dedup / retransmit cache TTL. Default is 30s.
    #[must_use]
    pub fn dedup_ttl(mut self, ttl: Duration) -> Self {
        self.dedup_ttl = ttl;
        self
    }

    /// Finalise the builder.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if either the client
    /// store or the handler was not set.
    pub fn build(self) -> io::Result<Server<S, H>> {
        let store = self
            .store
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing client store"))?;
        let handler = self
            .handler
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing handler"))?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Server {
            store,
            handler,
            udp_binds: self.udp_binds,
            #[cfg(feature = "radsec")]
            radsec_binds: self.radsec_binds,
            #[cfg(feature = "radsec")]
            connections: Arc::new(ConnectionRegistry::default()),
            dedup_ttl: self.dedup_ttl,
            shutdown_tx,
            shutdown_rx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::server::client::Client;
    use crate::server::handler::{HandlerResult, Request};
    use crate::server::store::{IpCidr, StaticClients};
    use std::net::Ipv4Addr;

    struct AcceptAll;

    impl Handler for AcceptAll {
        async fn handle(&self, request: Request<'_>) -> HandlerResult {
            HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_run_shutdown() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let store = StaticClients::builder()
            .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
            .build();

        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_udp("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();

        let task = tokio::spawn(server.run());
        // Yield once so the bind completes before we ask for shutdown.
        tokio::task::yield_now().await;
        shutdown.shutdown();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_requires_store_and_handler() {
        let res = Server::<StaticClients, AcceptAll>::builder().build();
        assert!(res.is_err());
    }
}
