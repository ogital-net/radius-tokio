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
use super::radsec::{serve_radsec, ConnectionRegistry};
use super::store::ClientStore;
use super::udp::{serve_udp, DEFAULT_DEDUP_TTL};

#[cfg(feature = "radsec")]
use crate::tls::TlsContext;

/// Bind a UDP listener with the socket options FreeRADIUS has long
/// considered table stakes for AAA traffic:
///
/// * **IPv4: disable Path MTU Discovery** (`IP_MTU_DISCOVER =
///   IP_PMTUDISC_DONT` on Linux, `IP_DONTFRAG = 0` on BSD/macOS).
///   The kernel default on modern Linux is `IP_PMTUDISC_WANT`,
///   which sets `DF=1` on outgoing replies; an Access-Accept that
///   exceeds the path MTU (common with EAP-Message payloads) is
///   then dropped with an ICMP "fragmentation needed" instead of
///   being IP-fragmented end-to-end. RADIUS frames are bounded at
///   4096 octets (RFC 2865 §3) and fragmentation is the expected
///   recovery path; PMTUD just turns transient MTU mismatches
///   into hard delivery failures.
/// * **IPv6: set `IPV6_V6ONLY`.** The dual-stack default for a
///   wildcard IPv6 bind is platform-dependent (Linux honours the
///   `net.ipv6.bindv6only` sysctl, BSD/Windows default to
///   v6-only, macOS varies). Forcing it on means
///   `listen_udp(v4_addr).listen_udp(v6_addr)` is two clean
///   single-family listeners on every platform, with no implicit
///   `::ffff:0.0.0.0/96` reception on the IPv6 socket.
///
/// All other knobs (`SO_RCVBUF`, `SO_BINDTODEVICE`,
/// `SO_REUSEPORT`, …) stay at kernel defaults; we'll add explicit
/// builder hooks if and when consumers ask for them.
fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;

    if matches!(addr, SocketAddr::V6(_)) {
        // Match FreeRADIUS: never accept v4-mapped traffic on a
        // socket the operator asked to bind as IPv6.
        sock.set_only_v6(true)?;
    }
    if matches!(addr, SocketAddr::V4(_)) {
        // socket2 doesn't expose IP_MTU_DISCOVER / IP_DONTFRAG, so
        // we drop into raw `setsockopt`. Best-effort: silently
        // tolerate platforms where neither name resolves.
        set_v4_dontfrag(&sock);
    }

    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Disable Path MTU Discovery / clear the DF bit on outgoing IPv4
/// datagrams. Mirrors FreeRADIUS's behaviour in `listen_bind`
/// (`src/main/listen.c`). Best-effort: any failure is logged via
/// `tracing` (when enabled) and otherwise silently ignored — the
/// listener still functions, just with the kernel's PMTUD policy.
#[cfg(unix)]
#[allow(unused_variables)]
fn set_v4_dontfrag(sock: &socket2::Socket) {
    use std::os::fd::AsRawFd;

    // Linux / Android: IP_MTU_DISCOVER = IP_PMTUDISC_DONT.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // c_int is 4 bytes on every platform we support; the
        // `as` cast here cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        const OPTLEN: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        // SAFETY: fd is a valid open IPv4 UDP socket; `&val` is a
        // 4-byte readable buffer with the matching `optlen`.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                std::ptr::addr_of!(val).cast(),
                OPTLEN,
            )
        };
        if rc != 0 {
            warn_!(
                event = "udp_bind_pmtud_failed",
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            );
        }
    }

    // BSD / macOS: IP_DONTFRAG = 0.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
    ))]
    {
        // `IP_DONTFRAG` isn't in every libc target's constants
        // table, so hard-code the BSD value (67). Matches FR's
        // `IP_DONTFRAG` use in src/main/listen.c.
        const IP_DONTFRAG: libc::c_int = 67;
        // c_int is 4 bytes on every platform we support; the
        // `as` cast here cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        const OPTLEN: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let val: libc::c_int = 0;
        // SAFETY: see Linux branch.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_DONTFRAG,
                std::ptr::addr_of!(val).cast(),
                OPTLEN,
            )
        };
        if rc != 0 {
            warn_!(
                event = "udp_bind_pmtud_failed",
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            );
        }
    }
}

#[cfg(not(unix))]
fn set_v4_dontfrag(_sock: &socket2::Socket) {
    // Windows / WASI: no equivalent in this crate's supported
    // matrix today. Reserved for a future contributor.
}

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
    radsec_binds: Vec<(SocketAddr, TlsContext)>,
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
            let socket = bind_udp(*addr)?;
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
        for (addr, ctx) in &self.radsec_binds {
            let listener = TcpListener::bind(addr).await?;
            info!(event = "radsec_bind", %addr);
            tasks.spawn(serve_radsec(
                listener,
                ctx.clone(),
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
    radsec_binds: Vec<(SocketAddr, TlsContext)>,
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
    /// connection accepted on that address.
    ///
    /// The pipeline is the same for every listener:
    ///
    /// 1. After `accept()`, the source address is passed to
    ///    [`ClientStore::admit_radsec`] — a cheap pre-handshake
    ///    `DoS` gate. Default `false` (deny all): consumers must
    ///    override this method (typically with a CIDR allow-list
    ///    or per-IP rate limit) before any peer can connect.
    ///    [`StaticClients`] provides an override that admits any
    ///    source IP matching a configured CIDR entry.
    /// 2. mTLS handshake against the listener-wide trust store from
    ///    [`TlsContext::server`].
    /// 3. The peer's leaf certificate (and source address) is
    ///    passed to [`ClientStore::lookup_radsec_by_cert`] for
    ///    final authorization. Returning `None` tears the
    ///    connection down.
    ///
    /// May be called multiple times to bind several addresses
    /// (dual-stack, multiple ports). Only available with the
    /// `radsec` cargo feature.
    ///
    /// [`ClientStore::admit_radsec`]:
    ///     super::store::ClientStore::admit_radsec
    /// [`ClientStore::lookup_radsec_by_cert`]:
    ///     super::store::ClientStore::lookup_radsec_by_cert
    /// [`StaticClients`]: super::store::StaticClients
    #[cfg(feature = "radsec")]
    #[must_use]
    pub fn listen_radsec(mut self, addr: SocketAddr, tls: TlsContext) -> Self {
        self.radsec_binds.push((addr, tls));
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
