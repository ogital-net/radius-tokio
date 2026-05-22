//! RadSec / RADIUS-over-TLS (RFC 6614) transport.
//!
//! # Pipeline
//!
//! ```text
//!   accept(TCP) ─▶ admit_radsec(src):bool ─▶ spawn ─▶ TLS handshake
//!                       │ false: drop                    │ fail: drop
//!                       ▼                                ▼
//!                  no spawn, no TLS                  no further work
//!                                                        │
//!                                                        ▼
//!                                          lookup_radsec_by_cert(src, peer)
//!                                                │ None: shutdown + drop
//!                                                ▼
//!                                            frame loop
//! ```
//!
//! Each accepted connection is gated on the accept loop's task
//! (no spawn for denied peers). Once admitted, a per-connection
//! task:
//!
//! 1. Runs a server-side mTLS handshake using the listener-wide
//!    [`TlsContext`]. libssl performs chain validation; a failure
//!    closes the connection.
//! 2. Maps the peer's leaf certificate to a registered [`Client`]
//!    via [`ClientStore::lookup_radsec_by_cert`]. The store may
//!    consult either the cert (Subject / SAN / SPKI) or the source
//!    address, or both — `radsecproxy`'s `verifyconfcert` policy.
//! 3. Loops reading whole RADIUS frames out of the TLS stream and
//!    dispatching them through the same authenticator-validation +
//!    dedup + handler pipeline as UDP. The reply is sealed and
//!    written back over the same TLS session.
//!
//! [`ClientStore::admit_radsec`] is awaited inline on the accept
//! loop so that a denied peer costs no more than the `accept()`
//! plus the store lookup — no spawn, no `TcpStream` handed off,
//! no per-task buffer. Implementations are expected to keep the
//! check cheap (CIDR match, in-memory rate limiter); a slow
//! backend should front itself with `CachedStore` or do its own
//! work asynchronously.
//!
//! [`ClientStore::admit_radsec`]:
//!     super::store::ClientStore::admit_radsec
//! [`ClientStore::lookup_radsec_by_cert`]:
//!     super::store::ClientStore::lookup_radsec_by_cert
//!
//! # Framing
//!
//! RFC 6614 §2.6.4: "The RADIUS over TLS connection MUST carry
//! RADIUS messages serialized as defined in [RFC 2865]". There is
//! no extra framing — the standard 20-byte header's `length` field
//! carries the total wire length, so the reader peeks the first
//! 4 bytes, decodes the length, and consumes exactly that many.
//!
//! # Concurrency
//!
//! Slice 2 is **sequential per connection**: read one packet,
//! dispatch, write reply, read next. Pipelining multiple in-flight
//! requests on a single connection is a future enhancement; the
//! UDP transport already covers the high-fan-out workload, and
//! NAS devices typically open one RadSec connection per device.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};

use crate::codec::header::{MAX_PACKET_LEN, MIN_PACKET_LEN};
#[cfg(feature = "metrics")]
use crate::obs::metrics;
use crate::tls::{HandshakeState, TlsConnection, TlsContext, TlsError};

use super::client::{Client, ClientId};
use super::dedup::DedupCache;
use super::handler::Handler;
use super::pipeline::{self, Dispatched, Validated};
use super::store::ClientStore;

/// How long a connection-level read may stall before we treat it
/// as dead and tear the TLS session down.
///
/// RadSec connections are expected to be long-lived (a NAS may keep
/// one open for the life of the device); but if no application data
/// arrives for this long we close the connection so the server
/// doesn't accumulate idle TLS state. Tunable later via the
/// builder.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Max ciphertext we'll buffer per `read` syscall. One TLS record
/// is at most ~16 KiB, so this comfortably handles a single record
/// per call without round-tripping.
const TLS_READ_CHUNK: usize = 16 * 1024;

/// How often the connection driver requests a TLS 1.3 traffic-key
/// update on a long-running session (RFC 8446 §4.6.3). Matches
/// `radsecproxy`'s `RSP_TLS_REKEY_INTERVAL`. No-op below TLS 1.3.
const TLS_KEY_UPDATE_INTERVAL: Duration = Duration::from_secs(3600);

/// TCP keepalive parameters applied to every accepted RadSec
/// socket. Mirrors `radsecproxy`'s `enable_keepalive` (`util.c`):
/// after [`KEEPALIVE_IDLE`] of silence the kernel emits probes,
/// repeating every [`KEEPALIVE_INTERVAL`] up to [`KEEPALIVE_RETRIES`]
/// times before declaring the connection dead. Without this the
/// server happily holds a half-open TCP socket forever when a NAS
/// or NAT box drops the path silently — `read_exact_or_eof`'s
/// idle timer only fires while *new* data is expected.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 3;

/// Apply [`KEEPALIVE_IDLE`] / [`KEEPALIVE_INTERVAL`] /
/// [`KEEPALIVE_RETRIES`] to `stream`. Errors are logged but not
/// propagated: keepalive is a hardening / liveness aid, not a
/// correctness requirement, and a kernel that refuses an option is
/// no reason to drop the connection.
fn apply_keepalive(stream: &TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    // `with_retries` is gated to platforms that expose `TCP_KEEPCNT`
    // (Linux, the BSDs, macOS, …); skip it on the rare platform
    // that doesn't and let the kernel use its default probe count.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "fuchsia",
    ))]
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "fuchsia",
    )))]
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    if let Err(_e) = SockRef::from(stream).set_tcp_keepalive(&ka) {
        #[allow(clippy::used_underscore_binding)]
        {
            warn!(event = "radsec_keepalive_failed", error = ?_e);
        }
    }
}

/// Tracks every active RadSec connection so the server can close
/// them (e.g. on client revocation) without waiting for the peer to
/// disconnect.
///
/// Linear-scan over an in-process `HashMap` is fine: NAS counts are
/// bounded by deployment fan-in, and the map is only mutated on
/// connection accept / drop / revocation. Lookups are not on the
/// hot path.
#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    inner: Mutex<HashMap<u64, ConnEntry>>,
    next: AtomicU64,
}

impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let active = self
            .inner
            .lock()
            .expect("ConnectionRegistry mutex poisoned")
            .len();
        f.debug_struct("ConnectionRegistry")
            .field("active", &active)
            .finish_non_exhaustive()
    }
}

struct ConnEntry {
    client_id: ClientId,
    closer: oneshot::Sender<()>,
}

/// RAII guard returned by [`ConnectionRegistry::register`]. Removes
/// the connection's entry on drop so a normally-exiting task does
/// not leak its slot in the registry.
struct ConnGuard {
    registry: Arc<ConnectionRegistry>,
    conn_id: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut map = self
            .registry
            .inner
            .lock()
            .expect("ConnectionRegistry mutex poisoned");
        map.remove(&self.conn_id);
        #[cfg(feature = "metrics")]
        {
            #[allow(clippy::cast_precision_loss)]
            let len = map.len() as f64;
            gauge!(metrics::RADSEC_ACTIVE_CONNECTIONS, len);
        }
    }
}

impl ConnectionRegistry {
    /// Register a freshly-authorized connection. The returned
    /// receiver fires when [`Self::close_for`] targets this
    /// connection's client_id.
    fn register(self: &Arc<Self>, client_id: ClientId) -> (ConnGuard, oneshot::Receiver<()>) {
        let conn_id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self
                .inner
                .lock()
                .expect("ConnectionRegistry mutex poisoned");
            map.insert(
                conn_id,
                ConnEntry {
                    client_id,
                    closer: tx,
                },
            );
            #[cfg(feature = "metrics")]
            {
                #[allow(clippy::cast_precision_loss)]
                let len = map.len() as f64;
                gauge!(metrics::RADSEC_ACTIVE_CONNECTIONS, len);
            }
        }
        (
            ConnGuard {
                registry: Arc::clone(self),
                conn_id,
            },
            rx,
        )
    }

    /// Signal every active connection bound to `client_id` to drain
    /// and exit. Returns the number of connections matched.
    pub(crate) fn close_for(&self, client_id: ClientId) -> usize {
        let taken: Vec<ConnEntry> = {
            let mut guard = self
                .inner
                .lock()
                .expect("ConnectionRegistry mutex poisoned");
            let mut keep = HashMap::new();
            let mut taken = Vec::new();
            for (cid, entry) in guard.drain() {
                if entry.client_id == client_id {
                    taken.push(entry);
                } else {
                    keep.insert(cid, entry);
                }
            }
            *guard = keep;
            #[cfg(feature = "metrics")]
            {
                #[allow(clippy::cast_precision_loss)]
                let len = guard.len() as f64;
                gauge!(metrics::RADSEC_ACTIVE_CONNECTIONS, len);
            }
            taken
        };
        let n = taken.len();
        for entry in taken {
            // Receiver may have already been dropped if the task
            // exited concurrently; ignore the error.
            let _ = entry.closer.send(());
        }
        n
    }
}

/// Run the TCP accept loop on `listener` until `shutdown` flips to
/// `true`. Owned by [`Server::run`](super::Server::run).
#[allow(clippy::too_many_arguments, clippy::used_underscore_binding)]
pub(crate) async fn serve_radsec<S, H>(
    listener: TcpListener,
    tls_ctx: TlsContext,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    registry: Arc<ConnectionRegistry>,
    role: super::status::ListenerRole,
    status_policy: Arc<super::status::StatusServerPolicy>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()>
where
    S: ClientStore,
    H: Handler,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            res = listener.accept() => {
                let (stream, peer) = res?;
                // Pre-handshake DoS gate. Run *before* we touch
                // the socket further or spawn a task: a denied
                // peer must cost no more than the accept() and
                // a `ClientStore` lookup. Pushing this past the
                // spawn would let a SYN-flood balloon Tokio's
                // task table even for an explicit-deny policy.
                //
                // The await briefly serializes the accept loop;
                // implementations are expected to keep `admit_radsec`
                // cheap (CIDR check, in-memory rate limiter). A
                // store with an inherently slow admission policy
                // should front it with `CachedStore` or spawn its
                // own work internally.
                if !store.admit_radsec(peer).await {
                    debug!(event = "radsec_admit_reject", %peer);
                    count!(metrics::RADSEC_ADMIT_REJECTS);
                    drop(stream);
                    continue;
                }
                // Disable Nagle: RADIUS replies are small and
                // request/response is naturally serialized, so any
                // coalescing buys nothing and just adds latency.
                let _ = stream.set_nodelay(true);
                // Enable TCP keepalive so half-open connections
                // (NAT timeout, NAS power-cycle, …) get reaped
                // by the kernel instead of squatting forever.
                apply_keepalive(&stream);
                let store = Arc::clone(&store);
                let handler = Arc::clone(&handler);
                let cache = Arc::clone(&cache);
                let registry = Arc::clone(&registry);
                let tls_ctx = tls_ctx.clone();
                let status_policy = Arc::clone(&status_policy);
                tokio::spawn(async move {
                    if let Err(_e) = handle_connection(
                        stream, peer, tls_ctx, store, handler, cache, registry,
                        role, status_policy,
                    ).await {
                        warn!(event = "radsec_connection_error", %peer, error = ?_e);
                    }
                });
            }
        }
    }
}

/// Per-connection driver: handshake → frame loop. Admission has
/// already been gated by [`serve_radsec`] before this task is
/// spawned.
#[allow(clippy::too_many_arguments, clippy::used_underscore_binding)]
async fn handle_connection<S, H>(
    stream: TcpStream,
    peer: SocketAddr,
    tls_ctx: TlsContext,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    registry: Arc<ConnectionRegistry>,
    role: super::status::ListenerRole,
    status_policy: Arc<super::status::StatusServerPolicy>,
) -> io::Result<()>
where
    S: ClientStore,
    H: Handler,
{
    // Step 2: server-side mTLS handshake against the listener-wide
    // trust store from `TlsContext::server`.
    // Capture the local address before the TLS wrapper takes
    // ownership of the `TcpStream`. Falls back to the unspecified
    // address if the kernel can't tell us (shouldn't happen on a
    // freshly-accepted connection, but a fallback keeps the
    // pipeline infallible).
    let local = stream.local_addr().unwrap_or_else(|_| match peer {
        SocketAddr::V4(_) => SocketAddr::from(([0u8; 4], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    });
    let tls = TlsConnection::accept(&tls_ctx).map_err(tls_to_io)?;
    let mut conn = AsyncTls::new(stream, tls);
    if let Err(_e) = conn.handshake().await {
        warn!(event = "radsec_handshake_failed", %peer, error = ?_e);
        count!(metrics::RADSEC_HANDSHAKE_FAILURES);
        return Ok(());
    }

    // Step 3: post-handshake authorization. Map the peer's leaf
    // cert (and source IP) to a registered client. An unknown
    // chain (one that libssl accepted but the consumer's store
    // doesn't recognize) tears the connection down before any
    // RADIUS frames are exchanged.
    let Some(peer_cert) = conn.peer_certificate() else {
        // mTLS is mandatory in TlsContext::server; absence here
        // would mean libssl let a no-cert client through, which
        // it shouldn't. Defensive close.
        warn!(event = "radsec_cert_missing", %peer);
        count!(metrics::RADSEC_CERT_LOOKUP_FAILURES, "reason" => "missing");
        let _ = conn.shutdown_clean().await;
        return Ok(());
    };
    let Some(client) = store.lookup_radsec_by_cert(peer, &peer_cert).await else {
        warn!(
            event = "radsec_cert_lookup_reject",
            %peer,
            subject = %peer_cert.subject_display(),
        );
        count!(
            metrics::RADSEC_CERT_LOOKUP_FAILURES,
            "reason" => "unknown_cert",
        );
        let _ = conn.shutdown_clean().await;
        return Ok(());
    };

    info!(event = "radsec_connected", %peer, client = ?client.id());
    count!(metrics::RADSEC_CONNECTIONS);

    // Register with the connection registry so a revocation can
    // tear the connection down. The guard removes the entry on
    // task exit.
    let (_guard, close_rx) = registry.register(client.id());

    // Step 4: per-frame loop. Routed through a helper so every
    // exit path lands at the graceful-shutdown block below.
    let loop_result = run_frame_loop(
        &mut conn,
        peer,
        local,
        &client,
        handler.as_ref(),
        cache.as_ref(),
        role,
        status_policy.as_ref(),
        close_rx,
    )
    .await;

    // Step 5: best-effort graceful close. Send `close_notify` and
    // flush any produced ciphertext so the peer logs a clean
    // shutdown rather than a truncation. We deliberately don't
    // wait for the peer's reciprocal close_notify — the upper
    // layer is already done and a misbehaving peer must not be
    // allowed to delay teardown.
    let _ = conn.shutdown_clean().await;
    loop_result
}

/// Per-frame read/dispatch/write loop. Returns when the peer
/// closes, the connection is revoked, the idle timer fires, or a
/// dispatch decision (bad authenticator, malformed framing) demands
/// a teardown.
#[allow(clippy::used_underscore_binding, clippy::too_many_arguments)]
async fn run_frame_loop<H: Handler>(
    conn: &mut AsyncTls,
    peer: SocketAddr,
    local: SocketAddr,
    client: &Arc<Client>,
    handler: &H,
    cache: &DedupCache,
    role: super::status::ListenerRole,
    status_policy: &super::status::StatusServerPolicy,
    mut close_rx: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut frame = vec![0u8; MAX_PACKET_LEN];
    let mut last_key_update = std::time::Instant::now();
    loop {
        // Long-running TLS 1.3 sessions get a periodic traffic-key
        // update (RFC 8446 §4.6.3). No-op below TLS 1.3 and when
        // an update is already in flight, so the check is cheap
        // even for short-lived connections.
        if last_key_update.elapsed() >= TLS_KEY_UPDATE_INTERVAL {
            match conn.tls.request_key_update() {
                Ok(true) => {
                    debug!(
                        event = "radsec_key_update",
                        %peer,
                        client = ?client.id(),
                    );
                    count!(metrics::RADSEC_KEY_UPDATES);
                }
                Ok(false) => {}
                Err(_e) => {
                    warn!(
                        event = "radsec_key_update_failed",
                        %peer,
                        error = ?_e,
                    );
                }
            }
            last_key_update = std::time::Instant::now();
        }

        tokio::select! {
            biased;
            _ = &mut close_rx => {
                debug!(event = "radsec_revoked", %peer, client = ?client.id());
                count!(metrics::RADSEC_REVOCATIONS_APPLIED);
                return Ok(());
            }
            res = read_frame(conn, &mut frame) => {
                let len = match res {
                    Ok(Some(n)) => n,
                    Ok(None) => {
                        debug!(event = "radsec_closed", %peer);
                        return Ok(());
                    }
                    Err(_e) => {
                        warn!(event = "radsec_read_error", %peer, error = ?_e);
                        return Ok(());
                    }
                };
                if let Err(_e) = process_frame(
                    conn,
                    &frame[..len],
                    peer,
                    local,
                    client,
                    handler,
                    cache,
                    role,
                    status_policy,
                )
                .await
                {
                    warn!(event = "radsec_dispatch_error", %peer, error = ?_e);
                    return Ok(());
                }
            }
        }
    }
}

/// Read exactly one RADIUS frame off the TLS stream into `out`,
/// returning its length. `Ok(None)` means the peer closed cleanly
/// before any new frame began.
async fn read_frame(conn: &mut AsyncTls, out: &mut [u8]) -> io::Result<Option<usize>> {
    debug_assert!(out.len() >= MAX_PACKET_LEN);

    // First read the 4-byte header prefix to learn the total length.
    match conn.read_exact_or_eof(&mut out[..4]).await? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Filled => {}
    }
    let length = u16::from_be_bytes([out[2], out[3]]) as usize;
    if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("radsec: invalid frame length {length}"),
        ));
    }
    // Read the rest.
    match conn.read_exact_or_eof(&mut out[4..length]).await? {
        ReadOutcome::Eof => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "radsec: peer closed mid-frame",
        )),
        ReadOutcome::Filled => Ok(Some(length)),
    }
}

/// Validate and dispatch one RADIUS frame, then write the sealed
/// reply (if any) back over the TLS session.
#[allow(clippy::used_underscore_binding, clippy::too_many_arguments)]
async fn process_frame<H: Handler>(
    conn: &mut AsyncTls,
    datagram: &[u8],
    peer: SocketAddr,
    local: SocketAddr,
    client: &Arc<Client>,
    handler: &H,
    cache: &DedupCache,
    role: super::status::ListenerRole,
    status_policy: &super::status::StatusServerPolicy,
) -> io::Result<()> {
    // Steps 1–3: transport-agnostic header + authenticator
    // validation. Inside an authenticated TLS session, any
    // validation failure is a teardown condition rather than a
    // drop-and-continue: matches `radsecproxy`'s `tlsserverrd`
    // policy. (UDP, by contrast, legitimately drops the offending
    // datagram.)
    let (header, attrs) = match pipeline::validate(datagram, client) {
        Validated::Ok { header, attrs } => (header, attrs),
        Validated::MalformedHeader(_e) => {
            warn!(
                event = "radsec_drop",
                reason = "malformed_header",
                %peer,
                client = ?client.id(),
                error = %_e,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "malformed_header");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header",
            ));
        }
        Validated::BadRequestAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "radsec_drop",
                reason = "bad_request_authenticator",
                %peer,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "bad_request_authenticator");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad request authenticator",
            ));
        }
        Validated::MissingMessageAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "radsec_drop",
                reason = "missing_message_authenticator",
                %peer,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "missing_message_authenticator"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing message authenticator",
            ));
        }
        Validated::BadMessageAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "radsec_drop",
                reason = "bad_message_authenticator",
                %peer,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "bad_message_authenticator");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad message authenticator",
            ));
        }
    };

    debug!(
        event = "radsec_request",
        %peer,
        client = ?client.id(),
        code = header.code.0,
        id = header.identifier,
        len = datagram.len(),
    );
    count!(metrics::REQUESTS_DISPATCHED, "code" => header.code.0.to_string());

    // Steps 4–5: dedup-aware dispatch. Cache hit replays the
    // previously-sent reply; cache miss either short-circuits a
    // Status-Server probe through the configured policy or runs
    // the handler, seals, caches, and returns the sealed bytes.
    let outcome = pipeline::dispatch_validated(
        header,
        attrs,
        peer,
        local,
        client,
        handler,
        cache,
        Some(pipeline::StatusServerContext {
            role,
            transport: super::status::StatusTransport::Radsec,
            policy: status_policy,
        }),
    )
    .await;

    match outcome {
        Dispatched::Replay {
            bytes,
            code: _code,
            identifier: _identifier,
        } => {
            debug!(
                event = "radsec_dedup_hit",
                %peer,
                client = ?client.id(),
                id = _identifier,
                reply_len = bytes.len(),
            );
            count!(metrics::DEDUP_HITS);
            conn.write_all(&bytes).await?;
            Ok(())
        }
        Dispatched::Reply {
            sealed,
            code: _code,
            identifier: _identifier,
        } => {
            let bytes = sealed.as_bytes();
            let _reply_code = bytes.first().copied().unwrap_or(0);
            match conn.write_all(bytes).await {
                Ok(()) => {
                    debug!(
                        event = "radsec_reply_sent",
                        code = _code.0,
                        reply_code = _reply_code,
                        id = _identifier,
                        len = bytes.len(),
                    );
                    count!(metrics::REPLIES_SENT, "code" => _reply_code.to_string());
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        event = "radsec_reply_send_error",
                        code = _code.0,
                        id = _identifier,
                        error = %e,
                    );
                    count!(metrics::SEND_ERRORS);
                    Err(e)
                }
            }
        }
        Dispatched::HandlerDrop {
            code: _code,
            identifier: _identifier,
        } => {
            debug!(event = "handler_drop", code = _code.0, id = _identifier,);
            count!(metrics::PACKETS_DROPPED, "reason" => "handler_drop");
            Ok(())
        }
        Dispatched::StatusServerReply {
            sealed,
            identifier: _identifier,
            role: _role,
        } => {
            let bytes = sealed.as_bytes();
            match conn.write_all(bytes).await {
                Ok(()) => {
                    debug!(
                        event = "radsec_status_server_reply",
                        %peer,
                        client = ?client.id(),
                        id = _identifier,
                        len = bytes.len(),
                    );
                    count!(
                        metrics::STATUS_SERVER_REPLIES,
                        "transport" => "radsec",
                        "role" => match _role {
                            super::status::ListenerRole::Auth => "auth",
                            super::status::ListenerRole::Acct => "acct",
                        },
                    );
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        event = "radsec_status_server_reply_send_error",
                        %peer,
                        id = _identifier,
                        error = %e,
                    );
                    count!(metrics::SEND_ERRORS);
                    Err(e)
                }
            }
        }
        Dispatched::StatusServerDisabledPerClient {
            identifier: _identifier,
        } => {
            debug!(
                event = "radsec_drop",
                reason = "status_server_disabled_per_client",
                %peer,
                client = ?client.id(),
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "status_server_disabled_per_client",
            );
            Ok(())
        }
        Dispatched::StatusServerDisabled {
            identifier: _identifier,
        } => {
            debug!(
                event = "radsec_drop",
                reason = "status_server_disabled",
                %peer,
                client = ?client.id(),
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "status_server_disabled",
            );
            Ok(())
        }
    }
}

fn tls_to_io(e: TlsError) -> io::Error {
    io::Error::other(e)
}

// ============================================================================
// AsyncTls — async adapter over `TcpStream` + `TlsConnection`.
//
// Pumps ciphertext between the two using the memory-BIO interface
// of `TlsConnection`. Sequential by design: only one of read /
// write may be in flight at a time per connection.
// ============================================================================

struct AsyncTls {
    stream: TcpStream,
    tls: TlsConnection,
    /// Scratch buffer for ciphertext read off the TCP socket before
    /// being fed into `feed_input`. Outbound ciphertext is written
    /// directly from libssl's mem-BIO buffer via
    /// [`TlsConnection::pending_output`] — no staging buffer needed.
    in_buf: Vec<u8>,
    /// Once the peer's `read_exact` returns 0 we know no more
    /// ciphertext will arrive; subsequent attempts must surface as
    /// EOF instead of looping forever asking for more bytes.
    eof: bool,
}

enum ReadOutcome {
    Filled,
    Eof,
}

impl AsyncTls {
    fn new(stream: TcpStream, tls: TlsConnection) -> Self {
        Self {
            stream,
            tls,
            in_buf: vec![0u8; TLS_READ_CHUNK],
            eof: false,
        }
    }

    /// Borrow the peer's leaf certificate, if the handshake has
    /// completed. Used by cert-keyed authorization.
    fn peer_certificate(&self) -> Option<crate::tls::PeerCertificate> {
        self.tls.peer_certificate()
    }

    /// Drive the handshake to completion (or failure).
    async fn handshake(&mut self) -> io::Result<()> {
        let timeout = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(timeout);
        loop {
            // 1. Advance the state machine.
            let state = self.tls.process().map_err(tls_to_io)?;
            // 2. Drain any ciphertext libssl produced.
            self.flush_tls_output().await?;
            // 3. If the handshake completed, we're done.
            if matches!(state, HandshakeState::Established) {
                return Ok(());
            }
            // 4. Otherwise we need more bytes from the peer.
            tokio::select! {
                () = &mut timeout => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "radsec handshake timed out",
                    ));
                }
                res = self.stream.read(&mut self.in_buf) => {
                    let n = res?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed during handshake",
                        ));
                    }
                    self.tls.feed_input(&self.in_buf[..n]).map_err(tls_to_io)?;
                }
            }
        }
    }

    /// Read exactly `out.len()` plaintext bytes, returning
    /// [`ReadOutcome::Eof`] if the peer closed cleanly *before any
    /// bytes were read into this buffer*. A close mid-buffer is an
    /// `UnexpectedEof` error.
    async fn read_exact_or_eof(&mut self, out: &mut [u8]) -> io::Result<ReadOutcome> {
        let total = out.len();
        let mut filled = 0;
        let timeout = tokio::time::sleep(DEFAULT_IDLE_TIMEOUT);
        tokio::pin!(timeout);
        while filled < total {
            // First try to satisfy from already-buffered plaintext.
            let n = self.tls.read(&mut out[filled..]).map_err(tls_to_io)?;
            if n > 0 {
                filled += n;
                continue;
            }
            if self.eof && !self.tls.has_plaintext_pending() {
                return if filled == 0 {
                    Ok(ReadOutcome::Eof)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed mid-frame",
                    ))
                };
            }
            // Pull more ciphertext from the TCP socket.
            tokio::select! {
                () = &mut timeout => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "radsec read idle timeout",
                    ));
                }
                res = self.stream.read(&mut self.in_buf) => {
                    let nb = res?;
                    if nb == 0 {
                        self.eof = true;
                        // Loop back: SSL_read may still return
                        // buffered data even after socket EOF.
                        continue;
                    }
                    self.tls.feed_input(&self.in_buf[..nb]).map_err(tls_to_io)?;
                }
            }
        }
        Ok(ReadOutcome::Filled)
    }

    /// Encrypt `bytes` and push every produced ciphertext byte out
    /// the TCP socket before returning.
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            let n = self.tls.write(&bytes[written..]).map_err(tls_to_io)?;
            if n == 0 {
                // SSL_ERROR_WANT_READ during a write means we need
                // to drain the peer's flight first (TLS 1.3
                // re-handshake / key update). Pump the socket once
                // and retry.
                self.flush_tls_output().await?;
                let nb = self.stream.read(&mut self.in_buf).await?;
                if nb == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed during write",
                    ));
                }
                self.tls.feed_input(&self.in_buf[..nb]).map_err(tls_to_io)?;
                continue;
            }
            written += n;
            self.flush_tls_output().await?;
        }
        Ok(())
    }

    /// Drain everything libssl has queued in the output BIO down
    /// the TCP socket.
    ///
    /// Borrows the BIO's internal buffer in place
    /// ([`TlsConnection::pending_output`]) and writes it straight
    /// to the socket — no intermediate copy. After the write
    /// completes the BIO is reset so the next `process` /
    /// `SSL_write` starts from an empty buffer.
    async fn flush_tls_output(&mut self) -> io::Result<()> {
        // Split the borrow so `pending_output(&mut tls)` and
        // `stream.write_all(...)` can coexist on disjoint fields.
        let Self { stream, tls, .. } = self;
        let pending = tls.pending_output();
        if pending.is_empty() {
            return Ok(());
        }
        stream.write_all(pending).await?;
        tls.consume_output().map_err(tls_to_io)?;
        Ok(())
    }

    /// Best-effort graceful shutdown: send TLS `close_notify`,
    /// flush the resulting ciphertext, then drop. Does not wait
    /// for the peer's reciprocal close_notify — the upper layer
    /// is already done and a misbehaving peer must not be allowed
    /// to delay teardown.
    async fn shutdown_clean(&mut self) -> io::Result<()> {
        let _ = self.tls.shutdown();
        // Use a short, bounded timer so the shutdown path can't
        // hang on a wedged socket. RadSec replies are small; the
        // close_notify alert is one record.
        let _ = tokio::time::timeout(Duration::from_secs(1), self.flush_tls_output()).await;
        Ok(())
    }
}

// ============================================================================
// End-to-end integration tests
// ============================================================================
//
// Spins up a real `Server` with a `listen_radsec` bind, opens a TCP
// connection from a client, drives an mTLS handshake to completion
// using the in-tree test client (memory BIOs pumped over the wire),
// then exchanges an Access-Request / Access-Accept frame.
//
// These tests live inline (rather than in `tests/`) because the
// shared `crate::crypto::tls::test_client` is `pub(crate)` and only
// reachable from in-crate `cfg(test)` code.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::codec::message_authenticator;
    use crate::codec::PacketBuffer;
    use crate::crypto::tls::test_client::{build_pki, client_side};
    use crate::server::client::Client;
    use crate::server::handler::{HandlerResult, Request};
    use crate::server::store::{IpCidr, StaticClients};
    use crate::server::Server;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    /// Trivial handler: any Access-Request → Access-Accept.
    struct AcceptAll;
    impl Handler for AcceptAll {
        async fn handle(&self, request: Request<'_>) -> HandlerResult {
            HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
        }
    }

    fn build_access_request(identifier: u8, secret: &[u8]) -> ([u8; 16], Vec<u8>) {
        let req_auth = crate::codec::authenticator::random_request_authenticator();
        let mut pkt = vec![Code::ACCESS_REQUEST.0, identifier, 0, 0];
        pkt.extend_from_slice(&req_auth);
        // User-Name = "alice"
        pkt.extend_from_slice(&[1, 7, b'a', b'l', b'i', b'c', b'e']);
        let len = u16::try_from(pkt.len()).unwrap();
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        let mut buf = PacketBuffer::from_bytes(&pkt).unwrap();
        let value_off = message_authenticator::append_zeroed_slot(&mut buf).unwrap();
        buf.patch_length();
        let tag = message_authenticator::compute(buf.as_bytes(), &req_auth, secret);
        message_authenticator::patch(&mut buf, value_off, &tag);
        (req_auth, buf.as_bytes().to_vec())
    }

    /// Drive handshake + send/recv on a TCP-attached client SSL.
    /// Pumps ciphertext between the test client's memory BIOs and
    /// the live tokio TCP stream until either:
    /// * the requested operation finishes, or
    /// * the budget runs out (test failure).
    struct ClientPump {
        stream: tokio::net::TcpStream,
        ssl: client_side::ClientSsl,
        buf: Vec<u8>,
    }

    impl ClientPump {
        fn new(stream: tokio::net::TcpStream, ssl: client_side::ClientSsl) -> Self {
            Self {
                stream,
                ssl,
                buf: vec![0u8; 16 * 1024],
            }
        }

        async fn flush_out(&mut self) -> io::Result<()> {
            loop {
                let n = self
                    .ssl
                    .take_output(&mut self.buf)
                    .map_err(super::tls_to_io)?;
                if n == 0 {
                    return Ok(());
                }
                self.stream.write_all(&self.buf[..n]).await?;
            }
        }

        async fn pump_in(&mut self) -> io::Result<()> {
            let n = self.stream.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
            }
            self.ssl
                .feed_input(&self.buf[..n])
                .map_err(super::tls_to_io)?;
            Ok(())
        }

        async fn handshake(&mut self) -> io::Result<()> {
            for _ in 0..32 {
                let s = self.ssl.process().map_err(super::tls_to_io)?;
                self.flush_out().await?;
                if matches!(s, super::HandshakeState::Established) {
                    return Ok(());
                }
                self.pump_in().await?;
            }
            Err(io::Error::other("client handshake budget exceeded"))
        }

        async fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
            while !bytes.is_empty() {
                let n = self.ssl.write(bytes).map_err(super::tls_to_io)?;
                if n == 0 {
                    self.flush_out().await?;
                    self.pump_in().await?;
                    continue;
                }
                bytes = &bytes[n..];
                self.flush_out().await?;
            }
            Ok(())
        }

        async fn read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
            let mut filled = 0;
            while filled < out.len() {
                let n = self
                    .ssl
                    .read(&mut out[filled..])
                    .map_err(super::tls_to_io)?;
                if n == 0 {
                    self.pump_in().await?;
                    continue;
                }
                filled += n;
            }
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn radsec_end_to_end_access_accept() {
        let pki = build_pki();
        let secret = b"shared-secret".to_vec();
        let client_record = Arc::new(Client::new(secret.as_slice()));

        // Reserve a free port by briefly binding, then dropping
        // before the server claims it. There is a tiny race window
        // here but it's accepted for an in-process test (the
        // alternative is wiring a oneshot for "bound address" out
        // of `Server::run`, which is a public-API expansion best
        // landed separately).
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server_ctx =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let store = StaticClients::builder()
            .add(
                IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                Arc::clone(&client_record),
            )
            .build();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec(addr, server_ctx)
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();
        let server_task = tokio::spawn(server.run());

        // Give the listener a moment to bind.
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        // Connect.
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki.ca_pem)
            .unwrap()
            .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        pump.handshake().await.expect("client handshake");

        // Send Access-Request.
        let (_req_auth, frame) = build_access_request(7, &secret);
        pump.write_all(&frame).await.expect("write request");

        // Read reply: header first, then body.
        let mut hdr = [0u8; 4];
        pump.read_exact(&mut hdr).await.expect("read header");
        assert_eq!(hdr[0], Code::ACCESS_ACCEPT.0, "expected Access-Accept");
        assert_eq!(hdr[1], 7, "identifier echo");
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        assert!((20..=4096).contains(&len));
        let mut body = vec![0u8; len - 4];
        pump.read_exact(&mut body).await.expect("read body");

        shutdown.shutdown();
        let _ = tokio::time::timeout(StdDuration::from_secs(2), server_task).await;
    }

    // -----------------------------------------------------------
    // Cert-keyed mode: post-handshake authorization via a custom
    // ClientStore that maps the leaf cert's identifier to a Client.
    // -----------------------------------------------------------

    /// Cert-keyed `ClientStore` for tests: a flat list of
    /// `(hostname -> Client)` pairs. Returns `None` from
    /// `lookup_udp`, admits every `RadSec` peer, and runs a
    /// proper RFC 6125 hostname match (SAN dNSName preferred,
    /// CN fallback allowed) via [`PeerCertificate::matches_hostname`].
    struct CertKeyedStore {
        entries: Vec<(String, Arc<Client>)>,
    }

    impl crate::server::store::ClientStore for CertKeyedStore {
        #[allow(clippy::manual_async_fn)]
        fn lookup_udp(
            &self,
            _src: SocketAddr,
        ) -> impl std::future::Future<Output = Option<Arc<Client>>> + Send {
            async { None }
        }

        // The library's default `admit_radsec` denies every peer
        // (deliberately conservative deny forces consumers to think
        // about DoS exposure). The test deals with a loopback
        // mTLS handshake against an ephemeral CA, so admitting
        // every source is fine.
        async fn admit_radsec(&self, _src: SocketAddr) -> bool {
            true
        }

        fn lookup_radsec_by_cert(
            &self,
            _src: SocketAddr,
            peer: &crate::tls::PeerCertificate,
        ) -> impl std::future::Future<Output = Option<Arc<Client>>> + Send {
            // RFC 6125 §6.4.4: prefer SAN, fall back to CN only
            // when no SAN of the matching type exists. Our test
            // PKI's client leaves carry both CN=nas-1 and
            // SAN dNSName=nas-1, so SAN always wins; we still pass
            // `allow_common_name = true` to mirror radsecproxy's
            // `certcncheck` legacy posture.
            let hit = self
                .entries
                .iter()
                .find(|(needle, _)| peer.matches_hostname(needle, true))
                .map(|(_, c)| Arc::clone(c));
            async move { hit }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn radsec_cert_keyed_happy_path() {
        let pki = build_pki();
        let secret = b"shared-secret".to_vec();
        let client_record = Arc::new(Client::new(secret.as_slice()));
        let store = CertKeyedStore {
            entries: vec![("nas-1".to_string(), Arc::clone(&client_record))],
        };

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server_ctx =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec(addr, server_ctx)
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();
        let server_task = tokio::spawn(server.run());
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki.ca_pem)
            .unwrap()
            .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        pump.handshake().await.expect("client handshake");

        let (_req_auth, frame) = build_access_request(13, &secret);
        pump.write_all(&frame).await.expect("write request");
        let mut hdr = [0u8; 4];
        pump.read_exact(&mut hdr).await.expect("read header");
        assert_eq!(hdr[0], Code::ACCESS_ACCEPT.0);
        assert_eq!(hdr[1], 13);
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; len - 4];
        pump.read_exact(&mut body).await.expect("read body");

        shutdown.shutdown();
        let _ = tokio::time::timeout(StdDuration::from_secs(2), server_task).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn radsec_cert_keyed_rejects_unknown_cert() {
        // PKI-A's clients are valid (chain to the CA the server
        // trusts), but the store only knows the subject "nas-known".
        // A peer with subject "nas-1" presents a chain libssl will
        // happily validate, but `lookup_radsec_by_cert` returns
        // None — the connection must be torn down before any
        // RADIUS frame is processed.
        let pki = build_pki();
        let unrelated = Arc::new(Client::new(b"shared-secret".as_slice()));
        let store = CertKeyedStore {
            entries: vec![("nas-known".to_string(), Arc::clone(&unrelated))],
        };

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server_ctx =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec(addr, server_ctx)
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();
        let server_task = tokio::spawn(server.run());
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki.ca_pem)
            .unwrap()
            .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        // Handshake itself completes (libssl is happy with the
        // chain); the rejection happens at the application layer.
        let _ = pump.handshake().await;
        let (_req_auth, frame) = build_access_request(15, b"shared-secret");
        let _ = pump.write_all(&frame).await;
        let mut hdr = [0u8; 4];
        let read_res =
            tokio::time::timeout(StdDuration::from_secs(2), pump.read_exact(&mut hdr)).await;
        assert!(
            matches!(read_res, Ok(Err(_)) | Err(_)),
            "unknown-cert peer unexpectedly received a reply",
        );

        shutdown.shutdown();
        let _ = tokio::time::timeout(StdDuration::from_secs(2), server_task).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn radsec_close_connections_for_revokes() {
        // Establish a cert-keyed connection, exchange one frame to
        // confirm it's healthy, then call `close_connections_for`
        // and verify the next read EOFs (the server tore the TLS
        // session down).
        let pki = build_pki();
        let secret = b"shared-secret".to_vec();
        let client_record = Arc::new(Client::new(secret.as_slice()));
        let target_id = client_record.id();
        let store = CertKeyedStore {
            entries: vec![("nas-1".to_string(), Arc::clone(&client_record))],
        };

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server_ctx =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec(addr, server_ctx)
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();
        let revoker = server.radsec_revoker();
        let server_task = tokio::spawn(server.run());
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki.ca_pem)
            .unwrap()
            .with_client_cert(&pki.client_chain_pem, &pki.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        pump.handshake().await.expect("handshake");
        let (_req_auth, frame) = build_access_request(17, &secret);
        pump.write_all(&frame).await.expect("write");
        let mut hdr = [0u8; 4];
        pump.read_exact(&mut hdr).await.expect("read header");
        assert_eq!(hdr[0], Code::ACCESS_ACCEPT.0);
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; len - 4];
        pump.read_exact(&mut body).await.expect("read body");

        // Revoke. The connection's read loop should bail and the
        // server should drop the TLS session.
        let n = revoker.revoke(target_id);
        assert_eq!(n, 1, "expected exactly one matching connection");

        // Next read must fail (EOF or error).
        let mut hdr2 = [0u8; 4];
        let res = tokio::time::timeout(StdDuration::from_secs(2), pump.read_exact(&mut hdr2)).await;
        assert!(
            matches!(res, Ok(Err(_)) | Err(_)),
            "expected the revoked connection to close",
        );

        shutdown.shutdown();
        let _ = tokio::time::timeout(StdDuration::from_secs(2), server_task).await;
    }
}
