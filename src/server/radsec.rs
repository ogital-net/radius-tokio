//! RadSec / RADIUS-over-TLS (RFC 6614) transport.
//!
//! # Pipeline
//!
//! ```text
//!   accept(TCP) ─▶ admit_radsec(src) ─▶ TLS handshake ─▶ frame loop
//!                      │ None: drop          │ fail: drop
//!                      ▼                     ▼
//!                  no allocation         no further work
//! ```
//!
//! Each accepted connection owns one Tokio task. The task:
//!
//! 1. Calls [`ClientStore::admit_radsec`] before any TLS bytes are
//!    read. Unknown peers are dropped with no TLS state allocated.
//! 2. Runs a server-side mTLS handshake using the listener-wide
//!    [`TlsContext`]. libssl performs chain validation; a failure
//!    closes the connection.
//! 3. Loops reading whole RADIUS frames out of the TLS stream and
//!    dispatching them through the same authenticator-validation +
//!    dedup + handler pipeline as UDP. The reply is sealed and
//!    written back over the same TLS session.
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

use crate::codec::header::{Code, Header, MAX_PACKET_LEN, MIN_PACKET_LEN};
use crate::codec::message_authenticator::Verification;
use crate::codec::{authenticator, message_authenticator};
use crate::tls::{HandshakeState, TlsConnection, TlsContext, TlsError};

use super::client::{Client, ClientId};
use super::dedup::{DedupCache, Key as DedupKey};
use super::handler::{Handler, HandlerResult, Request};
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

/// Per-listener admission policy.
///
/// See the design notes in `src/crypto/tls.rs` for the rationale
/// behind the split. Briefly:
///
/// * **`CertKeyed`** — the default. Handshake runs against the
///   listener-wide trust store, then
///   [`ClientStore::lookup_radsec_by_cert`] maps the leaf
///   certificate to a [`Client`]. This is the RFC 6614 §2.5 model
///   and works for every deployment shape (including NAT'd peers,
///   RFC 7585 dynamic discovery, consortium proxies).
/// * **`IpGated`** — `ClientStore::admit_radsec(src)` is consulted
///   *before* the TLS handshake. The returned client's per-record
///   trust set narrows libssl's chain validation, so a successful
///   handshake *is* the authorization decision. A performance /
///   DoS-resistance optimization for enterprise / SP edges where
///   every NAS source IP is known up front.
///
/// [`ClientStore::lookup_radsec_by_cert`]:
///     super::store::ClientStore::lookup_radsec_by_cert
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadSecMode {
    /// Post-handshake authorization via leaf certificate lookup.
    /// The default.
    CertKeyed,
    /// Pre-handshake admission by source IP, per-connection trust
    /// narrowing.
    IpGated,
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
        self.registry
            .inner
            .lock()
            .expect("ConnectionRegistry mutex poisoned")
            .remove(&self.conn_id);
    }
}

impl ConnectionRegistry {
    /// Register a freshly-authorized connection. The returned
    /// receiver fires when [`Self::close_for`] targets this
    /// connection's client_id.
    fn register(self: &Arc<Self>, client_id: ClientId) -> (ConnGuard, oneshot::Receiver<()>) {
        let conn_id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock()
            .expect("ConnectionRegistry mutex poisoned")
            .insert(
                conn_id,
                ConnEntry {
                    client_id,
                    closer: tx,
                },
            );
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
    mode: RadSecMode,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    registry: Arc<ConnectionRegistry>,
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
                // Disable Nagle: RADIUS replies are small and
                // request/response is naturally serialized, so any
                // coalescing buys nothing and just adds latency.
                let _ = stream.set_nodelay(true);
                let store = Arc::clone(&store);
                let handler = Arc::clone(&handler);
                let cache = Arc::clone(&cache);
                let registry = Arc::clone(&registry);
                let tls_ctx = tls_ctx.clone();
                tokio::spawn(async move {
                    if let Err(_e) = handle_connection(
                        stream, peer, tls_ctx, mode, store, handler, cache, registry,
                    ).await {
                        warn_!(event = "radsec_connection_error", %peer, error = ?_e);
                    }
                });
            }
        }
    }
}

/// Per-connection driver: admission → handshake → frame loop.
#[allow(clippy::too_many_arguments, clippy::used_underscore_binding)]
async fn handle_connection<S, H>(
    stream: TcpStream,
    peer: SocketAddr,
    tls_ctx: TlsContext,
    mode: RadSecMode,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    registry: Arc<ConnectionRegistry>,
) -> io::Result<()>
where
    S: ClientStore,
    H: Handler,
{
    // Step 1: in IP-gated mode, run pre-handshake admission. No
    // TLS state is allocated yet, so unknown peers cost us nothing
    // beyond the accept(). In cert-keyed mode the source IP isn't
    // the identity, so we skip this step and authorize after the
    // handshake (Step 3 below).
    let pre_client = match mode {
        RadSecMode::IpGated => {
            let Some(c) = store.admit_radsec(peer).await else {
                debug!(event = "radsec_admit_reject", %peer);
                count!("radius_tokio.radsec_admit_rejects");
                return Ok(());
            };
            Some(c)
        }
        RadSecMode::CertKeyed => None,
    };

    // Step 2: build TLS state. In IP-gated mode, narrow chain
    // validation to the admitted client's CA so libssl's check IS
    // the authorization. In cert-keyed mode, the listener-wide
    // trust store from `TlsContext::server` applies.
    let mut tls = TlsConnection::accept(&tls_ctx).map_err(tls_to_io)?;
    if let Some(client) = pre_client.as_ref() {
        if let Some(trust) = client.radsec_trust() {
            tls.set_client_trust(trust).map_err(tls_to_io)?;
        }
    }
    let mut conn = AsyncTls::new(stream, tls);
    if let Err(_e) = conn.handshake().await {
        warn_!(event = "radsec_handshake_failed", %peer, error = ?_e);
        count!("radius_tokio.radsec_handshake_failures");
        return Ok(());
    }

    // Step 3: in cert-keyed mode, run post-handshake authorization
    // by mapping the peer's leaf cert to a registered client. An
    // unknown chain (one that libssl accepted but the consumer's
    // store doesn't recognize) tears the connection down before
    // any RADIUS frames are exchanged.
    let client = match (pre_client, mode) {
        (Some(c), _) => c,
        (None, RadSecMode::CertKeyed) => {
            let Some(peer_cert) = conn.peer_certificate() else {
                // mTLS is mandatory in TlsContext::server; absence
                // here would mean libssl let a no-cert client
                // through, which it shouldn't. Defensive close.
                warn_!(event = "radsec_cert_missing", %peer);
                count!("radius_tokio.radsec_cert_lookup_failures", "reason" => "missing");
                return Ok(());
            };
            if let Some(c) = store.lookup_radsec_by_cert(&peer_cert).await {
                c
            } else {
                warn_!(
                    event = "radsec_cert_lookup_reject",
                    %peer,
                    subject = %peer_cert.subject(),
                );
                count!(
                    "radius_tokio.radsec_cert_lookup_failures",
                    "reason" => "unknown_cert",
                );
                return Ok(());
            }
        }
        (None, RadSecMode::IpGated) => {
            // Unreachable: pre_client is always Some in IP-gated.
            return Ok(());
        }
    };

    info!(event = "radsec_connected", %peer, client = ?client.id(), mode = ?mode);
    count!("radius_tokio.radsec_connections");

    // Register with the connection registry so a revocation can
    // tear the connection down. The guard removes the entry on
    // task exit.
    let (_guard, mut close_rx) = registry.register(client.id());

    // Step 4: per-frame loop.
    let mut frame = vec![0u8; MAX_PACKET_LEN];
    loop {
        tokio::select! {
            biased;
            _ = &mut close_rx => {
                debug!(event = "radsec_revoked", %peer, client = ?client.id());
                count!("radius_tokio.radsec_revocations_applied");
                return Ok(());
            }
            res = read_frame(&mut conn, &mut frame) => {
                let len = match res {
                    Ok(Some(n)) => n,
                    Ok(None) => {
                        debug!(event = "radsec_closed", %peer);
                        return Ok(());
                    }
                    Err(_e) => {
                        warn_!(event = "radsec_read_error", %peer, error = ?_e);
                        return Ok(());
                    }
                };
                if let Err(_e) = process_frame(
                    &mut conn,
                    &frame[..len],
                    peer,
                    &client,
                    handler.as_ref(),
                    cache.as_ref(),
                )
                .await
                {
                    warn_!(event = "radsec_dispatch_error", %peer, error = ?_e);
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
#[allow(clippy::used_underscore_binding)]
async fn process_frame<H: Handler>(
    conn: &mut AsyncTls,
    datagram: &[u8],
    peer: SocketAddr,
    client: &Arc<Client>,
    handler: &H,
    cache: &DedupCache,
) -> io::Result<()> {
    let (header, attrs) = match Header::parse(datagram) {
        Ok(parsed) => parsed,
        Err(_e) => {
            warn_!(
                event = "radsec_drop",
                reason = "malformed_header",
                %peer,
                client = ?client.id(),
                error = %_e,
            );
            count!("radius_tokio.packets_dropped", "reason" => "malformed_header");
            // Bad framing on a TLS-protected connection means we
            // can't trust subsequent bytes; close.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header",
            ));
        }
    };

    if !validate_request_authenticator(header.code, datagram, client.secret()) {
        warn_!(
            event = "radsec_drop",
            reason = "bad_request_authenticator",
            %peer,
            client = ?client.id(),
            code = header.code.0,
            id = header.identifier,
        );
        count!("radius_tokio.packets_dropped", "reason" => "bad_request_authenticator");
        return Ok(());
    }

    let ma_substitute = match header.code {
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => [0u8; 16],
        _ => header.authenticator,
    };
    match message_authenticator::verify(datagram, &ma_substitute, client.secret()) {
        Verification::Valid | Verification::Absent => {}
        Verification::Invalid => {
            warn_!(
                event = "radsec_drop",
                reason = "bad_message_authenticator",
                %peer,
                client = ?client.id(),
                code = header.code.0,
                id = header.identifier,
            );
            count!("radius_tokio.packets_dropped", "reason" => "bad_message_authenticator");
            return Ok(());
        }
    }

    let dedup_key = DedupKey {
        src: peer,
        code: header.code.0,
        identifier: header.identifier,
        request_authenticator: header.authenticator,
    };
    if let Some(cached) = cache.lookup(&dedup_key) {
        debug!(
            event = "radsec_dedup_hit",
            %peer,
            client = ?client.id(),
            id = header.identifier,
            reply_len = cached.len(),
        );
        count!("radius_tokio.dedup_hits");
        conn.write_all(&cached).await?;
        return Ok(());
    }

    debug!(
        event = "radsec_request",
        %peer,
        client = ?client.id(),
        code = header.code.0,
        id = header.identifier,
        len = datagram.len(),
    );
    count!("radius_tokio.requests_dispatched", "code" => header.code.0.to_string());

    let request = Request::new(
        header.code,
        header.identifier,
        header.authenticator,
        attrs,
        client,
        peer,
    );

    #[cfg(feature = "metrics")]
    let handler_t0 = std::time::Instant::now();
    let result = handler.handle(request).await;
    #[cfg(feature = "metrics")]
    observe!(
        "radius_tokio.handler_duration_seconds",
        handler_t0.elapsed().as_secs_f64()
    );

    let reply = match result {
        HandlerResult::Reply(reply) => reply,
        HandlerResult::Drop => {
            debug!(
                event = "handler_drop",
                code = header.code.0,
                id = header.identifier
            );
            count!("radius_tokio.packets_dropped", "reason" => "handler_drop");
            return Ok(());
        }
    };

    let sealed = reply.seal_for(&header.authenticator, client.secret());
    let bytes = sealed.as_bytes();
    cache.insert(dedup_key, bytes);
    let _reply_code = bytes.first().copied().unwrap_or(0);
    match conn.write_all(bytes).await {
        Ok(()) => {
            debug!(
                event = "radsec_reply_sent",
                code = header.code.0,
                reply_code = _reply_code,
                id = header.identifier,
                len = bytes.len(),
            );
            count!("radius_tokio.replies_sent", "code" => _reply_code.to_string());
            Ok(())
        }
        Err(e) => {
            warn_!(
                event = "radsec_reply_send_error",
                code = header.code.0,
                id = header.identifier,
                error = %e,
            );
            count!("radius_tokio.send_errors");
            Err(e)
        }
    }
}

/// Same logic as the UDP transport — kept private here to avoid
/// reaching into a sibling module's internals.
fn validate_request_authenticator(code: Code, datagram: &[u8], secret: &[u8]) -> bool {
    match code {
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => {
            authenticator::verify_zeroed_request(datagram, secret)
        }
        _ => true,
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
    /// Scratch buffer for ciphertext shuttled out of `take_output`
    /// before being written to the TCP socket.
    out_buf: Vec<u8>,
    /// Scratch buffer for ciphertext read off the TCP socket before
    /// being fed into `feed_input`.
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
            out_buf: vec![0u8; TLS_READ_CHUNK],
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
    async fn flush_tls_output(&mut self) -> io::Result<()> {
        loop {
            let n = self.tls.take_output(&mut self.out_buf).map_err(tls_to_io)?;
            if n == 0 {
                return Ok(());
            }
            self.stream.write_all(&self.out_buf[..n]).await?;
        }
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
    use crate::server::handler::HandlerResult;
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

        let server_ctx = TlsContext::server(
            &pki.server_chain_pem,
            &pki.server_key_pem,
            Some(&pki.ca_pem),
        )
        .unwrap();
        let store = StaticClients::builder()
            .add(
                IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                Arc::clone(&client_record),
            )
            .build();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec_ip_gated(addr, server_ctx)
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

    #[tokio::test(flavor = "current_thread")]
    async fn radsec_ip_gated_rejects_other_ca_cert() {
        // IP-gated mode: the listener-wide trust covers BOTH CAs,
        // but the client record at 127.0.0.1 is narrowed to CA-A.
        // A peer presenting a CA-B-signed cert from that IP must
        // fail the handshake — the connection is dropped.
        let pki_a = crate::crypto::tls::test_client::build_pki();
        let pki_b = crate::crypto::tls::test_client::build_pki();
        let combined_ca: Vec<u8> = [pki_a.ca_pem.as_slice(), pki_b.ca_pem.as_slice()].concat();

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server_ctx = TlsContext::server(
            &pki_a.server_chain_pem,
            &pki_a.server_key_pem,
            Some(&combined_ca),
        )
        .unwrap();

        let trust_a = crate::tls::ClientTrust::from_pem(&pki_a.ca_pem).unwrap();
        let client_record =
            Arc::new(Client::new(b"shared-secret".as_slice()).with_radsec_trust(trust_a));

        let store = StaticClients::builder()
            .add(
                IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                Arc::clone(&client_record),
            )
            .build();
        let server = Server::builder()
            .clients(store)
            .handler(AcceptAll)
            .listen_radsec_ip_gated(addr, server_ctx)
            .build()
            .unwrap();
        let shutdown = server.shutdown_handle();
        let server_task = tokio::spawn(server.run());

        tokio::time::sleep(StdDuration::from_millis(50)).await;

        // Wrong-CA peer. In TLS 1.3 the client-side handshake
        // reports "established" before the server has finished
        // validating the client cert; the server's rejection
        // arrives as a post-handshake alert. So we additionally
        // try to exchange a frame and assert that fails.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki_a.ca_pem)
            .unwrap()
            .with_client_cert(&pki_b.client_chain_pem, &pki_b.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        // The handshake call may or may not return Ok depending on
        // when the server's alert reaches us; either is fine.
        let _ = pump.handshake().await;
        let (_req_auth, frame) = build_access_request(9, b"shared-secret");
        // Best-effort write: may succeed locally, but...
        let _ = pump.write_all(&frame).await;
        // ...the reply must never arrive. Either the read errors
        // out or the connection EOFs.
        let mut hdr = [0u8; 4];
        let read_res =
            tokio::time::timeout(StdDuration::from_secs(2), pump.read_exact(&mut hdr)).await;
        assert!(
            matches!(read_res, Ok(Err(_)) | Err(_)),
            "wrong-CA peer unexpectedly received a reply"
        );

        // Right-CA peer on the same listener succeeds — confirms
        // the rejection above wasn't a listener-wide misconfig.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = stream.set_nodelay(true);
        let ssl = client_side::builder(&pki_a.ca_pem)
            .unwrap()
            .with_client_cert(&pki_a.client_chain_pem, &pki_a.client_key_pem)
            .unwrap()
            .build()
            .unwrap();
        let mut pump = ClientPump::new(stream, ssl);
        pump.handshake().await.expect("right-CA handshake");
        let (_req_auth, frame) = build_access_request(11, b"shared-secret");
        pump.write_all(&frame).await.expect("write request");
        let mut hdr = [0u8; 4];
        pump.read_exact(&mut hdr).await.expect("read header");
        assert_eq!(hdr[0], Code::ACCESS_ACCEPT.0);
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; len - 4];
        pump.read_exact(&mut body).await.expect("read body");

        shutdown.shutdown();
        let _ = tokio::time::timeout(StdDuration::from_secs(2), server_task).await;
    }

    // -----------------------------------------------------------
    // Cert-keyed mode: post-handshake authorization via a custom
    // ClientStore that maps the leaf cert's Subject DN to a Client.
    // -----------------------------------------------------------

    /// Cert-keyed `ClientStore` for tests: a flat list of
    /// `(subject-substring -> Client)` pairs. Returns `None` from
    /// `lookup_udp` and `admit_radsec` (cert-keyed only) and
    /// matches `lookup_radsec_by_cert` against the cert's Subject
    /// DN string.
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

        fn lookup_radsec_by_cert(
            &self,
            peer: &crate::tls::PeerCertificate,
        ) -> impl std::future::Future<Output = Option<Arc<Client>>> + Send {
            let subject = peer.subject();
            let hit = self
                .entries
                .iter()
                .find(|(needle, _)| subject.contains(needle.as_str()))
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

        let server_ctx = TlsContext::server(
            &pki.server_chain_pem,
            &pki.server_key_pem,
            Some(&pki.ca_pem),
        )
        .unwrap();
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

        let server_ctx = TlsContext::server(
            &pki.server_chain_pem,
            &pki.server_key_pem,
            Some(&pki.ca_pem),
        )
        .unwrap();
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

        let server_ctx = TlsContext::server(
            &pki.server_chain_pem,
            &pki.server_key_pem,
            Some(&pki.ca_pem),
        )
        .unwrap();
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
