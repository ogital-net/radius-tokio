//! UDP transport for the [`Server`](super::Server).
//!
//! Each bound address gets its own `recv_from` task. The task:
//!
//! 1. Reads a datagram into a reusable scratch buffer.
//! 2. Resolves the source to a [`Client`] via the
//!    [`ClientStore`](super::ClientStore). Unknown sources are dropped
//!    before any allocation beyond the receive buffer — this is the
//!    inline admission gate.
//! 3. **Spawns** a Tokio task that owns the datagram bytes and runs
//!    the rest of the pipeline: header parse, authenticator
//!    verification (Acct/CoA/Disconnect zeroed-request and
//!    Message-Authenticator), dedup cache lookup, handler dispatch,
//!    reply seal, cache insert, and `send_to`.
//!
//! # Why spawn just past the admission gate?
//!
//! Profiling shows ~90 % of per-packet cycles are in MD5 / HMAC-MD5:
//! one HMAC over the inbound Message-Authenticator, one HMAC over
//! the sealed reply's Message-Authenticator, and one MD5 for the
//! Response Authenticator. With everything serialized on the recv
//! task, throughput is capped at single-core HMAC speed regardless
//! of how many runtime workers Tokio has. Spawning right after the
//! admission check lets a multi-thread runtime fan that crypto out
//! across cores.
//!
//! The admission lookup itself stays inline so an unknown-source
//! flood costs zero spawns and zero allocations beyond the receive
//! buffer — the single most important DoS property of the recv loop.
//! Operators with expensive [`ClientStore`] backends (DB, network)
//! are expected to wrap them in
//! [`CachedStore`](super::CachedStore) so the inline lookup stays
//! O(1); that is documented on the trait.
//!
//! Note that this design assumes a multi-thread Tokio runtime. On a
//! `current_thread` runtime, spawned tasks still share the recv
//! task's thread — there is no parallelism win, only a small
//! per-packet scheduling cost. Consumers running single-threaded
//! workloads on hot hardware should pick the `multi_thread` flavor.
//!
//! Send and receive share the single `UdpSocket` — Tokio's
//! [`UdpSocket`] supports concurrent `send_to` from many tasks on
//! the same socket without an additional mutex.
//!
//! # Allocations
//!
//! Unknown-client drops cost zero allocations. Every admitted packet
//! costs one `Vec<u8>` for the datagram copy (so the recv buffer can
//! be reused for the next packet) plus the spawned task itself.
//! Subsequent drops (malformed header, bad authenticator, dedup hit)
//! happen inside that task and add no further allocations beyond the
//! datagram copy. Outbound bytes are produced into the
//! [`PacketBuffer`]'s `Vec`, which the dedup cache clones into its
//! own boxed slice for retransmit storage.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::codec::header::MAX_PACKET_LEN;
#[cfg(feature = "metrics")]
use crate::obs::metrics;

use super::dedup::DedupCache;
use super::handler::Handler;
use super::pipeline::{self, Dispatched, StatusServerContext, Validated};
use super::status::{ListenerRole, StatusServerPolicy, StatusTransport};
use super::store::ClientStore;

/// Default lifetime for an entry in the dedup / retransmit cache.
/// RFC 5080 §2.2.2 suggests "long enough to outlast the NAS retry
/// interval"; 30s comfortably covers every NAS we care about.
pub(crate) const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(30);

/// Run the UDP receive loop on `socket` until `shutdown` flips to
/// `true`. Owned by [`Server::run`](super::Server::run).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_udp<S, H>(
    socket: UdpSocket,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    role: ListenerRole,
    status_policy: Arc<StatusServerPolicy>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()>
where
    S: ClientStore,
    H: Handler,
{
    let socket = Arc::new(socket);
    // Captured once: the bound address never changes after
    // `bind()`, so exposing it through `Request::dst()` is just a
    // copy. For wildcard binds this is `0.0.0.0:port` /
    // `[::]:port` — see `Request::dst` for the caveat.
    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            res = socket.recv_from(&mut buf) => {
                // Tokio's I/O driver retries `WouldBlock`/`EINTR`
                // internally, so any error surfaced here is terminal
                // for the socket (e.g. ENOTCONN, EBADF). Bubble it up.
                let (len, src) = res?;

                // Inline admission gate: identify the peer before any
                // allocation beyond the receive buffer. Unknown sources
                // are dropped here; flood traffic never reaches the
                // scheduler.
                let Some(client) = store.lookup_udp(src).await else {
                    warn!(event = "drop", reason = "unknown_client", %src, len);
                    count!(metrics::PACKETS_DROPPED, "reason" => "unknown_client");
                    continue;
                };

                // Copy the datagram out of the shared scratch buffer
                // so the next recv_from can overwrite it, then spawn
                // the parse / verify / dispatch / seal / send pipeline
                // so MD5 / HMAC-MD5 (the dominant cost) can scale
                // across runtime workers on a multi-thread runtime.
                let datagram = buf[..len].to_vec();
                let socket = Arc::clone(&socket);
                let handler = Arc::clone(&handler);
                let cache = Arc::clone(&cache);
                let status_policy = Arc::clone(&status_policy);
                tokio::spawn(async move {
                    process_packet(
                        &socket,
                        datagram,
                        src,
                        local_addr,
                        client,
                        &handler,
                        &cache,
                        role,
                        &status_policy,
                    )
                    .await;
                });
            }
        }
    }
}

/// Spawned per-packet pipeline: parse the header, validate
/// authenticators, consult the dedup cache, and on a clean miss
/// either short-circuit a Status-Server probe through the
/// configured policy or invoke the handler and send the sealed
/// reply. Owns the datagram `Vec` produced by the recv loop.
#[allow(
    clippy::too_many_lines,
    clippy::used_underscore_binding,
    clippy::too_many_arguments
)]
async fn process_packet<H>(
    socket: &Arc<UdpSocket>,
    datagram: Vec<u8>,
    src: SocketAddr,
    dst: SocketAddr,
    client: Arc<super::client::Client>,
    handler: &Arc<H>,
    cache: &Arc<DedupCache>,
    role: ListenerRole,
    status_policy: &StatusServerPolicy,
) where
    H: Handler,
{
    let datagram = datagram.as_slice();

    // Steps 2–4: header parse, request-authenticator check,
    // Message-Authenticator check. All transport-agnostic; the
    // shared pipeline returns a single verdict we trace + act on.
    let (header, attrs) = match pipeline::validate(datagram, &client) {
        Validated::Ok { header, attrs } => (header, attrs),
        Validated::MalformedHeader(_e) => {
            warn!(
                event = "drop",
                reason = "malformed_header",
                %src,
                client = ?client.id(),
                error = %_e,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "malformed_header");
            return;
        }
        Validated::BadRequestAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "drop",
                reason = "bad_request_authenticator",
                %src,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "bad_request_authenticator");
            return;
        }
        Validated::MissingMessageAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "drop",
                reason = "missing_message_authenticator",
                %src,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "missing_message_authenticator"
            );
            return;
        }
        Validated::BadMessageAuthenticator {
            code: _code,
            identifier: _identifier,
        } => {
            warn!(
                event = "drop",
                reason = "bad_message_authenticator",
                %src,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
            );
            count!(metrics::PACKETS_DROPPED, "reason" => "bad_message_authenticator");
            return;
        }
    };

    // Steps 5–6: dedup lookup + (on miss) Status-Server
    // short-circuit or handler dispatch + seal + cache insert.
    // All transport-agnostic.
    debug!(
        event = "request",
        %src,
        client = ?client.id(),
        code = header.code.0,
        id = header.identifier,
        len = datagram.len(),
    );
    count!(metrics::REQUESTS_DISPATCHED, "code" => header.code.0.to_string());

    let outcome = pipeline::dispatch_validated(
        header,
        attrs,
        src,
        dst,
        &client,
        handler.as_ref(),
        cache,
        Some(StatusServerContext {
            role,
            transport: StatusTransport::Udp,
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
                event = "dedup_hit",
                %src,
                client = ?client.id(),
                code = _code.0,
                id = _identifier,
                reply_len = bytes.len(),
            );
            count!(metrics::DEDUP_HITS);
            let _ = socket.send_to(&bytes, src).await;
        }
        Dispatched::Reply {
            sealed,
            code: _code,
            identifier: _identifier,
        } => {
            let bytes = sealed.as_bytes();
            let _reply_code = bytes.first().copied().unwrap_or(0);
            match socket.send_to(bytes, src).await {
                Ok(_n) => {
                    debug!(
                        event = "reply_sent",
                        code = _code.0,
                        reply_code = _reply_code,
                        id = _identifier,
                        len = _n,
                    );
                    count!(metrics::REPLIES_SENT, "code" => _reply_code.to_string());
                }
                Err(_e) => {
                    warn!(
                        event = "reply_send_error",
                        code = _code.0,
                        id = _identifier,
                        error = %_e,
                    );
                    count!(metrics::SEND_ERRORS);
                }
            }
        }
        Dispatched::HandlerDrop {
            code: _code,
            identifier: _identifier,
        } => {
            debug!(event = "handler_drop", code = _code.0, id = _identifier);
            count!(metrics::PACKETS_DROPPED, "reason" => "handler_drop");
        }
        Dispatched::StatusServerReply {
            sealed,
            identifier: _identifier,
            role: _role,
        } => {
            let bytes = sealed.as_bytes();
            let _reply_code = bytes.first().copied().unwrap_or(0);
            match socket.send_to(bytes, src).await {
                Ok(_n) => {
                    debug!(
                        event = "status_server_reply",
                        %src,
                        client = ?client.id(),
                        role = ?_role,
                        reply_code = _reply_code,
                        id = _identifier,
                        len = _n,
                    );
                    count!(
                        metrics::STATUS_SERVER_REPLIES,
                        "transport" => "udp",
                        "role" => match _role {
                            ListenerRole::Auth => "auth",
                            ListenerRole::Acct => "acct",
                        },
                    );
                }
                Err(_e) => {
                    warn!(
                        event = "status_server_reply_send_error",
                        %src,
                        id = _identifier,
                        error = %_e,
                    );
                    count!(metrics::SEND_ERRORS);
                }
            }
        }
        Dispatched::StatusServerDisabledPerClient {
            identifier: _identifier,
        } => {
            debug!(
                event = "drop",
                reason = "status_server_disabled_per_client",
                %src,
                client = ?client.id(),
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "status_server_disabled_per_client",
            );
        }
        Dispatched::StatusServerDisabled {
            identifier: _identifier,
        } => {
            debug!(
                event = "drop",
                reason = "status_server_disabled",
                %src,
                client = ?client.id(),
                id = _identifier,
            );
            count!(
                metrics::PACKETS_DROPPED,
                "reason" => "status_server_disabled",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::{Code, Header};
    use crate::codec::{authenticator, message_authenticator};
    use crate::server::client::Client;
    use crate::server::handler::{HandlerResult, Request};
    use crate::server::store::{IpCidr, StaticClients};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use tokio::net::UdpSocket as TokioUdp;

    /// Test-only wrapper that picks `ListenerRole::Auth` and the
    /// default Status-Server policy. Keeps the existing test bodies
    /// readable now that `serve_udp` carries listener role +
    /// Status-Server policy.
    async fn serve_udp_test<S, H>(
        socket: UdpSocket,
        store: Arc<S>,
        handler: Arc<H>,
        cache: Arc<DedupCache>,
        rx: watch::Receiver<bool>,
    ) -> io::Result<()>
    where
        S: ClientStore,
        H: Handler,
    {
        serve_udp(
            socket,
            store,
            handler,
            cache,
            ListenerRole::Auth,
            Arc::new(StatusServerPolicy::Enabled),
            rx,
        )
        .await
    }

    /// A handler that always returns Access-Accept and counts calls.
    struct AcceptCounter {
        calls: Mutex<usize>,
    }

    impl Handler for AcceptCounter {
        async fn handle(&self, request: Request<'_>) -> HandlerResult {
            *self.calls.lock().unwrap() += 1;
            HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
        }
    }

    async fn bind_loopback() -> (TokioUdp, SocketAddr) {
        let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        (sock, addr)
    }

    fn build_access_request(identifier: u8, secret: &[u8]) -> ([u8; 16], Vec<u8>) {
        let req_auth = authenticator::random_request_authenticator();
        let mut pkt = vec![Code::ACCESS_REQUEST.0, identifier, 0, 0];
        pkt.extend_from_slice(&req_auth);
        // User-Name = "alice"
        pkt.extend_from_slice(&[1, 7, b'a', b'l', b'i', b'c', b'e']);
        let len = u16::try_from(pkt.len()).unwrap();
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        // Splice in a Message-Authenticator slot so the secure path
        // exercises the M-A verify branch on the request side.
        let mut buf = crate::codec::PacketBuffer::from_bytes(&pkt).unwrap();
        let value_off = message_authenticator::append_zeroed_slot(&mut buf).unwrap();
        buf.patch_length();
        let tag = message_authenticator::compute(buf.as_bytes(), &req_auth, secret);
        message_authenticator::patch(&mut buf, value_off, &tag);
        (req_auth, buf.as_bytes().to_vec())
    }

    /// Same shape as [`build_access_request`] but **without** a
    /// Message-Authenticator attribute. Models a legacy NAS that
    /// predates RFC 5080 §2.2.2 hardening.
    fn build_access_request_no_ma(identifier: u8) -> ([u8; 16], Vec<u8>) {
        let req_auth = authenticator::random_request_authenticator();
        let mut pkt = vec![Code::ACCESS_REQUEST.0, identifier, 0, 0];
        pkt.extend_from_slice(&req_auth);
        pkt.extend_from_slice(&[1, 7, b'a', b'l', b'i', b'c', b'e']);
        let len = u16::try_from(pkt.len()).unwrap();
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        (req_auth, pkt)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn happy_path_access_accept() {
        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);

        let server = tokio::spawn(serve_udp_test(
            server_sock,
            store,
            Arc::clone(&handler),
            Arc::clone(&cache),
            rx,
        ));

        // Client side: bind, send, await reply.
        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (req_auth, datagram) = build_access_request(7, &secret);
        client_sock.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf))
                .await
                .expect("server replied within timeout")
                .unwrap();
        let reply = &buf[..len];

        // Reply should be Access-Accept(2), identifier 7, with valid
        // Response Authenticator + Message-Authenticator.
        let (header, _) = Header::parse(reply).unwrap();
        assert_eq!(header.code, Code::ACCESS_ACCEPT);
        assert_eq!(header.identifier, 7);
        assert!(authenticator::verify_response(reply, &req_auth, &secret));
        assert_eq!(
            message_authenticator::verify(reply, &req_auth, &secret),
            message_authenticator::Verification::Valid,
        );
        assert_eq!(*handler.calls.lock().unwrap(), 1);

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_client_is_dropped() {
        let (server_sock, server_addr) = bind_loopback().await;
        let store = Arc::new(StaticClients::builder().build()); // empty
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(server_sock, store, handler, cache, rx));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (_, datagram) = build_access_request(1, b"shared");
        client_sock.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let res =
            tokio::time::timeout(Duration::from_millis(100), client_sock.recv_from(&mut buf)).await;
        assert!(res.is_err(), "no reply expected for unknown client");

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_request_is_replayed_from_cache() {
        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(
            server_sock,
            store,
            Arc::clone(&handler),
            Arc::clone(&cache),
            rx,
        ));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (_, datagram) = build_access_request(11, &secret);

        let mut buf1 = vec![0u8; MAX_PACKET_LEN];
        client_sock.send_to(&datagram, server_addr).await.unwrap();
        let (n1, _) =
            tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf1))
                .await
                .unwrap()
                .unwrap();

        // Replay the exact same datagram.
        let mut buf2 = vec![0u8; MAX_PACKET_LEN];
        client_sock.send_to(&datagram, server_addr).await.unwrap();
        let (n2, _) =
            tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf2))
                .await
                .unwrap()
                .unwrap();

        assert_eq!(buf1[..n1], buf2[..n2], "replayed reply must be identical");
        assert_eq!(
            *handler.calls.lock().unwrap(),
            1,
            "handler runs once even for duplicate requests",
        );

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    /// Captures `event = "…"` fields from `tracing` events into a
    /// shared vector, and notifies waiters whenever the vector
    /// grows. Lets tests wait deterministically for an expected
    /// event instead of sleeping.
    #[cfg(feature = "tracing")]
    #[derive(Default)]
    struct EventSink {
        events: std::sync::Mutex<Vec<(tracing::Level, String)>>,
        notify: tokio::sync::Notify,
    }

    #[cfg(feature = "tracing")]
    impl EventSink {
        fn snapshot(&self) -> Vec<(tracing::Level, String)> {
            self.events.lock().unwrap().clone()
        }

        /// Block (async) until `pred` is satisfied by the captured
        /// event list, or `timeout` elapses. Polls only on each
        /// `notify` wakeup, so it never spins.
        async fn wait_for<F>(&self, timeout: Duration, mut pred: F) -> bool
        where
            F: FnMut(&[(tracing::Level, String)]) -> bool,
        {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if pred(&self.events.lock().unwrap()) {
                    return true;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return false;
                }
                let notified = self.notify.notified();
                tokio::pin!(notified);
                if tokio::time::timeout_at(deadline, &mut notified)
                    .await
                    .is_err()
                {
                    return pred(&self.events.lock().unwrap());
                }
            }
        }
    }

    #[cfg(feature = "tracing")]
    impl tracing::Subscriber for EventSink {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            use std::fmt::Debug;
            use tracing::field::{Field, Visit};

            struct V<'a> {
                level: tracing::Level,
                sink: &'a std::sync::Mutex<Vec<(tracing::Level, String)>>,
                pushed: bool,
            }
            impl Visit for V<'_> {
                fn record_str(&mut self, field: &Field, value: &str) {
                    if field.name() == "event" {
                        self.sink.lock().unwrap().push((self.level, value.into()));
                        self.pushed = true;
                    }
                }
                fn record_debug(&mut self, _: &Field, _: &dyn Debug) {}
            }
            let m = event.metadata();
            let mut v = V {
                level: *m.level(),
                sink: &self.events,
                pushed: false,
            };
            event.record(&mut v);
            if v.pushed {
                self.notify.notify_waiters();
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[cfg(feature = "tracing")]
    #[tokio::test(flavor = "current_thread")]
    async fn tracing_emits_request_and_reply_events() {
        let sink = Arc::new(EventSink::default());
        let _guard = tracing::subscriber::set_default(Arc::clone(&sink));

        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(server_sock, store, handler, cache, rx));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (_, datagram) = build_access_request(42, &secret);
        client_sock.send_to(&datagram, server_addr).await.unwrap();
        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let _ = tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();

        let captured = sink.snapshot();
        let names: Vec<&str> = captured.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"request"), "captured: {names:?}");
        assert!(names.contains(&"reply_sent"), "captured: {names:?}");
    }

    #[cfg(feature = "tracing")]
    #[tokio::test(flavor = "current_thread")]
    async fn tracing_unknown_client_emits_warn_drop() {
        let sink = Arc::new(EventSink::default());
        let _guard = tracing::subscriber::set_default(Arc::clone(&sink));

        let (server_sock, server_addr) = bind_loopback().await;
        // Empty store → every source IP is unknown.
        let store = Arc::new(StaticClients::builder().build());
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(server_sock, store, handler, cache, rx));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        client_sock
            .send_to(
                &[
                    1u8, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                server_addr,
            )
            .await
            .unwrap();

        // Wait deterministically for the WARN drop event instead
        // of sleeping a fixed duration. The 1 s ceiling is a hard
        // upper bound for an in-process loopback packet; missing
        // it indicates a real regression, not load-induced jitter.
        let saw_drop = sink
            .wait_for(Duration::from_secs(1), |evs| {
                evs.iter()
                    .any(|(lvl, name)| *lvl == tracing::Level::WARN && name == "drop")
            })
            .await;

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();

        assert!(
            saw_drop,
            "expected WARN drop event, got {:?}",
            sink.snapshot(),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strict_client_drops_access_request_missing_message_authenticator() {
        // Default `Client::new(...)` requires Message-Authenticator
        // on Access-Request. A legacy-shaped packet (no M-A slot)
        // must be dropped without a reply.
        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()));
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(server_sock, store, handler, cache, rx));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (_, datagram) = build_access_request_no_ma(3);
        client_sock.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let res =
            tokio::time::timeout(Duration::from_millis(150), client_sock.recv_from(&mut buf)).await;
        assert!(res.is_err(), "strict client must drop missing-MA request");

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn legacy_client_accepts_access_request_missing_message_authenticator() {
        // Opt-out flag set: the same legacy-shaped packet now
        // round-trips to Access-Accept.
        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()).allow_missing_message_authenticator());
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(
            server_sock,
            store,
            Arc::clone(&handler),
            cache,
            rx,
        ));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let (req_auth, datagram) = build_access_request_no_ma(4);
        client_sock.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client_sock.recv_from(&mut buf))
                .await
                .expect("legacy-mode client must receive a reply")
                .unwrap();
        let reply = &buf[..len];
        let (header, _) = Header::parse(reply).unwrap();
        assert_eq!(header.code, Code::ACCESS_ACCEPT);
        assert_eq!(header.identifier, 4);
        assert!(authenticator::verify_response(reply, &req_auth, &secret));
        assert_eq!(*handler.calls.lock().unwrap(), 1);

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn legacy_client_still_drops_invalid_message_authenticator() {
        // The opt-out only relaxes the *Absent* case. A *present*
        // M-A with the wrong tag must still be discarded — RFC
        // 3579 §3.2 leaves no room there.
        let (server_sock, server_addr) = bind_loopback().await;
        let secret = b"shared".to_vec();
        let client = Arc::new(Client::new(secret.as_slice()).allow_missing_message_authenticator());
        let store = Arc::new(
            StaticClients::builder()
                .add(
                    IpCidr::host(Ipv4Addr::LOCALHOST.into()),
                    Arc::clone(&client),
                )
                .build(),
        );
        let handler = Arc::new(AcceptCounter {
            calls: Mutex::new(0),
        });
        let cache = Arc::new(DedupCache::new(DEFAULT_DEDUP_TTL));
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve_udp_test(server_sock, store, handler, cache, rx));

        let client_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        // Build a properly-MA'd request, then corrupt the tag's
        // last byte.
        let (_, mut datagram) = build_access_request(5, &secret);
        let last = datagram.len() - 1;
        datagram[last] ^= 0xFF;
        client_sock.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let res =
            tokio::time::timeout(Duration::from_millis(150), client_sock.recv_from(&mut buf)).await;
        assert!(res.is_err(), "invalid MA must always be dropped");

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
