//! UDP transport for the [`Server`](super::Server).
//!
//! Each bound address gets its own `recv_from` task. The task:
//!
//! 1. Reads a datagram into a reusable scratch buffer.
//! 2. Resolves the source to a [`Client`] via the
//!    [`ClientStore`](super::ClientStore). Unknown sources are dropped
//!    before any allocation beyond the receive buffer.
//! 3. Parses the header and verifies code-appropriate authenticators
//!    (Acct/CoA/Disconnect: zeroed-request; M-A: when present).
//! 4. Consults the dedup cache; on hit, replays the cached reply
//!    bytes inline.
//! 5. **On miss**, copies the attribute bytes out of the shared
//!    scratch buffer and spawns a Tokio task to run the
//!    [`Handler`](super::Handler), seal the reply, cache it, and
//!    send it.
//!
//! # Why spawn only at handler dispatch?
//!
//! Steps 1–4 are bounded, allocation-free, and constant-time
//! relative to packet size — doing them inline keeps the noise floor
//! (unknown clients, malformed packets, replays) off the runtime's
//! task scheduler entirely. The handler is the one step the library
//! cannot bound: a [`ClientStore`] returning a slow lookup is a
//! deliberate operator choice, but the [`Handler`] runs arbitrary
//! consumer code (DB writes, EAP method state machines, accounting
//! fan-out). Spawning there matches the pattern Hyper recommends
//! for HTTP and ensures one slow handler invocation cannot
//! head-of-line block other clients.
//!
//! Send and receive share the single `UdpSocket` — Tokio's
//! [`UdpSocket`] supports concurrent `send_to` from many tasks on
//! the same socket without an additional mutex.
//!
//! # Allocations
//!
//! Drops (unknown client, bad authenticator, dedup hit) cost zero
//! allocations on the hot path. A dispatched packet costs one
//! `Vec<u8>` for the attribute bytes (sized to the wire length minus
//! the 20-byte header) plus the spawned task itself. Outbound bytes
//! are produced into the [`PacketBuffer`]'s `Vec`, which the dedup
//! cache clones into its own boxed slice for retransmit storage.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::codec::header::{Code, Header, MAX_PACKET_LEN};
use crate::codec::message_authenticator::Verification;
use crate::codec::{authenticator, message_authenticator};

use super::dedup::{DedupCache, Key as DedupKey};
use super::handler::{Handler, HandlerResult, Request};
use super::store::ClientStore;

/// Default lifetime for an entry in the dedup / retransmit cache.
/// RFC 5080 §2.2.2 suggests "long enough to outlast the NAS retry
/// interval"; 30s comfortably covers every NAS we care about.
pub(crate) const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(30);

/// Run the UDP receive loop on `socket` until `shutdown` flips to
/// `true`. Owned by [`Server::run`](super::Server::run).
pub(crate) async fn serve_udp<S, H>(
    socket: UdpSocket,
    store: Arc<S>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()>
where
    S: ClientStore,
    H: Handler,
{
    let socket = Arc::new(socket);
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
                inspect_and_dispatch(
                    &socket,
                    &buf[..len],
                    src,
                    store.as_ref(),
                    &handler,
                    &cache,
                ).await;
            }
        }
    }
}

/// Inline portion of the pipeline: identify the peer, validate
/// authenticators, consult the dedup cache. Bounded and
/// allocation-free; runs on the receive task so noise (unknown
/// clients, replays, bad MACs) never reaches the scheduler.
///
/// On a clean miss, copies the attribute bytes into an owned `Vec`
/// and spawns the handler dispatch as a separate task — see the
/// module doc for the rationale.
#[allow(clippy::too_many_lines, clippy::used_underscore_binding)]
async fn inspect_and_dispatch<S, H>(
    socket: &Arc<UdpSocket>,
    datagram: &[u8],
    src: SocketAddr,
    store: &S,
    handler: &Arc<H>,
    cache: &Arc<DedupCache>,
) where
    S: ClientStore,
    H: Handler,
{
    // Step 1: identify the peer. Unknown sources are dropped before
    // we touch the packet beyond the receive buffer.
    let Some(client) = store.lookup_udp(src).await else {
        warn_!(event = "drop", reason = "unknown_client", %src, len = datagram.len());
        count!("radius_tokio.packets_dropped", "reason" => "unknown_client");
        return;
    };

    // Step 2: parse the fixed header. Malformed datagrams are dropped.
    let (header, attrs) = match Header::parse(datagram) {
        Ok(parsed) => parsed,
        Err(_e) => {
            warn_!(
                event = "drop",
                reason = "malformed_header",
                %src,
                client = ?client.id(),
                error = %_e,
            );
            count!("radius_tokio.packets_dropped", "reason" => "malformed_header");
            return;
        }
    };

    // Step 3: code-appropriate authenticator validation.
    if !validate_request_authenticator(header.code, datagram, client.secret()) {
        warn_!(
            event = "drop",
            reason = "bad_request_authenticator",
            %src,
            client = ?client.id(),
            code = header.code.0,
            id = header.identifier,
        );
        count!("radius_tokio.packets_dropped", "reason" => "bad_request_authenticator");
        return;
    }

    // Step 4: Message-Authenticator (when present). Mismatch is a
    // silent drop per RFC 3579 §3.2.
    //
    // The "Request Authenticator" the M-A formula substitutes into
    // bytes 4..20 differs by code:
    //
    // * Access-Request carries a random Request Authenticator; that
    //   value IS what the NAS used when computing the M-A, so we
    //   substitute the wire bytes back in.
    // * Accounting-Request / CoA-Request / Disconnect-Request derive
    //   the Authenticator from the rest of the packet, so the NAS
    //   computed M-A *before* the Authenticator existed — with the
    //   field treated as 16 zero octets. The verifier must do the
    //   same; substituting the wire authenticator here would never
    //   match.
    let ma_substitute = match header.code {
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => [0u8; 16],
        _ => header.authenticator,
    };
    match message_authenticator::verify(datagram, &ma_substitute, client.secret()) {
        Verification::Valid => {}
        Verification::Absent => {
            // RFC 5080 §2.2.2 / RFC 3579 §3.2: Access-Request
            // packets must carry Message-Authenticator if the
            // operator has opted in to the strict policy (which
            // is the default — see [`Client::require_message_authenticator`]).
            // Accounting-Request / CoA-Request / Disconnect-Request
            // are exempt: they authenticate via the Request
            // Authenticator over the packet body and have never
            // been required to carry M-A; forcing it would break
            // the installed base for no security gain.
            let strict_code = matches!(header.code, Code::ACCESS_REQUEST);
            if strict_code && client.require_message_authenticator() {
                warn_!(
                    event = "drop",
                    reason = "missing_message_authenticator",
                    %src,
                    client = ?client.id(),
                    code = header.code.0,
                    id = header.identifier,
                );
                count!(
                    "radius_tokio.packets_dropped",
                    "reason" => "missing_message_authenticator"
                );
                return;
            }
        }
        Verification::Invalid => {
            warn_!(
                event = "drop",
                reason = "bad_message_authenticator",
                %src,
                client = ?client.id(),
                code = header.code.0,
                id = header.identifier,
            );
            count!("radius_tokio.packets_dropped", "reason" => "bad_message_authenticator");
            return;
        }
    }

    // Step 5: dedup. A hit replays the previously-sent reply inline;
    // no spawn, no handler invocation.
    let dedup_key = DedupKey {
        src,
        code: header.code.0,
        identifier: header.identifier,
        request_authenticator: header.authenticator,
    };
    if let Some(cached) = cache.lookup(&dedup_key) {
        debug!(
            event = "dedup_hit",
            %src,
            client = ?client.id(),
            code = header.code.0,
            id = header.identifier,
            reply_len = cached.len(),
        );
        count!("radius_tokio.dedup_hits");
        let _ = socket.send_to(&cached, src).await;
        return;
    }

    debug!(
        event = "request",
        %src,
        client = ?client.id(),
        code = header.code.0,
        id = header.identifier,
        len = datagram.len(),
    );
    count!("radius_tokio.requests_dispatched", "code" => header.code.0.to_string());

    // Step 6+: hand off to a spawned task. Copy the attribute slice
    // out of the shared receive buffer (the next loop iteration will
    // overwrite it) and clone the Arcs into the task.
    let attrs_owned = attrs.to_vec();
    let socket = Arc::clone(socket);
    let handler = Arc::clone(handler);
    let cache = Arc::clone(cache);
    let code = header.code;
    let identifier = header.identifier;
    let request_authenticator = header.authenticator;
    tokio::spawn(async move {
        dispatch_handler(
            socket,
            client,
            handler,
            cache,
            dedup_key,
            code,
            identifier,
            request_authenticator,
            attrs_owned,
            src,
        )
        .await;
    });
}

/// Spawned portion of the pipeline: invoke the handler, seal the
/// reply against the request's authenticator + client secret, store
/// it in the dedup cache for retransmit, and send it.
#[allow(clippy::too_many_arguments, clippy::used_underscore_binding)]
async fn dispatch_handler<H>(
    socket: Arc<UdpSocket>,
    client: Arc<super::client::Client>,
    handler: Arc<H>,
    cache: Arc<DedupCache>,
    dedup_key: DedupKey,
    code: Code,
    identifier: u8,
    request_authenticator: [u8; 16],
    attrs: Vec<u8>,
    src: SocketAddr,
) where
    H: Handler,
{
    let request = Request::new(
        code,
        identifier,
        request_authenticator,
        &attrs,
        &client,
        src,
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
            debug!(event = "handler_drop", code = code.0, id = identifier);
            count!("radius_tokio.packets_dropped", "reason" => "handler_drop");
            return;
        }
    };

    // Seal against the request's Authenticator + client secret.
    let sealed = reply.seal_for(&request_authenticator, client.secret());
    let bytes = sealed.as_bytes();

    // Cache for retransmit, then send.
    cache.insert(dedup_key, bytes);
    let _reply_code = bytes.first().copied().unwrap_or(0);
    match socket.send_to(bytes, src).await {
        Ok(_n) => {
            debug!(
                event = "reply_sent",
                code = code.0,
                reply_code = _reply_code,
                id = identifier,
                len = _n,
            );
            count!("radius_tokio.replies_sent", "code" => _reply_code.to_string());
        }
        Err(_e) => {
            warn_!(
                event = "reply_send_error",
                code = code.0,
                id = identifier,
                error = %_e,
            );
            count!("radius_tokio.send_errors");
        }
    }
}

/// Returns `true` if the packet's Authenticator field is acceptable
/// for its code. Access-Request authenticators are random and cannot
/// be checked on their own; for everything else we recompute
/// `MD5(packet-with-zeros || secret)` and compare.
fn validate_request_authenticator(code: Code, datagram: &[u8], secret: &[u8]) -> bool {
    match code {
        // Accounting-Request (RFC 2866 §3), CoA-Request /
        // Disconnect-Request (RFC 5176): authenticator is
        // MD5(packet-with-zeros || secret) — verify in place.
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => {
            authenticator::verify_zeroed_request(datagram, secret)
        }
        // Access-Request (RFC 2865 §3) carries a random authenticator;
        // its integrity is bound by the Message-Authenticator (when
        // present) and by the response auth on the reply.
        // Status-Server / Status-Client follow the same shape; defer
        // to the M-A check (which the pipeline runs unconditionally)
        // for integrity.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::server::client::Client;
    use crate::server::store::{IpCidr, StaticClients};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use tokio::net::UdpSocket as TokioUdp;

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

        let server = tokio::spawn(serve_udp(
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
        let server = tokio::spawn(serve_udp(server_sock, store, handler, cache, rx));

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
        let server = tokio::spawn(serve_udp(
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
        let server = tokio::spawn(serve_udp(server_sock, store, handler, cache, rx));

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
        let server = tokio::spawn(serve_udp(server_sock, store, handler, cache, rx));

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
        let server = tokio::spawn(serve_udp(server_sock, store, handler, cache, rx));

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
        let server = tokio::spawn(serve_udp(
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
        let server = tokio::spawn(serve_udp(server_sock, store, handler, cache, rx));

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
