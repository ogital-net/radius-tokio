//! [`CachedStore`] — TTL + negative-cache + single-flight wrapper around
//! any [`ClientStore`].
//!
//! Many real-world deployments resolve a peer through a slow backend
//! (SQL, HTTP, LDAP, …). Looking that up on every inbound packet puts
//! the backend on the request hot path. `CachedStore` interposes a
//! small in-memory cache:
//!
//! * **Positive TTL.** Successful lookups are remembered for
//!   [`CacheConfig::positive_ttl`] before the backend is consulted
//!   again.
//! * **Negative TTL.** `None` results are cached for
//!   [`CacheConfig::negative_ttl`] (typically much shorter) so a flood
//!   of packets from one unknown peer can't hammer the backend.
//! * **Single-flight.** Concurrent lookups for the same source IP
//!   collapse to one upstream call; the rest wait and share the
//!   result.
//!
//! The cache is keyed by the packet's source [`IpAddr`] (not the full
//! [`SocketAddr`]): RADIUS clients are identified by IP per
//! RFC 2865 §3, and ephemeral source-port churn would otherwise
//! fragment the cache.
//!
//! `CachedStore` is intentionally *not* a session store, an LRU, or a
//! revocation broker. Invalidation is purely time-based; consumers
//! that need explicit eviction (e.g. when a NAS is removed from a
//! database) can either tighten the TTL or [`CachedStore::invalidate`]
//! a specific entry.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use super::client::Client;
use super::store::ClientStore;
#[allow(unused_imports)] // unused when both `tracing` and `metrics` are off
use crate::obs::metrics;

/// Tunables for a [`CachedStore`].
///
/// Defaults are conservative: 30 s positive TTL, 1 s negative TTL.
/// Pick values that match how quickly the backing store can publish
/// changes — a lower TTL means fresher results but more upstream
/// load.
#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    /// How long a successful (`Some`) lookup is cached.
    pub positive_ttl: Duration,
    /// How long a missing (`None`) lookup is cached.
    ///
    /// Kept short by default so a transient backend miss doesn't lock
    /// out a legitimate peer for long, while still absorbing repeat
    /// traffic from genuinely-unknown sources.
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            positive_ttl: Duration::from_secs(30),
            negative_ttl: Duration::from_secs(1),
        }
    }
}

/// TTL + negative-cache + single-flight wrapper around an inner
/// [`ClientStore`].
///
/// Cheap to clone via `Arc` if you need shared ownership; the cache
/// state itself is interior-mutable.
#[derive(Debug)]
pub struct CachedStore<S> {
    inner: S,
    config: CacheConfig,
    state: Mutex<HashMap<IpAddr, Slot>>,
}

/// Single map slot: either a finished lookup with an expiry, or an
/// in-flight call whose result will be broadcast to subscribers.
#[derive(Debug)]
enum Slot {
    Resolved {
        value: Option<Arc<Client>>,
        expires_at: Instant,
    },
    Pending(broadcast::Sender<Option<Arc<Client>>>),
}

impl<S> CachedStore<S> {
    /// Wrap `inner` with the given cache configuration.
    #[must_use]
    pub fn new(inner: S, config: CacheConfig) -> Self {
        Self {
            inner,
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Wrap `inner` with [`CacheConfig::default`].
    #[must_use]
    pub fn with_defaults(inner: S) -> Self {
        Self::new(inner, CacheConfig::default())
    }

    /// Borrow the wrapped store.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Drop any cached entry for `addr`. The next lookup for that IP
    /// will go to the backend.
    ///
    /// In-flight lookups are left alone — their result will still be
    /// delivered to existing waiters, but it will not be cached.
    pub fn invalidate(&self, addr: IpAddr) {
        let mut map = self.lock_state();
        if let Some(Slot::Resolved { .. }) = map.get(&addr) {
            map.remove(&addr);
            debug!(event = "client_cache_invalidate", %addr);
            #[cfg(feature = "metrics")]
            {
                #[allow(clippy::cast_precision_loss)]
                let len = map.len() as f64;
                gauge!(metrics::CLIENT_CACHE_SIZE, len);
            }
        }
    }

    /// Drop every cached entry. In-flight lookups are not interrupted.
    pub fn clear(&self) {
        let mut map = self.lock_state();
        let before = map.len();
        map.retain(|_, slot| matches!(slot, Slot::Pending(_)));
        let evicted = before.saturating_sub(map.len());
        info!(event = "client_cache_clear", evicted = evicted);
        let _ = evicted;
        #[cfg(feature = "metrics")]
        {
            #[allow(clippy::cast_precision_loss)]
            let len = map.len() as f64;
            gauge!(metrics::CLIENT_CACHE_SIZE, len);
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Slot>> {
        // Poisoned mutexes only happen if a thread panicked while
        // holding the lock — recover the guard so a single bad
        // lookup doesn't permanently brick the cache.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Action chosen while holding the map lock; the actual await happens
/// after the guard is dropped.
enum Action {
    Hit(Option<Arc<Client>>),
    Wait(broadcast::Receiver<Option<Arc<Client>>>),
    Resolve(broadcast::Sender<Option<Arc<Client>>>),
}

impl<S: ClientStore> ClientStore for CachedStore<S> {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let key = src.ip();
        let now = Instant::now();

        let action = {
            let mut map = self.lock_state();
            match map.get(&key) {
                Some(Slot::Resolved { value, expires_at }) if *expires_at > now => {
                    Action::Hit(value.clone())
                }
                Some(Slot::Pending(tx)) => Action::Wait(tx.subscribe()),
                _ => {
                    // Capacity 1 is enough: we send exactly one value
                    // per slot, and broadcast preserves the most recent
                    // message for every live receiver.
                    let (tx, _) = broadcast::channel(1);
                    map.insert(key, Slot::Pending(tx.clone()));
                    Action::Resolve(tx)
                }
            }
        };

        if matches!(action, Action::Hit(_)) {
            trace!(event = "client_cache_hit", %src);
            count!(metrics::CLIENT_CACHE_HITS);
        }

        async move {
            match action {
                Action::Hit(value) => value,
                Action::Wait(mut rx) => {
                    // The resolver always sends exactly one value
                    // before dropping its sender. `Lagged` cannot
                    // happen with a single send on a fresh receiver;
                    // `Closed` only fires if the resolver task was
                    // cancelled before sending — fall through to a
                    // direct lookup so we never deadlock.
                    match rx.recv().await {
                        Ok(v) => v,
                        Err(_) => self.inner.lookup_udp(src).await,
                    }
                }
                Action::Resolve(tx) => {
                    let value = self.inner.lookup_udp(src).await;
                    let ttl = if value.is_some() {
                        self.config.positive_ttl
                    } else {
                        self.config.negative_ttl
                    };
                    let result = if value.is_some() {
                        "positive"
                    } else {
                        "negative"
                    };
                    trace!(event = "client_cache_miss", %src, result = result);
                    count!(metrics::CLIENT_CACHE_MISSES, "result" => result);
                    let _ = result;
                    let expires_at = Instant::now() + ttl;
                    {
                        let mut map = self.lock_state();
                        map.insert(
                            key,
                            Slot::Resolved {
                                value: value.clone(),
                                expires_at,
                            },
                        );
                        #[cfg(feature = "metrics")]
                        {
                            #[allow(clippy::cast_precision_loss)]
                            let len = map.len() as f64;
                            gauge!(metrics::CLIENT_CACHE_SIZE, len);
                        }
                    }
                    // Broadcast to any waiters. `send` returns Err if
                    // there are no live receivers, which is fine.
                    let _ = tx.send(value.clone());
                    value
                }
            }
        }
    }

    /// `RadSec` admission is consulted exactly once per long-lived
    /// TCP connection, so the dedup / TTL machinery used for the
    /// per-packet UDP path would add overhead without value.
    /// Forward straight through to the inner store.
    #[cfg(feature = "radsec")]
    fn admit_radsec(&self, src: SocketAddr) -> impl Future<Output = bool> + Send {
        self.inner.admit_radsec(src)
    }

    /// Cert-keyed `RadSec` lookups are also one-per-connection;
    /// pass through unchanged.
    #[cfg(feature = "radsec")]
    fn lookup_radsec_by_cert(
        &self,
        src: SocketAddr,
        peer: &crate::tls::PeerCertificate,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        self.inner.lookup_radsec_by_cert(src, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// Test store: counts calls and optionally blocks until released.
    struct CountingStore {
        calls: AtomicUsize,
        gate: Option<Arc<Notify>>,
        result: Option<Arc<Client>>,
    }

    impl CountingStore {
        fn new(result: Option<Arc<Client>>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                gate: None,
                result,
            }
        }

        fn with_gate(result: Option<Arc<Client>>, gate: Arc<Notify>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                gate: Some(gate),
                result,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ClientStore for CountingStore {
        fn lookup_udp(&self, _src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let gate = self.gate.clone();
            let result = self.result.clone();
            async move {
                if let Some(g) = gate {
                    g.notified().await;
                }
                result
            }
        }
    }

    fn addr(s: &str) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()), 1812)
    }

    #[tokio::test]
    async fn caches_positive_lookup() {
        let client = Arc::new(Client::new(b"sekret".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);

        let a = cache.lookup_udp(addr("10.0.0.1")).await.unwrap();
        let b = cache.lookup_udp(addr("10.0.0.1")).await.unwrap();
        assert_eq!(a.id(), client.id());
        assert_eq!(b.id(), client.id());
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn caches_negative_lookup() {
        let inner = CountingStore::new(None);
        let cache = CachedStore::with_defaults(inner);

        assert!(cache.lookup_udp(addr("10.0.0.2")).await.is_none());
        assert!(cache.lookup_udp(addr("10.0.0.2")).await.is_none());
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn distinct_ips_are_independent() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);

        cache.lookup_udp(addr("10.0.0.1")).await;
        cache.lookup_udp(addr("10.0.0.2")).await;
        assert_eq!(cache.inner().calls(), 2);
    }

    #[tokio::test]
    async fn ephemeral_port_does_not_fragment_cache() {
        // Two packets from the same NAS but different source ports
        // (e.g. retry behaviour) must hit the same cache entry.
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);

        let one = SocketAddr::new(IpAddr::V4("10.0.0.1".parse().unwrap()), 1812);
        let two = SocketAddr::new(IpAddr::V4("10.0.0.1".parse().unwrap()), 5555);
        cache.lookup_udp(one).await;
        cache.lookup_udp(two).await;
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn positive_entry_expires() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::new(
            inner,
            CacheConfig {
                positive_ttl: Duration::from_millis(0),
                negative_ttl: Duration::from_secs(1),
            },
        );
        cache.lookup_udp(addr("10.0.0.1")).await;
        // Zero TTL means the entry is already expired by the time we
        // re-enter the lookup.
        cache.lookup_udp(addr("10.0.0.1")).await;
        assert_eq!(cache.inner().calls(), 2);
    }

    #[tokio::test]
    async fn invalidate_forces_refresh() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);

        cache.lookup_udp(addr("10.0.0.1")).await;
        cache.invalidate(IpAddr::V4("10.0.0.1".parse().unwrap()));
        cache.lookup_udp(addr("10.0.0.1")).await;
        assert_eq!(cache.inner().calls(), 2);
    }

    #[tokio::test]
    async fn single_flight_collapses_concurrent_lookups() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let gate = Arc::new(Notify::new());
        let inner = CountingStore::with_gate(Some(Arc::clone(&client)), Arc::clone(&gate));
        let cache = Arc::new(CachedStore::with_defaults(inner));

        // Spawn N concurrent lookups; only one should reach the inner
        // store thanks to single-flight.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&cache);
            handles.push(tokio::spawn(
                async move { c.lookup_udp(addr("10.0.0.1")).await },
            ));
        }

        // Yield enough times that every spawned task has parked on the
        // pending slot before we release the gate.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        gate.notify_waiters();

        for h in handles {
            assert_eq!(h.await.unwrap().unwrap().id(), client.id());
        }
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn clear_drops_resolved_entries_only() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);

        // Resolve two entries; both end up in `Resolved` state.
        cache.lookup_udp(addr("10.0.0.1")).await;
        cache.lookup_udp(addr("10.0.0.2")).await;
        assert_eq!(cache.inner().calls(), 2);

        // `clear` evicts both resolved entries — next lookups must
        // hit the backend again.
        cache.clear();
        cache.lookup_udp(addr("10.0.0.1")).await;
        cache.lookup_udp(addr("10.0.0.2")).await;
        assert_eq!(cache.inner().calls(), 4);
    }

    #[tokio::test]
    async fn invalidate_is_noop_for_unknown_addr() {
        // Invalidating an addr we've never seen must not panic and
        // must not poison the cache for subsequent lookups.
        let client = Arc::new(Client::new(b"x".as_slice()));
        let inner = CountingStore::new(Some(Arc::clone(&client)));
        let cache = CachedStore::with_defaults(inner);
        cache.invalidate(IpAddr::V4("10.99.99.99".parse().unwrap()));
        assert!(cache.lookup_udp(addr("10.0.0.1")).await.is_some());
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn returned_future_is_send() {
        // Compile-time check that the future implements Send so the
        // server's spawn loop can park it across worker tasks.
        fn assert_send<T: Send>(_: &T) {}
        let inner = CountingStore::new(None);
        let cache = CachedStore::with_defaults(inner);
        let fut = cache.lookup_udp(addr("10.0.0.1"));
        assert_send(&fut);
        let boxed: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(fut);
        drop(boxed);
    }
}
