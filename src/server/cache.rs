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

use std::collections::{BTreeSet, HashMap};
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
///
/// Stores at most 65,536 entries by default. Expired entries are
/// cleaned incrementally, and capacity pressure evicts the earliest
/// resolved deadline. Use [`Self::with_capacity`] to change the limit.
#[derive(Debug)]
pub struct CachedStore<S> {
    inner: S,
    config: CacheConfig,
    state: Mutex<CacheState>,
    capacity: usize,
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

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<IpAddr, Slot>,
    expirations: BTreeSet<(Instant, IpAddr)>,
}

impl CacheState {
    fn remove(&mut self, key: &IpAddr) {
        if let Some(Slot::Resolved { expires_at, .. }) = self.entries.remove(key) {
            self.expirations.remove(&(expires_at, *key));
        }
    }

    fn evict_first(&mut self) {
        if let Some((_, key)) = self.expirations.pop_first() {
            self.entries.remove(&key);
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        for _ in 0..64 {
            if self
                .expirations
                .first()
                .is_none_or(|(deadline, _)| *deadline > now)
            {
                break;
            }
            self.evict_first();
        }
    }

    fn action(&mut self, key: IpAddr, now: Instant, capacity: usize) -> Action {
        self.evict_expired(now);
        match self.entries.get(&key) {
            Some(Slot::Resolved { value, expires_at }) if *expires_at > now => {
                return Action::Hit(value.clone());
            }
            Some(Slot::Pending(tx)) => return Action::Wait(tx.subscribe()),
            _ => {}
        }
        self.remove(&key);
        if self.entries.len() >= capacity {
            self.evict_first();
        }
        if self.entries.len() >= capacity {
            return Action::Uncached;
        }
        let (tx, _) = broadcast::channel(1);
        self.entries.insert(key, Slot::Pending(tx.clone()));
        Action::Resolve(tx)
    }
}

impl<S> CachedStore<S> {
    /// Wrap `inner` with the given cache configuration.
    #[must_use]
    pub fn new(inner: S, config: CacheConfig) -> Self {
        Self::with_capacity(inner, config, 65_536)
    }

    /// Wrap `inner` with a hard limit on resolved and pending entries.
    /// If all slots are pending, new keys bypass caching rather than
    /// interrupting existing single-flight lookups.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn with_capacity(inner: S, config: CacheConfig, capacity: usize) -> Self {
        assert!(capacity > 0, "client cache capacity must be positive");
        Self {
            inner,
            config,
            state: Mutex::new(CacheState::default()),
            capacity,
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
    /// In-flight lookups are left alone and may still populate the cache.
    pub fn invalidate(&self, addr: IpAddr) {
        let mut map = self.lock_state();
        if let Some(Slot::Resolved { .. }) = map.entries.get(&addr) {
            map.remove(&addr);
            debug!(event = "client_cache_invalidate", %addr);
            #[cfg(feature = "metrics")]
            {
                #[allow(clippy::cast_precision_loss)]
                let len = map.entries.len() as f64;
                gauge!(metrics::CLIENT_CACHE_SIZE, len);
            }
        }
    }

    /// Drop every resolved entry and release unused map capacity.
    /// In-flight lookups are not interrupted.
    pub fn clear(&self) {
        let mut map = self.lock_state();
        let before = map.entries.len();
        map.entries
            .retain(|_, slot| matches!(slot, Slot::Pending(_)));
        map.expirations.clear();
        map.entries.shrink_to_fit();
        let evicted = before.saturating_sub(map.entries.len());
        debug!(event = "client_cache_clear", evicted = evicted);
        let _ = evicted;
        #[cfg(feature = "metrics")]
        {
            #[allow(clippy::cast_precision_loss)]
            let len = map.entries.len() as f64;
            gauge!(metrics::CLIENT_CACHE_SIZE, len);
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, CacheState> {
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
    Uncached,
}

struct PendingLookup<'a, S> {
    cache: &'a CachedStore<S>,
    key: IpAddr,
    tx: broadcast::Sender<Option<Arc<Client>>>,
}

impl<S> Drop for PendingLookup<'_, S> {
    fn drop(&mut self) {
        let mut map = self.cache.lock_state();
        if matches!(map.entries.get(&self.key), Some(Slot::Pending(current)) if current.same_channel(&self.tx))
        {
            map.remove(&self.key);
        }
    }
}

impl<S: ClientStore> ClientStore for CachedStore<S> {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let key = src.ip();
        let now = Instant::now();

        let action = self.lock_state().action(key, now, self.capacity);

        if matches!(action, Action::Hit(_)) {
            trace!(event = "client_cache_hit", %src);
            count!(metrics::CLIENT_CACHE_HITS);
        }

        let pending = match &action {
            Action::Resolve(tx) => Some(PendingLookup {
                cache: self,
                key,
                tx: tx.clone(),
            }),
            _ => None,
        };

        async move {
            let _pending = pending;
            match action {
                Action::Hit(value) => value,
                Action::Uncached => self.inner.lookup_udp(src).await,
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
                        map.entries.insert(
                            key,
                            Slot::Resolved {
                                value: value.clone(),
                                expires_at,
                            },
                        );
                        map.expirations.insert((expires_at, key));
                        #[cfg(feature = "metrics")]
                        {
                            #[allow(clippy::cast_precision_loss)]
                            let len = map.entries.len() as f64;
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

    #[tokio::test]
    async fn dropping_unpolled_resolver_allows_retry() {
        let cache = CachedStore::with_defaults(CountingStore::new(None));
        let src = addr("10.0.0.1");
        drop(cache.lookup_udp(src));
        tokio::time::timeout(Duration::from_secs(1), cache.lookup_udp(src))
            .await
            .expect("abandoned lookup must not leave a pending slot");
        assert_eq!(cache.inner().calls(), 1);
    }

    #[tokio::test]
    async fn cancelling_running_resolver_allows_retry() {
        let gate = Arc::new(Notify::new());
        let cache = CachedStore::with_defaults(CountingStore::with_gate(None, gate.clone()));
        let src = addr("10.0.0.1");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), cache.lookup_udp(src))
                .await
                .is_err()
        );
        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(1), cache.lookup_udp(src))
            .await
            .expect("cancelled resolver must allow a new lookup");
        assert_eq!(cache.inner().calls(), 2);
    }

    #[tokio::test]
    async fn cancelling_resolver_wakes_existing_waiter() {
        use std::task::Poll;

        let gate = Arc::new(Notify::new());
        let cache = CachedStore::with_defaults(CountingStore::with_gate(None, gate.clone()));
        let src = addr("10.0.0.1");
        let mut resolver = Box::pin(cache.lookup_udp(src));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(resolver.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let mut waiter = Box::pin(cache.lookup_udp(src));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(resolver);
        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("cancelled resolver must wake waiters");
        assert_eq!(cache.inner().calls(), 2);
    }

    #[tokio::test]
    async fn expired_negative_entries_are_removed_during_source_churn() {
        let cache = CachedStore::new(
            CountingStore::new(None),
            CacheConfig {
                positive_ttl: Duration::ZERO,
                negative_ttl: Duration::ZERO,
            },
        );
        for counter in 0..1000u32 {
            cache
                .lookup_udp(SocketAddr::from((Ipv4Addr::from(counter), 1812)))
                .await;
            let state = cache.lock_state();
            assert!(state.entries.len() <= 1);
            assert!(state.expirations.len() <= 1);
        }
    }

    #[tokio::test]
    async fn capacity_bounds_live_entries_and_clear_releases_buckets() {
        let cache = CachedStore::with_capacity(CountingStore::new(None), CacheConfig::default(), 8);
        for counter in 0..1000u32 {
            cache
                .lookup_udp(SocketAddr::from((Ipv4Addr::from(counter), 1812)))
                .await;
            let state = cache.lock_state();
            assert!(state.entries.len() <= 8);
            assert_eq!(state.entries.len(), state.expirations.len());
        }
        cache.clear();
        let state = cache.lock_state();
        assert!(state.entries.is_empty());
        assert!(state.expirations.is_empty());
        assert_eq!(state.entries.capacity(), 0);
    }

    #[tokio::test]
    async fn capacity_pressure_preserves_pending_resolvers() {
        let cache = CachedStore::with_capacity(CountingStore::new(None), CacheConfig::default(), 1);
        let first = addr("10.0.0.1");
        let pending = cache.lookup_udp(first);
        cache.lookup_udp(addr("10.0.0.2")).await;
        assert!(matches!(
            cache.lock_state().entries.get(&first.ip()),
            Some(Slot::Pending(_))
        ));
        assert_eq!(cache.lock_state().entries.len(), 1);
        pending.await;
        assert_eq!(cache.inner().calls(), 2);
        assert!(cache.lock_state().entries.contains_key(&first.ip()));
    }
}
