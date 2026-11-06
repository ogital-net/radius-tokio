//! Per-source request deduplication and reply retransmit cache.
//!
//! RFC 5080 §2.2.2 requires a RADIUS server to detect duplicate
//! requests (same NAS retransmitting because it didn't see our reply
//! in time) and resend the cached reply rather than re-running the
//! handler. The cache key is the four-tuple `(src, code, identifier,
//! request-authenticator)`; the value is the previously-sent reply
//! bytes plus an expiry deadline.
//!
//! # Sharding
//!
//! A single `Mutex<HashMap>` would serialize the entire receive loop
//! on its critical section. We split the table into a fixed number of
//! shards (power-of-two for cheap masking) keyed by the bottom bits
//! of the four-tuple's hash, so concurrent traffic from many sources
//! contends only inside its own shard.
//!
//! # Sweep
//!
//! Expired entries are indexed by deadline and evicted lazily during
//! `insert`, with a fixed cleanup budget per insertion. Unexpired
//! entries are never scanned. The cache is bounded by lifetime, not
//! cardinality. Operators that need a hard cap should layer a rate
//! limiter on top.

use std::collections::{BTreeSet, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

#[allow(unused_imports)] // unused when the `metrics` feature is off
use crate::obs::metrics;

/// The four-tuple a RADIUS dedup cache keys on (RFC 5080 §2.2.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Key {
    pub src: SocketAddr,
    pub code: u8,
    pub identifier: u8,
    pub request_authenticator: [u8; 16],
}

#[derive(Debug)]
struct Entry {
    reply: Arc<[u8]>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct ReplyShard {
    entries: HashMap<Key, Entry>,
    expirations: BTreeSet<(Instant, Key)>,
}

impl ReplyShard {
    fn evict_expired(&mut self, now: Instant) {
        for _ in 0..64 {
            let Some((deadline, _)) = self.expirations.first() else {
                break;
            };
            if *deadline > now {
                break;
            }
            if let Some((_, key)) = self.expirations.pop_first() {
                self.entries.remove(&key);
            }
        }
    }
}

/// Number of shards. 16 is plenty for the throughput levels this
/// crate targets and keeps the per-shard map small.
const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;

type RequestGate = tokio::sync::Mutex<RequestCleanup>;
type RequestShard = Arc<Mutex<HashMap<Key, Weak<RequestGate>>>>;

#[derive(Debug)]
struct RequestCleanup {
    gate: Weak<RequestGate>,
    shard: RequestShard,
    key: Key,
}

impl Drop for RequestCleanup {
    fn drop(&mut self) {
        let mut shard = self
            .shard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if shard
            .get(&self.key)
            .is_some_and(|gate| Weak::ptr_eq(gate, &self.gate))
        {
            shard.remove(&self.key);
        }
    }
}

/// Held while processing a request; releases its lock before its gate.
pub(crate) struct RequestReservation {
    _guard: tokio::sync::OwnedMutexGuard<RequestCleanup>,
}

/// Bounded-lifetime, sharded dedup + retransmit cache.
#[derive(Debug)]
pub(crate) struct DedupCache {
    shards: [Mutex<ReplyShard>; SHARD_COUNT],
    in_flight: [RequestShard; SHARD_COUNT],
    ttl: Duration,
}

impl DedupCache {
    /// Construct a new cache with the given entry TTL.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(ReplyShard::default())),
            in_flight: std::array::from_fn(|_| Arc::new(Mutex::new(HashMap::new()))),
            ttl,
        }
    }

    fn shard_for(key: &Key) -> usize {
        let mut h = BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default()
            .build_hasher();
        std::hash::Hash::hash(key, &mut h);
        // SHARD_MASK fits in usize on every supported target; the
        // mask discards the high bits we care nothing about.
        #[allow(clippy::cast_possible_truncation)]
        let bucket = h.finish() as usize;
        bucket & SHARD_MASK
    }

    /// Serialize processing of one request key, releasing on cancellation.
    pub(crate) async fn lock_request(&self, key: &Key) -> RequestReservation {
        let request_shard = &self.in_flight[Self::shard_for(key)];
        let gate = {
            let mut shard = request_shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(gate) = shard.get(key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new_cyclic(|gate| {
                    tokio::sync::Mutex::new(RequestCleanup {
                        gate: gate.clone(),
                        shard: Arc::clone(request_shard),
                        key: key.clone(),
                    })
                });
                shard.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        RequestReservation {
            _guard: gate.lock_owned().await,
        }
    }

    /// Look up a cached reply. Returns `None` on miss or expiry.
    ///
    /// On a hit the returned handle is a cheap [`Arc`] clone — no
    /// allocation, no copy of the reply bytes.
    pub(crate) fn lookup(&self, key: &Key) -> Option<Arc<[u8]>> {
        let idx = Self::shard_for(key);
        // Lock-poison recovery: we own the data, a poisoned lock just
        // means a previous holder panicked. The cache is best-effort
        // anyway — fall back to the inner data.
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if let Some(entry) = shard.entries.get(key) {
            if entry.expires_at > now {
                return Some(Arc::clone(&entry.reply));
            }
            let expires_at = entry.expires_at;
            shard.entries.remove(key);
            shard.expirations.remove(&(expires_at, key.clone()));
        }
        None
    }

    /// Insert (or refresh) a cached reply.
    pub(crate) fn insert(&self, key: Key, reply: &[u8]) {
        let idx = Self::shard_for(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        shard.evict_expired(now);
        let expires_at = now + self.ttl;
        if let Some(previous) = shard.entries.insert(
            key.clone(),
            Entry {
                reply: Arc::from(reply),
                expires_at,
            },
        ) {
            shard
                .expirations
                .remove(&(previous.expires_at, key.clone()));
        }
        shard.expirations.insert((expires_at, key));
        // Gauge the just-locked shard's size as a cheap proxy for
        // load. Summing all shards on every insert would defeat the
        // point of sharding; this gives a per-shard signal that scales
        // ~linearly with overall occupancy.
        #[cfg(feature = "metrics")]
        {
            #[allow(clippy::cast_precision_loss)]
            let len = shard.entries.len() as f64;
            gauge!(metrics::DEDUP_CACHE_SIZE, len, "shard" => idx.to_string());
        }
    }

    /// Test-only: total live entries across every shard.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap().entries.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(id: u8) -> Key {
        Key {
            src: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345),
            code: 1,
            identifier: id,
            request_authenticator: [id; 16],
        }
    }

    #[test]
    fn miss_then_hit() {
        let cache = DedupCache::new(Duration::from_secs(30));
        assert!(cache.lookup(&key(1)).is_none());
        cache.insert(key(1), b"reply-bytes");
        assert_eq!(&*cache.lookup(&key(1)).unwrap(), b"reply-bytes");
    }

    #[test]
    fn expiry_evicts() {
        let cache = DedupCache::new(Duration::from_millis(0));
        cache.insert(key(2), b"x");
        // Any positive elapsed time exceeds zero TTL.
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.lookup(&key(2)).is_none());
        assert_eq!(cache.len(), 0, "lookup miss should sweep the shard");
    }

    #[test]
    fn distinct_keys_independent() {
        let cache = DedupCache::new(Duration::from_secs(30));
        cache.insert(key(1), b"a");
        cache.insert(key(2), b"b");
        assert_eq!(&*cache.lookup(&key(1)).unwrap(), b"a");
        assert_eq!(&*cache.lookup(&key(2)).unwrap(), b"b");
    }

    #[test]
    fn refresh_keeps_one_expiration_per_reply() {
        let cache = DedupCache::new(Duration::from_secs(30));
        for _ in 0..100 {
            cache.insert(key(1), b"latest reply");
        }
        let shard = cache.shards[DedupCache::shard_for(&key(1))].lock().unwrap();
        assert_eq!(shard.entries.len(), 1);
        assert_eq!(shard.expirations.len(), 1);
        assert!(shard
            .expirations
            .contains(&(shard.entries[&key(1)].expires_at, key(1))));
    }

    #[test]
    fn expiration_cleanup_is_bounded_and_preserves_live_replies() {
        let mut shard = ReplyShard::default();
        let now = Instant::now();
        for identifier in 0..129 {
            let expires_at = if identifier == 128 {
                now + Duration::from_secs(30)
            } else {
                now
            };
            shard.entries.insert(
                key(identifier),
                Entry {
                    reply: Arc::from(b"reply".as_slice()),
                    expires_at,
                },
            );
            shard.expirations.insert((expires_at, key(identifier)));
        }
        shard.evict_expired(now);
        assert_eq!(shard.entries.len(), 65);
        assert_eq!(shard.expirations.len(), 65);
        shard.evict_expired(now);
        assert_eq!(shard.entries.len(), 1);
        assert!(shard.entries.contains_key(&key(128)));
        assert_eq!(shard.expirations.len(), 1);
    }

    #[tokio::test]
    async fn cancellation_releases_request_reservation() {
        use std::future::Future;
        use std::task::Poll;

        let cache = DedupCache::new(Duration::from_secs(30));
        let request_key = key(1);
        let owner = cache.lock_request(&request_key).await;
        let mut waiter = Box::pin(cache.lock_request(&request_key));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(owner);
        let next = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("reservation must release on cancellation");
        drop(next);
        drop(cache.lock_request(&key(2)).await);
        let retained: usize = cache
            .in_flight
            .iter()
            .map(|shard| shard.lock().unwrap().len())
            .sum();
        assert_eq!(retained, 0);
    }

    #[tokio::test]
    async fn cancelling_waiter_and_owner_removes_reservation_metadata() {
        use std::future::Future;
        use std::task::Poll;

        let cache = DedupCache::new(Duration::from_secs(30));
        let request_key = key(1);
        let owner = cache.lock_request(&request_key).await;
        let mut waiter = Box::pin(cache.lock_request(&request_key));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(waiter);
        assert_eq!(
            cache.in_flight[DedupCache::shard_for(&request_key)]
                .lock()
                .unwrap()
                .len(),
            1
        );
        drop(owner);
        assert!(cache.in_flight[DedupCache::shard_for(&request_key)]
            .lock()
            .unwrap()
            .is_empty());
    }
}
