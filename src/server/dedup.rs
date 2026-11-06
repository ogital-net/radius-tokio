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
//! Expired entries are evicted lazily during `insert` (we sweep the
//! shard we're already locking). Lookups never sweep — under sustained
//! traffic with few duplicates, every packet is a miss followed by an
//! insert, so sweeping on both halves would do the O(n) walk twice per
//! packet for no benefit. The cache is bounded by lifetime, not
//! cardinality. Operators that need a hard cap should layer a rate
//! limiter on top.

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

#[allow(unused_imports)] // unused when the `metrics` feature is off
use crate::obs::metrics;

/// The four-tuple a RADIUS dedup cache keys on (RFC 5080 §2.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// Number of shards. 16 is plenty for the throughput levels this
/// crate targets and keeps the per-shard map small.
const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;

/// Bounded-lifetime, sharded dedup + retransmit cache.
#[derive(Debug)]
pub(crate) struct DedupCache {
    shards: [Mutex<HashMap<Key, Entry>>; SHARD_COUNT],
    in_flight: [Mutex<HashMap<Key, Weak<tokio::sync::Mutex<()>>>>; SHARD_COUNT],
    ttl: Duration,
}

impl DedupCache {
    /// Construct a new cache with the given entry TTL.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            in_flight: std::array::from_fn(|_| Mutex::new(HashMap::new())),
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
    pub(crate) async fn lock_request(&self, key: &Key) -> tokio::sync::OwnedMutexGuard<()> {
        let gate = {
            let mut shard = self.in_flight[Self::shard_for(key)]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            shard.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = shard.get(key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                shard.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        gate.lock_owned().await
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
        if let Some(entry) = shard.get(key) {
            if entry.expires_at > now {
                return Some(Arc::clone(&entry.reply));
            }
            shard.remove(key);
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
        // Sweep before insert so an active source doesn't grow the
        // shard unboundedly between misses.
        shard.retain(|_, e| e.expires_at > now);
        shard.insert(
            key,
            Entry {
                reply: Arc::from(reply),
                expires_at: now + self.ttl,
            },
        );
        // Gauge the just-locked shard's size as a cheap proxy for
        // load. Summing all shards on every insert would defeat the
        // point of sharding; this gives a per-shard signal that scales
        // ~linearly with overall occupancy.
        #[cfg(feature = "metrics")]
        {
            #[allow(clippy::cast_precision_loss)]
            let len = shard.len() as f64;
            gauge!(metrics::DEDUP_CACHE_SIZE, len, "shard" => idx.to_string());
        }
    }

    /// Test-only: total live entries across every shard.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
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
        let _other = cache.lock_request(&key(2)).await;
        let retained: usize = cache
            .in_flight
            .iter()
            .map(|shard| shard.lock().unwrap().len())
            .sum();
        assert!(retained <= 2);
    }
}
