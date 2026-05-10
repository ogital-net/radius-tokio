//! Example: an in-memory, runtime-mutable `ClientStore` built on
//! `arc-swap`.
//!
//! Run with:
//!
//! ```text
//! cargo run --example mutable_clients
//! ```
//!
//! ## Why this lives in `examples/`
//!
//! `radius-tokio` deliberately ships only one built-in store
//! ([`StaticClients`](radius_tokio::server::StaticClients)) plus the
//! generic [`CachedStore`](radius_tokio::server::CachedStore)
//! wrapper. Mutable in-memory tables come in too many flavours
//! (exact-IP keying vs. CIDR, atomic multi-row swaps, change
//! notification, eviction policy, …) for the library to pick a
//! one-size-fits-all answer. The `ClientStore` trait is small enough
//! that consumers can roll their own in a few dozen lines — this
//! file is a sketch you can copy-paste.
//!
//! ## Pattern
//!
//! State is held inside an `arc_swap::ArcSwap<HashMap<IpAddr,
//! Arc<Client>>>`. Reads (`lookup_udp`) load the current snapshot
//! lock-free; writes (`upsert`, `remove`) clone the map, mutate the
//! clone, and atomically publish it. Inflight readers keep their
//! snapshot alive via `Arc`, so a write never blocks or invalidates
//! a request that's already being served.
//!
//! This is the right shape when:
//! * The full client set fits comfortably in memory.
//! * Updates are rare relative to lookups (a few writes per second
//!   against thousands of lookups per second).
//! * You want zero contention on the hot path.
//!
//! It is *not* the right shape when updates dominate (use a sharded
//! `DashMap`) or when the table is too large to copy on every write
//! (use a database-backed store fronted by `CachedStore`).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use radius_tokio::server::{Client, ClientStore};

/// Runtime-mutable `ClientStore` keyed by exact source IP.
///
/// CIDR matching is intentionally omitted — keep the example small.
/// Add a `Vec<(IpCidr, Arc<Client>)>` alongside the map if you need
/// it, or wrap [`StaticClients`] for the prefix lookups and use this
/// type for per-host overrides.
pub struct MutableClients {
    table: ArcSwap<HashMap<IpAddr, Arc<Client>>>,
}

impl MutableClients {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Insert or replace the entry for `addr`.
    ///
    /// Atomic: the swap is a single pointer store. Concurrent
    /// lookups either see the old map or the new one; never a
    /// half-built state.
    pub fn upsert(&self, addr: IpAddr, client: &Arc<Client>) {
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(addr, Arc::clone(client));
            next
        });
    }

    /// Remove the entry for `addr`, if any.
    pub fn remove(&self, addr: IpAddr) {
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            next.remove(&addr);
            next
        });
    }

    /// Number of entries currently published.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.load().len()
    }

    /// `true` if the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MutableClients {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientStore for MutableClients {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // `load` returns a `Guard<Arc<Map>>`; clone the inner Arc
        // out of the entry so we don't hold the guard across the
        // await point. (There is no real await here, but writing it
        // this way keeps the future `Send` for any inner type.)
        let snapshot = self.table.load();
        let result = snapshot.get(&src.ip()).map(Arc::clone);
        async move { result }
    }
}

#[tokio::main]
async fn main() {
    let store = MutableClients::new();

    // Seed two NASes.
    let alpha_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    let beta_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
    store.upsert(alpha_ip, &Arc::new(Client::new(b"alpha-secret".as_slice())));
    store.upsert(beta_ip, &Arc::new(Client::new(b"beta-secret".as_slice())));
    println!("seeded: {} clients", store.len());

    // Look one up.
    let hit = store
        .lookup_udp(SocketAddr::new(alpha_ip, 1812))
        .await
        .expect("alpha is registered");
    println!(
        "alpha id = {:?}, secret bytes = {}",
        hit.id(),
        hit.secret().len()
    );

    // Add a third entry while a "lookup" is in flight. The earlier
    // `hit` Arc keeps pointing at alpha regardless of what happens
    // to the table.
    let gamma_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();
    store.upsert(gamma_ip, &Arc::new(Client::new(b"gamma-secret".as_slice())));
    println!("after upsert: {} clients", store.len());

    // Revoke beta. Subsequent lookups for that IP miss; any request
    // already dispatched against the prior snapshot still completes
    // safely with the old `Arc<Client>`.
    store.remove(beta_ip);
    assert!(store
        .lookup_udp(SocketAddr::new(beta_ip, 1812))
        .await
        .is_none());
    println!("after remove: {} clients", store.len());

    // To plug this into a real `Server`, just hand it to the
    // builder:
    //
    // ```ignore
    // Server::builder()
    //     .clients(Arc::new(store))
    //     .handler(MyHandler)
    //     .listen_udp("0.0.0.0:1812".parse()?)
    //     .run()
    //     .await?;
    // ```
    //
    // For DB-backed stores, wrap your `ClientStore` impl in
    // `CachedStore::with_defaults(...)` to absorb repeat lookups.
}
