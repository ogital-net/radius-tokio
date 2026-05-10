//! Example: a SQLite-backed `ClientStore`, fronted by `CachedStore`.
//!
//! Run with:
//!
//! ```text
//! cargo run --example sqlite_clients
//! ```
//!
//! ## Why this example
//!
//! The library deliberately does not bundle a database integration —
//! every deployment has its own schema, connection pooling, and
//! freshness requirements. This file shows the recommended shape:
//!
//! 1. Implement [`ClientStore`] over your real backend. The lookup
//!    is `async`, but most database drivers (rusqlite included) are
//!    synchronous; bridge that with [`tokio::task::spawn_blocking`]
//!    so the lookup doesn't stall the runtime worker.
//! 2. Wrap the result in [`CachedStore`] so the steady-state hot
//!    path stays in memory. The cache absorbs both repeat hits from
//!    a chatty NAS and repeat misses from a port-scanner.
//!
//! Plug the wrapped store into `Server::builder().clients(...)` —
//! the rest of the pipeline doesn't know or care that there is a
//! database behind the trait.
//!
//! ## What's intentionally omitted
//!
//! * Connection pooling. A real deployment should use a pool
//!   (`r2d2_sqlite`, `deadpool`, …) instead of opening a single
//!   `Connection` behind a mutex.
//! * Schema migrations. The `clients` table is created inline.
//! * Authn / authz beyond the shared secret lookup.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use radius_tokio::server::{CacheConfig, CachedStore, Client, ClientStore};
use rusqlite::{params, Connection, OptionalExtension};

/// `ClientStore` backed by a `SQLite` database.
///
/// The single `Connection` lives behind a `std::sync::Mutex`; lookups
/// are bridged onto Tokio's blocking pool so the (synchronous)
/// `rusqlite` call doesn't block a runtime worker.
pub struct SqliteClients {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteClients {
    /// Open (or create) the database at `path` and ensure the
    /// `clients` table exists.
    ///
    /// # Errors
    ///
    /// Surfaces any `rusqlite` error from `open` or `execute`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS clients (
                ip      TEXT PRIMARY KEY,
                secret  BLOB NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert or replace the secret for `ip`.
    ///
    /// # Errors
    ///
    /// Surfaces any `rusqlite` error from `execute`.
    ///
    /// # Panics
    ///
    /// Panics if the connection mutex was poisoned by a prior
    /// panic. A real deployment would use a connection pool and
    /// would not surface this case.
    pub fn upsert(&self, ip: IpAddr, secret: &[u8]) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO clients (ip, secret) VALUES (?1, ?2)",
            params![ip.to_string(), secret],
        )?;
        Ok(())
    }
}

impl ClientStore for SqliteClients {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let conn = Arc::clone(&self.conn);
        let ip = src.ip().to_string();
        async move {
            // SQLite calls are blocking; hand them off to the
            // dedicated blocking pool so the runtime worker stays
            // free to drive other futures.
            let secret: Option<Vec<u8>> = tokio::task::spawn_blocking(move || {
                let conn = conn.lock().expect("sqlite mutex poisoned");
                conn.query_row(
                    "SELECT secret FROM clients WHERE ip = ?1",
                    params![ip],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .ok()
                .flatten()
            })
            .await
            .ok()
            .flatten();

            secret.map(|bytes| Arc::new(Client::new(bytes.as_slice())))
        }
    }
}

#[tokio::main]
async fn main() {
    // In-memory database for the example; pass a real path in
    // production. `:memory:` creates a transient DB that lives only
    // for the lifetime of this `Connection`.
    let backend = SqliteClients::open(":memory:").expect("open sqlite");

    // Seed two NASes.
    let alpha_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    let beta_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
    backend.upsert(alpha_ip, b"alpha-secret").unwrap();
    backend.upsert(beta_ip, b"beta-secret").unwrap();

    // Wrap the slow backend in `CachedStore`. The first lookup for
    // each IP hits SQLite; subsequent lookups within the positive
    // TTL are served from memory.
    let store = CachedStore::new(
        backend,
        CacheConfig {
            positive_ttl: Duration::from_secs(60),
            // Keep negative TTL short so a NAS that gets added a
            // second after a probe still works without restarting.
            negative_ttl: Duration::from_millis(500),
        },
    );

    // Cold lookup: goes to SQLite.
    let hit = store
        .lookup_udp(SocketAddr::new(alpha_ip, 1812))
        .await
        .expect("alpha is registered");
    println!("cold lookup: alpha id = {:?}", hit.id());

    // Hot lookup: served from the cache, never touches SQLite.
    let again = store
        .lookup_udp(SocketAddr::new(alpha_ip, 1812))
        .await
        .expect("still cached");
    println!(
        "hot lookup:  alpha id = {:?} (same Arc address: {})",
        again.id(),
        Arc::ptr_eq(&hit, &again)
    );

    // Unknown IP: also cached, briefly, so a port-scanner can't
    // hammer the database.
    let unknown: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
    assert!(store
        .lookup_udp(SocketAddr::new(unknown, 1812))
        .await
        .is_none());
    println!(
        "unknown ip cached as miss for {:?}",
        Duration::from_millis(500)
    );

    // To plug this into a real `Server`:
    //
    // ```ignore
    // Server::builder()
    //     .clients(Arc::new(store))
    //     .handler(MyHandler)
    //     .listen_udp("0.0.0.0:1812".parse()?)
    //     .run()
    //     .await?;
    // ```
}
