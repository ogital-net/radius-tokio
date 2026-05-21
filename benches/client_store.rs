//! [`StaticClients`] lookup-throughput benchmarks at varying table
//! sizes. The performance budget calls out 10k-client
//! tables; we sweep 10 / 100 / 1 000 / 10 000 to make any super-linear
//! growth visible.

#![allow(missing_docs)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use radius_tokio::server::{CacheConfig, CachedStore, Client, ClientStore, IpCidr, StaticClients};

fn build_store(n: u32) -> StaticClients {
    let mut b = StaticClients::builder();
    for i in 0..n {
        let octets = i.to_be_bytes();
        let addr = Ipv4Addr::new(10, octets[1], octets[2], octets[3]);
        b = b.add(
            IpCidr::host(IpAddr::V4(addr)),
            Arc::new(Client::new(b"secret".as_slice())),
        );
    }
    b.build()
}

fn poll_now<F: std::future::Future>(fut: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
    const RAW: RawWaker = RawWaker::new(std::ptr::null(), &VTABLE);
    // SAFETY: the no-op vtable does nothing with the data pointer.
    let waker = unsafe { Waker::from_raw(RAW) };
    let mut cx = Context::from_waker(&waker);
    match pin!(fut).poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("StaticClients lookup must be ready immediately"),
    }
}

fn bench_static(c: &mut Criterion) {
    // Worst-case hit: target is the last inserted entry, so a linear
    // scan walks the entire table.
    let mut g = c.benchmark_group("client_store/static_lookup_hit_last");
    for &n in &[10u32, 100, 1_000, 10_000] {
        let store = build_store(n);
        let last = n - 1;
        let octets = last.to_be_bytes();
        let target = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3])),
            1812,
        );
        g.bench_with_input(BenchmarkId::from_parameter(n), &store, |b, store| {
            b.iter(|| {
                let hit = poll_now(store.lookup_udp(black_box(target)));
                black_box(hit.is_some());
            });
        });
    }
    g.finish();

    // Miss path: same scan cost regardless of address, but no clone.
    let mut g = c.benchmark_group("client_store/static_lookup_miss");
    for &n in &[10u32, 100, 1_000, 10_000] {
        let store = build_store(n);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 1812);
        g.bench_with_input(BenchmarkId::from_parameter(n), &store, |b, store| {
            b.iter(|| {
                let hit = poll_now(store.lookup_udp(black_box(target)));
                black_box(hit.is_some());
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_static, bench_cached);
criterion_main!(benches);

fn bench_cached(c: &mut Criterion) {
    // 10k-client inner table — the worst case from the static
    // benchmark above. The cache should make every steady-state
    // lookup independent of inner table size.
    let inner = build_store(10_000);
    let cache = CachedStore::new(
        inner,
        CacheConfig {
            positive_ttl: std::time::Duration::from_secs(3600),
            negative_ttl: std::time::Duration::from_secs(3600),
        },
    );

    // Warm both a hit and a miss into the cache so the steady-state
    // path never re-enters the inner store.
    let hit_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 1812);
    let miss_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 1812);
    poll_now(cache.lookup_udp(hit_target));
    poll_now(cache.lookup_udp(miss_target));

    let mut g = c.benchmark_group("client_store/cached");
    g.bench_function("hit_warm", |b| {
        b.iter(|| {
            let v = poll_now(cache.lookup_udp(black_box(hit_target)));
            black_box(v.is_some());
        });
    });
    g.bench_function("miss_warm", |b| {
        b.iter(|| {
            let v = poll_now(cache.lookup_udp(black_box(miss_target)));
            black_box(v.is_some());
        });
    });
    g.finish();
}
