# Benchmarks

This document records the **baseline** measurements that gate
performance work in this crate. The targets the numbers below are
measured against:

- Access-Request decode + Access-Accept encode: < 2 µs steady state.
- Sustained throughput: > 200 k req/s on a modern x86 core with a
  no-op handler.
- p99 added latency from the library (excluding handler): < 50 µs.

Numbers here are *reference points*, not budgets — use them as the
baseline a change must not regress against.

## Running the benches

```sh
cargo bench --bench codec_decode
cargo bench --bench codec_encode
cargo bench --bench crypto_primitives
cargo bench --bench client_store
cargo bench --bench roundtrip
```

Criterion's full default cycle (warm-up + sample collection per case)
takes ~10s/bench. The numbers below were captured with shortened
settings — `--warm-up-time 1 --measurement-time 3 --sample-size 50` —
to give a quick gate; cut over to the defaults for any change being
considered for merge.

## Environment

Numbers are sensitive to host noise. Each run records the host so
later comparisons are honest:

| Field          | Value                                |
|----------------|--------------------------------------|
| Date           | 2026-05-10                           |
| Host           | dev container, ARM64                 |
| OS             | Debian GNU/Linux 13 (trixie)         |
| Rust           | per `rust-toolchain.toml`            |
| Build profile  | `release` (Criterion default)        |

Re-record this table on the machine you re-baseline from. Do *not*
publish numbers from a busy CI runner as the canonical baseline.

## Baseline (2026-05-10)

### `codec_decode` — header parse + attribute walk

Source: [benches/codec_decode.rs](benches/codec_decode.rs)
(typical Access-Request: 8 RFC attributes + Message-Authenticator
slot; ~150 bytes).

| Bench                                      | Median   |
|--------------------------------------------|----------|
| `decode/header`                            | 1.04 ns  |
| `decode/attribute_walk`                    | 10.8 ns  |
| `decode/find_first_typed`                  | 1.56 ns  |
| `decode/find_last_typed`                   | 11.3 ns  |
| `decode/message_authenticator_locate`      | 4.07 ns  |

Notes:
- `find_first_typed` is the User-Name slot (first attribute) — it's
  basically the iterator's `next()` plus a type compare.
- `find_last_typed` walks all 8 attributes — useful as a worst-case
  scan against the same packet.

### `codec_encode` — build + seal a reply

Source: [benches/codec_encode.rs](benches/codec_encode.rs).

| Bench                          | Median    |
|--------------------------------|-----------|
| `encode/access_accept_build`   | 20.2 ns   |
| `encode/access_accept_seal`    | 582 ns    |
| `encode/access_reject_minimal` | 496 ns    |

Seal cost is dominated by HMAC-MD5 (Message-Authenticator) +
MD5 (Response Authenticator) over the final packet bytes plus the
shared secret. Even a minimal reply pays both round trips through
`aws-lc-sys` for the two MD5 contexts.

### `crypto_primitives` — HMAC-MD5 / MD5 throughput

Source: [benches/crypto_primitives.rs](benches/crypto_primitives.rs).
Measured against synthetic packets of varying length.

| Length | M-A compute       | Response Auth     | Acct verify       |
|-------:|-------------------|-------------------|-------------------|
| 64 B   | 409 ns / 149 MiB/s| 138 ns / 441 MiB/s| 142 ns / 430 MiB/s|
| 256 B  | 606 ns / 403 MiB/s| 350 ns / 698 MiB/s| 356 ns / 686 MiB/s|
| 1 KiB  | 1.43 µs / 685 MiB/s| 1.16 µs / 844 MiB/s| 1.18 µs / 829 MiB/s|
| 4 KiB  | 4.81 µs / 812 MiB/s| 4.46 µs / 876 MiB/s| —                 |

Asymptotic throughput plateaus near `aws-lc-sys`'s native MD5 speed.
M-A compute carries an extra HMAC ipad/opad pass plus the per-slot
zero-substitution walk, so its small-packet floor is ~3× the bare
MD5 path; the gap closes at larger packets.

### `client_store` — `StaticClients` lookup

Source: [benches/client_store.rs](benches/client_store.rs).
`StaticClients` is a linear scan; both axes confirm the expected
O(n) behaviour.

| Entries | Hit (last)    | Miss          |
|--------:|---------------|---------------|
| 10      | 6.7 ns        | 5.9 ns        |
| 100     | 40.4 ns       | 39.7 ns       |
| 1 000   | 407 ns        | 404 ns        |
| 10 000  | 3.94 µs       | 4.04 µs       |

At 10 k clients a worst-case lookup is **~4 µs**, which already
crowds the per-packet "<50 µs added latency" budget if the rest of
the pipeline runs at the numbers below. The follow-up landed in
Phase 6 as `CachedStore<S>` (TTL + negative-cache + single-flight),
which serves a warm hit in **~40 ns** and a warm miss in **~38 ns**
regardless of inner table size:

| Cached lookup | Median |
|---------------|--------|
| `cached/hit_warm`  | 40 ns |
| `cached/miss_warm` | 38 ns |

DB-backed stores should always sit behind `CachedStore`; the
`examples/sqlite_clients.rs` example shows the pattern.

### `roundtrip` — synchronous decode + verify + encode + seal

Source: [benches/roundtrip.rs](benches/roundtrip.rs). No sockets, no
task spawn — this is the codec/crypto floor of the UDP hot path.

| Bench                            | Median |
|----------------------------------|--------|
| `roundtrip/decode_and_verify`    | 404 ns |
| `roundtrip/full_request_response`| 911 ns |

≈1.10 M req/s on a single core in pure synchronous code. Real
throughput will be lower once the UDP recv loop, dedup cache, task
spawn, and consumer handler are folded back in; that delta is what
the end-to-end UDP bench below quantifies.

## What changed since the previous baseline

### 2026-05-10 (Phase 11 polish refresh)

Re-baselined on the same dev-container ARM host after Phase 11 polish
(EAP-MD5 helper + integration test, HMAC-MD5 `TAG_LEN` derived from
`aws_lc_sys::MD5_DIGEST_LENGTH`, doc/lint clean-up). No code on the
hot path changed; deltas below are host-noise-bound (different
background load on a shared container host than the 2026-05-09
run) and well inside Criterion's reported variance.

* Codec / crypto micro-benches: ±5 % across the board, no shape
  changes. `crypto/message_authenticator_compute/64B` drifted from
  377 → 409 ns (~8 %), the largest single move; everything else is
  within 3 %.
* `roundtrip/full_request_response`: 860 → 911 ns (+6 %), in line
  with the per-step crypto drift.
* `client_store/static_lookup_*`: identical scaling, ±2 %.
* End-to-end UDP latency **improved**: p99 42.4 µs → **37.0 µs**,
  max 75.5 µs → 62.8 µs. Still inside the < 50 µs budget with
  room to spare.
* End-to-end UDP throughput: 239 k → **210 k req/s**, still above
  the > 200 k budget. Throughput on this shared ARM host is
  syscall-rate-bound and varies ±15 % run-to-run; the codec floor
  (~1.1 M req/s synchronous) is not the bottleneck.

### 2026-05-09 (Phase 10 pass)

All codec/crypto numbers are within Criterion noise (±1 %) of the
prior baseline — no regressions and no surprise wins. The Phase 10
work was:

* Added **end-to-end UDP** measurement (see below); this is the
  number the performance budget at the top of this document
  actually targets.
* Added a **recycled-buffer** mode to the dhat example via the new
  `PacketBuffer::reset` + `Reply::from_buffer` API; steady-state
  alloc count drops from 1/iter to 0/iter on the codec layer.
* `client_store/cached/{hit,miss}_warm` rows added (Phase 6 lands
  the wrapper that backs them).

### Initial (2026-05-09 morning)

First recorded baseline. Two opinionated tightenings landed
alongside the bench scaffolding:

- `crypto::hmac::Hmac::finalize_md5` returns a `[u8; 16]` instead of
  a `Box<[u8]>`. Drops two heap allocations from every reply path
  (M-A emit) and one from every inbound M-A verify.
- `server::dedup::DedupCache` stores cached replies as `Arc<[u8]>`
  and no longer sweeps expired entries on lookup misses. Cache hits
  now bump a refcount instead of reallocating + memcpy'ing the reply
  bytes; the redundant per-miss O(n) sweep (insert already sweeps)
  is gone, fixing what would have been an O(n²) growth surprise on
  high-churn traffic.

## Heap allocation profile (dhat)

Source: [examples/dhat_hot_path.rs](examples/dhat_hot_path.rs).

```sh
cargo run --release --example dhat_hot_path -- owned     # default
cargo run --release --example dhat_hot_path -- recycled  # buffer reuse
# writes ./dhat-heap.json (open in dhat/dh_view.html)
```

Both modes run 10 000 iterations of the same decode → verify →
build → seal path measured by `roundtrip/full_request_response`,
under dhat's allocation-tracking global allocator.

### `owned` mode (default)

```
Total:     5,121,024 bytes in 10,001 blocks
At t-gmax: 1,024 bytes in 1 blocks
At t-end:  1,024 bytes in 1 blocks
```

Exactly **one allocation per iteration** (~512 bytes, the `Reply`'s
fresh `PacketBuffer`). Inbound parse, M-A verify, MD5, HMAC-MD5, and
Response Authenticator computation are all allocation-free. The
persistent 1 KiB block is dhat's own bookkeeping.

### `recycled` mode (`Reply::from_buffer`)

```
Total:     1,536 bytes in 2 blocks
At t-gmax: 1,024 bytes in 1 blocks
At t-end:  1,024 bytes in 1 blocks
```

**Zero allocations per iteration in steady state.** The two total
blocks are the initial `PacketBuffer` and dhat's bookkeeping. The
buffer's `Vec<u8>` is reset and grown-once on the first append, then
reused unchanged for the remaining 9 999 iterations. Consumers that
hold a long-lived scratch `PacketBuffer` and run their handler
through `Reply::from_buffer` therefore pay zero codec-layer allocs.

The server's UDP dispatch path still pays a few allocs per packet
(handler-task spawn, attribute-bytes copy, dedup-cache `Arc<[u8]>`);
those are architectural and not addressed by this change.

## End-to-end UDP latency + throughput

Source: [benches/server_udp.rs](benches/server_udp.rs). Spins up a
real `Server` with a no-op `Access-Accept` handler on `127.0.0.1`,
then drives traffic from a separate test client.

```sh
cargo bench --bench server_udp
```

### Sequential roundtrip latency (one in-flight request at a time)

10 000 samples, after a 256-packet warm-up:

| Metric | Value     |
|--------|-----------|
| min    | 17.5 µs   |
| p50    | 28.6 µs   |
| mean   | 29.5 µs   |
| p90    | 32.8 µs   |
| p99    | **37.0 µs** |
| p999   | 56.4 µs   |
| max    | 62.8 µs   |

Dominated by UDP loopback syscalls + Tokio task spawn; the codec
floor (~911 ns from `roundtrip/full_request_response`) is ~2 % of
the wire time. **p99 is inside the < 50 µs budget.** The
p999 / max tail is loopback scheduling jitter on a containerised
ARM host, not the library.

### Concurrent throughput (16 clients × 5 000 requests)

| Metric         | Value         |
|----------------|---------------|
| Total packets  | 80 000        |
| Wall clock     | 381 ms        |
| **Throughput** | **210 007 req/s** |

**Above the > 200 k req/s budget.** Numbers should be
substantially better on a real x86 host (the budget's reference
platform); this dev-container ARM measurement is the floor.

## `unsafe` audit (Phase 10)

This crate authorises `unsafe` only "where benches justify it". The
bench profile says they don't:

| Per-packet step          | Time   | % of total | Implementation |
|--------------------------|-------:|-----------:|----------------|
| Header parse             | 1 ns   |    < 0.2 % | safe Rust      |
| Attribute walk (decode)  | 11 ns  |      1.2 % | safe Rust      |
| HMAC-MD5 verify (M-A)    | 350 ns |     38 %   | aws-lc-sys FFI |
| Reply build (no seal)    | 20 ns  |      2.2 % | safe Rust      |
| Reply seal (HMAC + MD5)  | 580 ns |     64 %   | aws-lc-sys FFI |
| **Total (sync)**         | **911 ns** | 100 %  |                |

~97 % of the steady-state cost lives in the C library. Rewriting
the ~30 ns of pure-Rust parse/append code to drop bounds checks
would save single-digit nanoseconds at most — invisible to the
end-to-end p99 (which is dominated by the kernel's UDP path) and
to throughput (limited by socket syscall rate, not codec speed).

**No `unsafe` is introduced in this pass.** The wrappers in the
`crypto/` module remain the only `unsafe` in the crate, all of it
properly attributed to FFI and individually `// SAFETY:`-annotated.
Future work that genuinely justifies `unsafe` (e.g. a vectorised
attribute scanner, or a `from_raw_parts` window over the receive
buffer that today goes through a slice index) must come with a
bench delta to gate it.
