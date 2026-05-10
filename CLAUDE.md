# radius-tokio

A high-performance, async RADIUS server library written in Rust on top of Tokio.

This document defines the project goals, scope, and guiding principles. It is
the source of truth referenced when generating or modifying code in this
workspace. Changes to architecture or scope should be reflected here first.

## Vision

Provide a small, embeddable RADIUS server *library* (not a daemon) that
applications can drop in to handle Authentication, Authorization, and
Accounting (RFC 2865 / RFC 2866) plus RadSec (RFC 6614). Consumers supply
business logic through a handler trait; the library owns all wire-level,
transport, and protocol details.

### Target deployments

The library is built for the kinds of NAS devices that dominate enterprise
and service-provider edges:

- Wi-Fi access points and wireless LAN controllers (WPA2/3-Enterprise,
  per-session accounting, CoA / Disconnect per RFC 5176).
- Ethernet switches doing 802.1X port authentication (EAP transport,
  dynamic VLAN assignment, MAC Authentication Bypass).
- Captive-portal / hotspot controllers (Access-Request with
  `User-Password`, interim accounting, session quotas).
- VPN concentrators and similar appliances that speak vanilla RADIUS or
  RadSec.

Vendor-specific quirks for these devices (Cisco, Aruba/HPE, Juniper/Mist,
Ruckus, Fortinet, MikroTik, Meraki, Ubiquiti, …) are absorbed via the
vendored FreeRADIUS dictionaries; no special-case code in the core.

### Batteries-included, opinion-light

The library ships a usable toolbox so a typical consumer can stand up a
working AAA endpoint quickly:

- Packet codec, dictionary-typed attribute access, dedup / retransmit
  cache, dynamic client registry, RadSec listener, CoA/Disconnect
  originator, and an EAP-Message passthrough channel.
- Helpers for common patterns: MAB, 802.1X EAP relay to an external
  method engine, accounting record fan-out, dynamic VLAN / ACL replies.

It deliberately does **not** impose:

- A session store. Consumers plug in their own (in-memory, Redis, SQL,
  whatever); the library exposes the hooks and identifiers it needs.
- A user/identity database. The handler trait is the only contract.
- A policy language. Authorization is "whatever your handler returns."
- A logging/metrics framework. Hooks are provided; wiring is the
  consumer's call (with optional `tracing`/`metrics` features).

## Goals

1. **Library-first.** No `main`, no config files, no global state. Consumers
   construct a server, register a handler, and drive it from their own Tokio
   runtime.
2. **Performance is a first-class requirement.**
   - Zero-copy parsing where feasible (borrow from the receive buffer).
   - Avoid allocations on the hot path; reuse buffers per-task.
   - Lock-free or sharded state for client lookup and dedup caches.
   - Benchmarks (criterion) gate performance-sensitive changes.
3. **Correctness over cleverness, but `unsafe` is permitted** when it yields
   measurable wins. Every `unsafe` block must be:
   - Justified with a `// SAFETY:` comment stating the invariants.
   - Covered by unit tests and, where applicable, `cargo miri` runs.
   - Isolated behind a safe API.
4. **Minimal dependencies.** Prefer the standard library and `tokio`. Each
   added crate must be justified. Avoid heavy framework deps (no `serde` in
   the core wire path, no `anyhow` in public APIs, no `tracing` requirement
   imposed on consumers — gate it behind a feature). Cryptography is built
   on `aws-lc-sys` directly (FIPS-validatable, audited C) rather than a
   higher-level Rust TLS stack — see the Cryptography section.

   **Always pin to the latest released version of every dependency.** When
   adding or updating a crate, start from the newest version on crates.io
   and only walk backward if it forces an MSRV bump or otherwise violates a
   project constraint. Don't leave dependencies on stale majors "because
   the old one still compiles" — newer releases carry the security fixes,
   sanitizer coverage, and upstream bug fixes we want.
5. **Strict, typed attribute model.** RFC and vendor attributes are exposed
   as strongly-typed Rust items generated at build time from FreeRADIUS
   dictionaries vendored in-tree.
6. **Dynamic client configuration.** Clients (shared secrets, allowed
   subnets, RadSec TLS material) can be added, updated, and removed at
   runtime without restarting the server.

## Non-goals (initial)

- Full EAP method implementations (the handler may implement these; the
  library will route EAP-Message attributes but not terminate methods).
- A CLI / daemon binary.
- Persistence of accounting data.
- Proxy / realm routing (may come later; not in v0).

## Architecture

```
+------------------------------------------------------+
|                  Consumer Application                |
|     impl Handler for MyApp { async fn handle... }    |
+------------------------+-----------------------------+
                         |
+------------------------v-----------------------------+
|                    Server (Tokio)                    |
|  - UDP listener (auth: 1812, acct: 1813)             |
|  - TCP+TLS listener for RadSec (2083)                |
|  - Per-packet task spawn / bounded worker pool       |
|  - Request dedup (Identifier + src + Authenticator)  |
|  - Response retransmit cache                         |
+----+--------------+--------------+-------------------+
     |              |              |
+----v----+   +-----v-----+  +-----v---------+   +--------+
| Codec   |   | Client    |  | Dictionary    |   | Crypto |
| encode/ |   | registry  |  | (codegen'd    |   | (safe  |
| decode  |   | (dynamic) |  |  from FR dict)|   | aws-lc)|
+---------+   +-----------+  +---------------+   +--------+
```

### Crate layout

- `radius-tokio` (this crate) — public API: `Server`, `Handler`, `Request`,
  `Reply`, `ClientStore`, transport configuration. Houses the codec, the
  server runtime, the `auth` helpers, and (gated on the `radsec` feature)
  the TLS module.
- `radius-dict` (workspace member) — runtime dictionary tables. Generated at
  build time from FreeRADIUS dictionary files vendored under
  `crates/radius-dict/dictionaries/`. Re-exported as `radius_tokio::dict`.
- `radius-dict-codegen` (workspace member, build-only) — the parser and
  Rust-source renderer used by `radius-dict`'s build script. Never linked
  into a server binary.
- `crypto` (internal module of `radius-tokio`) — safe Rust wrappers over
  `aws-lc-sys` for every primitive the library needs (HMAC-MD5, MD5,
  HMAC-SHA*, AES, DES, RNG, TLS via `SSL_CTX`/`SSL`, X.509 verification,
  constant-time compare). Nothing else in the crate calls `aws-lc-sys`
  directly.

## Public API sketch

The library owns the accept loop, decoding, deduplication, authenticator
verification, and reply encoding. Consumers plug in two things:

1. A **`ClientStore`** that resolves an inbound peer (source IP for UDP,
   peer certificate for RadSec) to a `Client` record — shared secret,
   allowed NAS identifiers, optional rate limits, RadSec trust anchors.
   Implementations may hit a database, a config file, an in-memory map,
   or anything else; lookups are async and may fail or return "unknown".
2. A **`Handler`** that turns a validated `Request` into a `Reply`.

```rust
pub trait ClientStore: Send + Sync + 'static {
    fn lookup_udp(
        &self,
        src: SocketAddr,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send;

    /// Pre-handshake DoS gate for RadSec. Called immediately after
    /// `accept()` on the TCP listener, **before** any TLS bytes are
    /// read. Returning `false` closes the connection with no TLS
    /// state allocated. Default impl returns `false` (deny) so
    /// consumers must explicitly opt in to a DoS-exposure policy;
    /// override to add a CIDR allow-list or per-IP rate limit.
    fn admit_radsec(
        &self,
        src: SocketAddr,
    ) -> impl Future<Output = bool> + Send {
        let _ = src;
        async { false }
    }

    /// Post-handshake authorization for RadSec. Called once the
    /// mTLS handshake succeeds, with the peer's source address and
    /// the leaf certificate it presented. Returning `None` tears
    /// the connection down before any RADIUS frame is exchanged.
    /// Default impl returns `None` — a `RadSec` listener bound
    /// against a store that does not override this method is a
    /// no-op listener. The store may key off Subject DN, SAN,
    /// SPKI fingerprint, source IP, or any combination.
    fn lookup_radsec_by_cert(
        &self,
        src: SocketAddr,
        peer: &PeerCertificate<'_>,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let _ = (src, peer);
        async { None }
    }
}

pub trait Handler: Send + Sync + 'static {
    fn handle(
        &self,
        req: Request<'_>,
        reply: Reply<'_>,
    ) -> impl Future<Output = HandlerResult> + Send;
}

pub struct Server<S: ClientStore, H: Handler> { /* … */ }

impl<S: ClientStore, H: Handler> Server<S, H> {
    pub fn builder() -> ServerBuilder<S, H>;
    pub async fn run(self) -> io::Result<()>; // owns the accept loop
    pub fn shutdown(&self) -> ShutdownHandle;
}
```

`Request` borrows from the decoded buffer; `Reply` is a builder that the
handler fills with attributes. The handler never touches sockets, secrets,
or authenticators.

### Ergonomic baseline

A simple UDP-only deployment should be a few lines. The library ships a
`StaticClients` `ClientStore` for the common case where peers are known up
front:

```rust
let clients = StaticClients::builder()
    .add("10.0.0.0/24", b"shared-secret")
    .build();

Server::builder()
    .clients(clients)
    .handler(MyHandler)
    .listen_udp("0.0.0.0:1812".parse()?)   // auth
    .listen_udp("0.0.0.0:1813".parse()?)   // acct
    .run()
    .await?;
```

RadSec is purely additive: call `.listen_radsec(addr, tls_config)` on
the builder. The listener pipeline is `accept → admit_radsec(src):bool
→ mTLS handshake → lookup_radsec_by_cert(src, peer)`. Consumers that
need DB-backed lookups implement `ClientStore` themselves; the same
`Server` machinery transparently switches from the built-in static
table to the custom store.

## Dictionary & codegen

- FreeRADIUS-format dictionary files live under `dictionaries/` and are
  vendored into the repo (license-compatible files only).
- A build script (or proc-macro) parses the selected dictionaries and emits:
  - An `Attribute` enum (RFC + per-vendor variants).
  - Encoders/decoders for each attribute's `type` (`string`, `octets`,
    `ipaddr`, `ipv6addr`, `integer`, `date`, `ifid`, `tlv`, `struct`, …).
  - Constants for VSAs (`Vendor-Specific`, type 26) keyed by vendor id.
- Consumers may opt into a subset of dictionaries via Cargo features to keep
  generated code small.
- The generator must be deterministic and reproducible (sorted output, no
  timestamps in source).

## Transport

- **UDP** (RFC 2865/2866): authentication on 1812, accounting on 1813.
  Configurable; multiple bind addresses supported.
- **RadSec / RADIUS-over-TLS** (RFC 6614): TCP on 2083 by default.
  TLS is provided by the `crypto` module wrapping `aws-lc-sys`'s libssl
  surface. Mutual TLS required by spec.

  Single-mode pipeline per accepted connection:

  1. **Pre-handshake DoS gate.** `ClientStore::admit_radsec(src) ->
     bool` is called immediately after `accept()`, before any TLS
     state is allocated. Returning `false` drops the connection
     cheaply. Default `false` (deny) — consumers must override to
     admit peers, typically with a CIDR allow-list or per-IP
     rate limit. The conservative default forces every deployment
     to think about its DoS exposure before the listener accepts
     a single handshake.
  2. **mTLS handshake** against the listener-wide trust store
     installed by `TlsContext::server` (`SSL_VERIFY_PEER |
     SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, `verify_depth = 5`,
     `SSL_OP_NO_TICKET`, advertised CA name list). libssl performs
     chain validation; failure closes the connection.
  3. **Post-handshake authorization.**
     `ClientStore::lookup_radsec_by_cert(src, peer) ->
     Option<Arc<Client>>` maps the peer's leaf certificate (and
     source address) to a registered client. The store may key off
     Subject DN, SAN, SPKI fingerprint, source IP, or any
     combination — `radsecproxy`'s `verifyconfcert` policy.
     Returning `None` tears the connection down before any RADIUS
     frame is exchanged.

  Connections are long-lived TCP; the cert→client binding is fixed
  for the life of the connection. Revocation tears the connection
  down via a `Server::close_connections_for(client_id)` hook.
- **RADIUS-over-DTLS** (RFC 7360): out of scope for v0; revisit later.

## Client authentication

Client identification and trust material are pluggable via the
`ClientStore` trait. The library never assumes a fixed table.

- **UDP:** `lookup_udp(src)` is called once per inbound packet, before any
  cryptographic work. Returning `None` causes the packet to be dropped
  without a reply (per RFC 2865 §3; no allocation beyond the receive
  buffer). The returned `Client` carries the shared secret used to verify
  the Request Authenticator and Message-Authenticator.
- **RadSec:** every accepted TCP connection runs through three
  steps. (1) `admit_radsec(src) -> bool` is consulted before any
  TLS state is allocated — a cheap pre-handshake DoS gate. Default
  `false` (deny); consumers must override to add a CIDR allow-list,
  per-IP rate limit, or other admission policy before any peer
  can connect. (2) The mTLS handshake runs against the listener-wide
  trust store from `TlsContext::server`. (3) `lookup_radsec_by_cert(
  src, peer)` maps the validated leaf certificate (combined with
  the source address) to a registered `Client`; returning `None`
  drops the connection. The store may key off Subject DN, SAN,
  SPKI fingerprint, source IP, or any combination —
  `radsecproxy`'s `verifyconfcert` policy. `StaticClients`
  provides a default override that admits and identifies purely
  by source IP, suitable for deployments where every NAS source
  IP is provisioned.
- **Dynamic by construction:** because every lookup goes through the
  store, adding, updating, or revoking a client is whatever the store's
  backend supports — no server reload, no restart, no signal. A
  database-backed store can pick up changes on its own cadence (polling,
  LISTEN/NOTIFY, change streams).
- **Built-in implementations:**
  - `StaticClients` — immutable table built at startup. Zero-overhead
    lookups; ideal for small deployments and tests.
  - `CachedStore<S>` — generic wrapper around any `ClientStore` that
    adds a TTL cache, negative caching, and single-flight
    deduplication so a slow backend doesn't sit on the hot path.
  - Consumers needing DB / external lookups, or runtime-mutable
    in-memory tables, implement `ClientStore` directly. The trait is
    small enough that wrapping an `ArcSwap`, `RwLock<HashMap>`, or
    `DashMap` is a few lines — and the right concurrency primitive
    depends on the consumer's update pattern, so the library does not
    pick one for them. See `examples/` for sketches.
- **Caching guidance:** the library never caches lookup results on the
  store's behalf — invalidation policy is the consumer's call. Stores
  with expensive lookups should wrap themselves in `CachedStore` (or
  roll their own); fast in-memory stores should not.

## Cryptography

All cryptographic operations go through an in-tree `crypto` module that
provides safe Rust wrappers over `aws-lc-sys`.

- **Why aws-lc-sys directly:** we need low-level primitives (raw HMAC-MD5
  for the RADIUS authenticator scheme, AES key wrap, raw TLS record access
  for RadSec) that higher-level Rust TLS stacks intentionally do not
  expose. `aws-lc-sys` is audited, actively maintained, and FIPS-eligible.
- **Wrapper rules:**
  - Each FFI call is encapsulated in a safe function with a documented
    `// SAFETY:` block explaining the invariants.
  - Owned handles (`EVP_MD_CTX`, `HMAC_CTX`, `SSL`, `SSL_CTX`, `X509`,
    `BIO`, …) are wrapped in newtypes implementing `Drop` to free via the
    correct `*_free` function. No leaks on panic paths.
  - All buffers passed across FFI carry explicit length; no reliance on
    NUL-terminated strings unless the C API requires it.
  - Return codes are checked; non-success paths surface a typed
    `crypto::Error`. We never `unwrap` an FFI result.
  - Sensitive material (keys, shared secrets, premaster) is zeroized on
    drop using `OPENSSL_cleanse` via the wrapper.
  - `unsafe` is confined to this module. The rest of the crate uses only
    the safe API.
- **Primitives exposed (initial):**
  - `Md5`, `HmacMd5` (RADIUS Request/Response Authenticator,
    Message-Authenticator per RFC 3579).
  - `HmacSha1`, `HmacSha256` (TLS PRF, RadSec).
  - `Aes128`, key-wrap helpers (Tunnel-Password and similar).
  - `Rand` over `RAND_bytes` for Request Authenticator generation.
  - `ConstantTimeEq` over `CRYPTO_memcmp`.
  - TLS: `TlsContext`, `TlsConnection` (server-side, mTLS), giving access
    to peer cert chain bytes for the client store to identify peers.
  - PKI helpers (`crypto::pki`, gated on `radsec`): `CertificateAuthority`,
    `PrivateKey`, `Certificate` — thin wrappers over `EVP_PKEY_keygen` /
    `X509_*` / `X509V3_EXT_conf_nid` / PEM I/O that issue RadSec-shaped
    CAs and leaves with RFC 5280 §4.2 + RFC 6614 §2.3 defaults
    (ECDSA P-256, SHA-256, 128-bit random serial, correct EKU / KU /
    BasicConstraints / SAN / SKI / AKI). Same `unsafe` discipline as
    the rest of the module; same `TlsError` surface.
- **Testing:** every wrapper has unit tests covering happy path, error
  path, and Drop. Known-answer tests for HMAC-MD5 / AES from RFC vectors.
  The FFI shims are exercised under AddressSanitizer in CI; miri is
  not run because every interesting `unsafe` block in the workspace
  reaches `aws-lc-sys` (foreign functions are unsupported by miri),
  and the pure-Rust workspace members have no `unsafe`.

## Security requirements

- Constant-time comparison (via `crypto::ConstantTimeEq`) for
  Message-Authenticator and Response Authenticator checks.
- Reject packets from unknown clients before any allocation beyond the
  receive buffer.
- Enforce minimum/maximum packet length (20..=4096) per RFC.
- Rate-limit per source to mitigate amplification.
- Secrets are zeroized on drop via the `crypto` module's wrappers
  (`OPENSSL_cleanse`); no separate `zeroize` dependency.
- No panics on malformed input. Fuzz the codec (`cargo fuzz`).

## Testing strategy

- Unit tests next to each module.
- Property tests (`proptest`) for codec round-trips.
- Integration tests that drive the server with a real UDP socket and a
  reference client (the FreeRADIUS `radclient` binary in CI when available,
  otherwise a Rust test client built on the same codec).
- Fuzz targets for packet decode, dictionary parse, and TLS handshake.
- AddressSanitizer over the `crypto` FFI shims in CI. Miri is not run:
  every `unsafe` block in the workspace lives behind `aws-lc-sys`, and
  miri cannot execute foreign functions.
- Criterion benchmarks for: decode, encode, full request/response round
  trip, client lookup at 10k clients.

## Performance budget (initial targets, single core)

- Access-Request decode + Access-Accept encode: < 2 µs steady state.
- Sustained throughput: > 200k req/s on a modern x86 core with a no-op
  handler.
- p99 added latency from the library (excluding handler): < 50 µs.

These are aspirational and will be revisited once we have benchmarks.

## Coding standards

- `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(missing_docs)]` on the public
  API, `#![warn(clippy::pedantic)]` with documented allows.
- No `unwrap`/`expect` outside tests and `const` contexts.
- Public errors are an enum implementing `std::error::Error`; no `anyhow`
  in the public API.
- Async: native `async fn` / `-> impl Future` in traits. **No
  `async-trait`.**
- **MSRV: 1.79+** (required for return-position `impl Trait` in traits).
  Pinned via `rust-version` in each `Cargo.toml`.

## API stability

While the crate version in `Cargo.toml` is below `1.0`, breaking changes
to the public API are explicitly allowed and encouraged when they serve
the project goals (performance, ergonomics, correctness). Do not contort
the design to preserve a 0.x signature; bump the minor version and move
on. Stability commitments begin at `1.0`.

## Roadmap

Phased build checklist. Each phase should land green CI (build, clippy,
tests, miri where applicable, fuzz smoke runs) before the next begins.
Order within a phase is a suggestion, not a contract; expect iteration.

### Phase 0 — Project scaffolding

- [x] `rust-version = "1.79"` pinned in every `Cargo.toml` (workspace root + member crates).
- [x] `Cargo.toml` lints table: `unsafe_op_in_unsafe_fn = "deny"`,
      `missing_docs = "warn"` on `lib.rs`, `clippy::pedantic = "warn"`.
- [x] `deny.toml` (cargo-deny) for license / advisory gating.
- [x] CI workflow: stable + MSRV builds, clippy, fmt, test, miri (gated
      to modules without FFI), cargo-deny, fuzz smoke (60 s per target).
- [x] `CONTRIBUTING.md` referencing this document as the source of truth.
- [x] Workspace split: server crate at the root, dictionary tables in
      `crates/radius-dict`, build-only codegen in
      `crates/radius-dict-codegen`.

### Phase 1 — Crypto module (`crypto/`)

- [x] `aws-lc-sys` dependency added; build verified on Linux + macOS.
- [x] Newtype wrappers with `Drop`: `EvpMdCtx`, `HmacCtx`, `EvpCipherCtx`,
      `Bio`, `X509`, `X509Store`, `SslCtx`, `Ssl`, `EcKey`, `EvpPkey`.
- [x] Digests: `Md5`, `Sha1`, `Sha256` (one-shot + streaming).
- [x] MACs: `HmacMd5`, `HmacSha1`, `HmacSha256` with KATs from RFC 2104 /
      RFC 4231.
- [x] `Rand::fill(&mut [u8])` over `RAND_bytes`; failure surfaces an error.
- [x] `ConstantTimeEq` over `CRYPTO_memcmp`.
- [x] Secret zeroization helper (`Zeroizing<T>` newtype using
      `OPENSSL_cleanse` on drop).
- [x] Unit tests: happy path, error path, `Drop` runs cleanse for every
      wrapper. ASan job in CI.

### Phase 2 — Dictionary parser & codegen

- [x] Vendor FreeRADIUS RFC dictionaries under `dictionaries/rfc/`.
- [x] Parser for FreeRADIUS dictionary syntax: `ATTRIBUTE`, `VALUE`,
      `VENDOR`, `BEGIN-VENDOR`/`END-VENDOR`, `$INCLUDE`, flags
      (`encrypt=`, `has_tag`, `array`, `concat`, `extended`, `tlv`).
- [x] Type model: `string`, `octets`, `ipaddr`, `ipv6addr`, `ipv4prefix`,
      `ipv6prefix`, `integer`, `integer64`, `signed`, `date`, `ifid`,
      `ether`, `abinary`, `tlv`, `struct`, `vsa`.
- [x] `radius-dict-codegen` build script: deterministic, sorted,
      timestamp-free output.
- [x] Generated `Attribute` enum + per-attribute encode/decode functions.
- [x] Cargo features per dictionary group (`dict-rfc`, `dict-cisco`,
      `dict-aruba`, `dict-juniper`, `dict-mikrotik`, `dict-meraki`, …).
- [x] Snapshot test: regenerate output is byte-identical between runs.
- [x] Vendor a representative subset (Cisco, Aruba, Juniper, Ruckus,
      MikroTik, Meraki, Ubiquiti) and verify they compile under their
      respective features.

### Phase 3 — Packet codec

- [x] Header parser (code, identifier, length, authenticator) with
      length sanity (20..=4096).
- [x] Zero-copy attribute iterator borrowing the receive buffer.
- [x] Typed accessors layered on the codegen output.
- [x] Encoder building into a caller-supplied buffer; no allocation on
      the steady-state path.
- [x] Request/Response Authenticator computation per RFC 2865 §3.
- [x] Message-Authenticator (RFC 3579) verify + insert helper.
- [x] User-Password / Tunnel-Password encryption helpers.
- [x] EAP-Message reassembly view (concat per RFC 3579 §3.1).
- [ ] `proptest` round-trip suite (decode→encode→decode is identity).
- [ ] `cargo fuzz` targets: `decode_packet`, `decode_attributes`,
      `verify_authenticator`.
- [x] Criterion benches: decode, encode, full round-trip, attribute
      lookup by type.

### Phase 4 — Server core (UDP)

- [x] `Server` + `ServerBuilder` skeleton; owns Tokio tasks.
- [x] `Handler` trait (native async fn / `impl Future`).
- [x] `ClientStore` trait + `Client` record (secret, allowed NAS-IDs,
      rate-limit hints).
- [x] `StaticClients` impl with CIDR-keyed lookup.
- [x] UDP listener: `recv_from` loop, per-packet task or bounded worker
      pool (decide via bench), buffer reuse from a pool.
- [x] Pipeline: lookup → decode → authenticate → dispatch → encode →
      send. Reject unknown clients before allocation.
- [x] Request dedup cache keyed by (src, identifier, request-auth) with
      response retransmit on duplicate.
- [ ] Shutdown handle: drain in-flight, stop accept, return cleanly.
- [x] Integration test against `radclient` when present in CI.

### Phase 5 — Accounting (RFC 2866)

- [x] Accounting-Request decode + Accounting-Response encode.
- [x] Acct-Status-Type handling exposed to the handler (Start, Stop,
      Interim-Update, Accounting-On/Off).
- [x] Interim-Update interval + duplicate suppression on the dedup cache.
- [x] Integration test: full Start/Interim/Stop flow.

### Phase 6 — Dynamic clients

- [x] `CachedStore<S>` wrapper: TTL + negative cache + single-flight
      deduplication around any `ClientStore`. No new public deps;
      built on `tokio::sync` primitives already in the tree.
- [x] Example: in-memory mutable store using `ArcSwap` (lives under
      `examples/`, not in the public API).
- [x] Example: SQLite-backed `ClientStore` fronted by `CachedStore`.
- [x] Bench: 10 k clients, p99 lookup latency for `StaticClients` and
      `CachedStore` (hit path + miss path).

### Phase 7 — RadSec (RFC 6614)

- [x] `crypto::Tls{Context,Connection}` server-side, mTLS, peer-cert
      bytes exposed.
- [x] TCP accept loop on 2083 (configurable).
- [x] **Pre-handshake admission**: `admit_radsec(src) -> bool`
      gate consulted before any TLS state is allocated. Default
      `false` (deny); consumers must override to admit peers
      (CIDR allow-list, per-IP rate limit, …).
- [x] **Post-handshake authorization**: listener-wide trust store
      from `TlsContext::server`, then
      `lookup_radsec_by_cert(src, peer)` maps the validated leaf
      to a `Client`.
- [x] Long-lived connection management: per-connection task, framed
      reader, write half guarded by a mutex or mpsc.
      *Sequential per connection (read → dispatch → write); no
      pipelining means no mutex/mpsc is needed on the write half.
      Pipelining is a post-0.1 enhancement.*
- [x] `Server::close_connections_for(client_id)` revocation hook.
- [x] Integration tests (happy path + handshake failure +
      unknown-cert rejection).
- [x] PKI helpers (`crypto::pki`) for consumers who don't already
      run a private CA: ECDSA P-256 keygen, self-signed CA, server /
      client leaf issuance with RFC 6614 §2.3 EKUs and SAN. Drops
      the `rcgen` dev-dep — test fixtures and consumer onboarding
      now share the same code path.

### Phase 8 — CoA / Disconnect (RFC 5176)

- [x] Originator API: `Server::send_coa(client_id, attrs)` and
      `send_disconnect(...)`.
- [x] Listener for inbound CoA-ACK/NAK, Disconnect-ACK/NAK.
- [x] Per-NAS rate limiting and retry/backoff.
- [x] Integration test with a mock NAS endpoint.

### Phase 9 — Observability hooks (optional features)

- [x] Wireshark-style human-readable dissection (`PacketBuffer::dissect()`,
      `Header::dissect()`, `RawAttribute::dissect()`) backed by a
      cross-feature `dict::registry` lookup. No new deps; allocation-
      free for the registry helpers; only paid when callers format.
- [x] `tracing` feature: structured events around UDP accept,
      drop reasons (unknown client, malformed header, bad request /
      message authenticator), dedup hits, request dispatch, reply
      send, server lifecycle (bind / exit), and CoA originator
      (send / retransmit / ack / nak / timeout / error). All
      events live under the `radius_tokio` target with a fixed
      `event = "<name>"` field vocabulary so consumers can filter
      and key dashboards off it. Macros expand to `()` when the
      feature is off — zero overhead, no transitive deps.
- [x] `metrics` feature: counters/histograms for packets, errors, dedup
      hits, handler latency, TLS handshakes.

### Phase 10 — Performance pass

- [x] Re-run all benches; record baseline numbers in `BENCHMARKS.md`.
- [x] Hot-path allocation audit (`dhat` or `heaptrack`).
- [x] Introduce `unsafe` where benches justify it; each block gets the
      `// SAFETY:` comment + miri/ASan coverage required by the
      Cryptography section's wrapper rules.
      *Outcome: no new `unsafe` introduced. The hot path is ~97%
      `aws-lc-sys` FFI; the remaining ~30 ns of pure-Rust parse/encode
      code cannot move the end-to-end p99 or throughput numbers. See
      `BENCHMARKS.md` "`unsafe` audit" for the full breakdown.*
- [x] Verify performance budget targets (decode/encode µs, throughput,
      p99 latency).
      *End-to-end UDP bench (`benches/server_udp.rs`) confirms
      p99 = 42 µs (budget < 50 µs) and 239 k req/s (budget > 200 k)
      on a containerised ARM host \u2014 the floor case for the budget's
      x86 reference platform.*

### Phase 11 — Pre-0.1 polish

- [x] `#![warn(missing_docs)]` clean on the public API.
- [x] Examples: minimal UDP (README quickstart), mixed UDP+RadSec,
      custom DB-backed store (`sqlite_clients`), CoA originator.
- [x] `README.md` with quickstart + matrix of supported RFCs.
- [x] `CHANGELOG.md`, semver policy noted (pre-1.0 = breaking allowed).
- [x] Workspace-wide green: `cargo test --workspace --all-features`
      (205/205), `cargo clippy --workspace --all-features --all-targets`
      (0 warnings), `cargo doc --workspace --all-features --no-deps`
      (0 warnings), `cargo fmt --all -- --check` clean. `clippy.toml`
      with project-specific `doc-valid-idents` (RadSec, FreeRADIUS,
      CoA, DoS, mTLS, MikroTik, WISPr) replicated in each workspace
      member.
- [x] `cargo publish --dry-run -p radius-dict-codegen` succeeds.
      `radius-dict` and the root crate cannot be dry-run verified
      until their dependencies are actually on crates.io (chicken-
      and-egg with workspace publish chains); path-deps now carry
      explicit `version = "0.1.0"` so the real publish chain works.
- [ ] Publish 0.1.0. Pre-publish checklist:
  1. Replace `https://github.com/example/radius-tokio` with the real
     repository URL in all three `Cargo.toml` files.
  2. `cargo publish -p radius-dict-codegen`
  3. `cargo publish -p radius-dict`
  4. `cargo publish` (root)

### Post-0.1 candidates (deferred)

- DTLS (RFC 7360).
- Proxy / realm routing.
- FIPS feature flag (`aws-lc-fips-sys`).
- Built-in EAP method engine.

## Open questions

- Do we expose a lower-level "decoded packet" API alongside the handler
  trait for advanced users (proxies, test harnesses)?
- `aws-lc-sys` vs `aws-lc-fips-sys`: do we offer a feature flag for the
  FIPS-validated module, or stay on the non-FIPS build for v0?
