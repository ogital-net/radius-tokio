# radius-tokio

A high-performance, async RADIUS server **library** for Rust on top of Tokio.

`radius-tokio` is built to be embedded in an application — it is not a
daemon, has no `main`, and reads no config files. You construct a
`Server`, plug in two small traits (`ClientStore` and `Handler`), and
drive it from your own Tokio runtime. The library owns every wire- and
protocol-level detail (decoding, deduplication, authenticator
verification, reply sealing, RadSec mTLS); your code owns the policy
("who is this peer?", "what should I send back?").

```text
+------------------------------------------------------+
|                  Your Application                    |
|     impl Handler for MyApp { async fn handle... }    |
+------------------------+-----------------------------+
                         |
+------------------------v-----------------------------+
|                  radius-tokio Server                 |
|  - UDP listeners (auth: 1812, acct: 1813)            |
|  - TCP+TLS listener for RadSec (2083)                |
|  - Request dedup + reply retransmit cache            |
|  - Authenticator + Message-Authenticator validation  |
+----+--------------+--------------+-------------------+
     |              |              |
+----v----+   +-----v-----+  +-----v---------+   +--------+
| Codec   |   | Client    |  | Dictionary    |   | Crypto |
| encode/ |   | registry  |  | (codegen'd    |   | (safe  |
| decode  |   | (dynamic) |  |  from FR dict)|   | aws-lc)|
+---------+   +-----------+  +---------------+   +--------+
```

## Status

Pre-0.1. Breaking API changes are explicitly allowed and will happen
without deprecation cycles until a `1.0` release.

## Supported RFCs

| RFC      | Title                                         | Status        |
|----------|-----------------------------------------------|---------------|
| RFC 2865 | RADIUS                                        | implemented   |
| RFC 2866 | RADIUS Accounting                             | implemented   |
| RFC 2867 | RADIUS Accounting / Tunnel Protocol Support   | dictionaries  |
| RFC 2868 | RADIUS Attributes for Tunnel Protocol Support | dictionaries  |
| RFC 2869 | RADIUS Extensions                             | dictionaries  |
| RFC 3162 | RADIUS and IPv6                               | dictionaries  |
| RFC 3579 | RADIUS Support For EAP                        | passthrough   |
| RFC 3580 | IEEE 802.1X RADIUS Usage Guidelines           | dictionaries  |
| RFC 5080 | Common RADIUS Implementation Issues           | dedup cache   |
| RFC 5176 | Dynamic Authorization (CoA / Disconnect)      | implemented   |
| RFC 6614 | RADIUS over TLS (RadSec)                      | implemented   |
| RFC 8044 / RFC 6158 | Data type guidance                 | dict types    |

EAP method termination (PEAP, EAP-TLS, EAP-TTLS, …) is intentionally
out of scope: the codec exposes the `EAP-Message` reassembly view so
your handler can pass the EAP payload to whatever method engine you
already use.

## Quickstart

A minimal Access-Request → Access-Accept loop, UDP only:

```no_run
use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::Code;
use radius_tokio::dict::generated::rfc::attrs;

struct MyApp;

impl Handler for MyApp {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }
        // Inspect attributes, run policy, build the reply ...
        let mut reply = request.reply(Code::ACCESS_ACCEPT);
        reply.add(attrs::SESSION_TIMEOUT, 3600u32).unwrap();
        HandlerResult::Reply(reply)
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cidr = IpCidr::new(Ipv4Addr::new(10, 0, 0, 0).into(), 24).unwrap();
    let store = StaticClients::builder()
        .add(cidr, Arc::new(Client::new(b"shared-secret".as_slice())))
        .build();

    let server = Server::builder()
        .clients(store)
        .handler(MyApp)
        .listen_udp("0.0.0.0:1812".parse().unwrap())   // auth
        .listen_udp("0.0.0.0:1813".parse().unwrap())   // acct
        .build()?;

    server.run().await
}
```

### Tagged tunnel attributes (RFC 2868)

Attributes carrying an RFC 2868 §3.1 tag — `Tunnel-Type`,
`Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, … — are exposed
through `Tagged<V>` so consumers never hand-roll the tag byte or the
24-bit packing of tagged integers. The typed handle picks the right
wire shape automatically:

```rust,no_run
use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::dict::typed::Tagged;
# fn demo(request: radius_tokio::server::Request<'_>) {
# use radius_tokio::Code;
# let mut reply = request.reply(Code::ACCESS_ACCEPT);

// Encode: a `(tag, value)` tuple is the shorthand; `Tagged::untagged`
// drops the tag byte. Tagged-integer values are clamped to 24 bits.
reply.add(attrs::TUNNEL_TYPE, (1u8, 13u32)).unwrap();           // tag=1, VLAN
reply.add(attrs::TUNNEL_MEDIUM_TYPE, (1u8, 6u32)).unwrap();     // tag=1, IEEE-802
reply.add(attrs::TUNNEL_PRIVATE_GROUP_ID, (1u8, "42")).unwrap();// tag=1, VLAN 42
reply.add(attrs::TUNNEL_PREFERENCE, Tagged::untagged(1u32)).unwrap();

// Decode: `get(...)` yields `Tagged<V>`; the tag is `None` when the
// peer sent the attribute without one.
for attr in request.attributes_iter().flatten() {
    if let Some(t) = attr.get(attrs::TUNNEL_TYPE) {
        let _ = (t.tag, t.value); // Option<u8>, u32
    }
}
# }
```

See [`examples/`](examples/) for richer scenarios:

- `mutable_clients.rs` — a runtime-mutable in-memory `ClientStore`.
- `sqlite_clients.rs` — a SQLite-backed `ClientStore` fronted by
  `CachedStore<S>` for TTL + single-flight dedup.
- `threadlocal_responder.rs` — bypassing the `Handler` trait for
  custom thread-local reply paths.
- `dhat_hot_path.rs` — allocation profiling of the codec hot path.

## Cargo features

| Feature           | Default | Effect                                              |
|-------------------|---------|-----------------------------------------------------|
| `dict-rfc`        | yes     | RFC dictionaries (small, recommended).              |
| `dict-cisco`      | no      | Cisco VSAs.                                         |
| `dict-aruba`      | no      | Aruba / HPE VSAs.                                   |
| `dict-ascend`     | no      | Ascend VSAs.                                        |
| `dict-fortinet`   | no      | Fortinet VSAs.                                      |
| `dict-hp`         | no      | HP VSAs.                                            |
| `dict-juniper`    | no      | Juniper VSAs.                                       |
| `dict-meraki`     | no      | Meraki VSAs.                                        |
| `dict-microsoft`  | no      | Microsoft VSAs (NPS, MS-CHAP attributes).           |
| `dict-mikrotik`   | no      | MikroTik VSAs.                                      |
| `dict-ruckus`     | no      | Ruckus VSAs.                                        |
| `dict-wispr`      | no      | WISPr VSAs.                                         |
| `dict-vendor-all` | no      | Umbrella enabling every vendored vendor dictionary. |
| `radsec`          | no      | RADIUS-over-TLS (RFC 6614) listener + `tls` and `pki` modules. |
| `fast-md5`        | **yes** | Swap the MD5 block compressor from `aws-lc-sys` to the [`fast-md5`](https://crates.io/crates/fast-md5) crate (hand-written x86_64 + aarch64 assembly, portable Rust fallback, `#![no_std]`). Disabling falls back to `aws-lc-sys`'s MD5, which is always available. |
| `tracing`         | no      | Structured spans/events around accept and dispatch. |
| `metrics`         | no      | Counters/histograms via the `metrics` facade.       |

Vendor VSA dictionaries are opt-in to keep generated code small;
enable only the ones you need.

The `radsec` feature pulls in `aws-lc-sys`'s `ssl` build, which runs
`bindgen` and adds ~30s to a cold build (and requires `cmake` +
`clang`/`libclang`).

`fast-md5` is on by default. It is a pure-Rust crate with no native
build dependency — it uses Rust inline assembly for x86_64 and aarch64,
and a portable fallback for every other target.
If you need a build that avoids all optional dependencies, disable it
with `--no-default-features --features dict-rfc`; the public API is
identical and you fall back to `aws-lc-sys`'s MD5.

## RadSec (RFC 6614)

Enable the `radsec` feature, then add a TLS listener to the builder.
The pipeline for every accepted connection is:

1. **Pre-handshake DoS gate.** `ClientStore::admit_radsec(src) -> bool`
   is called immediately after `accept()`, before any TLS state is
   allocated. The default returns `false` (deny all) so every
   deployment makes a deliberate choice about its DoS exposure.
   Override it to add a CIDR allow-list or per-IP rate limit;
   `StaticClients` ships an override that admits any source IP
   matching a configured CIDR entry.
2. **mTLS handshake** against the listener-wide trust store passed
   to `TlsContext::server`. libssl performs chain validation against
   the configured CA(s); failures close the connection.
3. **Post-handshake authorization.**
   `ClientStore::lookup_radsec_by_cert(src, peer)` maps the peer's
   leaf certificate (and source address) to a registered `Client`.
   The store may key off Subject DN, SAN, SPKI fingerprint, source
   IP, or any combination — `radsecproxy`'s `verifyconfcert` policy.
   Returning `None` tears the connection down before any RADIUS
   frame is exchanged.

Long-lived connections can be torn down on revocation via
`Server::close_connections_for(client_id)`.

### PKI helpers

Standing up a RadSec deployment usually stalls on PKI: a CA, a
server cert with the right SAN, and one client cert per NAS, all
with the EKUs / KUs / BasicConstraints that modern verifiers
actually require. The `radius_tokio::pki` module (also gated on
the `radsec` feature) wraps `aws-lc-sys` to do exactly that, with
RFC 5280 / RFC 6614 §2.3 defaults baked in:

```rust,no_run
# #[cfg(feature = "radsec")]
# fn run() -> Result<(), Box<dyn std::error::Error>> {
use radius_tokio::pki::{CertificateAuthority, SubjectAltName};

// 1. Spin up a private CA (ECDSA P-256, SHA-256, 10y validity).
let ca = CertificateAuthority::new("RadSec Root")?;

// 2. Issue the server cert your listener will present.
//    EKU = serverAuth, KU = digitalSignature+keyEncipherment.
let server = ca.issue_server(
    "radsec.example.com",
    &[SubjectAltName::Dns("radsec.example.com".into())],
)?;

// 3. Issue one cert per NAS. EKU = clientAuth.
let nas = ca.issue_client(
    "nas-1",
    &[SubjectAltName::Ip("10.0.0.5".parse()?)],
)?;

// `server.chain_pem` + `server.key_pem` go to TlsContext::server;
// `nas.chain_pem` + `nas.key_pem` + `ca.cert_pem()?` go to the NAS.
# Ok(())
# }
```

The module is deliberately small — no CSRs, no CRLs, no encrypted
keys, no custom extensions. If you already run a real PKI, ignore
it and feed your existing PEM straight to `TlsContext::server`.

## CoA / Disconnect (RFC 5176)

The server can also originate `CoA-Request` / `Disconnect-Request` to
a NAS via `CoaOriginator`. Replies (`CoA-ACK` / `CoA-NAK`,
`Disconnect-ACK` / `Disconnect-NAK`) are correlated and surfaced as a
typed `CoaOutcome`. The originator carries both the Authenticator
field and a `Message-Authenticator` attribute on every request, per
RFC 5176 §3.

## Cryptography

All cryptographic operations go through an in-tree `crypto` module
that wraps `aws-lc-sys` directly:

- HMAC-MD5 / MD5 — Request and Response Authenticators (RFC 2865 §3),
  Message-Authenticator (RFC 3579 §3.2).
- HMAC-SHA1 / HMAC-SHA256, AES, DES, key-wrap — used by
  Tunnel-Password, MS-CHAP, and the RadSec `SSL` layer.
- `RAND_bytes` — Request Authenticator generation.
- `CRYPTO_memcmp` — constant-time tag comparisons.

Every `unsafe` block carries a `// SAFETY:` comment explaining the
invariants. FFI handles (`SSL`, `EVP_MD_CTX`, `HMAC_CTX`, `X509`, …)
are wrapped in newtypes whose `Drop` impl frees via the correct
`*_free` function.

## Observability

The `tracing` and `metrics` features are additive and dependency-free
when off. With them on, the library emits a fixed event vocabulary
under the `radius_tokio` target / metric prefix:

- `packets_dropped{reason=…}`, `requests_dispatched{code=…}`,
  `replies_sent{code=…}`, `dedup_hits`, `send_errors`,
  `handler_duration_seconds` (histogram).
- RadSec-specific: `radsec_connections`, `radsec_admit_rejects`,
  `radsec_handshake_failures`, `radsec_cert_lookup_failures`,
  `radsec_revocations_applied`.
- CoA originator: `coa_requests_sent{code=…}`, `coa_outcomes{outcome=…}`.

Off-by-default macros expand to nothing — there is no runtime cost
when the features are disabled.

## MSRV

**Rust 1.79** (required for return-position `impl Trait` in traits;
used pervasively for `async fn` in traits without `async-trait`).
Pinned via `rust-version` in each `Cargo.toml`.

## Platforms & testing

CI builds and tests every push on:

| Host                        | Stable | MSRV (1.79) |
| --------------------------- | :----: | :---------: |
| Linux x86_64 (glibc)        |   ✓    |      ✓      |
| macOS aarch64 (Apple Si.)   |   ✓    |      ✓      |
| Windows x86_64 (MSVC)       |   ✓    |      ✓      |

There is no architecture-specific code in the crate; the matrix
exists to catch portability regressions in the codec, server, and
`aws-lc-sys` wrappers (AWS-LC builds via `cmake` on every host,
plus `nasm` on Windows for the perl-asm sources).

End-to-end integration tests under `tests/` drive the server with
real RADIUS tooling — `radclient`, `radsecproxy`, and `eapol_test`.
Those binaries only ship convenient packages on Linux, so the
suites self-skip on macOS and Windows; the Linux CI cell installs
them and runs the full set. Local development on macOS / Windows
still gets the unit, codec, and TLS handshake coverage.

A separate AddressSanitizer job (Linux nightly, x86_64) exercises
every `unsafe` block in `src/crypto/` against the underlying
`aws-lc-sys` FFI. Miri is not run: every `unsafe` block in the
workspace lives behind an FFI call (which miri cannot execute),
and the pure-Rust workspace members have no `unsafe` worth
checking.

## Performance

End-to-end UDP throughput with a no-op handler on a containerised
ARM host: **239 k req/s, p99 = 42 µs** (budget: > 200 k req/s,
p99 < 50 µs). See [`BENCHMARKS.md`](BENCHMARKS.md) for the full
methodology, hardware, and per-component numbers.

## License

Licensed under the BSD 2-Clause License — see the `LICENSE` file at
the root of the repository.

The vendored FreeRADIUS dictionaries under
`crates/radius-dict/dictionaries/` carry their own upstream licenses;
see the `LICENSE` files in those directories.
