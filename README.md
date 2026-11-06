# radius-tokio

An async RADIUS client and server library for Rust on top of Tokio,
with UDP and mutually authenticated RadSec. Enable either role or both;
they share the wire codec, crypto, dictionaries, and TLS transport.
The crate is meant to be embedded: there is no `main`, config file, or
daemonisation. Server applications construct a `Server` with two traits
(`ClientStore` and `Handler`) and drive it from their own runtime.
The library handles the wire-level work — decoding, deduplication,
authenticator verification, reply sealing, RadSec mTLS — and stays
out of the policy layer.

EAP method termination lives in a companion crate,
[`radius-tokio-eap`](crates/radius-tokio-eap/), which plugs into the
same `Handler` surface and ships PEAP, EAP-TTLS, EAP-TLS, EAP-MD5
and bare EAP-MSCHAPv2.

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

`0.1`. The wire codec, dedup pipeline, UDP and RadSec listeners,
UDP/RadSec clients, CoA originator, Status-Server responder and the EAP method drivers
are all in. Breaking API changes are still on the table until
`1.0`; the wire-touching internals are settling first, the
trait-facing surface second.

## Supported RFCs

| RFC      | Title                                         | Status                |
|----------|-----------------------------------------------|-----------------------|
| RFC 2865 | RADIUS                                        | implemented           |
| RFC 2866 | RADIUS Accounting                             | implemented           |
| RFC 2867 | Tunnel Protocol Accounting                    | dictionaries          |
| RFC 2868 | Tunnel Protocol Attributes                    | implemented (`Tagged`)|
| RFC 2869 | RADIUS Extensions                             | dictionaries          |
| RFC 3162 | RADIUS and IPv6                               | dictionaries          |
| RFC 3579 | RADIUS Support for EAP                        | reassembly + MA       |
| RFC 3580 | IEEE 802.1X Usage Guidelines                  | dictionaries          |
| RFC 3748 | EAP                                           | `radius-tokio-eap`    |
| RFC 5080 | Common RADIUS Implementation Issues           | dedup cache           |
| RFC 5176 | Dynamic Authorization (CoA / Disconnect)      | implemented           |
| RFC 5216 | EAP-TLS                                       | `radius-tokio-eap`    |
| RFC 5281 | EAP-TTLS v0                                   | `radius-tokio-eap`    |
| RFC 5997 | Status-Server                                 | implemented           |
| RFC 6614 | RADIUS over TLS (RadSec)                      | implemented           |
| RFC 7542 | NAI (`user@realm` parsing)                    | implemented           |
| RFC 8044 / 6158 | Data type guidance                     | dict types            |

## Quickstart

Server support remains enabled by default. Client-only consumers use:

```toml
radius-tokio = { version = "0.1", default-features = false, features = ["client", "radsec", "dict-rfc", "fast-md5"] }
```

### Client

```rust,no_run
# #[cfg(all(feature = "client", feature = "dict-rfc"))]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use radius_tokio::client::{ClientConfig, Request, UdpClient};
use radius_tokio::dict::rfc::attrs;
use radius_tokio::{AttributesView, Code};

let client = UdpClient::bind("0.0.0.0:0".parse()?, ClientConfig::default()).await?;
let mut request = Request::access();
request.add(attrs::USER_NAME, "alice")?;
request.user_password(b"example-password")?;
let response = client.send("127.0.0.1:1812".parse()?, b"example-secret", request).await?;
match response.code() {
    Code::ACCESS_ACCEPT => {}
    Code::ACCESS_REJECT => {}
    Code::ACCESS_CHALLENGE => {
        let mut next = Request::access();
        next.add(attrs::USER_NAME, "alice")?;
        if let Some(state) = response.attributes().state() {
            next.add_state(state)?;
        }
        // Add the challenge response before sending `next`.
    }
    _ => unreachable!(),
}
# Ok(())
# }
```

For RadSec, construct `tls::TlsContext::client(client_chain, private_key,
server_ca_bundle)`, then call `RadsecClient::connect(endpoint, &context,
expected_server_name, config).await` and `client.send(request).await`.
The client requires a matching DNS/IP SAN, sends SNI for DNS names, and
never falls back to Common Name or an unverified TLS connection.
See the runnable [UDP](examples/udp_client.rs) and
[RadSec](examples/radsec_client.rs) examples for credential configuration.

Requests support Access, Accounting, Status-Server, CoA, and Disconnect.
Responses are owned, verified, and expose `AttributesView` through
`response.attributes()`. Reject and Challenge are protocol outcomes,
not transport errors. EAP-Message and State can be carried without adding
supplicant-side EAP state machines.

UDP retries send identical bytes. RadSec uses a persistent multiplexed
connection and never retransmits or automatically reconnects/replays a
request. Cancellation may finish an already-started write; a timeout or
disconnect does not prove that the server did not process the request.
Reconnect explicitly and decide whether replay is safe for the operation.
Call `RadsecClient::close().await` for best-effort close-notify.
Incoming CoA/Disconnect requests receive NAK with Error-Cause 406
(Unsupported-Extension); there is no client-side session-control handler.

Access, Status, and dynamic-authorization replies require a valid
Message-Authenticator. Accounting replies may omit it; any present tag
must verify. UDP replies also require the expected source endpoint,
identifier, response code, and Response Authenticator.

### Server

A minimal Access-Request → Access-Accept loop, UDP only:

```rust,no_run
# #[cfg(all(feature = "server", feature = "dict-rfc"))]
# mod example {
use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, Request, Server, StaticClients,
};
use radius_tokio::{AttributesView, Code};
use radius_tokio::dict::rfc::attrs;

struct MyApp;

impl Handler for MyApp {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            return HandlerResult::Drop;
        }
        // `AttributesView` exposes zero-copy accessors that borrow
        // straight from the inbound buffer.
        let _user = request.user_name().unwrap_or_default();

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
# }
# fn main() {}
```

### Reading attributes — `AttributesView`

`Request`, the EAP crate's `Outer` (passed to credential lookups)
and the EAP crate's `AcceptContext` (passed to authorisation
decorators) all implement the same `AttributesView<'a>` trait.
Bringing it into scope unlocks the same set of zero-copy accessors
everywhere:

```rust,no_run
use radius_tokio::AttributesView;
# #[cfg(feature = "server")]
# fn demo(req: radius_tokio::server::Request<'_>) {
let user_name = req.user_name();                   // Option<&[u8]>
let state     = req.state();                       // Option<&[u8]>
let split     = req.user_name_realm();             // (user, realm) — NAI / DOMAIN\ / %
let eap_msg   = req.eap_message();                 // reassembled EAP-Message
for slot in req.attributes_iter() { /* ... */ }
# }
```

### Tagged tunnel attributes (RFC 2868)

Attributes carrying an RFC 2868 §3.1 tag — `Tunnel-Type`,
`Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, … — are exposed
through `Tagged<V>` so consumers never hand-roll the tag byte or
the 24-bit packing of tagged integers:

```rust,no_run
# #[cfg(all(feature = "server", feature = "dict-rfc"))]
# mod example {
use radius_tokio::AttributesView;
use radius_tokio::dict::rfc::attrs;
use radius_tokio::dict::Tagged;
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
# }
```

### Examples

[`examples/`](examples/):

| File                          | What it shows                                       |
|-------------------------------|-----------------------------------------------------|
| `udp_client.rs`               | PAP authentication using the UDP client.           |
| `radsec_client.rs`            | PAP authentication over mutually authenticated TLS. |
| `routing_dispatcher.rs`       | Routing on `Service-Type` / VSA via `CodeRouter`.   |
| `mutable_clients.rs`          | Runtime-mutable in-memory `ClientStore`.            |
| `sqlite_clients.rs`           | SQLite-backed `ClientStore` behind `CachedStore`.   |
| `mixed_udp_radsec.rs`         | One handler, UDP + RadSec listeners side by side.   |
| `coa_originator.rs`           | Sending CoA / Disconnect to a NAS.                  |
| `graceful_shutdown.rs`        | `ShutdownHandle` + in-flight draining.              |
| `threadlocal_responder.rs`    | Bypassing `Handler` for thread-local reply paths.   |
| `eap_identity_challenge.rs`   | Identity / MD5-challenge without the EAP crate.     |
| `dhat_hot_path.rs`            | Allocation profiling of the codec hot path.         |

[`crates/radius-tokio-eap/examples/`](crates/radius-tokio-eap/examples/):

| File                | What it shows                                           |
|---------------------|---------------------------------------------------------|
| `peap_mschapv2.rs`  | PEAPv0 + inner EAP-MSCHAPv2, end-to-end.                |
| `multi_method.rs`   | Method negotiation across PEAP / EAP-TLS / EAP-TTLS.    |

## EAP — `radius-tokio-eap`

The companion crate ships server-side EAP state machines that slot
into the same `Handler` plumbing:

| Method        | Spec              | Inner method               | Cargo feature   |
|---------------|-------------------|----------------------------|-----------------|
| EAP-MD5       | RFC 3748 §5.4     | (none — bare)              | `eap-md5`       |
| EAP-MSCHAPv2  | draft-kamath §3   | (none — bare, legacy wired)| `eap-mschapv2`  |
| EAP-TLS       | RFC 5216 / 9190   | (none — TLS cert)          | `eap-tls`       |
| PEAP v0       | draft-josefsson   | EAP (commonly MSCHAPv2)    | `peap`          |
| EAP-TTLS      | RFC 5281          | AVP (PAP / inner EAP)      | `eap-ttls`      |

Each method exposes a small `Credentials` (lookup-style) or
`PapCredentials` (verify-style) trait that takes an `Outer<'_>` and
a username; closures and in-memory `StaticCredentials` stores are
provided for tests and small deployments. `EapHandler::with_accept_decorator`
lets you stamp authorisation attributes (VLAN assignment, ACL
profiles, session timeouts) onto each `Access-Accept` as it leaves
the handler. End-to-end interop is exercised against `eapol_test`
under `crates/radius-tokio-eap/tests/`.

## Cargo features

### `radius-tokio`

| Feature           | Default | Effect                                              |
|-------------------|---------|-----------------------------------------------------|
| `server`          | yes     | Server runtime, handler-facing auth helpers, and compatible CoA originator API. |
| `client`          | no      | Outgoing requests, verified responses, and UDP client. |
| `tls`             | no      | Shared memory-BIO TLS and PKI, without RadSec socket I/O. |
| `dict-rfc`        | yes     | RFC dictionaries (small, recommended).              |
| `fast-md5`        | yes     | Swap the MD5 block compressor from `aws-lc-sys` to the [`fast-md5`](https://crates.io/crates/fast-md5) crate (hand-written x86_64 + aarch64 assembly, portable Rust fallback, `#![no_std]`). |
| `radsec`          | no      | RADIUS-over-TLS for enabled roles; includes `tls`. |
| `tracing`         | no      | Structured spans/events around accept and dispatch. |
| `metrics`         | no      | Counters / histograms via the `metrics` facade.     |
| `test-util`       | no      | `server::test_support::MockRequest` for downstream handler tests. |
| `dict-vendor-all` | no      | Umbrella over every vendored vendor dictionary.     |
| `dict-<vendor>`   | no      | Per-vendor VSAs: `airespace`, `aruba`, `ascend`, `cisco`, `eleven`, `fortinet`, `hp`, `juniper`, `meraki`, `microsoft`, `mikrotik`, `ruckus`, `tplink`, `wispr`. |

Vendor VSA dictionaries are opt-in to keep generated code small.
The `tls` feature (also enabled by `radsec`) pulls in `aws-lc-sys`'s `ssl` build, which
runs `bindgen` and adds ~30s to a cold build (requires `cmake` and
`clang`/`libclang`).

`fast-md5` has no native build dependency — it uses Rust inline
assembly for x86_64 and aarch64 and a portable fallback elsewhere.
For a server using the `aws-lc-sys` MD5 backend instead of `fast-md5`, use
`--no-default-features --features server,dict-rfc`. Neither role requires
the other; both disabled leaves the shared protocol APIs. Cargo features
are additive, so another dependency enabling `server` also enables it
for your build.

### `radius-tokio-eap`

| Feature        | Default | Effect                                              |
|----------------|---------|-----------------------------------------------------|
| `eap-md5`      | no      | EAP-MD5-Challenge.                                  |
| `eap-mschapv2` | no      | Native EAP-MSCHAPv2 (legacy wired 802.1X).          |
| `eap-tls`      | no      | EAP-TLS (pulls `radius-tokio/tls`).                 |
| `peap`         | no      | PEAP v0 + EAP-MSCHAPv2 inner.                       |
| `eap-ttls`     | no      | EAP-TTLS with bundled PAP inner.                    |
| `all-methods`  | no      | Umbrella over every method above.                   |
| `tracing`      | no      | Per-session / per-method `tracing` events.          |
| `metrics`      | no      | Counters via the `metrics` facade.                  |

## RadSec (RFC 6614)

The RadSec client always uses the RFC 6614 legacy packet secret `radsec`;
TLS provides confidentiality and peer authentication. Configure RadSec
server-side `Client` records with `b"radsec"` as well. Keep UDP shared
secrets distinct and private. Existing server APIs still allow an
explicit secret for legacy deployments.

Enable `server` and `radsec`, then add a TLS listener to the builder.
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

No CSRs, no CRLs, no encrypted keys, no custom extensions. If you
already run a real PKI, ignore this and feed your PEM straight to
`TlsContext::server`.

## CoA / Disconnect (RFC 5176)

The server can originate `CoA-Request` / `Disconnect-Request` to a
NAS via `CoaOriginator`. Replies (`CoA-ACK` / `CoA-NAK`,
`Disconnect-ACK` / `Disconnect-NAK`) are correlated and surfaced
as a typed `CoaOutcome`. The originator carries both the
Authenticator field and a `Message-Authenticator` attribute on
every request, per RFC 5176 §3.

## Cryptography

All cryptographic operations go through an in-tree `crypto` module
that wraps `aws-lc-sys` directly:

- HMAC-MD5 / MD5 — Request and Response Authenticators (RFC 2865 §3),
  Message-Authenticator (RFC 3579 §3.2).
- HMAC-SHA1 / HMAC-SHA256, AES, DES, key-wrap — Tunnel-Password,
  MS-CHAP, and the RadSec `SSL` layer.
- `RAND_bytes` — Request Authenticator generation.
- `CRYPTO_memcmp` — constant-time tag comparisons; re-exported
  to consumers as `radius_tokio::ct_eq` for handler-side use.

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

The EAP crate emits its own vocabulary under `radius_tokio_eap`
(session create / complete, method dispatch, fragment overflow,
TLS handshake completion) so consumers can filter independently.

Off-by-default macros expand to nothing when the features are
disabled — there is no runtime cost.

## MSRV

**Rust 1.83.** Required for return-position `impl Trait` in traits;
used pervasively for `async fn` in traits without `async-trait`.
Pinned via `rust-version` in each `Cargo.toml`.

## Platforms & testing

CI builds and tests every push on:

| Host                        | Stable | MSRV (1.83) |
| --------------------------- | :----: | :---------: |
| Linux x86_64 (glibc)        |   ✓    |      ✓      |
| macOS aarch64 (Apple Si.)   |   ✓    |      ✓      |
| Windows x86_64 (MSVC)       |   ✓    |      ✓      |

There is no architecture-specific code in the crate; the matrix
exists to catch portability regressions in the codec, server, and
`aws-lc-sys` wrappers (AWS-LC builds via `cmake` on every host,
plus `nasm` on Windows for the perl-asm sources).

End-to-end integration tests under `tests/` and
`crates/radius-tokio-eap/tests/` drive the server with real RADIUS
tooling — `radclient`, `radsecproxy`, and `eapol_test`. Those
binaries only ship convenient packages on Linux, so the suites
self-skip on macOS and Windows; the Linux CI cell installs them
and runs the full set. Local development on macOS / Windows still
gets the unit, codec, and TLS handshake coverage.

A separate AddressSanitizer job (Linux nightly, x86_64) exercises
every `unsafe` block in `src/crypto/` against the underlying
`aws-lc-sys` FFI. Miri is not run: every `unsafe` block in the
workspace lives behind an FFI call (which miri cannot execute),
and the pure-Rust workspace members have no `unsafe` worth
checking.

## Performance

End-to-end UDP throughput with a no-op handler on a containerised
ARM host: **239 k req/s, p99 = 42 µs** (target: > 200 k req/s,
p99 < 50 µs). See [`BENCHMARKS.md`](BENCHMARKS.md) for the full
methodology, hardware, and per-component numbers.

## Non-goals

[`NON_GOALS.md`](NON_GOALS.md) lists what this crate deliberately
will not do. Roadmap items live in [`ROADMAP.md`](ROADMAP.md).

## License

BSD 2-Clause — see [LICENSE](./LICENSE).

The vendored FreeRADIUS dictionaries under
`crates/radius-tokio-dict/dictionaries/` carry their own upstream
licenses; see the `LICENSE` files in those directories.

