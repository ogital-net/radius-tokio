# Changelog

All notable changes to `radius-tokio` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning policy

While the version stays below `1.0`, **breaking changes are allowed
without a deprecation cycle** and may land in any release. Each
release notes which surface broke and why.

`1.0` will mark the point at which the public API is locked under
SemVer guarantees: breaking changes will then require a major bump,
and deprecation precedes removal by at least one minor release.

## [Unreleased]

### Added

- **PKI helpers (`radius_tokio::pki`, gated on `radsec`).** Sensible-
  defaults wrappers over `aws-lc-sys` for spinning up a private CA
  and issuing RadSec server / client leaves with RFC 5280 §4.2 +
  RFC 6614 §2.3 defaults pre-applied (ECDSA P-256, SHA-256, 128-bit
  random serial, correct EKU / KU / BasicConstraints / SAN / SKI /
  AKI). Reduces the from-zero-to-working-RadSec friction without
  pulling in a third-party PKI library.

### Removed

- `rcgen` dev-dependency. Test fixtures now build their PKI through
  the in-tree `pki` module, which is also what consumers see.

## [0.1.0] - 2026-05-10

Initial release. Pre-1.0 \u2014 the API may evolve.

### Added

- **Codec.** Zero-copy decode of RFC 2865 packets and attribute
  lists, allocation-free encode of replies into a caller-supplied
  buffer, Request / Response Authenticator computation per RFC 2865
  \u00a73 + RFC 2866 \u00a73, Message-Authenticator (RFC 3579 \u00a73.2) verify +
  insert helpers, EAP-Message reassembly view (RFC 3579 \u00a73.1),
  User-Password / Tunnel-Password helpers.
- **Server runtime.** Async `Server` + `ServerBuilder` driving
  per-listener accept loops on Tokio. Pluggable `ClientStore` and
  `Handler` traits using native `async fn` in traits (no
  `async-trait`). Per-source dedup cache for RFC 5080 \u00a72.2.2
  retransmits. Graceful shutdown handle.
- **Transports.** UDP authentication / accounting (RFC 2865 / RFC
  2866). RadSec / RADIUS-over-TLS (RFC 6614) under the `radsec`
  feature, in cert-keyed (default) or IP-gated mode, with mTLS and
  per-connection trust narrowing. Long-lived connection revocation
  hook (`Server::close_connections_for`).
- **Dynamic Authorization.** `CoaOriginator` for RFC 5176
  CoA-Request / Disconnect-Request with retry, backoff, and per-NAS
  rate limiting. Replies surfaced as a typed `CoaOutcome`.
- **Client store.** `StaticClients` (immutable, CIDR-keyed) and
  `CachedStore<S>` (TTL + negative-cache + single-flight wrapper)
  for any backend.
- **Auth helpers.** PAP, CHAP, MS-CHAPv1, MS-CHAPv2 inspectors
  taking a borrowed `Request` and the expected password, returning a
  typed `VerifyOutcome`.
- **Crypto.** Safe wrappers over `aws-lc-sys` for HMAC-MD5, MD5,
  HMAC-SHA1, HMAC-SHA256, AES, DES, RNG, constant-time compare, and
  the RadSec TLS layer (`SSL_CTX` / `SSL` / X.509 verification).
- **Dictionaries.** Build-time codegen from vendored FreeRADIUS
  dictionary files, exposed as typed `Attr<T>` / `VsaAttr<T>`
  handles. RFC dictionaries on by default; per-vendor
  dictionaries (Cisco, Aruba, Juniper, Ruckus, MikroTik, Meraki,
  Microsoft, Fortinet, HP, Ascend, WISPr, Ubiquiti) opt-in via
  `dict-*` features. Workspace split: runtime tables live in the
  `radius-dict` crate, the parser + renderer in the build-only
  `radius-dict-codegen` crate.
- **Observability.** Optional `tracing` and `metrics` features with
  a fixed event vocabulary under the `radius_tokio` target / metric
  prefix; macros expand to nothing when the features are off.
- **Examples.** Minimal UDP (in the README quickstart),
  `mutable_clients` (in-memory `ArcSwap`-backed store),
  `sqlite_clients` (SQLite-backed store fronted by `CachedStore`),
  `threadlocal_responder` (synchronous worker pattern bypassing
  `Handler`), `coa_originator` (RFC 5176 originator),
  `mixed_udp_radsec` (one server, both transports), `dhat_hot_path`
  (allocation profile).
- **Documentation.** Module-level docs across the public API, the
  README is the rustdoc landing page, `BENCHMARKS.md` records
  recorded baselines, `CONTRIBUTING.md` covers the development
  workflow.

### Performance

End-to-end UDP throughput with a no-op handler on a containerised
ARM host: **239 k req/s, p99 = 42 \u00b5s**. See `BENCHMARKS.md` for
methodology and per-component numbers.
