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

### Security

- **Message-Authenticator now required by default on Access-Request
  packets.** Inbound Access-Request packets that omit RFC 3579 §3.2
  Message-Authenticator are dropped before dispatch, closing the
  default exposure to the `BlastRADIUS` family of attacks
  (CVE-2024-3596). The policy is per-`Client` and defaults to
  strict; legacy NAS firmware that cannot emit the attribute can be
  opted out one device at a time via
  `Client::allow_missing_message_authenticator()`. The verbose
  method name is deliberate — flipping the bit should be a
  conscious, audit-visible act. Accounting / CoA / Disconnect
  packets are unaffected (they authenticate via the Request
  Authenticator and have never been required to carry M-A).
  Listeners emit a `tracing` warn event and a
  `radius_tokio.packets_dropped{reason="missing_message_authenticator"}`
  metric on each drop.

### Added

- **EAP-over-RADIUS ergonomics.** The codec now exposes the full
  parse / encode pair for EAP-Message payloads so consumers writing
  an EAP method engine never reach for raw bytes:
  - `codec::eap::Packet::parse` — borrowed, validated view over a
    reassembled `EAP-Message` payload (`Code` / `Identifier` /
    `Length` / `Type` / `Type-Data`), with `eap::Code` and `eap::Type`
    newtypes carrying the well-known RFC 3748 §4 / §5 constants
    (`IDENTITY`, `MD5_CHALLENGE`, `MSCHAPV2`, `TLS`, `PEAP`, …).
  - `codec::eap::write_request` / `write_response` /
    `write_success` / `write_failure` — symmetric encoders that
    round-trip through `Packet::parse`; method-specific code only
    has to build the `Type-Data` blob.
  - `Reply::add_eap_message(&[u8])` — fragments an EAP packet into
    consecutive ≤253-byte `EAP-Message` attributes per RFC 3579 §3.1
    (inverse of `eap::reassemble_into`). `Reply::add_eap_success(id)`
    / `Reply::add_eap_failure(id)` sugar over it for the common
    terminal-EAP reply shapes.
  - `Request::eap_message()` / `Request::eap_message_into(&mut Vec<u8>)`
    — reassemble every `EAP-Message` attribute into a fresh or
    caller-supplied buffer in one call.
  - `Request::state()` / `Reply::add_state(&[u8])` — opaque
    `State` (RFC 2865 §5.24) round-trip helpers for multi-round
    exchanges. `Request::user_name()` mirrors the same shape for
    the canonical RFC 2865 §5.1 attribute.
  - New `examples/eap_identity_challenge.rs` — worked EAP-MD5
    `Access-Request` → `Access-Challenge` → `Access-Request` →
    `Access-Accept` flow in ≤ 30 lines of handler code, driven by
    hostap's `eapol_test`. The sister `tests/eapol_test_md5.rs`
    and `tests/eapol_test_mschapv2.rs` integration tests run the
    same idiom end-to-end against the real `eapol_test` binary.

  Terminating EAP methods inside the library (PEAP, EAP-TLS,
  EAP-TTLS, EAP-MSCHAPv2 state machinery) remains a permanent
  non-goal; the codec view plus `auth::eap_md5` / `auth::mschap`
  primitives are everything the library exposes — consumers plug in
  whatever method engine they already use.
- **Status-Server (RFC 5997 / RFC 6614 §2.6).** Built-in keepalive
  responder runs inline on every UDP and RadSec listener — no
  consumer `Handler` invocation, no new task — so probe traffic
  cannot queue behind application latency. Listener role
  (`ListenerRole::Auth` → `Access-Accept`,
  `ListenerRole::Acct` → `Accounting-Response`) selects the reply
  code per RFC 5997 §6. Reply-side Message-Authenticator is always
  emitted (already a project-wide secure default); request-side is
  required unconditionally (RFC 5997 §6 mandates it regardless of
  the per-`Client` strict-M-A toggle that governs Access-Request).
  Server-wide policy via
  `ServerBuilder::status_server_policy(StatusServerPolicy::{Disabled,Enabled,Custom})`;
  per-client mute via `Client::disable_status_server()`. Custom
  policy gets a synchronous `StatusResponder` callback that may
  append a `Reply-Message` (helper:
  `radius_tokio::server::status::append_reply_message`) or veto the
  reply with `StatusAction::Drop`. Retransmits replay byte-identical
  through the existing dedup cache.
- `ServerBuilder::listen_udp_with(addr, role)` and
  `ServerBuilder::listen_radsec_with(addr, tls, role)` for binding
  a listener with an explicit `ListenerRole`. The default
  `listen_udp` / `listen_radsec` retain `ListenerRole::Auth`.
- `PacketBuffer::seal_as_random_authenticator_request(req_auth, secret)`
  — public helper that finalises an Access-Request-shaped frame
  (Status-Server probes, fuzz / test harnesses) by installing the
  random Request Authenticator and an HMAC-MD5
  Message-Authenticator computed against the final packet bytes.
- `Client::require_message_authenticator()` accessor and
  `Client::allow_missing_message_authenticator()` builder method
  (see Security note above).
- **PKI helpers (`radius_tokio::pki`, gated on `radsec`).** Sensible-
  defaults wrappers over `aws-lc-sys` for spinning up a private CA
  and issuing RadSec server / client leaves with RFC 5280 §4.2 +
  RFC 6614 §2.3 defaults pre-applied (ECDSA P-256, SHA-256, 128-bit
  random serial, correct EKU / KU / BasicConstraints / SAN / SKI /
  AKI). Reduces the from-zero-to-working-RadSec friction without
  pulling in a third-party PKI library.
- `PeerCertificate::matches_hostname(name, allow_common_name)`
  implementing RFC 6125 §6.4.3 (SAN dNSName preferred, leftmost-
  label wildcards, IP-literal expectations matched against
  iPAddress SANs) and §6.4.4 (CN consulted only when no DNS SAN
  exists *and* the caller opts in). The `mixed_udp_radsec` example
  and `radsec_e2e` integration test both consume it.

### Changed

- **Behaviour change**: deployments that previously relied on the
  permissive Message-Authenticator default and have NAS devices
  which do not emit the attribute on Access-Request will now drop
  those packets. Migration: call
  `.allow_missing_message_authenticator()` on the affected
  `Client` records.

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
  `radius-tokio-dict` crate, the parser + renderer in the build-only
  `radius-tokio-dict-codegen` crate.
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
