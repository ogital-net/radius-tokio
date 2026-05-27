# Roadmap

Planned, not-yet-shipped work. Items here are **intent, not commitment** —
they describe shape and rationale so contributors can pick them up or
veto them without re-deriving the context. Once a roadmap item lands,
its entry moves to [`CHANGELOG.md`](CHANGELOG.md) and is removed from
this file.

Shipped, in-scope features live in `CHANGELOG.md`. Permanent
non-goals (e.g. terminating EAP methods inside the library) are
called out in [`NON_GOALS.md`](NON_GOALS.md) and the relevant module
docs.

## Transport

### RADIUS/DTLS (RFC 7360)

Datagram-secured RADIUS over UDP. Same wire layout as plain RADIUS but
each packet rides inside a DTLS record; shares the certificate /
trust-anchor plumbing already in `src/crypto/tls.rs` and `src/crypto/pki.rs`.
Sits alongside `server::radsec` (RADIUS/TLS over TCP, RFC 6614) as
the second transport that lets operators retire the static shared
secret. Open design questions: cookie / `HelloVerifyRequest` policy,
fragment cache lifetime, ID-space sharing with the plain UDP listener.

### PROXY protocol v2 ingress

Five-byte PROXY v2 header parsing at accept time on both UDP and
TCP/TLS listeners so the library can recover the original NAS source
address when a load balancer is in front (HAProxy, AWS NLB, Envoy).
Off by default; enabled per-listener so trusted-LB and direct-NAS
deployments don't collide. The recovered address feeds back into
`ClientStore` lookup and tracing spans.

## Codec

### Long-attribute fragmentation (RFC 7268)

Encoder helper that splits a value larger than 253 bytes across
consecutive `Long-Extended-Type` slots with the M-bit set, and a
matching decoder helper that reassembles them on the receive side.
Today callers can stuff multi-slot `EAP-Message` payloads (handled
explicitly in `Reply::add_eap_message`), but no general
fragmentation/reassembly exists for arbitrary long values. Pairs
naturally with the dissector work for `LongExtended` already in
`codec::dissect`.

## Server

### Request governor

Two complementary back-pressure knobs, both off by default:

* A global in-flight semaphore that caps the number of concurrent
  handler invocations and rejects (or queues with a deadline) once
  saturated, so a slow downstream cannot grow the Tokio task set
  without bound.
* A per-client token bucket on top of `ClientStore` for QPS shaping
  — protects against a single misbehaving NAS swamping the listener
  before the de-dup cache catches the retransmits.

Both should integrate with the existing `radius_tokio.packets_dropped`
counter so operators see *why* a drop happened, not just that it did.

### Tracing spans

Structured `tracing::span!`s threaded from accept → validate →
dispatch → reply with stable field names (`code`, `identifier`,
`client_addr`, `handler_outcome`). Consumers wire this into their
own subscriber; we don't pick a backend. Most of the call sites
already emit `tracing::debug!` events — promoting the surrounding
scopes to spans makes per-request timing and correlation IDs
available without extra plumbing.

## Auth / Identity

### Realm parser

Helper that decomposes the `User-Name` attribute into `(user, realm)`
across the three forms RFC 7542 and historical deployments use:
`user@realm` (NAI), `realm\user` (Windows-style), and `user%realm`
(legacy Cisco). Returns owned slices so handlers can dispatch on the
realm without hand-rolling string ops; non-goal is any opinion on
*what* to do with the realm (that's a `ClientStore` / `Handler`
concern).

## EAP

### Additional EAP methods in `radius-tokio-eap`

The companion `radius-tokio-eap` crate ships MD5-Challenge and the
TLS family today. The roadmap, in rough priority order:

* **EAP-GTC (RFC 3748 §5.6)** — straight token / OTP prompt, no
  crypto state machine. Lowest-effort addition; useful inside
  TTLS/PEAP tunnels.
* **EAP-PWD (RFC 5931)** — password-authenticated key exchange,
  avoids the cleartext-to-tunnel pattern of PEAP/TTLS. Lower
  priority because deployments are rare.
* **EAP-FAST (RFC 4851) / EAP-TEAP (RFC 7170)** — Cisco / IETF
  successor to PEAP. Useful for sites already on FAST; design
  question is whether PAC provisioning is in or out of scope.

### EAP-AKA' extensions

The first-cut EAP-AKA' driver in `radius-tokio-eap` (feature
`eap-aka-prime`) covers the basic IMSI-based full-authentication
flow with an in-memory `StaticVectorProvider` fixture. The
following layer cleanly on top of the existing codec and trait:

* **Fast re-authentication** (`AKA-Reauthentication`,
  `AT_NEXT_REAUTH_ID`, `AT_COUNTER`, `AT_IV` / `AT_ENCR_DATA`) —
  avoids a fresh AV per session for repeat connections.
* **Pseudonym identity** (`AT_NEXT_PSEUDONYM`) — IMSI-privacy
  rotation between full authentications.
* **Synchronisation-failure recovery** — today we forward `AUTS`
  to `report_sync_failure` and fail the current session; the
  next-step is restarting the challenge in-band once the HSS
  refresh completes.
* **Reference Milenage `f1..f5` helper crate** — most HSS-less
  deployments want one, but it doesn't belong in the EAP state
  machine itself.

