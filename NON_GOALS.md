# Non-Goals

Permanent boundaries: features this library will not grow, and
patches adding them will be declined. Each item is paired with a
short rationale so contributors can route their effort elsewhere
without re-litigating the decision.

Roadmap items (intent, not commitment) live in
[`ROADMAP.md`](ROADMAP.md). Shipped features live in
[`CHANGELOG.md`](CHANGELOG.md).

## Protocol topology

### RADIUS proxy / home-server pools / Proxy-State chains

`radius-tokio` is an authoritative AAA library: it terminates the
RADIUS exchange and hands an `&Request` to a `Handler`. It will not
grow a proxy mode (rewrite `Proxy-State`, pick an upstream from a
realm-keyed home-server pool, forward and stitch the reply,
fail-over across pool members). Operators who need a proxy reach for
`radsecproxy` or FreeRADIUS in `proxy.conf` mode — both purpose-built
for that role.

Consumers can still build a forwarder on top of `CoaOriginator`-style
client primitives if they want narrow point-to-point relaying inside
their own handler.

### RADIUS/TCP plain (RFC 6613)

Plain RADIUS over TCP without TLS. RFC 6613 §2.6.4 itself warns
"this transport SHOULD NOT be used for production deployments";
RFC 6614 (RADIUS/TLS) and the planned RFC 7360 RADIUS/DTLS support
cover every operational case where TCP framing matters, with the
secrecy and authentication TCP-alone is missing.

### Status-Client (code 13, RFC 5997)

RFC 5997 §4 explicitly says "this document does not define a
Status-Client packet" and notes there is no widely deployed use
case. Status-Server (code 12) is fully supported and covers the
operational need.

### Server-originated Interim-Update

Already a non-goal in `src/server/accounting.rs`: the *NAS* sends
Interim-Update when its `Acct-Interim-Interval` timer fires; the
AAA server's job is to accept those and respond. This library will
not synthesize Interim-Update packets toward a NAS — that would be
inventing accounting data the NAS never authored.

## Operations

### Configuration file / hot reload / daemonization

No `radius.conf`, no SIGHUP reload, no init script, no `--daemon`
flag, no `clients.conf` parser. `radius-tokio` is a library: the
consumer's `main.rs` owns process model, signal handling, config
representation, and reload semantics. `ClientStore` is a trait so
the consumer's config layer can plug in whatever
file/SQL/etcd/Consul backend it already uses.

### HTTP health / metrics endpoint

Metrics are emitted via `tracing` and the `metrics` crate facade;
consumers wire their own exporter (Prometheus, OpenTelemetry,
statsd, …). Health is covered at the protocol level by Status-Server
(RFC 5997). Bolting an HTTP listener into a UDP/TLS library is
scope creep that every consumer would then have to disable.

### Built-in user database

No bundled SQL schema, LDAP client, file-backed user store, or
password-policy engine. Authentication decisions live in the
consumer's `Handler::handle`; that's the entire point of the trait.
The `sqlite_clients` example demonstrates plugging *a* store in —
it is illustrative, not a feature surface.

### Multi-method policy language

No `unlang` / `policy.conf` equivalent. The policy language is
Rust + the `Handler` trait: pattern-match on `Request`, branch,
build a `Reply`. Adding a second imperative DSL on top would
duplicate the host language without adding expressive power.

## EAP

### Supplicant / NAS side of EAP

Already a non-goal in `crates/radius-tokio-eap/src/lib.rs`. The
companion `radius-tokio-eap` crate implements only the
*authenticator* (AAA-server) half of each EAP method. Peer-side
state machines, EAPOL framing, and 802.1X supplicant logic belong
in `wpa_supplicant` / `hostapd` / vendor 802.1X stacks — not here.
