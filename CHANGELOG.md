# Changelog

All notable changes to `radius-tokio` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Public MS-CHAPv2 field extraction for backend verification, including the
	MS-CHAP identifier needed for success replies (with the `server` feature).
- MPPE key decryption with retained request authenticators for verified client
	responses, reusing the existing zeroizing salted-MD5 implementation.
- Independent `server` (default) and `client` roles sharing protocol and crypto.
- Multiplexed UDP and mutually authenticated RadSec clients, outgoing request
	builders, owned verified responses, and PAP password hiding.
- Production TLS client contexts with explicit trust, DNS/IP SAN verification,
	SNI, and certificate-chain emission. TLS is independently enabled by `tls`.
- Client examples and feature-matrix CI coverage.

### Changed

- CoA originator now uses the same UDP exchange engine as the client;
	existing server imports and configuration remain supported.
- EAP TLS methods enable `tls` rather than RadSec socket support.
- TLS pumping and cancellation-safe stream framing are shared by both roles.
- `SecretBytes` is available at the crate root and its original server paths.

### Fixed

- Invalid CoA replies no longer consume pending requests; they are silently
	discarded until a valid reply arrives or the retry budget expires.
- Cancelled exchanges reclaim identifiers, including queued RadSec writes.
- UDP response verification ignores padding beyond the declared packet length.
- Accounting replies with malformed Message-Authenticator values are rejected,
	rather than treated as legacy replies without a tag.
- CoA retransmission events and timeout outcome metrics survive the shared-engine
	migration.
- Temporary PAP plaintext used for password hiding is scrubbed on drop.

## Versioning policy

While the version stays below `1.0`, **breaking changes are allowed
without a deprecation cycle** and may land in any release. Each
release notes which surface broke and why.

`1.0` will mark the point at which the public API is locked under
SemVer guarantees: breaking changes will then require a major bump,
and deprecation precedes removal by at least one minor release.
