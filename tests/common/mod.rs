//! Shared fixtures for the `eapol_test_*` integration tests.
//!
//! Cargo treats `tests/common/mod.rs` specially: it is **not** compiled
//! as a standalone integration test, so anything in here is only built
//! when a sibling `tests/*.rs` imports it with `mod common;`.
//!
//! Only items that are byte-identical across both test files live
//! here; per-test scaffolding (handler implementations, parsing
//! helpers for specific EAP methods) stays with the test that owns
//! it.

#![allow(dead_code)] // each test imports a subset; unused ones are fine.

use std::time::{SystemTime, UNIX_EPOCH};

// ── Test-bed identity ────────────────────────────────────────────────

/// Shared secret the test NAS and the in-test server agree on.
pub const SHARED_SECRET: &str = "testing123";
/// EAP-Identity the peer sends.
pub const IDENTITY: &str = "alice";
/// Cleartext password the simulated user knows.
pub const PASSWORD: &str = "hello123";

// ── RADIUS attribute types we touch directly ────────────────────────
//
// Spelled out here so the tests do not depend on the `dict-rfc`
// codegen surface for these well-known constants — they are
// transport-level tests, not dictionary tests.

/// `User-Name` attribute type.
pub const ATTR_USER_NAME: u8 = 1;
/// `State` attribute type, RFC 2865 §5.24.
pub const ATTR_STATE: u8 = 24;
/// `EAP-Message` attribute type, RFC 3579 §3.1.
pub const ATTR_EAP_MESSAGE: u8 = 79;

// ── EAP codes (RFC 3748 §4) ──────────────────────────────────────────

/// EAP `Request`.
pub const EAP_CODE_REQUEST: u8 = 1;
/// EAP `Response`.
pub const EAP_CODE_RESPONSE: u8 = 2;
/// EAP `Success`.
pub const EAP_CODE_SUCCESS: u8 = 3;
/// EAP `Failure`.
pub const EAP_CODE_FAILURE: u8 = 4;

// ── EAP types (RFC 3748 §5) ──────────────────────────────────────────

/// EAP-Identity type.
pub const EAP_TYPE_IDENTITY: u8 = 1;

// ── EAP packet builders ─────────────────────────────────────────────

/// Build an `EAP-Success` packet (`Code=3, Identifier=id, Length=4`).
#[must_use]
pub fn build_eap_success(id: u8) -> Vec<u8> {
    vec![EAP_CODE_SUCCESS, id, 0, 4]
}

/// Build an `EAP-Failure` packet (`Code=4, Identifier=id, Length=4`).
#[must_use]
pub fn build_eap_failure(id: u8) -> Vec<u8> {
    vec![EAP_CODE_FAILURE, id, 0, 4]
}

/// Append an EAP packet to a reply, fragmenting into ≤253-byte
/// `EAP-Message` attributes per RFC 3579 §3.1.
pub fn add_eap_message(reply: &mut radius_tokio::Reply, eap: &[u8]) {
    for chunk in eap.chunks(253) {
        reply
            .add_attribute(ATTR_EAP_MESSAGE, chunk)
            .expect("EAP-Message fragment fits");
    }
}

/// Best-effort wall-clock nanoseconds since the Unix epoch, truncated
/// to 64 bits. Used by the test fixtures to seed the per-session
/// `State` attribute and the EAP challenge bytes — never relied on
/// for monotonicity, just for "random enough that two parallel
/// sessions get different state."
#[must_use]
pub fn nanos_now() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0)
}
