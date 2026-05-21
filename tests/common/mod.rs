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
