//! Authentication helpers for common RADIUS credential schemes.
//!
//! Each submodule exposes a small inspector that takes a borrowed
//! [`Request`](crate::server::Request) plus the *expected* password
//! (looked up by the consumer in whatever identity store it uses) and
//! returns a [`VerifyOutcome`]. The helpers never touch sockets,
//! never look at the [`Client`](crate::server::Client) record beyond
//! its shared secret, and never allocate beyond what the underlying
//! crypto step already requires.
//!
//! # Supported schemes
//!
//! | Scheme | Module | RFC | Status |
//! |--------|--------|-----|--------|
//! | PAP (`User-Password`)        | [`pap`]    | RFC 2865 §5.2 | implemented |
//! | CHAP (`CHAP-Password`)       | [`chap`]   | RFC 2865 §5.3 + RFC 1994 | implemented |
//! | MS-CHAPv1                    | [`mschap`] | RFC 2433 / RFC 2548 | implemented |
//! | MS-CHAPv2                    | [`mschap`] | RFC 2759 / RFC 2548 | implemented |
//! | EAP-MD5-Challenge            | [`eap_md5`] | RFC 3748 §5.4 | response computation |
//!
//! The credential primitives in this module are deliberately
//! state-machine-free — they verify one credential against an
//! expected value and return. For a full EAP server state machine
//! that drives these primitives over the `EAP-Message` codec
//! (including identity capture, identifier allocation, and `State`
//! cookie management), see the companion `radius-tokio-eap` crate:
//! its `EapMd5Factory` wraps [`eap_md5`] and the PEAP / EAP-TTLS
//! factories wrap [`mschap`].
//!
//! # Pattern
//!
//! ```ignore
//! use radius_tokio::auth::{self, VerifyOutcome};
//!
//! match auth::verify_pap(&request, expected_password)? {
//!     VerifyOutcome::Match    => /* build Access-Accept */,
//!     VerifyOutcome::Mismatch => /* build Access-Reject */,
//!     VerifyOutcome::Missing  => /* try the next method (CHAP, EAP, …) */,
//!     VerifyOutcome::Malformed => /* drop or log */,
//! }
//! ```
//!
//! Helpers do not chain methods themselves — that policy belongs in
//! the consumer's handler.

#[cfg(feature = "server")]
pub mod chap;
pub mod eap_md5;
#[cfg(feature = "server")]
pub mod mschap;
#[cfg(feature = "server")]
pub mod pap;

/// Outcome of a credential check.
///
/// The four-variant shape lets handlers distinguish "this isn't my
/// scheme" (`Missing`) from "the credential was wrong" (`Mismatch`)
/// from "the wire was garbled" (`Malformed`). All three non-`Match`
/// variants typically lead to either a fall-through to another method
/// or an Access-Reject; the distinction is preserved for metrics and
/// auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Credential attribute is present and validated against the
    /// expected password.
    Match,
    /// Credential attribute is present and well-formed but did not
    /// validate.
    Mismatch,
    /// The request does not carry the credential attribute this
    /// helper checks. The handler should fall through to another
    /// authentication method.
    Missing,
    /// The credential attribute is present but cannot be parsed
    /// (wrong length, attribute-list parse error, etc.). Treat as a
    /// hostile or buggy NAS; do not fall through.
    Malformed,
}

impl VerifyOutcome {
    /// `true` only for [`VerifyOutcome::Match`].
    #[must_use]
    pub fn is_match(self) -> bool {
        matches!(self, VerifyOutcome::Match)
    }
}

#[cfg(test)]
mod tests {
    use super::VerifyOutcome;

    #[test]
    fn is_match_only_for_match_variant() {
        assert!(VerifyOutcome::Match.is_match());
        assert!(!VerifyOutcome::Mismatch.is_match());
        assert!(!VerifyOutcome::Missing.is_match());
        assert!(!VerifyOutcome::Malformed.is_match());
    }

    #[test]
    fn outcome_traits_are_useful() {
        // Exercise Debug, Clone, Copy, PartialEq derives so they are not
        // silently dropped from the public surface.
        let a = VerifyOutcome::Match;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), VerifyOutcome::Match);
        assert!(format!("{a:?}").contains("Match"));
        assert_ne!(VerifyOutcome::Match, VerifyOutcome::Mismatch);
    }
}
