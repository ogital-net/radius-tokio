//! Borrowed view of the outer RADIUS Access-Request the handler
//! is currently processing.
//!
//! Every credential / verifier trait in this crate
//! ([`eap_md5::Credentials`](crate::eap_md5::Credentials),
//! [`mschapv2::Credentials`](crate::mschapv2::Credentials),
//! [`eap_ttls::PapCredentials`](crate::eap_ttls::PapCredentials))
//! receives an `&Outer<'_>` as its first argument, followed by the
//! asserted username (and, for verifiers, the candidate
//! credential bytes).
//!
//! Most credential stores only need the username and can ignore
//! the outer view. Stores that want to make policy decisions
//! based on NAS-side metadata (`NAS-IP-Address`,
//! `Called-Station-Id`, vendor attributes, …) bring the
//! [`AttributesView`](radius_tokio::AttributesView) trait into
//! scope, which is implemented for both [`Outer`] and
//! [`radius_tokio::server::Request`].
//!
//! The slice is borrowed straight from the inbound RADIUS
//! request — no allocations, no stashing.

use radius_tokio::AttributesView;

/// Borrowed view of the outer Access-Request attribute region.
#[non_exhaustive]
pub struct Outer<'a> {
    attributes: &'a [u8],
}

impl<'a> Outer<'a> {
    /// Wrap a raw attribute region.
    #[must_use]
    pub fn new(attributes: &'a [u8]) -> Self {
        Self { attributes }
    }
}

impl<'a> AttributesView<'a> for Outer<'a> {
    #[inline]
    fn raw_attributes(&self) -> &'a [u8] {
        self.attributes
    }
}
