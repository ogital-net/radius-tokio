//! Client records: the per-NAS metadata the server needs to validate
//! and respond to a request.
//!
//! A [`Client`] is what a [`crate::server::ClientStore`] returns when
//! it identifies the source of an inbound packet. The library treats
//! the record as an opaque, immutable value: shared between many
//! in-flight requests via `Arc`, never mutated after construction.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::cleanse;

/// Opaque, process-unique identifier for a [`Client`].
///
/// Used by server-level hooks (revocation, metrics tagging,
/// `Server::close_connections_for`) to refer to a client without
/// holding the `Arc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(NonZeroU64);

impl ClientId {
    /// Allocate a fresh, process-unique id.
    ///
    /// # Panics
    ///
    /// Panics if the process-wide counter wraps past `u64::MAX`,
    /// which is not reachable in any realistic deployment.
    #[must_use]
    pub fn new() -> Self {
        // Start at 1 so NonZeroU64 invariant always holds.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let raw = NEXT.fetch_add(1, Ordering::Relaxed);
        // Wrap-around at u64::MAX would yield 0; vanishingly unlikely
        // in any realistic process lifetime.
        let nz = NonZeroU64::new(raw).expect("ClientId allocator wrapped to zero");
        Self(nz)
    }
}

impl Default for ClientId {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned shared-secret bytes. The buffer is overwritten with
/// `OPENSSL_cleanse` on drop.
///
/// Display / Debug deliberately do not reveal contents.
pub struct SecretBytes(Box<[u8]>);

impl SecretBytes {
    /// Wrap an existing byte buffer.
    #[must_use]
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec().into_boxed_slice())
    }
}

impl<const N: usize> From<&[u8; N]> for SecretBytes {
    fn from(b: &[u8; N]) -> Self {
        Self::new(b.as_slice().to_vec().into_boxed_slice())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// Per-client metadata returned by a [`crate::server::ClientStore`].
///
/// Records are immutable after construction; runtime mutation happens
/// at the store level by publishing a new `Arc<Client>`.
///
/// The library deliberately keeps this record minimal: shared secret,
/// process-unique id, and (for `RadSec`) the per-connection trust
/// material. Any *application*-level policy — NAS-Identifier
/// allow-lists, time-of-day windows, per-NAS attribute filters,
/// quota / rate limits — belongs in the [`Handler`] where it can be
/// expressed against the live request and produce a meaningful
/// rejection (Access-Reject + Reply-Message). Carrying such fields
/// here would make them silent admission gates that drop packets
/// without trace.
///
/// [`Handler`]: crate::server::Handler
#[derive(Debug)]
pub struct Client {
    id: ClientId,
    secret: SecretBytes,
}

impl Client {
    /// Build a client with just the shared secret.
    #[must_use]
    pub fn new(secret: impl Into<SecretBytes>) -> Self {
        Self {
            id: ClientId::new(),
            secret: secret.into(),
        }
    }

    /// Process-unique handle.
    #[must_use]
    pub fn id(&self) -> ClientId {
        self.id
    }

    /// The shared secret used to verify Authenticators and to seed
    /// reply HMACs.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        let a = ClientId::new();
        let b = ClientId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_bytes_round_trip() {
        let s = SecretBytes::from(b"shh".as_slice());
        assert_eq!(s.as_bytes(), b"shh");
        assert!(format!("{s:?}").contains("3 bytes"));
    }

    #[test]
    fn client_id_default_allocates_unique() {
        let a = ClientId::default();
        let b = ClientId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_bytes_from_array_ref_round_trip() {
        let s = SecretBytes::from(b"abcd");
        assert_eq!(s.as_bytes(), b"abcd");
        let s2: SecretBytes = (&[1u8, 2, 3, 4, 5]).into();
        assert_eq!(s2.as_bytes(), &[1, 2, 3, 4, 5]);
    }
}
