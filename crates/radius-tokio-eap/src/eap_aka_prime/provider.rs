//! Authentication-vector source for EAP-AKA'.
//!
//! A real EAP-AKA' deployment obtains UMTS authentication vectors
//! one of two ways:
//!
//! * **HSS-backed** — the RADIUS / AAA server proxies vector
//!   requests to the subscriber's HSS over the Diameter S6a
//!   `Authentication-Information-Request` interface (3GPP TS
//!   29.272 §5.2.3). One AV per RAND, single use.
//! * **Locally generated** — the AAA holds the subscriber's
//!   permanent key `K` and `OPc` and runs the Milenage `f1..f5`
//!   functions (3GPP TS 35.205) over a freshly generated
//!   `RAND | SQN | AMF` triple.
//!
//! Both are out of scope for this crate. Instead we expose a
//! [`AuthVectorProvider`] trait so consumers plug in whichever
//! backend they actually use, and ship
//! [`StaticVectorProvider`] as a fixture for tests and demos.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use super::attr::{AUTN_LEN, RAND_LEN};

/// One UMTS Authentication Vector as defined in 3GPP TS 33.102
/// §6.3.2.  Sized for AKA': XRES is variable length (32..=128
/// bits), CK / IK are 128 bits each, RAND / AUTN are 128 bits
/// each.
#[derive(Debug, Clone)]
pub struct AuthVector {
    /// 128-bit random challenge sent to the peer in `AT_RAND`.
    pub rand: [u8; RAND_LEN],
    /// 128-bit authentication token sent in `AT_AUTN` —
    /// concatenation of `(SQN ⊕ AK) | AMF | MAC` per TS 33.102.
    pub autn: [u8; AUTN_LEN],
    /// Expected response (4..=16 bytes). The peer returns its
    /// computed RES in `AT_RES`; we compare in constant time.
    pub xres: Vec<u8>,
    /// 128-bit Confidentiality Key.
    pub ck: [u8; 16],
    /// 128-bit Integrity Key.
    pub ik: [u8; 16],
}

/// Outcome of [`AuthVectorProvider::next_vector`].
#[derive(Debug)]
pub enum VectorOutcome {
    /// Vector ready — drive the AKA-Challenge round with it.
    Ready(Box<AuthVector>),
    /// No vector available for this subscriber; the state machine
    /// terminates with `EAP-Failure`.
    Unknown,
}

/// Source of UMTS authentication vectors for the EAP-AKA' server.
///
/// Implementations must be `Send + Sync + 'static` because the
/// EAP method factory holds them inside an `Arc` and dispatches
/// across worker tasks.
pub trait AuthVectorProvider: Send + Sync + 'static {
    /// Fetch one fresh authentication vector for `imsi_or_identity`
    /// bound to `network_name` (the access-network identity that
    /// will appear in `AT_KDF_INPUT`).
    ///
    /// `network_name` is supplied so HSS-backed implementations
    /// can re-key the vector with the network name before
    /// returning, when the HSS supports that. Implementations
    /// that ignore `network_name` simply return raw CK / IK and
    /// let the state machine apply the CK'/IK' binding.
    fn next_vector<'a>(
        &'a self,
        imsi_or_identity: &'a [u8],
        network_name: &'a [u8],
    ) -> impl Future<Output = VectorOutcome> + Send + 'a;

    /// Optional: report an `AKA-Synchronization-Failure` so the
    /// backend can refresh the subscriber's `SQN` window. Default
    /// is a no-op; HSS-backed implementations should issue an
    /// S6a `AIR` with `Re-synchronization-Info` set.
    ///
    /// The state machine still terminates the current session
    /// with `EAP-Failure` after calling this — resync recovery
    /// happens on the *next* `Access-Request` for the same
    /// subscriber.
    fn report_sync_failure<'a>(
        &'a self,
        _imsi_or_identity: &'a [u8],
        _auts: &'a [u8; 14],
    ) -> impl Future<Output = ()> + Send + 'a {
        async {}
    }
}

/// In-memory provider returning pre-canned vectors. Intended for
/// unit tests, integration tests, and bring-up demos — not for
/// production deployments where vectors are one-time-use values
/// minted from a per-subscriber sequence number.
///
/// Internally each identity is mapped to a vector queue; calls to
/// [`next_vector`][`AuthVectorProvider::next_vector`] pop one
/// entry at a time and return [`VectorOutcome::Unknown`] when the
/// queue is empty.
pub struct StaticVectorProvider {
    inner: Mutex<HashMap<Vec<u8>, Vec<AuthVector>>>,
}

impl Default for StaticVectorProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticVectorProvider {
    /// Build an empty provider. Add vectors with [`Self::push`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Queue `vector` for `identity`. Vectors are popped in FIFO
    /// order on subsequent calls.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex has been poisoned by a panic
    /// in another thread — a test-only failure mode.
    pub fn push(&self, identity: impl Into<Vec<u8>>, vector: AuthVector) {
        let mut guard = self
            .inner
            .lock()
            .expect("StaticVectorProvider mutex poisoned");
        guard.entry(identity.into()).or_default().push(vector);
    }

    fn pop(&self, identity: &[u8]) -> Option<AuthVector> {
        let mut guard = self
            .inner
            .lock()
            .expect("StaticVectorProvider mutex poisoned");
        let queue = guard.get_mut(identity)?;
        if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        }
    }
}

impl AuthVectorProvider for StaticVectorProvider {
    async fn next_vector<'a>(
        &'a self,
        imsi_or_identity: &'a [u8],
        _network_name: &'a [u8],
    ) -> VectorOutcome {
        match self.pop(imsi_or_identity) {
            Some(v) => VectorOutcome::Ready(Box::new(v)),
            None => VectorOutcome::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> AuthVector {
        AuthVector {
            rand: [0xAAu8; 16],
            autn: [0xBBu8; 16],
            xres: vec![0xCC; 8],
            ck: [0xDD; 16],
            ik: [0xEE; 16],
        }
    }

    #[tokio::test]
    async fn fifo_then_unknown() {
        let p = StaticVectorProvider::new();
        p.push(b"alice".to_vec(), fixture());
        let r = p.next_vector(b"alice", b"WLAN").await;
        assert!(matches!(r, VectorOutcome::Ready(_)));
        let r2 = p.next_vector(b"alice", b"WLAN").await;
        assert!(matches!(r2, VectorOutcome::Unknown));
    }

    #[tokio::test]
    async fn unknown_identity() {
        let p = StaticVectorProvider::new();
        let r = p.next_vector(b"nobody", b"WLAN").await;
        assert!(matches!(r, VectorOutcome::Unknown));
    }
}
