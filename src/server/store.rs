//! [`ClientStore`] trait and the bundled [`StaticClients`] implementation.
//!
//! The store is the seam between the library's accept loop and the
//! consumer's notion of "who is allowed to talk to me?". The library
//! never assumes a fixed table — every inbound packet drives a fresh
//! lookup, so adding, updating, or revoking a client is a property of
//! the store implementation rather than a server reload.
//!
//! `lookup_udp` is intentionally async: a database-backed store can
//! await its query, and an in-memory store can return immediately
//! (`async { … }` compiles to a no-op state machine).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use super::client::Client;

/// Identifies the inbound peer of a packet and resolves it to the
/// matching [`Client`] record.
///
/// Implementations must be `Send + Sync + 'static`: the server holds
/// the store inside an `Arc` and shares it across all worker tasks.
pub trait ClientStore: Send + Sync + 'static {
    /// Resolve a UDP packet's source address to a [`Client`].
    ///
    /// Returning `None` causes the packet to be silently dropped per
    /// RFC 2865 §3, before any allocation beyond the receive buffer.
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send;

    /// Pre-handshake admission for a `RadSec` (RFC 6614) connection.
    ///
    /// Called immediately after `accept()` on the TCP listener,
    /// **before** any TLS bytes are read. Returning `None` causes
    /// the connection to be closed with no TLS state allocated
    /// — cheap DoS-resistance against unknown peers.
    ///
    /// The returned [`Client`] supplies the shared secret used to
    /// verify Request / Message authenticators on packets carried
    /// over the connection. The TLS chain validation itself is
    /// performed by the listener's `TlsContext`; per-connection
    /// trust-store narrowing is a future enhancement.
    ///
    /// The default implementation rejects all `RadSec` peers, which
    /// matches the library's policy that `RadSec` must be opted into.
    #[cfg(feature = "radsec")]
    fn admit_radsec(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let _ = src;
        async { None }
    }

    /// Post-handshake authorization for a `RadSec` listener running
    /// in **cert-keyed** mode (RFC 6614 §2.5 / RFC 7585).
    ///
    /// Called *after* a successful mTLS handshake against the
    /// listener's listener-wide trust store, with the leaf
    /// certificate the peer presented. Returning `None` causes the
    /// connection to be torn down before any RADIUS frames are
    /// exchanged.
    ///
    /// The returned [`Client`] supplies the shared secret used to
    /// verify Request / Message authenticators on packets carried
    /// over the connection. Implementations typically map the
    /// peer's Subject DN, SAN, or SPKI fingerprint to a registered
    /// client record. NAT'd / shared-IP / dynamic-discovery
    /// deployments where the source address can't identify the
    /// peer use this hook instead of [`Self::admit_radsec`].
    ///
    /// The default implementation rejects every peer, which means
    /// a listener bound via `listen_radsec` (cert-keyed by default)
    /// against a store that does not override this method will
    /// close every connection after the handshake completes — i.e.
    /// it is a no-op listener. Override this method to enable
    /// cert-keyed authorization, or use `listen_radsec_ip_gated`
    /// if your deployment wants the IP-keyed model instead.
    #[cfg(feature = "radsec")]
    fn lookup_radsec_by_cert(
        &self,
        peer: &crate::tls::PeerCertificate,
    ) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let _ = peer;
        async { None }
    }
}

/// IPv4-or-IPv6 CIDR prefix used by [`StaticClients`].
///
/// The host bits below the prefix length are masked off at construction
/// time, so the `address` carried by the matcher is the canonical
/// network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

/// Errors that can arise when constructing an [`IpCidr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrError {
    /// The prefix length exceeds the address width
    /// (32 for IPv4, 128 for IPv6).
    PrefixOutOfRange {
        /// Width of the address in bits (32 or 128).
        max: u8,
        /// The supplied, invalid prefix length.
        actual: u8,
    },
}

impl std::fmt::Display for CidrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CidrError::PrefixOutOfRange { max, actual } => {
                write!(f, "prefix length {actual} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for CidrError {}

impl IpCidr {
    /// Build a new CIDR prefix. Host bits are masked off.
    ///
    /// # Errors
    ///
    /// Returns [`CidrError::PrefixOutOfRange`] if `prefix_len` exceeds
    /// the address width (32 for IPv4, 128 for IPv6).
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, CidrError> {
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CidrError::PrefixOutOfRange {
                max,
                actual: prefix_len,
            });
        }
        let network = match address {
            IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix_len)),
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix_len)),
        };
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Convenience: a `/32` IPv4 or `/128` IPv6 entry for a single host.
    ///
    /// # Panics
    ///
    /// Never panics in practice — the prefix length is derived from
    /// the address family, so it is always within bounds.
    #[must_use]
    pub fn host(address: IpAddr) -> Self {
        let prefix_len = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        // Host bits are already absent at full prefix; cannot fail.
        Self::new(address, prefix_len).expect("full-prefix CIDR is always valid")
    }

    /// Returns `true` if `addr` is contained in this prefix. Mixing
    /// address families always returns `false`.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => mask_v4(candidate, self.prefix_len) == net,
            (IpAddr::V6(net), IpAddr::V6(candidate)) => mask_v6(candidate, self.prefix_len) == net,
            _ => false,
        }
    }

    /// Prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

fn mask_v4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::from(addr);
    let mask = u32::MAX << (32 - prefix_len);
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let bits = u128::from(addr);
    let mask = u128::MAX << (128 - prefix_len);
    Ipv6Addr::from(bits & mask)
}

/// Immutable, CIDR-keyed [`ClientStore`].
///
/// Built up front via [`StaticClients::builder`]. Lookup is a linear
/// scan over the entries — fine for the small tables this is meant
/// for (a few hundred entries at most). Larger deployments should
/// implement [`ClientStore`] directly with their own data structure.
///
/// Entries are searched in insertion order; the first matching CIDR
/// wins, so callers should add more-specific prefixes before broader
/// ones.
#[derive(Debug)]
pub struct StaticClients {
    entries: Vec<(IpCidr, Arc<Client>)>,
}

impl StaticClients {
    /// Begin building a static client table.
    #[must_use]
    pub fn builder() -> StaticClientsBuilder {
        StaticClientsBuilder {
            entries: Vec::new(),
        }
    }
}

impl ClientStore for StaticClients {
    fn lookup_udp(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        let result = self
            .entries
            .iter()
            .find(|(cidr, _)| cidr.contains(src.ip()))
            .map(|(_, client)| Arc::clone(client));
        async move { result }
    }

    /// `StaticClients` admits a `RadSec` peer iff its source IP
    /// matches a configured CIDR entry. The same client record (and
    /// its shared secret) is returned for both transports.
    #[cfg(feature = "radsec")]
    fn admit_radsec(&self, src: SocketAddr) -> impl Future<Output = Option<Arc<Client>>> + Send {
        // Identical to the UDP path: the lookup key is the peer IP.
        // RadSec listeners that need a different policy plug in
        // their own `ClientStore` impl.
        self.lookup_udp(src)
    }
}

/// Fluent builder for [`StaticClients`].
#[derive(Debug)]
pub struct StaticClientsBuilder {
    entries: Vec<(IpCidr, Arc<Client>)>,
}

impl StaticClientsBuilder {
    /// Add a `(cidr, client)` entry. Returns `self` for chaining.
    #[must_use]
    pub fn add(mut self, cidr: IpCidr, client: Arc<Client>) -> Self {
        self.entries.push((cidr, client));
        self
    }

    /// Finish building the table.
    #[must_use]
    pub fn build(self) -> StaticClients {
        StaticClients {
            entries: self.entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).unwrap())
    }

    #[test]
    fn cidr_contains_ipv4() {
        let c = IpCidr::new(v4("10.0.0.0"), 24).unwrap();
        assert!(c.contains(v4("10.0.0.1")));
        assert!(c.contains(v4("10.0.0.255")));
        assert!(!c.contains(v4("10.0.1.0")));
    }

    #[test]
    fn cidr_masks_host_bits() {
        // 10.0.0.7/24 should normalize to 10.0.0.0/24.
        let c = IpCidr::new(v4("10.0.0.7"), 24).unwrap();
        assert_eq!(c.network, v4("10.0.0.0"));
    }

    #[test]
    fn cidr_zero_prefix_matches_everything() {
        let c = IpCidr::new(v4("1.2.3.4"), 0).unwrap();
        assert!(c.contains(v4("8.8.8.8")));
        assert!(c.contains(v4("0.0.0.0")));
    }

    #[test]
    fn cidr_rejects_oversized_prefix() {
        assert!(matches!(
            IpCidr::new(v4("1.2.3.4"), 33),
            Err(CidrError::PrefixOutOfRange {
                max: 32,
                actual: 33
            }),
        ));
    }

    #[test]
    fn cidr_address_family_mismatch() {
        let c = IpCidr::new(v4("10.0.0.0"), 24).unwrap();
        assert!(!c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn static_clients_lookup() {
        let alpha = Arc::new(Client::new(b"alpha".as_slice()));
        let beta = Arc::new(Client::new(b"beta".as_slice()));
        let store = StaticClients::builder()
            .add(IpCidr::new(v4("10.0.0.0"), 24).unwrap(), Arc::clone(&alpha))
            .add(IpCidr::new(v4("10.0.0.0"), 8).unwrap(), Arc::clone(&beta))
            .build();

        // The future from a StaticClients lookup is immediately ready;
        // we poll it once with a no-op waker rather than pull in a
        // runtime just for this test.
        let hit = poll_now(store.lookup_udp(SocketAddr::new(v4("10.0.0.5"), 0))).expect("hit");
        // First match wins — should be alpha (the /24).
        assert_eq!(hit.id(), alpha.id());

        let hit = poll_now(store.lookup_udp(SocketAddr::new(v4("10.5.0.5"), 0))).expect("hit");
        assert_eq!(hit.id(), beta.id());

        assert!(poll_now(store.lookup_udp(SocketAddr::new(v4("192.168.1.1"), 0))).is_none());
    }

    fn poll_now<F: Future>(fut: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
        const RAW: RawWaker = RawWaker::new(std::ptr::null(), &VTABLE);
        // SAFETY: the vtable functions are no-ops that ignore the data
        // pointer; satisfying the Waker contract trivially.
        let waker = unsafe { Waker::from_raw(RAW) };
        let mut cx = Context::from_waker(&waker);
        match pin!(fut).poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("expected an immediately ready future"),
        }
    }

    #[test]
    fn cidr_contains_ipv6() {
        let c = IpCidr::new(v6("2001:db8::"), 32).unwrap();
        assert!(c.contains(v6("2001:db8::1")));
        assert!(c.contains(v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!c.contains(v6("2001:db9::1")));
        assert!(!c.contains(v6("::1")));
    }

    #[test]
    fn cidr_masks_host_bits_ipv6() {
        // 2001:db8::dead:beef/32 should normalize to 2001:db8::/32.
        let c = IpCidr::new(v6("2001:db8::dead:beef"), 32).unwrap();
        assert_eq!(c.network, v6("2001:db8::"));
    }

    #[test]
    fn cidr_masks_host_bits_ipv6_non_byte_aligned() {
        // /35 keeps the high 3 bits of the third 16-bit group.
        // 2001:db8:ffff::/35 normalizes to 2001:db8:e000::/35.
        let c = IpCidr::new(v6("2001:db8:ffff::1"), 35).unwrap();
        assert_eq!(c.network, v6("2001:db8:e000::"));
        assert!(c.contains(v6("2001:db8:e000::")));
        assert!(c.contains(v6("2001:db8:ffff:ffff::1")));
        assert!(!c.contains(v6("2001:db8:dfff::1")));
    }

    #[test]
    fn cidr_zero_prefix_matches_everything_ipv6() {
        let c = IpCidr::new(v6("2001:db8::1"), 0).unwrap();
        assert!(c.contains(v6("::")));
        assert!(c.contains(v6("::1")));
        assert!(c.contains(v6("ffff::1")));
    }

    #[test]
    fn cidr_full_prefix_ipv6_is_host_route() {
        let c = IpCidr::new(v6("2001:db8::1"), 128).unwrap();
        assert!(c.contains(v6("2001:db8::1")));
        assert!(!c.contains(v6("2001:db8::2")));
    }

    #[test]
    fn cidr_rejects_oversized_prefix_ipv6() {
        assert!(matches!(
            IpCidr::new(v6("2001:db8::"), 129),
            Err(CidrError::PrefixOutOfRange {
                max: 128,
                actual: 129,
            }),
        ));
    }

    #[test]
    fn cidr_address_family_mismatch_ipv6_to_ipv4() {
        // Even ::/0 must not swallow IPv4 addresses.
        let c = IpCidr::new(v6("::"), 0).unwrap();
        assert!(!c.contains(v4("10.0.0.1")));
        assert!(!c.contains(v4("0.0.0.0")));
    }

    #[test]
    fn cidr_host_ipv6() {
        let c = IpCidr::host(v6("2001:db8::1"));
        assert_eq!(c.prefix_len(), 128);
        assert!(c.contains(v6("2001:db8::1")));
        assert!(!c.contains(v6("2001:db8::2")));
    }

    #[test]
    fn static_clients_lookup_ipv6() {
        let alpha = Arc::new(Client::new(b"alpha".as_slice()));
        let beta = Arc::new(Client::new(b"beta".as_slice()));
        let store = StaticClients::builder()
            .add(
                IpCidr::new(v6("2001:db8:1::"), 48).unwrap(),
                Arc::clone(&alpha),
            )
            .add(
                IpCidr::new(v6("2001:db8::"), 32).unwrap(),
                Arc::clone(&beta),
            )
            .build();

        // More-specific /48 added first wins inside its range.
        let hit = poll_now(store.lookup_udp(SocketAddr::new(v6("2001:db8:1::5"), 0))).expect("hit");
        assert_eq!(hit.id(), alpha.id());

        // Outside the /48 but inside the /32 falls through to beta.
        let hit = poll_now(store.lookup_udp(SocketAddr::new(v6("2001:db8:2::5"), 0))).expect("hit");
        assert_eq!(hit.id(), beta.id());

        // Outside both prefixes: miss.
        assert!(poll_now(store.lookup_udp(SocketAddr::new(v6("2001:db9::1"), 0))).is_none());

        // IPv4 source must not match an IPv6-only table.
        assert!(poll_now(store.lookup_udp(SocketAddr::new(v4("10.0.0.1"), 0))).is_none());
    }
}
