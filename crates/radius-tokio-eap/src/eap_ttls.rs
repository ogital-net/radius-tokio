//! EAP-TTLS (RFC 5281) outer state machine.
//!
//! EAP-TTLS wraps a Diameter-style *AVP* exchange inside a
//! server-authenticated TLS tunnel. Unlike PEAP — where the
//! inner conversation is a nested EAP method — EAP-TTLS carries
//! plain RADIUS/Diameter attribute–value pairs over the TLS
//! record stream. The simplest and most common inner method is
//! PAP: the peer sends a `User-Name` AVP plus a `User-Password`
//! AVP, the server verifies the password, and the outer
//! `EAP-Success` is sent unencrypted on the RADIUS reply.
//!
//! # Wire shape
//!
//! Outer EAP frames are identical to EAP-TLS / PEAP — same
//! [`crate::framing`] envelope, only the EAP `Type` byte differs
//! ([`radius_tokio::eap::Type::TTLS`] = 21).
//!
//! Inner AVPs follow RFC 5281 §10.1:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           AVP Code                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V M r r r r r r|                  AVP Length                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Vendor-ID (opt)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Data ...                                                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! * **AVP Code** — 32-bit code (Diameter AVP code or RADIUS attr).
//! * **V** — Vendor-Id present (header is 12 bytes instead of 8).
//! * **M** — Mandatory: the peer must understand this AVP or fail.
//! * **AVP Length** — total length including header, *excluding*
//!   the trailing zero-padding that round-trips it to a 4-byte
//!   boundary.
//!
//! # Keying material
//!
//! RFC 5281 §11.1: 64-byte MSK + 64-byte EMSK are exported from
//! the TLS session using the RFC 5705 exporter with label
//! `"ttls keying material"` and an empty context. `wpa_supplicant`
//! uses the same label for both TLS 1.2 and TLS 1.3.
//!
//! # End-of-conversation sequence
//!
//! 1. TLS handshake completes (outer EAP carries handshake
//!    fragments to/from the peer).
//! 2. Peer encrypts the first AVP batch (typically `User-Name` +
//!    `User-Password` for PAP) into a TLS application-data
//!    record.
//! 3. The driver decrypts, parses the AVPs, dispatches them to
//!    the [`crate::eap_ttls::TtlsInner`], and returns [`MethodOutcome::Success`]
//!    or [`MethodOutcome::Failure`] based on the inner outcome.
//!    The outer [`crate::EapHandler`] then ships the
//!    `Access-Accept` (with MS-MPPE keys derived from the TLS
//!    exporter) or `Access-Reject`.

use std::sync::Arc;

use radius_tokio::eap::Type;
use radius_tokio::tls::{TlsConnection, TlsContext};

use crate::method::{EapMethod, MethodFactory, MethodOutcome};
use crate::tls_tunnel::{self, TlsTunnel};
use crate::Error;

pub use crate::tls_tunnel::{DEFAULT_FRAME_MTU, EMSK_LEN, MSK_LEN};

/// TLS exporter label for EAP-TTLS keying material (RFC 5281
/// §11.1). `wpa_supplicant` uses the same label for both TLS 1.2
/// and TLS 1.3.
pub const EXPORTER_LABEL: &str = "ttls keying material";

// RFC 2865 / 5281 AVP codes the inner methods care about.
/// RADIUS / Diameter `User-Name` AVP code (RFC 2865 §5.1).
pub const AVP_USER_NAME: u32 = 1;
/// RADIUS / Diameter `User-Password` AVP code (RFC 2865 §5.2). In
/// EAP-TTLS the password is carried in cleartext (TLS protects
/// it) padded with NUL bytes to a 16-byte boundary.
pub const AVP_USER_PASSWORD: u32 = 2;
/// RADIUS / Diameter `CHAP-Password` AVP code (RFC 2865 §5.3).
pub const AVP_CHAP_PASSWORD: u32 = 3;
/// RADIUS / Diameter `CHAP-Challenge` AVP code (RFC 2865 §5.40).
pub const AVP_CHAP_CHALLENGE: u32 = 60;
/// RADIUS / Diameter `EAP-Message` AVP code (RFC 3579 §3.1).
pub const AVP_EAP_MESSAGE: u32 = 79;

/// AVP `V` flag — Vendor-Id present.
const AVP_FLAG_V: u8 = 0b1000_0000;
/// AVP `M` flag — Mandatory.
const AVP_FLAG_M: u8 = 0b0100_0000;

/// One Diameter / RADIUS attribute–value pair as carried inside
/// the EAP-TTLS tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avp {
    /// AVP code (RADIUS attribute number or Diameter AVP code).
    pub code: u32,
    /// Optional Vendor-Id (RADIUS Vendor-Specific Attribute or
    /// Diameter vendor-specific AVP).
    pub vendor: Option<u32>,
    /// Mandatory bit. When set, an implementation that does not
    /// understand `code` must reject the entire packet.
    pub mandatory: bool,
    /// AVP payload, header + padding stripped.
    pub data: Vec<u8>,
}

impl Avp {
    /// Borrow the payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Parse a concatenated stream of AVPs (RFC 5281 §10.1).
///
/// Returns `Error::Framing` on a malformed AVP (truncated header,
/// length-field smaller than the header, length running past the
/// buffer end).
///
/// # Errors
///
/// Returns [`Error::Framing`] on any of the parse failures above.
pub fn parse_avps(mut bytes: &[u8]) -> Result<Vec<Avp>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err(Error::Framing("AVP header truncated"));
        }
        let code = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let flags = bytes[4];
        let length = u32::from_be_bytes([0, bytes[5], bytes[6], bytes[7]]) as usize;
        let has_vendor = flags & AVP_FLAG_V != 0;
        let header_len = if has_vendor { 12 } else { 8 };
        if length < header_len {
            return Err(Error::Framing("AVP length smaller than header"));
        }
        if bytes.len() < length {
            return Err(Error::Framing("AVP length exceeds buffer"));
        }
        let vendor = if has_vendor {
            Some(u32::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ]))
        } else {
            None
        };
        let data = bytes[header_len..length].to_vec();
        out.push(Avp {
            code,
            vendor,
            mandatory: flags & AVP_FLAG_M != 0,
            data,
        });
        // Pad to 4-byte boundary.
        let padded = (length + 3) & !3;
        if bytes.len() < padded {
            // Last AVP may legitimately omit trailing padding when
            // the TLS record ends exactly at `length`.
            bytes = &bytes[length..];
        } else {
            bytes = &bytes[padded..];
        }
    }
    Ok(out)
}

/// Server-side EAP-TTLS inner method.
///
/// Called once the peer has shipped its first batch of AVPs over
/// the TLS tunnel. Implementations validate the AVPs and return
/// [`TtlsInnerOutcome::Success`] / [`TtlsInnerOutcome::Failure`].
/// Multi-round inner exchanges (e.g. CHAP-challenge round-trips,
/// tunneled EAP) are supported via [`TtlsInnerOutcome::Continue`].
pub trait TtlsInner: Send {
    /// Process one decrypted batch of AVPs from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] on inner-method protocol errors.
    fn process<'a>(
        &'a mut self,
        avps: &'a [Avp],
    ) -> impl std::future::Future<Output = Result<TtlsInnerOutcome, Error>> + Send + 'a;
}

/// Outcome of a single [`TtlsInner::process`] call.
#[derive(Debug)]
pub enum TtlsInnerOutcome {
    /// Send the wrapped AVP-encoded bytes back to the peer and
    /// wait for its next batch.
    Continue(Vec<u8>),
    /// Inner authentication succeeded. The outer driver will
    /// emit `MethodOutcome::Success` plus MS-MPPE keys.
    Success,
    /// Inner authentication failed.
    Failure,
}

/// Factory producing a fresh [`TtlsInner`] per EAP-TTLS session.
pub trait TtlsInnerFactory: Send + Sync + 'static {
    /// Concrete inner state machine type produced.
    type Inner: TtlsInner;
    /// Build a fresh inner state machine.
    ///
    /// # Errors
    ///
    /// Returns whatever error the inner construction surfaces.
    fn create(&self) -> Result<Self::Inner, Error>;
}

/// Credential lookup for the bundled [`PapInner`].
pub trait PapCredentials: Send + Sync + 'static {
    /// Returns `true` iff `password` is the correct cleartext
    /// password for `username`.
    ///
    /// The returned future is `Send` so the inner method can
    /// `.await` it across runtime boundaries (e.g. while talking
    /// to a database or LDAP backend).
    fn verify<'a>(
        &'a self,
        username: &'a [u8],
        password: &'a [u8],
    ) -> impl std::future::Future<Output = bool> + Send + 'a;
}

/// Single-user PAP credential store. Useful for tests and
/// trivial deployments.
pub struct StaticPapCredentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl StaticPapCredentials {
    /// Build a store that accepts exactly `(username, password)`.
    #[must_use]
    pub fn new(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl PapCredentials for StaticPapCredentials {
    async fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        // Constant-time compare on the password to avoid timing
        // leaks on the secret half; username equality is fine to
        // short-circuit.
        if username != self.username.as_slice() {
            return false;
        }
        radius_tokio::ct_eq(password, &self.password)
    }
}

/// EAP-TTLS inner method: PAP (RFC 5281 §11.2.1).
///
/// Expects the peer's first AVP batch to contain exactly a
/// `User-Name` AVP and a `User-Password` AVP. The password is
/// NUL-padded to a 16-byte boundary by the supplicant (RFC 5281
/// §11.2.1); we strip the trailing NULs before verification.
pub struct PapInner<C: PapCredentials> {
    creds: Arc<C>,
}

impl<C: PapCredentials> PapInner<C> {
    /// Wrap a credential store.
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self { creds }
    }
}

#[allow(clippy::manual_async_fn)] // explicit `+ Send` bound on the RPITIT future
impl<C: PapCredentials> TtlsInner for PapInner<C> {
    fn process<'a>(
        &'a mut self,
        avps: &'a [Avp],
    ) -> impl std::future::Future<Output = Result<TtlsInnerOutcome, Error>> + Send + 'a {
        async move {
            let mut user = None;
            let mut pass = None;
            for avp in avps {
                if avp.vendor.is_some() {
                    continue;
                }
                match avp.code {
                    AVP_USER_NAME => user = Some(avp.data.as_slice()),
                    AVP_USER_PASSWORD => pass = Some(avp.data.as_slice()),
                    _ => {}
                }
            }
            let (Some(user), Some(pass)) = (user, pass) else {
                return Ok(TtlsInnerOutcome::Failure);
            };
            // Strip trailing NUL padding from the password AVP.
            let trimmed = match pass.iter().rposition(|&b| b != 0) {
                Some(idx) => &pass[..=idx],
                None => &[][..],
            };
            if self.creds.verify(user, trimmed).await {
                Ok(TtlsInnerOutcome::Success)
            } else {
                Ok(TtlsInnerOutcome::Failure)
            }
        }
    }
}

/// Factory for [`PapInner`].
pub struct PapInnerFactory<C: PapCredentials> {
    creds: Arc<C>,
}

impl<C: PapCredentials> PapInnerFactory<C> {
    /// Build a factory bound to `creds`.
    #[must_use]
    pub fn new(creds: Arc<C>) -> Self {
        Self { creds }
    }
}

impl<C: PapCredentials> TtlsInnerFactory for PapInnerFactory<C> {
    type Inner = PapInner<C>;
    fn create(&self) -> Result<Self::Inner, Error> {
        Ok(PapInner::new(self.creds.clone()))
    }
}

#[derive(Clone, Copy)]
enum InnerResult {
    Success,
    Failure,
}

/// EAP-TTLS outer state machine driving TLS phase 1 + an inner
/// AVP-based conversation in phase 2.
pub struct EapTtls<I: TtlsInner> {
    tunnel: TlsTunnel,
    inner: I,
    /// Decrypted plaintext bytes pending AVP parse. May span
    /// multiple TLS records when the peer fragments AVPs across
    /// records (rare; AVPs are short).
    inner_rx_buf: Vec<u8>,
    /// Set once the inner method has terminated. Outer outcome
    /// is held until every queued ciphertext fragment has been
    /// flushed to the peer.
    inner_terminator: Option<InnerResult>,
}

impl<I: TtlsInner> EapTtls<I> {
    /// Build a fresh state machine bound to `ctx` (server-only TLS,
    /// constructed via
    /// [`TlsContext::server_without_client_auth`]) and `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`] if the per-session SSL handle cannot
    /// be allocated.
    pub fn new(ctx: &TlsContext, inner: I) -> Result<Self, Error> {
        Ok(Self {
            tunnel: TlsTunnel::new(ctx, DEFAULT_FRAME_MTU)?,
            inner,
            inner_rx_buf: Vec::new(),
            inner_terminator: None,
        })
    }

    /// Override the default outbound fragmentation budget.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0`.
    #[must_use]
    pub fn with_frame_mtu(mut self, mtu: usize) -> Self {
        self.tunnel.set_frame_mtu(mtu);
        self
    }

    /// Borrow the underlying TLS connection.
    #[must_use]
    pub fn tls(&self) -> &TlsConnection {
        self.tunnel.tls()
    }

    fn export_msk_emsk(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.tunnel.export_msk_emsk(EXPORTER_LABEL)
    }
}

impl<I: TtlsInner> EapMethod for EapTtls<I> {
    fn typ(&self) -> Type {
        Type::TTLS
    }

    fn start(&mut self) -> crate::method::MethodFuture<'_> {
        Box::pin(async move {
            // RFC 5281 §7.1: server-issued Start frame is a single
            // Flags byte with S set (and the low 3 bits as version,
            // which we leave at 0 for TTLSv0 — the only deployed
            // version).
            Ok(MethodOutcome::Continue(tls_tunnel::start_frame()))
        })
    }

    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> crate::method::MethodFuture<'a> {
        Box::pin(async move {
            // 1. Ingest the peer's TTLS fragment and, if a full TLS
            //    message just reassembled, feed libssl + drive the
            //    handshake.
            if let Some(tls_bytes) = self.tunnel.ingest_peer_frame(peer_type_data)? {
                self.tunnel.feed_tls(&tls_bytes)?;
                self.tunnel.drive_handshake()?;
            }

            // 2. Once the handshake is up, pull any decrypted AVP
            //    bytes out of libssl.
            if self.tunnel.is_handshake_done() {
                self.tunnel.drain_decrypted(&mut self.inner_rx_buf)?;
            }

            // 3. Drain ciphertext libssl produced into the outbound
            //    buffer and ship the next fragment first. Mirrors
            //    the PEAP driver's "flush Finished before queueing
            //    app data" invariant.
            self.tunnel.refill_pending_tx()?;
            if self.tunnel.has_pending_tx() {
                return Ok(MethodOutcome::Continue(
                    self.tunnel.emit_next_outbound_fragment(),
                ));
            }

            // 4. Handshake done and ciphertext fully flushed. If the
            //    peer has delivered any AVP bytes, dispatch them to
            //    the inner method (unless we already terminated).
            if self.tunnel.is_handshake_done()
                && self.inner_terminator.is_none()
                && !self.inner_rx_buf.is_empty()
            {
                // Hand the buffer to the inner method and leave a
                // fresh empty Vec in place for the next batch —
                // cheaper than `drain(..).collect()` since we reuse
                // the existing allocation only when the next call
                // re-grows it.
                let avp_bytes = std::mem::take(&mut self.inner_rx_buf);
                let avps = parse_avps(&avp_bytes)?;
                match self.inner.process(&avps).await? {
                    TtlsInnerOutcome::Continue(reply) => {
                        if !reply.is_empty() {
                            self.tunnel.write_app_data(&reply)?;
                        }
                    }
                    TtlsInnerOutcome::Success => {
                        self.inner_terminator = Some(InnerResult::Success);
                    }
                    TtlsInnerOutcome::Failure => {
                        self.inner_terminator = Some(InnerResult::Failure);
                    }
                }
            }

            // 5. Drain any ciphertext produced by step 4 and ship it.
            self.tunnel.refill_pending_tx()?;
            if self.tunnel.has_pending_tx() {
                return Ok(MethodOutcome::Continue(
                    self.tunnel.emit_next_outbound_fragment(),
                ));
            }

            // 6. Nothing left to send. If the inner method has
            //    terminated, declare the outer outcome.
            if let Some(term) = self.inner_terminator {
                return Ok(match term {
                    InnerResult::Success => {
                        let (msk, emsk) = self.export_msk_emsk()?;
                        MethodOutcome::Success { msk, emsk }
                    }
                    InnerResult::Failure => MethodOutcome::Failure,
                });
            }

            // 7. Otherwise the peer is mid-fragmentation or just
            //    ACKed an interim message — emit our own ACK.
            Ok(MethodOutcome::Continue(tls_tunnel::ack_frame()))
        })
    }
}

/// Long-lived factory backing an [`EapTtls`] state machine per
/// session. Holds the shared [`TlsContext`] and the inner
/// [`TtlsInnerFactory`].
pub struct EapTtlsFactory<F: TtlsInnerFactory> {
    ctx: Arc<TlsContext>,
    inner: Arc<F>,
    frame_mtu: usize,
}

impl<F: TtlsInnerFactory> EapTtlsFactory<F> {
    /// Build a factory bound to `ctx` + `inner`. Uses
    /// [`DEFAULT_FRAME_MTU`].
    #[must_use]
    pub fn new(ctx: Arc<TlsContext>, inner: Arc<F>) -> Self {
        Self {
            ctx,
            inner,
            frame_mtu: DEFAULT_FRAME_MTU,
        }
    }

    /// Override the outbound fragmentation budget for every
    /// session created by this factory.
    ///
    /// # Panics
    ///
    /// Panics if `mtu == 0`.
    #[must_use]
    pub fn with_frame_mtu(mut self, mtu: usize) -> Self {
        assert!(mtu > 0, "frame_mtu must be positive");
        self.frame_mtu = mtu;
        self
    }
}

impl<F: TtlsInnerFactory> MethodFactory for EapTtlsFactory<F> {
    type Method = EapTtls<F::Inner>;

    fn create(&self) -> Result<Self::Method, Error> {
        let inner = self.inner.create()?;
        Ok(EapTtls::new(&self.ctx, inner)?.with_frame_mtu(self.frame_mtu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_name_and_user_password() {
        // User-Name(1) "alice" + User-Password(2) "hello123" padded to 16
        let mut buf = Vec::new();
        // AVP 1: User-Name
        buf.extend_from_slice(&1u32.to_be_bytes()); // code
        buf.push(AVP_FLAG_M); // M flag
        buf.extend_from_slice(&[0, 0, 8 + 5]); // length 13
        buf.extend_from_slice(b"alice");
        buf.extend_from_slice(&[0, 0, 0]); // pad to 16
                                           // AVP 2: User-Password (NUL padded to 16)
        buf.extend_from_slice(&2u32.to_be_bytes()); // code
        buf.push(AVP_FLAG_M);
        buf.extend_from_slice(&[0, 0, 8 + 16]); // length 24
        buf.extend_from_slice(b"hello123\0\0\0\0\0\0\0\0");

        let avps = parse_avps(&buf).expect("parse");
        assert_eq!(avps.len(), 2);
        assert_eq!(avps[0].code, AVP_USER_NAME);
        assert!(avps[0].mandatory);
        assert_eq!(avps[0].data, b"alice");
        assert_eq!(avps[1].code, AVP_USER_PASSWORD);
        assert_eq!(avps[1].data.len(), 16);
        assert_eq!(&avps[1].data[..8], b"hello123");
    }

    #[test]
    fn parse_rejects_truncated_header() {
        assert!(parse_avps(&[0, 0, 0, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn parse_rejects_length_below_header() {
        // length = 4 < header 8
        let buf = [0, 0, 0, 1, 0, 0, 0, 4];
        assert!(parse_avps(&buf).is_err());
    }

    #[tokio::test]
    async fn pap_inner_accepts_correct_creds() {
        let creds = Arc::new(StaticPapCredentials::new("alice", "hello123"));
        let mut inner = PapInner::new(creds);
        let avps = vec![
            Avp {
                code: AVP_USER_NAME,
                vendor: None,
                mandatory: true,
                data: b"alice".to_vec(),
            },
            Avp {
                code: AVP_USER_PASSWORD,
                vendor: None,
                mandatory: true,
                data: b"hello123\0\0\0\0\0\0\0\0".to_vec(),
            },
        ];
        match inner.process(&avps).await.unwrap() {
            TtlsInnerOutcome::Success => {}
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pap_inner_rejects_wrong_password() {
        let creds = Arc::new(StaticPapCredentials::new("alice", "hello123"));
        let mut inner = PapInner::new(creds);
        let avps = vec![
            Avp {
                code: AVP_USER_NAME,
                vendor: None,
                mandatory: true,
                data: b"alice".to_vec(),
            },
            Avp {
                code: AVP_USER_PASSWORD,
                vendor: None,
                mandatory: true,
                data: b"wrong\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
            },
        ];
        match inner.process(&avps).await.unwrap() {
            TtlsInnerOutcome::Failure => {}
            other => panic!("expected Failure, got {other:?}"),
        }
    }
}
