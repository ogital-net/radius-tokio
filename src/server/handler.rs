//! Handler trait, `Request` view, and the `HandlerResult` enum.
//!
//! A [`Handler`] is the consumer's plug-in business logic: take a
//! validated [`Request`], decide what to do, and return either a
//! [`Reply`] for the server to seal and send, or [`HandlerResult::Drop`]
//! for an intentional silent discard.
//!
//! The handler never touches sockets, secrets, or authenticators —
//! the surrounding server pipeline owns those. It also never sees an
//! unauthenticated packet: by the time `handle` is called, the source
//! has been resolved to a [`Client`], the Request Authenticator (for
//! `Accounting` / `CoA` / `Disconnect`) and any Message-Authenticator have
//! been verified, and any reply will be sealed against the same
//! shared secret.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::codec::attributes::{self, AttributeError, AttributesIter, RawAttribute};
use crate::codec::encode::Reply;
use crate::codec::header::Code;
use crate::codec::typed::{Attr, TlvAttr, VsaAttr, VsaTlvAttr, WireType};

use super::client::Client;

/// Outcome of a handler invocation.
#[derive(Debug)]
pub enum HandlerResult {
    /// Send the supplied reply (after the server seals it with the
    /// matching request's Authenticator and the client's shared
    /// secret).
    Reply(Reply),
    /// Intentional silent discard — no reply is generated. RFC 2865 §3
    /// permits this for any malformed or unauthorised request; the
    /// handler may also use it to rate-limit or to ignore unknown
    /// codes.
    Drop,
}

/// Errors a handler may surface.
///
/// The server will turn any error into a silent drop and surface the
/// detail through the optional `tracing` / `metrics` features.
/// Handlers that intend to send a NAK should return
/// `HandlerResult::Reply` with the appropriate code, not an error.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandlerError {
    /// The handler produced an attribute that exceeded the codec's
    /// limits. Forwarded from [`crate::codec::CodecError`].
    Codec(crate::codec::CodecError),
    /// The handler abandoned the request for an application-specific
    /// reason. The supplied message is for diagnostics only.
    Application(String),
}

impl From<crate::codec::CodecError> for HandlerError {
    fn from(err: crate::codec::CodecError) -> Self {
        HandlerError::Codec(err)
    }
}

impl From<String> for HandlerError {
    fn from(msg: String) -> Self {
        HandlerError::Application(msg)
    }
}

impl From<&str> for HandlerError {
    fn from(msg: &str) -> Self {
        HandlerError::Application(msg.to_owned())
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Codec(e) => write!(f, "codec: {e}"),
            HandlerError::Application(msg) => write!(f, "application: {msg}"),
        }
    }
}

impl std::error::Error for HandlerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandlerError::Codec(e) => Some(e),
            HandlerError::Application(_) => None,
        }
    }
}

/// Validated, borrowed view of an inbound RADIUS request.
///
/// Lifetime `'a` ties the view to the receive buffer that owns the
/// packet bytes and to the resolved [`Client`] record. Handlers that
/// need to retain anything past their `await` boundaries should copy
/// it out — `Request` is deliberately not `Clone`.
#[derive(Debug)]
pub struct Request<'a> {
    code: Code,
    identifier: u8,
    authenticator: [u8; 16],
    attributes: &'a [u8],
    client: &'a Arc<Client>,
    src: SocketAddr,
}

impl<'a> Request<'a> {
    /// Construct a request view. Used by the server pipeline; not
    /// part of the public consumer surface (callers receive a
    /// `Request` from the handler trait).
    pub(crate) fn new(
        code: Code,
        identifier: u8,
        authenticator: [u8; 16],
        attributes: &'a [u8],
        client: &'a Arc<Client>,
        src: SocketAddr,
    ) -> Self {
        Self {
            code,
            identifier,
            authenticator,
            attributes,
            client,
            src,
        }
    }

    /// RADIUS code (Access-Request, Accounting-Request, …).
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// Request Identifier — must be echoed in any reply.
    #[must_use]
    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    /// Request Authenticator. For Access-Request this is 16 random
    /// bytes; for `Accounting` / `CoA` / `Disconnect` it is the verified
    /// `MD5(packet || secret)` digest.
    #[must_use]
    pub fn authenticator(&self) -> &[u8; 16] {
        &self.authenticator
    }

    /// Resolved client metadata.
    #[must_use]
    pub fn client(&self) -> &Arc<Client> {
        self.client
    }

    /// UDP source address (or peer address for `RadSec`).
    #[must_use]
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    /// Iterate the raw attribute region.
    ///
    /// This is the recommended primitive for **multi-attribute
    /// routing**. When a root handler needs to dispatch on the
    /// combined presence of several attributes (RFC and/or
    /// vendor-specific), walk the region once and fold the
    /// predicates inline — one pass, zero allocation, no extra API
    /// surface:
    ///
    /// ```ignore
    /// use radius_tokio::dict::generated::rfc::attrs;
    /// use radius_tokio::dict::generated::cisco::vsas;
    ///
    /// let (mut has_eap, mut has_pap, mut has_chap, mut has_cisco_av) =
    ///     (false, false, false, false);
    ///
    /// for slot in req.attributes_iter() {
    ///     let Ok(raw) = slot else { break }; // stop at first parse error
    ///     has_eap      |= raw.matches(attrs::EAP_MESSAGE);
    ///     has_pap      |= raw.matches(attrs::USER_PASSWORD);
    ///     has_chap     |= raw.matches(attrs::CHAP_PASSWORD);
    ///     has_cisco_av |= raw.matches_vsa(vsas::CISCO_AV_PAIR);
    /// }
    ///
    /// match (has_eap, has_pap, has_chap, has_cisco_av) {
    ///     (true, _, _, _) => handle_eap(req).await,
    ///     (_, true, _, _) => handle_pap(req).await,
    ///     (_, _, true, _) => handle_chap(req).await,
    ///     (_, _, _, true) => handle_cisco(req).await,
    ///     _               => handle_default(req).await,
    /// }
    /// ```
    ///
    /// For a *single*-attribute presence check, prefer
    /// [`Self::contains`] / [`Self::contains_vsa`] /
    /// [`Self::contains_tlv`] — they short-circuit on the first
    /// match.
    #[must_use]
    pub fn attributes_iter(&self) -> AttributesIter<'a> {
        attributes::iter(self.attributes)
    }

    /// Find the first well-formed attribute with the given type byte.
    /// Returns `Ok(None)` if no attribute of that type was present;
    /// returns `Err` if a malformed attribute was hit before one
    /// could be located.
    ///
    /// # Errors
    ///
    /// Forwards [`AttributeError`] from the underlying iterator.
    pub fn first_raw(&self, typ: u8) -> Result<Option<RawAttribute<'a>>, AttributeError> {
        for raw in self.attributes_iter() {
            let raw = raw?;
            if raw.attribute_type() == typ {
                return Ok(Some(raw));
            }
        }
        Ok(None)
    }

    /// Presence-only check for a typed attribute handle.
    ///
    /// Returns `true` iff the request carries a well-formed
    /// attribute slot matching `attr`. The payload is *not* decoded
    /// under `T`, which is exactly what a top-level dispatch needs:
    /// ```ignore
    /// use radius_tokio::dict::generated::rfc::attrs;
    ///
    /// if req.contains(attrs::EAP_MESSAGE) {
    ///     handle_eap(req).await
    /// } else if req.contains(attrs::USER_PASSWORD) {
    ///     handle_pap(req).await
    /// } else if req.contains(attrs::CHAP_PASSWORD) {
    ///     handle_chap(req).await
    /// } else {
    ///     // …
    /// }
    /// ```
    ///
    /// A malformed attribute encountered before a match yields
    /// `false` — consistent with [`Self::first_raw`]'s find-or-fail
    /// behaviour but collapsed to a single boolean for dispatch use.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains<T: WireType>(&self, attr: Attr<T>) -> bool {
        attributes::contains(self.attributes, attr)
    }

    /// Presence-only check for a Vendor-Specific attribute handle.
    /// See [`Self::contains`] for the dispatch idiom.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains_vsa<T: WireType>(&self, attr: VsaAttr<T>) -> bool {
        attributes::contains_vsa(self.attributes, attr)
    }

    /// Presence-only check for a TLV child handle.
    /// See [`Self::contains`] for the dispatch idiom.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains_tlv<T: WireType>(&self, attr: TlvAttr<T>) -> bool {
        attributes::contains_tlv(self.attributes, attr)
    }

    /// Presence-only check for a vendor-specific TLV child handle.
    /// See [`Self::contains`] for the dispatch idiom.
    #[inline]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn contains_vsa_tlv<T: WireType>(&self, attr: VsaTlvAttr<T>) -> bool {
        attributes::contains_vsa_tlv(self.attributes, attr)
    }

    /// Presence-only check for a raw attribute type byte.
    ///
    /// Cheaper than [`Self::first_raw`] for callers that only need
    /// "is it there?": no `Result` to unwrap, no `RawAttribute`
    /// returned. Equivalent to `self.first_raw(typ).ok().flatten().is_some()`.
    #[inline]
    #[must_use]
    pub fn contains_raw(&self, typ: u8) -> bool {
        for slot in self.attributes_iter() {
            let Ok(raw) = slot else { return false };
            if raw.attribute_type() == typ {
                return true;
            }
        }
        false
    }

    /// Decode the `Acct-Status-Type` attribute (RFC 2866 §5.1) if
    /// present and well-formed.
    ///
    /// Returns `None` for non-accounting requests, for accounting
    /// requests that omit the attribute, and for malformed values
    /// (wrong length, attribute list parse error). Handlers that
    /// want to distinguish "absent" from "malformed" should iterate
    /// [`attributes_iter`](Self::attributes_iter) directly.
    #[must_use]
    pub fn acct_status_type(&self) -> Option<super::accounting::AcctStatusType> {
        // Acct-Status-Type is a 4-byte big-endian integer (attribute 40).
        for raw in self.attributes_iter() {
            let raw = raw.ok()?;
            if raw.attribute_type() == super::accounting::ACCT_STATUS_TYPE_CODE {
                let bytes: [u8; 4] = raw.value().try_into().ok()?;
                return Some(super::accounting::AcctStatusType::from_u32(
                    u32::from_be_bytes(bytes),
                ));
            }
        }
        None
    }

    /// Build an unsealed [`Reply`] for the matching reply code,
    /// pre-loaded with this request's Identifier.
    ///
    /// The underlying buffer is sized via [`Reply::new`], which uses
    /// the codec's `DEFAULT_CAPACITY` (512 bytes) — large
    /// enough that typical Access-Accept / Accounting-Response /
    /// CoA-ACK replies never trigger a reallocation while still
    /// avoiding the full 4 KiB headroom the protocol allows. Reach
    /// for [`reply_with_capacity`](Self::reply_with_capacity) when
    /// the reply is known to be unusually large (EAP-Message
    /// fragments) or unusually small.
    #[must_use]
    pub fn reply(&self, code: Code) -> Reply {
        Reply::new(code, self.identifier)
    }

    /// Like [`reply`](Self::reply) but lets the caller override the
    /// initial buffer capacity. The hint is clamped to the protocol's
    /// 20..=4096 range by [`Reply::with_capacity`].
    #[must_use]
    pub fn reply_with_capacity(&self, code: Code, capacity: usize) -> Reply {
        Reply::with_capacity(code, self.identifier, capacity)
    }

    /// Append a `Tunnel-Password` attribute (RFC 2868 §3.5) to `reply`,
    /// using this request's authenticator and shared secret as the
    /// encryption material.
    ///
    /// This is a convenience wrapper around [`Reply::add_tunnel_password`]
    /// that removes the need to thread `request.authenticator()` and
    /// `request.client().secret()` through the call site:
    ///
    /// ```ignore
    /// let mut reply = request.reply(Code::ACCESS_ACCEPT);
    /// request.add_tunnel_password(&mut reply, 0x01, b"vlan42-psk")?;
    /// ```
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] from [`Reply::add_tunnel_password`],
    /// including [`CodecError::WrongPacketType`] when `reply` is not an
    /// `Access-Accept`.
    ///
    /// [`CodecError`]: crate::CodecError
    /// [`CodecError::WrongPacketType`]: crate::CodecError::WrongPacketType
    pub fn add_tunnel_password(
        &self,
        reply: &mut Reply,
        tag: u8,
        password: &[u8],
    ) -> Result<(), crate::CodecError> {
        reply
            .add_tunnel_password(tag, password, self.authenticator(), self.client().secret())
            .map(|_| ())
    }
}

/// Consumer-supplied request handler.
///
/// `Send + Sync + 'static` so the server can hold the handler in an
/// `Arc` and dispatch from any worker task.
pub trait Handler: Send + Sync + 'static {
    /// Produce a [`HandlerResult`] for the given request.
    ///
    /// The returned future is polled on the same task that decoded
    /// the packet; long-running work should be offloaded explicitly
    /// (e.g. `tokio::spawn`) so the receive loop is not stalled.
    fn handle(&self, request: Request<'_>) -> impl Future<Output = HandlerResult> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;

    #[test]
    fn request_reply_preserves_identifier() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        let req = Request::new(
            Code::ACCESS_REQUEST,
            42,
            [0; 16],
            &[],
            &client,
            "127.0.0.1:1812".parse().unwrap(),
        );
        let reply = req.reply(Code::ACCESS_ACCEPT);
        // Drop and inspect via seal: identifier should round-trip.
        let sealed = reply.seal_for(req.authenticator(), client.secret());
        assert_eq!(sealed.header().identifier, 42);
        assert_eq!(sealed.header().code, Code::ACCESS_ACCEPT);
    }

    #[test]
    fn first_raw_finds_attribute() {
        let client = Arc::new(Client::new(b"x".as_slice()));
        // User-Name (1) = "alice"
        let attrs = &[1u8, 7, b'a', b'l', b'i', b'c', b'e', 6, 6, 0, 0, 0, 2];
        let req = Request::new(
            Code::ACCESS_REQUEST,
            1,
            [0; 16],
            attrs,
            &client,
            "127.0.0.1:1812".parse().unwrap(),
        );
        let raw = req.first_raw(1).unwrap().expect("present");
        assert_eq!(raw.value(), b"alice");
        assert!(req.first_raw(99).unwrap().is_none());
    }

    #[test]
    fn add_tunnel_password_convenience_roundtrip() {
        let secret = b"shared";
        let req_auth = [0x55u8; 16];
        let password = b"vlan42-psk";

        let client = Arc::new(Client::new(secret.as_slice()));
        let req = Request::new(
            Code::ACCESS_REQUEST,
            7,
            req_auth,
            &[],
            &client,
            "127.0.0.1:1812".parse().unwrap(),
        );

        let mut reply = req.reply(Code::ACCESS_ACCEPT);
        req.add_tunnel_password(&mut reply, 0x01, password)
            .expect("ok");

        let pkt = reply.seal_for(&req_auth, secret);
        // Tunnel-Password (type 69) is present.
        let attr = crate::codec::attributes::iter(pkt.attributes())
            .filter_map(std::result::Result::ok)
            .find(|r| r.attribute_type() == 69)
            .expect("Tunnel-Password present");

        let val = attr.value();
        let salt = [val[1], val[2]];
        let pt =
            crate::crypto::password::tunnel_password_decrypt(&val[3..], secret, &req_auth, salt)
                .expect("decrypt");
        assert_eq!(pt.as_bytes(), password);
    }

    #[test]
    fn add_tunnel_password_convenience_rejects_non_accept() {
        let client = Arc::new(Client::new(b"s".as_slice()));
        let req = Request::new(
            Code::ACCESS_REQUEST,
            1,
            [0; 16],
            &[],
            &client,
            "127.0.0.1:1812".parse().unwrap(),
        );
        let mut reply = req.reply(Code::ACCESS_REJECT);
        assert_eq!(
            req.add_tunnel_password(&mut reply, 0, b"x"),
            Err(crate::CodecError::WrongPacketType),
        );
    }
}
