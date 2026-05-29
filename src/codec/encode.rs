//! High-level reply builder.
//!
//! Wraps [`super::PacketBuffer`] with the orchestration needed to
//! produce a valid, signed reply: reserve a Message-Authenticator
//! placeholder up front, append attributes after it, then on seal
//! patch the Length, compute the Message-Authenticator HMAC, and
//! compute the Response Authenticator on top.
//!
//! # Attribute ordering
//!
//! When Message-Authenticator emission is enabled (the default), the
//! attribute is reserved as the **first** attribute in the reply.
//! Placing it first matches the recommendation in
//! `draft-ietf-radext-deprecating-radius` and makes life easier for
//! NASes that scan for the attribute before fully buffering the
//! packet. The 16 value bytes are zeroed at reservation time and
//! patched in place during [`Reply::seal_for`].
//!
//! # Secure defaults
//!
//! [`Reply::new`] enables Message-Authenticator emission unconditionally
//! (see [`super::message_authenticator`] for the reasoning). Callers
//! who genuinely need to interoperate with a peer that misbehaves on
//! the attribute can call [`Reply::without_message_authenticator`] —
//! that opt-out is intentionally verbose.

use super::constants::{
    TUNNEL_PASSWORD as TUNNEL_PASSWORD_TYPE, VENDOR_SPECIFIC as VENDOR_SPECIFIC_TYPE,
};
use super::header::Code;
use super::typed::{Attr, IntoWire, VsaAttr, WireType};
use super::{authenticator, message_authenticator, CodecError, PacketBuffer, TlvWriter};

/// Maximum plaintext length for a `Tunnel-Password` attribute (RFC 2868 §3.5).
///
/// The 1-byte length prefix + up to 239 password bytes fits within one
/// 16-byte-aligned ciphertext block sequence of ≤ 240 bytes. Combined with
/// the 1-byte tag and 2-byte salt, the total attribute value is ≤ 243 bytes,
/// which is within the 253-byte attribute value limit.
const TUNNEL_PASSWORD_MAX_LEN: usize = 239;

/// Microsoft Private Enterprise Number (RFC 2548).
const MS_VENDOR_ID: u32 = 311;
/// `MS-MPPE-Send-Key` vendor-type (RFC 2548 §2.4.2).
const MS_MPPE_SEND_KEY_TYPE: u8 = 16;
/// `MS-MPPE-Recv-Key` vendor-type (RFC 2548 §2.4.2).
const MS_MPPE_RECV_KEY_TYPE: u8 = 17;
/// Maximum plaintext key length for an MS-MPPE-Key attribute.
///
/// The VSA value field carries `Vendor-Id (4) || Vendor-Type (1) ||
/// Vendor-Length (1) || Salt (2) || Encrypted-Key (N × 16)`, capped
/// at the 253-byte attribute-value limit. That leaves at most 245
/// bytes for `Salt || Encrypted-Key`, so the plaintext (which is a
/// 1-byte length prefix, the key, then zero-padding to a 16-byte
/// multiple) tops out around 239 bytes — well past the 32-byte keys
/// produced by every EAP method in practice. We pin the cap to 239
/// to match `Tunnel-Password` and to keep the contract obvious.
const MS_MPPE_KEY_MAX_LEN: usize = 239;

/// Builder for an outbound reply.
#[derive(Debug)]
pub struct Reply {
    buf: PacketBuffer,
    /// Absolute offset of the reserved Message-Authenticator value
    /// bytes, or `None` if the caller opted out via
    /// [`Reply::without_message_authenticator`].
    ma_value_offset: Option<usize>,
}

/// Default initial capacity for the underlying packet buffer.
///
/// Most replies to vanilla Access-Request / Accounting-Request
/// transactions fit comfortably in a few hundred bytes (header + a
/// handful of small attributes + Message-Authenticator). Pre-sizing
/// the `Vec` to 512 bytes avoids the realloc that a fresh `Vec` would
/// hit on the first attribute append, while staying well under the
/// 4 096-byte protocol ceiling we'd otherwise reserve up front.
pub const DEFAULT_CAPACITY: usize = 512;

impl Reply {
    /// Begin a reply for the given code + identifier.
    ///
    /// A Message-Authenticator placeholder is reserved as the first
    /// attribute immediately. Call
    /// [`without_message_authenticator`](Self::without_message_authenticator)
    /// to opt out (strongly discouraged — see the module doc).
    ///
    /// Equivalent to [`with_capacity`](Self::with_capacity) using
    /// the module's `DEFAULT_CAPACITY` (512 bytes).
    ///
    /// # Panics
    ///
    /// Reserving the 20-byte placeholder cannot fail in a fresh
    /// buffer (header + 20 ≪ 4096); the operation is therefore
    /// infallible from the caller's perspective.
    #[must_use]
    pub fn new(code: Code, identifier: u8) -> Self {
        Self::with_capacity(code, identifier, DEFAULT_CAPACITY)
    }

    /// Like [`new`](Self::new) but the underlying buffer is allocated
    /// with the supplied capacity hint (clamped to the protocol's
    /// 20..=4096 range). Use this when the caller knows the reply
    /// will be unusually large (e.g. EAP-Message fragments) or
    /// unusually small (status probes) and wants to avoid either a
    /// realloc or wasted headroom.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // cannot panic: fresh buffer always has headroom
    pub fn with_capacity(code: Code, identifier: u8, capacity: usize) -> Self {
        let mut buf = PacketBuffer::with_capacity(code, identifier, capacity);
        // Append the M-A slot up front so subsequent attributes land
        // after it on the wire. A fresh buffer has at least
        // `MIN_PACKET_LEN` bytes of headroom, so this cannot overflow.
        let offset = message_authenticator::append_zeroed_slot(&mut buf)
            .expect("fresh PacketBuffer has room for an 18-byte attribute");
        Self {
            buf,
            ma_value_offset: Some(offset),
        }
    }

    /// Recycle an existing [`PacketBuffer`] as the storage for a
    /// fresh reply.
    ///
    /// The buffer's allocation is reused; only the header bytes
    /// (code, identifier, length placeholder, zeroed Authenticator)
    /// and the Message-Authenticator placeholder are written.
    ///
    /// Hot-path consumers that hold a long-lived scratch buffer can
    /// flow it through `Reply::from_buffer → reply.add(…) →
    /// reply.seal_for(…) → buf.reset(…)` to keep the per-packet
    /// allocation count flat:
    ///
    /// ```ignore
    /// let mut scratch = PacketBuffer::with_capacity(Code::ACCESS_ACCEPT, 0, 512);
    /// loop {
    ///     scratch.reset(Code::ACCESS_ACCEPT, request.identifier());
    ///     let mut reply = Reply::from_buffer(scratch);
    ///     reply.add(attrs::FRAMED_IP_ADDRESS, ...)?;
    ///     scratch = reply.seal_for(&request.authenticator(), client.secret());
    ///     socket.send_to(scratch.as_bytes(), addr).await?;
    /// }
    /// ```
    ///
    /// The supplied buffer must already carry the desired code +
    /// identifier in its header (use [`PacketBuffer::reset`] to
    /// install them).
    ///
    /// # Panics
    ///
    /// Panics only if the buffer's invariants have been violated by
    /// internal misuse; never on construction-validated input.
    #[must_use]
    pub fn from_buffer(mut buf: PacketBuffer) -> Self {
        let offset = message_authenticator::append_zeroed_slot(&mut buf)
            .expect("recycled PacketBuffer has room for an 18-byte attribute");
        Self {
            buf,
            ma_value_offset: Some(offset),
        }
    }

    /// Disable Message-Authenticator emission and discard the
    /// reserved placeholder. Strongly discouraged — see
    /// [`super::message_authenticator`] for the `BlastRADIUS` context.
    #[must_use]
    pub fn without_message_authenticator(mut self) -> Self {
        if self.ma_value_offset.take().is_some() {
            // Drop the placeholder bytes (TLV header + 16-byte value)
            // so the on-wire reply is byte-identical to one built
            // without the slot.
            self.buf.truncate_attributes_to(0);
        }
        self
    }

    /// Append an attribute. Same constraints as
    /// [`PacketBuffer::add_attribute`].
    ///
    /// # Errors
    ///
    /// Forwards [`CodecError`].
    pub fn add_attribute(&mut self, typ: u8, val: &[u8]) -> Result<&mut Self, CodecError> {
        self.buf.add_attribute(typ, val)?;
        Ok(self)
    }

    /// Append an opaque `State` attribute (RFC 2865 §5.24, attribute
    /// type 24).
    ///
    /// The server emits `State` on an Access-Challenge so the NAS
    /// can echo it on its follow-up Access-Request, letting the
    /// handler stitch a multi-round exchange (EAP, CHAP retry, …)
    /// back together without leaking session identity onto the wire.
    /// `value` is opaque to the protocol — typically a random or
    /// session-keyed token minted from a CSPRNG. The
    /// payload must be 1–253 bytes, matching the RADIUS attribute
    /// value cap; an empty slice is rejected as a malformed
    /// attribute by [`PacketBuffer::add_attribute`].
    ///
    /// Pair with [`AttributesView::state`](crate::AttributesView::state) on the response
    /// side to read the echoed value back.
    ///
    /// # Errors
    ///
    /// Forwards [`CodecError`] from
    /// [`PacketBuffer::add_attribute`] (value too long, packet
    /// length budget exceeded, …).
    pub fn add_state(&mut self, value: &[u8]) -> Result<&mut Self, CodecError> {
        // 24 = State (RFC 2865 §5.24). Hard-coded rather than pulled
        // from the generated dictionary so the codec layer stays
        // dictionary-agnostic; the typed handle for callers who want
        // it is `dict::rfc::attrs::STATE`.
        self.add_attribute(24, value)
    }

    /// Append an EAP packet as one or more back-to-back `EAP-Message`
    /// attributes (RFC 3579 §3.1, attribute type 79).
    ///
    /// EAP packets routinely exceed the 253-byte RADIUS attribute
    /// value cap; the spec mandates splitting the payload across
    /// consecutive `EAP-Message` slots, which the receiver
    /// concatenates back together. Pair with
    /// [`AttributesView::eap_message`](crate::AttributesView::eap_message) on the request side to
    /// read the reassembled payload back. The 253-byte fragmentation
    /// is the inverse of
    /// [`crate::codec::eap::reassemble_into`].
    ///
    /// Empty `eap` payloads are a no-op (zero attributes appended),
    /// matching the parse-side behaviour where a request with no
    /// `EAP-Message` attribute reassembles to an empty `Vec`.
    /// Construct the payload via [`crate::codec::eap::write_request`]
    /// / [`crate::codec::eap::write_success`] /
    /// [`crate::codec::eap::write_failure`], or supply your own
    /// pre-encoded EAP packet bytes.
    ///
    /// # Errors
    ///
    /// Forwards [`CodecError`] from
    /// [`PacketBuffer::add_attribute`] (packet length budget exceeded
    /// — individual fragments are always ≤253 bytes by construction).
    pub fn add_eap_message(&mut self, eap: &[u8]) -> Result<&mut Self, CodecError> {
        for chunk in eap.chunks(253) {
            self.buf.add_attribute(super::eap::TYPE, chunk)?;
        }
        Ok(self)
    }

    /// Append a bare `EAP-Success` packet as an `EAP-Message`
    /// attribute (RFC 3748 §4.2).
    ///
    /// One-liner over [`crate::codec::eap::write_success`] +
    /// [`Self::add_eap_message`] for the common Access-Accept reply
    /// shape:
    ///
    /// ```ignore
    /// let mut reply = request.reply(Code::ACCESS_ACCEPT);
    /// reply.add_eap_success(eap_pkt.identifier())?;
    /// ```
    ///
    /// # Errors
    ///
    /// Forwards [`CodecError`] from [`Self::add_eap_message`].
    pub fn add_eap_success(&mut self, id: u8) -> Result<&mut Self, CodecError> {
        let mut buf = [0u8; 4];
        // SAFETY: write_success always writes exactly 4 bytes into an
        // empty Vec; emulate with a stack buffer to avoid a heap alloc.
        buf[0] = super::eap::Code::SUCCESS.0;
        buf[1] = id;
        buf[2..].copy_from_slice(&4u16.to_be_bytes());
        self.add_eap_message(&buf)
    }

    /// Append a bare `EAP-Failure` packet as an `EAP-Message`
    /// attribute (RFC 3748 §4.2).
    ///
    /// Symmetric companion to [`Self::add_eap_success`] for the
    /// common Access-Reject reply shape.
    ///
    /// # Errors
    ///
    /// Forwards [`CodecError`] from [`Self::add_eap_message`].
    pub fn add_eap_failure(&mut self, id: u8) -> Result<&mut Self, CodecError> {
        let mut buf = [0u8; 4];
        buf[0] = super::eap::Code::FAILURE.0;
        buf[1] = id;
        buf[2..].copy_from_slice(&4u16.to_be_bytes());
        self.add_eap_message(&buf)
    }

    /// Append a top-level attribute by typed handle, with the value
    /// encoded through [`IntoWire`]. The companion to the decode-side
    /// [`super::attributes::RawAttribute::get`].
    ///
    /// ```ignore
    /// use radius_tokio::dict::rfc::attrs;
    ///
    /// reply.add(attrs::USER_NAME, "alice")?;
    /// reply.add(attrs::NAS_PORT, 12u32)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`PacketBuffer::add`].
    pub fn add<T, V>(&mut self, attr: Attr<T>, value: V) -> Result<&mut Self, CodecError>
    where
        T: WireType,
        V: IntoWire<T>,
    {
        self.buf.add(attr, value)?;
        Ok(self)
    }

    /// Append a Vendor-Specific Attribute by typed handle. The
    /// companion to [`super::attributes::RawAttribute::get_vsa`].
    ///
    /// ```ignore
    /// use radius_tokio::dict::cisco::attrs;
    ///
    /// reply.add_vsa(attrs::CISCO_AVPAIR, "shell:priv-lvl=15")?;
    /// ```
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`PacketBuffer::add_vsa`].
    pub fn add_vsa<T, V>(&mut self, attr: VsaAttr<T>, value: V) -> Result<&mut Self, CodecError>
    where
        T: WireType,
        V: IntoWire<T>,
    {
        self.buf.add_vsa(attr, value)?;
        Ok(self)
    }

    /// Append a top-level TLV-typed parent attribute, building its
    /// children inside the supplied closure.
    ///
    /// Mirrors [`PacketBuffer::add_tlv`]. Use the typed
    /// [`super::typed::TlvAttr`] handles emitted by the dictionary
    /// codegen for child entries:
    ///
    /// ```ignore
    /// use radius_tokio::dict::rfc::attrs;
    /// reply.add_tlv(attrs::IPV6_6RD_CONFIGURATION.code, |t| {
    ///     t.add(attrs::IPV6_6RD_IPV4MASKLEN, 32u8)?;
    ///     t.add(attrs::IPV6_6RD_BR_IPV4_ADDRESS,
    ///           std::net::Ipv4Addr::new(192, 0, 2, 1))?;
    ///     Ok(())
    /// })?;
    /// ```
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`PacketBuffer::add_tlv`].
    pub fn add_tlv<F>(&mut self, parent_type: u8, build: F) -> Result<&mut Self, CodecError>
    where
        F: FnOnce(&mut TlvWriter<'_>) -> Result<(), CodecError>,
    {
        self.buf.add_tlv(parent_type, build)?;
        Ok(self)
    }

    /// Append a vendor-specific TLV-typed parent attribute, building
    /// its children inside the supplied closure.
    ///
    /// Mirrors [`PacketBuffer::add_vsa_tlv`]. Use the typed
    /// [`super::typed::VsaTlvAttr`] handles emitted by the dictionary
    /// codegen.
    ///
    /// # Errors
    ///
    /// Forwards every [`CodecError`] surfaced by
    /// [`PacketBuffer::add_vsa_tlv`].
    pub fn add_vsa_tlv<F>(
        &mut self,
        vendor: u32,
        vendor_type: u8,
        build: F,
    ) -> Result<&mut Self, CodecError>
    where
        F: FnOnce(&mut TlvWriter<'_>) -> Result<(), CodecError>,
    {
        self.buf.add_vsa_tlv(vendor, vendor_type, build)?;
        Ok(self)
    }

    /// Append a `Tunnel-Password` attribute (RFC 2868 §3.5) with automatic
    /// encryption.
    ///
    /// The library generates a fresh random 2-byte salt (with the MSB of the
    /// first byte set, as required by RFC 2868 §3.5) and encrypts `password`
    /// using the Tunnel-Password scheme before appending the result as
    /// attribute type 69. Callers supply the plaintext password and the
    /// encryption material from the corresponding request; no manual cipher
    /// work is required.
    ///
    /// Wire layout of the appended attribute value:
    /// `tag (1 byte) || salt (2 bytes) || ciphertext (N × 16 bytes)`
    ///
    /// # Arguments
    ///
    /// - `tag` — tunnel tag byte. `0x00` means untagged; `0x01`–`0x1F`
    ///   identify tunnels 1–31 (RFC 2868 §3.1).
    /// - `password` — plaintext tunnel secret (at most 239 bytes).
    /// - `request_authenticator` — the 16-byte Request Authenticator from the
    ///   corresponding Access-Request, used as the encryption seed per
    ///   RFC 2868 §3.5.
    /// - `secret` — the shared secret for this client.
    ///
    /// # Errors
    ///
    /// - [`CodecError::AttributeValueTooLong`] — `password` exceeds 239 bytes.
    /// - [`CodecError::PacketTooLarge`] — the encrypted attribute would push
    ///   the packet past 4 096 bytes.
    pub fn add_tunnel_password(
        &mut self,
        tag: u8,
        password: &[u8],
        request_authenticator: &[u8; 16],
        secret: &[u8],
    ) -> Result<&mut Self, CodecError> {
        // RFC 2868 §3.5: Tunnel-Password may only be included in an Access-Accept.
        if self.buf.header().code != Code::ACCESS_ACCEPT {
            return Err(CodecError::WrongPacketType);
        }
        if password.len() > TUNNEL_PASSWORD_MAX_LEN {
            return Err(CodecError::AttributeValueTooLong {
                len: password.len(),
            });
        }
        let (salt, ciphertext) = crate::crypto::password::tunnel_password_encrypt(
            password,
            secret,
            request_authenticator,
        );
        // Wire value: tag(1) || salt(2) || ciphertext(n × 16)
        let mut value = Vec::with_capacity(3 + ciphertext.len());
        value.push(tag);
        value.extend_from_slice(&salt);
        value.extend_from_slice(&ciphertext);
        self.add_attribute(TUNNEL_PASSWORD_TYPE, &value)
    }

    /// Append the `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key`
    /// Microsoft VSAs (RFC 2548 §2.4.2), encrypting each key under
    /// the shared secret with a fresh per-attribute salt.
    ///
    /// Used by every EAP method that produces keying material
    /// (EAP-MD5 does **not**; EAP-TLS / PEAP / TTLS / FAST do): the
    /// supplicant and authenticator derive the MSK from the inner
    /// method, the authentication server forwards the first 32
    /// bytes as the Recv-Key and the next 32 as the Send-Key, and
    /// the NAS uses those keys for the link-layer cipher (typically
    /// 802.11i PTK derivation).
    ///
    /// Per RFC 2548 §2.4.3 the encryption scheme is the same salted
    /// MD5 chain as [`Self::add_tunnel_password`], with one
    /// independent salt per attribute and a 1-byte key-length
    /// prefix on the plaintext.
    ///
    /// Wire layout of each appended VSA value:
    /// `Vendor-Id (4, BE = 311) || Vendor-Type (1, = 16/17) ||
    ///  Vendor-Length (1) || Salt (2) || Encrypted-Key (N × 16)`
    ///
    /// # Arguments
    ///
    /// - `send_key` — plaintext MS-MPPE-Send-Key (typically 32
    ///   bytes for EAP-TLS-family MSKs).
    /// - `recv_key` — plaintext MS-MPPE-Recv-Key (typically 32
    ///   bytes).
    /// - `request_authenticator` — the 16-byte Request
    ///   Authenticator from the corresponding Access-Request, used
    ///   as the encryption seed per RFC 2548 §2.4.3.
    /// - `secret` — the shared secret for this client.
    ///
    /// # Errors
    ///
    /// - [`CodecError::WrongPacketType`] — not an `Access-Accept`.
    ///   MS-MPPE keys are only meaningful in a successful auth.
    /// - [`CodecError::AttributeValueTooLong`] — either key exceeds
    ///   239 bytes (well past every realistic EAP MSK size).
    /// - [`CodecError::PacketTooLarge`] — the encrypted attributes
    ///   would push the packet past 4 096 bytes.
    pub fn add_mppe_keys(
        &mut self,
        send_key: &[u8],
        recv_key: &[u8],
        request_authenticator: &[u8; 16],
        secret: &[u8],
    ) -> Result<&mut Self, CodecError> {
        // RFC 2548 §2.4.2: MS-MPPE-{Send,Recv}-Key are only
        // meaningful in a successful authentication response.
        if self.buf.header().code != Code::ACCESS_ACCEPT {
            return Err(CodecError::WrongPacketType);
        }
        self.write_mppe_key(
            MS_MPPE_SEND_KEY_TYPE,
            send_key,
            request_authenticator,
            secret,
        )?;
        self.write_mppe_key(
            MS_MPPE_RECV_KEY_TYPE,
            recv_key,
            request_authenticator,
            secret,
        )?;
        Ok(self)
    }

    /// Emit one `MS-MPPE-{Send,Recv}-Key` VSA. Shared body for
    /// [`Self::add_mppe_keys`].
    fn write_mppe_key(
        &mut self,
        vendor_type: u8,
        key: &[u8],
        request_authenticator: &[u8; 16],
        secret: &[u8],
    ) -> Result<(), CodecError> {
        if key.len() > MS_MPPE_KEY_MAX_LEN {
            return Err(CodecError::AttributeValueTooLong { len: key.len() });
        }
        // RFC 2548 §2.4.3's salted-MD5 chain is byte-for-byte the
        // same construction Tunnel-Password uses (RFC 2868 §3.5);
        // reuse that helper rather than maintain a second copy.
        // Both encodings prepend a 1-byte length to the plaintext,
        // pad to a 16-byte multiple, and set the salt's MSB.
        let (salt, ciphertext) =
            crate::crypto::password::tunnel_password_encrypt(key, secret, request_authenticator);
        // VSA inner length: Vendor-Type (1) + Vendor-Length (1)
        // + Salt (2) + Encrypted-Key bytes.
        // SAFETY (no_panic): MS_MPPE_KEY_MAX_LEN caps `key.len()`
        // at 239 → ciphertext ≤ 240 → vendor_length ≤ 244, fits u8.
        #[allow(clippy::cast_possible_truncation)]
        let vendor_length = (2 + 2 + ciphertext.len()) as u8;
        let mut value = Vec::with_capacity(4 + 2 + 2 + ciphertext.len());
        value.extend_from_slice(&MS_VENDOR_ID.to_be_bytes());
        value.push(vendor_type);
        value.push(vendor_length);
        value.extend_from_slice(&salt);
        value.extend_from_slice(&ciphertext);
        self.add_attribute(VENDOR_SPECIFIC_TYPE, &value)?;
        Ok(())
    }

    /// Finalize the reply against the matching request's Authenticator
    /// and the shared secret.
    ///
    /// Steps, in order:
    /// 1. Patch the Length field.
    /// 2. (If M-A enabled) compute the Message-Authenticator HMAC and
    ///    patch the reserved slot.
    /// 3. Compute the Response Authenticator and patch the
    ///    `4..20` byte range.
    ///
    /// Returns the underlying buffer; `as_bytes()` is the wire payload.
    #[must_use]
    pub fn seal_for(mut self, request_authenticator: &[u8; 16], secret: &[u8]) -> PacketBuffer {
        self.buf.patch_length();

        if let Some(offset) = self.ma_value_offset {
            let tag =
                message_authenticator::compute(self.buf.as_bytes(), request_authenticator, secret);
            message_authenticator::patch(&mut self.buf, offset, &tag);
        }

        let resp =
            authenticator::compute_response(self.buf.as_bytes(), request_authenticator, secret);
        self.buf.set_authenticator(resp);
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::super::attributes;
    use super::super::header::Code;
    use super::super::{authenticator, message_authenticator, PacketBuffer};
    use super::*;

    #[test]
    fn sealed_reply_passes_both_checks() {
        let secret = b"shared";
        let req_auth = [0x42; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 5);
        reply.add_attribute(1, b"alice").unwrap();
        let pkt: PacketBuffer = reply.seal_for(&req_auth, secret);

        // Response Authenticator over the final packet matches.
        assert!(authenticator::verify_response(
            pkt.as_bytes(),
            &req_auth,
            secret,
        ));
        // Message-Authenticator is present and valid.
        assert_eq!(
            message_authenticator::verify(pkt.as_bytes(), &req_auth, secret),
            message_authenticator::Verification::Valid,
        );
    }

    #[test]
    fn message_authenticator_is_first_attribute() {
        let secret = b"shared";
        let req_auth = [0x11; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        reply.add_attribute(1, b"alice").unwrap();
        reply.add_attribute(6, &[0, 0, 0, 2]).unwrap();
        let pkt = reply.seal_for(&req_auth, secret);

        let first = attributes::iter(pkt.attributes())
            .next()
            .expect("at least one attribute")
            .expect("well-formed");
        assert_eq!(first.attribute_type(), message_authenticator::TYPE);
        assert_eq!(first.value().len(), message_authenticator::VALUE_LEN);
    }

    #[test]
    fn opt_out_skips_message_authenticator() {
        let secret = b"shared";
        let req_auth = [0x42; 16];
        let mut reply = Reply::new(Code::ACCESS_REJECT, 9).without_message_authenticator();
        reply.add_attribute(18, b"nope").unwrap();
        let pkt = reply.seal_for(&req_auth, secret);

        assert!(authenticator::verify_response(
            pkt.as_bytes(),
            &req_auth,
            secret,
        ));
        assert_eq!(
            message_authenticator::verify(pkt.as_bytes(), &req_auth, secret),
            message_authenticator::Verification::Absent,
        );
        // Opt-out really drops the placeholder: only User-Password (18) is
        // on the wire.
        let attrs: Vec<u8> = attributes::iter(pkt.attributes())
            .map(|r| r.unwrap().attribute_type())
            .collect();
        assert_eq!(attrs, vec![18]);
    }

    #[test]
    fn add_tunnel_password_encrypts_and_roundtrips() {
        let secret = b"shared";
        let req_auth = [0x55u8; 16];
        let password = b"tunnel-secret";
        let tag = 0x01;

        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        reply
            .add_tunnel_password(tag, password, &req_auth, secret)
            .unwrap();
        let pkt = reply.seal_for(&req_auth, secret);

        // Locate the Tunnel-Password attribute (type 69).
        let attr = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .find(|r| r.attribute_type() == TUNNEL_PASSWORD_TYPE)
            .expect("Tunnel-Password attribute present");

        let val = attr.value();
        // Minimum: tag(1) + salt(2) + one 16-byte ciphertext block = 19.
        assert!(val.len() >= 3 + 16, "value too short: {} bytes", val.len());
        assert_eq!(val[0], tag, "tag byte preserved");
        assert!(val[1] & 0x80 != 0, "salt MSB must be set per RFC 2868 §3.5");

        // Decrypt and verify plaintext.
        let salt = [val[1], val[2]];
        let ciphertext = &val[3..];
        let plaintext =
            crate::crypto::password::tunnel_password_decrypt(ciphertext, secret, &req_auth, salt)
                .expect("decrypt");
        assert_eq!(plaintext.as_bytes(), password);
    }

    #[test]
    fn add_tunnel_password_untagged() {
        // tag 0 (untagged) must work identically.
        let secret = b"s3cr3t";
        let req_auth = [0u8; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 2);
        reply
            .add_tunnel_password(0, b"pass", &req_auth, secret)
            .unwrap();
        let pkt = reply.seal_for(&req_auth, secret);
        let attr = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .find(|r| r.attribute_type() == TUNNEL_PASSWORD_TYPE)
            .expect("present");
        assert_eq!(attr.value()[0], 0u8, "tag byte is 0");
    }

    #[test]
    fn add_tunnel_password_too_long_is_error() {
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 3);
        let result = reply.add_tunnel_password(0, &[0u8; 240], &[0; 16], b"s");
        assert!(
            matches!(result, Err(CodecError::AttributeValueTooLong { .. })),
            "expected AttributeValueTooLong, got {result:?}",
        );
    }

    #[test]
    fn add_tunnel_password_wrong_packet_type_is_error() {
        // Tunnel-Password is only permitted in Access-Accept (RFC 2868 §3.5).
        for code in [Code::ACCESS_REJECT, Code::ACCESS_CHALLENGE] {
            let mut reply = Reply::new(code, 1);
            let result = reply.add_tunnel_password(0, b"pass", &[0; 16], b"s");
            assert_eq!(
                result.map(|_| ()),
                Err(CodecError::WrongPacketType),
                "expected WrongPacketType for code {code:?}",
            );
        }
    }

    #[test]
    fn add_mppe_keys_encrypts_and_roundtrips() {
        let secret = b"shared";
        let req_auth = [0x33u8; 16];
        // 32-byte keys mimic the MSK halves produced by EAP-TLS family methods.
        let send_key: [u8; 32] = std::array::from_fn(|i| 0x10u8 ^ u8::try_from(i).unwrap());
        let recv_key: [u8; 32] = std::array::from_fn(|i| 0xA0u8 ^ u8::try_from(i).unwrap());

        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 7);
        reply
            .add_mppe_keys(&send_key, &recv_key, &req_auth, secret)
            .unwrap();
        let pkt = reply.seal_for(&req_auth, secret);

        // Collect both MS-MPPE VSAs in order of appearance.
        let vsas: Vec<_> = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .filter(|r| r.attribute_type() == VENDOR_SPECIFIC_TYPE)
            .collect();
        assert_eq!(vsas.len(), 2, "expected two MS-MPPE VSAs");

        for (vsa, (expected_vt, expected_key)) in vsas.iter().zip([
            (MS_MPPE_SEND_KEY_TYPE, &send_key[..]),
            (MS_MPPE_RECV_KEY_TYPE, &recv_key[..]),
        ]) {
            let val = vsa.value();
            // Vendor-Id (4) || Vendor-Type (1) || Vendor-Length (1)
            // || Salt (2) || Encrypted-Key (≥ 16, multiple of 16).
            assert!(val.len() >= 4 + 2 + 2 + 16, "value too short");
            let vendor_id = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            assert_eq!(vendor_id, MS_VENDOR_ID, "Microsoft vendor id");
            assert_eq!(val[4], expected_vt, "vendor-type");
            assert_eq!(
                usize::from(val[5]),
                val.len() - 4,
                "vendor-length covers vendor-type..ciphertext",
            );
            assert!(
                val[6] & 0x80 != 0,
                "salt MSB must be set per RFC 2548 §2.4.3"
            );
            let salt = [val[6], val[7]];
            let ciphertext = &val[8..];
            let plaintext = crate::crypto::password::tunnel_password_decrypt(
                ciphertext, secret, &req_auth, salt,
            )
            .expect("decrypt");
            assert_eq!(plaintext.as_bytes(), expected_key);
        }
    }

    #[test]
    fn add_mppe_keys_uses_independent_salts() {
        // Even with identical Send and Recv keys, each VSA must carry
        // an independently generated salt (RFC 2548 §2.4.3 requires
        // freshness per attribute, not per packet).
        let secret = b"shared";
        let req_auth = [0u8; 16];
        let key = [0x55u8; 32];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 9);
        reply.add_mppe_keys(&key, &key, &req_auth, secret).unwrap();
        let pkt = reply.seal_for(&req_auth, secret);
        let salts: Vec<[u8; 2]> = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .filter(|r| r.attribute_type() == VENDOR_SPECIFIC_TYPE)
            .map(|r| {
                let v = r.value();
                [v[6], v[7]]
            })
            .collect();
        assert_eq!(salts.len(), 2);
        assert_ne!(salts[0], salts[1], "Send and Recv salts must differ");
    }

    #[test]
    fn add_mppe_keys_wrong_packet_type_is_error() {
        for code in [Code::ACCESS_REJECT, Code::ACCESS_CHALLENGE] {
            let mut reply = Reply::new(code, 1);
            let result = reply.add_mppe_keys(&[0u8; 32], &[0u8; 32], &[0; 16], b"s");
            assert_eq!(
                result.map(|_| ()),
                Err(CodecError::WrongPacketType),
                "expected WrongPacketType for code {code:?}",
            );
        }
    }

    #[test]
    fn add_mppe_keys_too_long_is_error() {
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        let big = vec![0u8; 240];
        let result = reply.add_mppe_keys(&big, &[0u8; 32], &[0; 16], b"s");
        assert!(
            matches!(result, Err(CodecError::AttributeValueTooLong { .. })),
            "expected AttributeValueTooLong, got {result:?}",
        );
    }

    #[test]
    fn wrong_secret_fails_response_check() {
        let req_auth = [0x42; 16];
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        reply.add_attribute(1, b"x").unwrap();
        let pkt = reply.seal_for(&req_auth, b"correct");
        assert!(!authenticator::verify_response(
            pkt.as_bytes(),
            &req_auth,
            b"wrong",
        ));
    }

    #[test]
    fn from_buffer_reuses_allocation_and_seals_correctly() {
        let secret = b"shared";
        let req_auth = [0x77; 16];

        // Build, seal, and capture the original allocation pointer
        // so we can prove the next round reuses it.
        let buf = PacketBuffer::with_capacity(Code::ACCESS_ACCEPT, 1, 512);
        let ptr_before = buf.as_bytes().as_ptr();
        // First reply.
        let mut r1 = Reply::from_buffer(buf);
        r1.add_attribute(1, b"alice").unwrap();
        let sealed1 = r1.seal_for(&req_auth, secret);
        assert!(authenticator::verify_response(
            sealed1.as_bytes(),
            &req_auth,
            secret,
        ));
        assert_eq!(
            message_authenticator::verify(sealed1.as_bytes(), &req_auth, secret),
            message_authenticator::Verification::Valid,
        );

        // Recycle for a second reply with a different code/id.
        let mut buf = sealed1;
        buf.reset(Code::ACCESS_REJECT, 9);
        // Allocation invariants: same backing buffer, no realloc.
        assert_eq!(buf.as_bytes().as_ptr(), ptr_before);

        let mut r2 = Reply::from_buffer(buf);
        r2.add_attribute(18, b"nope").unwrap();
        let req_auth2 = [0x33; 16];
        let sealed2 = r2.seal_for(&req_auth2, secret);
        assert_eq!(sealed2.as_bytes()[0], Code::ACCESS_REJECT.0);
        assert_eq!(sealed2.as_bytes()[1], 9);
        assert!(authenticator::verify_response(
            sealed2.as_bytes(),
            &req_auth2,
            secret,
        ));
        assert_eq!(sealed2.as_bytes().as_ptr(), ptr_before);
    }

    #[test]
    fn reset_clears_attribute_region() {
        let mut buf = PacketBuffer::with_capacity(Code::ACCESS_ACCEPT, 1, 512);
        buf.add_attribute(1, b"alice").unwrap();
        buf.add_attribute(2, b"bob").unwrap();
        assert!(!buf.attributes().is_empty());

        buf.reset(Code::ACCESS_REJECT, 9);
        let h = buf.header();
        assert_eq!(h.code, Code::ACCESS_REJECT);
        assert_eq!(h.identifier, 9);
        assert_eq!(h.authenticator, [0u8; 16]);
        assert!(buf.attributes().is_empty());
    }

    #[test]
    fn add_eap_message_fragments_at_253_and_reassembles() {
        let eap: Vec<u8> = (0..600u32).map(|i| (i & 0xFF) as u8).collect();
        let mut reply = Reply::new(Code::ACCESS_CHALLENGE, 1);
        reply.add_eap_message(&eap).expect("fragments fit");
        let pkt = reply.seal_for(&[0u8; 16], b"shared");

        // Inspect on-wire: every EAP-Message attribute is ≤253 bytes.
        let frags: Vec<&[u8]> = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .filter(|r| r.attribute_type() == super::super::eap::TYPE)
            .map(|r| r.value())
            .collect();
        assert_eq!(frags.len(), 3, "600 bytes → 253 + 253 + 94");
        assert_eq!(frags[0].len(), 253);
        assert_eq!(frags[1].len(), 253);
        assert_eq!(frags[2].len(), 94);

        // Reassembly recovers the original bytes.
        let mut out = Vec::new();
        super::super::eap::reassemble_into(pkt.attributes(), &mut out);
        assert_eq!(out, eap);
    }

    #[test]
    fn add_eap_message_empty_is_noop() {
        let mut reply = Reply::new(Code::ACCESS_CHALLENGE, 1);
        reply.add_eap_message(&[]).expect("ok");
        let pkt = reply.seal_for(&[0u8; 16], b"shared");
        // Only the Message-Authenticator placeholder is present.
        let typs: Vec<u8> = attributes::iter(pkt.attributes())
            .filter_map(Result::ok)
            .map(|r| r.attribute_type())
            .collect();
        assert_eq!(typs, vec![message_authenticator::TYPE]);
    }

    #[test]
    fn add_eap_success_writes_four_byte_terminal() {
        let mut reply = Reply::new(Code::ACCESS_ACCEPT, 1);
        reply.add_eap_success(42).expect("ok");
        let pkt = reply.seal_for(&[0u8; 16], b"shared");

        let mut out = Vec::new();
        super::super::eap::reassemble_into(pkt.attributes(), &mut out);
        let eap = super::super::eap::Packet::parse(&out).expect("parses");
        assert_eq!(eap.code(), super::super::eap::Code::SUCCESS);
        assert_eq!(eap.identifier(), 42);
        assert_eq!(eap.length(), 4);
        assert_eq!(eap.typ(), None);
    }

    #[test]
    fn add_eap_failure_writes_four_byte_terminal() {
        let mut reply = Reply::new(Code::ACCESS_REJECT, 1);
        reply.add_eap_failure(99).expect("ok");
        let pkt = reply.seal_for(&[0u8; 16], b"shared");

        let mut out = Vec::new();
        super::super::eap::reassemble_into(pkt.attributes(), &mut out);
        let eap = super::super::eap::Packet::parse(&out).expect("parses");
        assert_eq!(eap.code(), super::super::eap::Code::FAILURE);
        assert_eq!(eap.identifier(), 99);
    }
}
