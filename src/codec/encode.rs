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

use super::header::Code;
use super::typed::{Attr, IntoWire, VsaAttr, WireType};
use super::{authenticator, message_authenticator, CodecError, PacketBuffer, TlvWriter};

/// Attribute type code for `Tunnel-Password` (RFC 2868 §3.5).
const TUNNEL_PASSWORD_TYPE: u8 = 69;

/// Maximum plaintext length for a `Tunnel-Password` attribute (RFC 2868 §3.5).
///
/// The 1-byte length prefix + up to 239 password bytes fits within one
/// 16-byte-aligned ciphertext block sequence of ≤ 240 bytes. Combined with
/// the 1-byte tag and 2-byte salt, the total attribute value is ≤ 243 bytes,
/// which is within the 253-byte attribute value limit.
const TUNNEL_PASSWORD_MAX_LEN: usize = 239;

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

    /// Append a top-level attribute by typed handle, with the value
    /// encoded through [`IntoWire`]. The companion to the decode-side
    /// [`super::attributes::RawAttribute::get`].
    ///
    /// ```ignore
    /// use radius_tokio::dict::generated::rfc::attrs;
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
    /// use radius_tokio::dict::generated::cisco::attrs;
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
    /// use radius_tokio::dict::generated::rfc::attrs;
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
}
