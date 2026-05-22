//! EAP-Message reassembly view (RFC 3579 §3.1; attribute type 79)
//! and a typed view over the EAP packet header (RFC 3748 §4).
//!
//! A single EAP packet may exceed the 253-byte cap on a RADIUS
//! attribute value. Implementations split the EAP payload across
//! multiple `EAP-Message` attributes carried back-to-back; the
//! receiver concatenates the value bytes of every `EAP-Message` it
//! finds, in attribute order, to recover the original EAP packet.
//!
//! This module exposes:
//!
//! * [`fragments`] — a borrowed iterator over the value bytes of each
//!   `EAP-Message` slot, in source order.
//! * [`reassemble_into`] — append the concatenated payload to a
//!   caller-supplied buffer (the only allocation point — and only when
//!   you actually want a contiguous slice).
//! * [`reassemble`] — allocate a fresh `Vec<u8>` carrying the
//!   reassembled payload (returns an empty vector when no
//!   `EAP-Message` attribute is present).
//! * [`Packet`] — borrowed, validated view of the EAP header
//!   (`Code` / `Identifier` / `Length` / `Type`) over a reassembled
//!   payload. Pair with [`Code`] and [`Type`] for dispatch.
//!
//! No allocation happens unless the caller asks for a contiguous
//! payload; consumers that can stream EAP fragments (e.g. straight
//! into a method engine) should use [`fragments`]. Handlers that
//! already hold a [`Request`](crate::server::Request) can skip this
//! module's argument-shape entirely and call
//! [`Request::eap_message`](crate::server::Request::eap_message) /
//! [`Request::eap_message_into`](crate::server::Request::eap_message_into).

/// RADIUS attribute type for EAP-Message (RFC 3579 §3.1).
pub const TYPE: u8 = 79;

/// Iterate every `EAP-Message` value in attribute order.
///
/// Each yielded slice borrows from `attrs` directly (no copy). Stops
/// at the first malformed attribute slot — partial EAP payloads are
/// never silently truncated for the caller; pair this with
/// [`super::attributes::iter`] if you need to surface the parse
/// error.
pub fn fragments(attrs: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    super::attributes::iter(attrs)
        .map_while(Result::ok)
        .filter(|raw| raw.attribute_type() == TYPE)
        .map(|raw| raw.value())
}

/// Concatenate every `EAP-Message` value into `out`, returning the
/// total number of bytes appended.
///
/// `out` is *appended to*, not cleared — the caller controls reuse of
/// the buffer.
pub fn reassemble_into(attrs: &[u8], out: &mut Vec<u8>) -> usize {
    let start = out.len();
    for fragment in fragments(attrs) {
        out.extend_from_slice(fragment);
    }
    out.len() - start
}

/// Allocate and return the reassembled EAP payload.
///
/// Returns an empty [`Vec`] when no `EAP-Message` attribute is
/// present. Prefer [`reassemble_into`] in hot paths so the buffer
/// can be reused across requests.
#[must_use]
pub fn reassemble(attrs: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    reassemble_into(attrs, &mut out);
    out
}

/// EAP packet Code byte (RFC 3748 §4).
///
/// Newtype over `u8` rather than a closed enum so unknown codes
/// surface verbatim — match against the associated constants for the
/// well-known values:
///
/// ```ignore
/// use radius_tokio::codec::eap;
/// match pkt.code() {
///     eap::Code::REQUEST  => { /* server-issued */ }
///     eap::Code::RESPONSE => { /* peer-issued */ }
///     eap::Code::SUCCESS  => { /* terminal */ }
///     eap::Code::FAILURE  => { /* terminal */ }
///     other               => { /* `other.0` is the raw byte */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Code(pub u8);

impl Code {
    /// `Request` — server → peer (RFC 3748 §4.1).
    pub const REQUEST: Code = Code(1);
    /// `Response` — peer → server (RFC 3748 §4.1).
    pub const RESPONSE: Code = Code(2);
    /// `Success` — terminal, no Type-Data (RFC 3748 §4.2).
    pub const SUCCESS: Code = Code(3);
    /// `Failure` — terminal, no Type-Data (RFC 3748 §4.2).
    pub const FAILURE: Code = Code(4);
}

/// EAP packet Type byte (RFC 3748 §5).
///
/// Only meaningful on [`Code::REQUEST`] and [`Code::RESPONSE`]
/// packets; [`Code::SUCCESS`] and [`Code::FAILURE`] carry no Type
/// field at all and [`Packet::typ`] returns `None` for them.
///
/// Newtype over `u8`: match against the associated constants for the
/// well-known values, or `Type(other)` for vendor- or
/// expansion-coded types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Type(pub u8);

impl Type {
    /// `Identity` — RFC 3748 §5.1. Universal first response.
    pub const IDENTITY: Type = Type(1);
    /// `Notification` — RFC 3748 §5.2.
    pub const NOTIFICATION: Type = Type(2);
    /// `Legacy Nak` — RFC 3748 §5.3.
    pub const NAK: Type = Type(3);
    /// `MD5-Challenge` — RFC 3748 §5.4.
    pub const MD5_CHALLENGE: Type = Type(4);
    /// `One-Time Password` — RFC 3748 §5.5.
    pub const OTP: Type = Type(5);
    /// `Generic Token Card` — RFC 3748 §5.6.
    pub const GTC: Type = Type(6);
    /// `EAP-TLS` — RFC 5216.
    pub const TLS: Type = Type(13);
    /// `EAP-SIM` — RFC 4186.
    pub const SIM: Type = Type(18);
    /// `EAP-TTLS` — RFC 5281.
    pub const TTLS: Type = Type(21);
    /// `EAP-AKA` — RFC 4187.
    pub const AKA: Type = Type(23);
    /// `PEAP` — `draft-josefsson-pppext-eap-tls-eap`.
    pub const PEAP: Type = Type(25);
    /// `EAP-MSCHAPv2` — `draft-kamath-pppext-eap-mschapv2`.
    pub const MSCHAPV2: Type = Type(26);
    /// `EAP-FAST` — RFC 4851.
    pub const FAST: Type = Type(43);
    /// `EAP-AKA'` — RFC 5448.
    pub const AKA_PRIME: Type = Type(50);
}

/// Errors returned by [`Packet::parse`] and the [`write_request`] /
/// [`write_success`] / [`write_failure`] encoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    /// Buffer shorter than the 4-byte fixed header.
    ShortHeader,
    /// `Length` field below the 4-byte minimum.
    LengthTooSmall,
    /// `Length` field exceeds the supplied buffer.
    LengthExceedsBuffer,
    /// Encoder: the requested EAP payload (Type byte + Type-Data, or
    /// raw payload) would push the total packet length past the
    /// `u16` `Length` field's `65_535`-byte cap (RFC 3748 §4).
    PayloadTooLong {
        /// Total packet length the caller asked for, in bytes
        /// (`4 + 1 + type_data.len()` for [`write_request`]).
        len: usize,
    },
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::ShortHeader => f.write_str("EAP header shorter than 4 bytes"),
            PacketError::LengthTooSmall => f.write_str("EAP length field < 4"),
            PacketError::LengthExceedsBuffer => f.write_str("EAP length field exceeds buffer"),
            PacketError::PayloadTooLong { len } => {
                write!(f, "EAP packet length {len} exceeds u16 maximum 65535")
            }
        }
    }
}

impl std::error::Error for PacketError {}

/// Append an `EAP-Request` packet to `out`, returning the total
/// number of bytes written.
///
/// Wire layout (RFC 3748 §4.1):
/// `Code(1)=1 | Identifier(1) | Length(2 BE) | Type(1) | Type-Data(*)`
///
/// The result round-trips through [`Packet::parse`]; pair with
/// [`crate::Reply::add_eap_message`] to fragment into
/// `EAP-Message` attributes on the reply.
///
/// `out` is *appended to*, not cleared — the caller owns the
/// buffer's lifecycle and can reuse it across replies.
///
/// # Errors
///
/// Returns [`PacketError::PayloadTooLong`] when
/// `4 + 1 + type_data.len()` exceeds `u16::MAX` (`65_535`). EAP
/// implementations typically cap a single packet well below this
/// (RFC 3748 §3.1 suggests an MTU around `1020` bytes); the check is
/// here for protocol correctness rather than as a practical limit.
#[allow(clippy::cast_possible_truncation)]
pub fn write_request(
    out: &mut Vec<u8>,
    id: u8,
    typ: Type,
    type_data: &[u8],
) -> Result<u16, PacketError> {
    write_with_type(out, Code::REQUEST, id, typ, type_data)
}

/// Append an `EAP-Response` packet to `out`, returning the total
/// number of bytes written.
///
/// Mirrors [`write_request`] but with `Code = 2`. The library is a
/// RADIUS *server* — it does not normally emit EAP-Responses — but
/// this is the natural symmetric primitive (useful for test
/// fixtures, proxies, and the parser's round-trip tests).
///
/// # Errors
///
/// Returns [`PacketError::PayloadTooLong`] under the same condition
/// as [`write_request`].
pub fn write_response(
    out: &mut Vec<u8>,
    id: u8,
    typ: Type,
    type_data: &[u8],
) -> Result<u16, PacketError> {
    write_with_type(out, Code::RESPONSE, id, typ, type_data)
}

#[allow(clippy::cast_possible_truncation)]
fn write_with_type(
    out: &mut Vec<u8>,
    code: Code,
    id: u8,
    typ: Type,
    type_data: &[u8],
) -> Result<u16, PacketError> {
    let total = 4usize
        .checked_add(1)
        .and_then(|n| n.checked_add(type_data.len()))
        .ok_or(PacketError::PayloadTooLong { len: usize::MAX })?;
    let length = u16::try_from(total).map_err(|_| PacketError::PayloadTooLong { len: total })?;
    out.reserve(total);
    out.push(code.0);
    out.push(id);
    out.extend_from_slice(&length.to_be_bytes());
    out.push(typ.0);
    out.extend_from_slice(type_data);
    Ok(length)
}

/// Append a bare `EAP-Success` packet (`Code=3, Length=4`) to `out`.
///
/// Returns the 4 bytes written, for symmetry with [`write_request`].
/// Success / Failure carry no Type byte at all (RFC 3748 §4.2) — pair
/// with [`crate::Reply::add_eap_success`] for the common
/// "Access-Accept + EAP-Success" reply shape.
pub fn write_success(out: &mut Vec<u8>, id: u8) -> u16 {
    write_terminal(out, Code::SUCCESS, id)
}

/// Append a bare `EAP-Failure` packet (`Code=4, Length=4`) to `out`.
///
/// Symmetric companion to [`write_success`]; pair with
/// [`crate::Reply::add_eap_failure`] for the common
/// "Access-Reject + EAP-Failure" reply shape.
pub fn write_failure(out: &mut Vec<u8>, id: u8) -> u16 {
    write_terminal(out, Code::FAILURE, id)
}

fn write_terminal(out: &mut Vec<u8>, code: Code, id: u8) -> u16 {
    out.reserve(4);
    out.push(code.0);
    out.push(id);
    out.extend_from_slice(&4u16.to_be_bytes());
    4
}

/// Borrowed, validated view of an EAP packet (RFC 3748 §4).
///
/// Produced by [`Packet::parse`] over a reassembled `EAP-Message`
/// payload (see [`reassemble_into`]). The view holds no allocations
/// of its own — the underlying buffer must outlive it.
///
/// ```ignore
/// use radius_tokio::codec::eap;
///
/// let mut buf = Vec::new();
/// eap::reassemble_into(attrs, &mut buf);
/// let Ok(pkt) = eap::Packet::parse(&buf) else { return };
///
/// match (pkt.code(), pkt.typ()) {
///     (eap::Code::RESPONSE, Some(eap::Type::IDENTITY)) => {
///         let identity = pkt.type_data();
///         // ...
///     }
///     (eap::Code::RESPONSE, Some(eap::Type::MD5_CHALLENGE)) => {
///         // Method-specific parse over `pkt.type_data()`
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    code: Code,
    identifier: u8,
    /// Bytes following the 4-byte EAP header, truncated to the
    /// declared `Length`. Includes the Type byte (if any) and
    /// Type-Data.
    payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse the EAP fixed header and bound the payload to the
    /// declared `Length` field.
    ///
    /// `buf` is typically the output of [`reassemble_into`]; any
    /// trailing bytes past the `Length` field are ignored (per
    /// RFC 3748 §4 packets are self-delimiting via Length).
    ///
    /// # Errors
    ///
    /// Returns [`PacketError`] when the header is short, the length
    /// field is below the 4-byte minimum, or the length field
    /// exceeds the supplied buffer.
    pub fn parse(buf: &'a [u8]) -> Result<Self, PacketError> {
        if buf.len() < 4 {
            return Err(PacketError::ShortHeader);
        }
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if length < 4 {
            return Err(PacketError::LengthTooSmall);
        }
        if length > buf.len() {
            return Err(PacketError::LengthExceedsBuffer);
        }
        Ok(Self {
            code: Code(buf[0]),
            identifier: buf[1],
            payload: &buf[4..length],
        })
    }

    /// EAP `Code` field.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// EAP `Identifier` field — round-tripped on Request/Response
    /// pairs so a peer's response binds to a specific server-issued
    /// request.
    #[must_use]
    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    /// EAP `Length` field — the on-wire 16-bit value, equal to
    /// `4 + payload.len()`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn length(&self) -> u16 {
        (4 + self.payload.len()) as u16
    }

    /// EAP `Type` byte (RFC 3748 §5).
    ///
    /// `None` for [`Code::SUCCESS`] / [`Code::FAILURE`] packets,
    /// which carry no Type at all (their Length is exactly 4). For
    /// well-formed [`Code::REQUEST`] / [`Code::RESPONSE`] packets
    /// this returns `Some` — a missing Type byte on those codes is a
    /// protocol violation by the peer and yields `None` here too.
    #[must_use]
    pub fn typ(&self) -> Option<Type> {
        self.payload.first().copied().map(Type)
    }

    /// EAP `Type-Data` — bytes following the Type byte.
    ///
    /// Empty when [`Self::typ`] returns `None`. The method-specific
    /// parser (e.g. for `MD5-Challenge` or `MSCHAPv2`) drives off this
    /// slice.
    #[must_use]
    pub fn type_data(&self) -> &'a [u8] {
        self.payload.get(1..).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(attrs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for (typ, val) in attrs {
            v.push(*typ);
            v.push(u8::try_from(2 + val.len()).unwrap());
            v.extend_from_slice(val);
        }
        v
    }

    #[test]
    fn collects_in_order_skips_others() {
        let bytes = region(&[
            (TYPE, &[1, 2, 3]),
            (1, b"username"),
            (TYPE, &[4, 5]),
            (TYPE, &[6]),
        ]);
        let frags: Vec<&[u8]> = fragments(&bytes).collect();
        assert_eq!(frags, vec![&[1, 2, 3][..], &[4, 5][..], &[6][..]]);

        let mut out = Vec::new();
        let n = reassemble_into(&bytes, &mut out);
        assert_eq!(n, 6);
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn empty_when_no_eap_attributes() {
        let bytes = region(&[(1, b"x"), (5, &[0, 0, 0, 1])]);
        assert_eq!(fragments(&bytes).count(), 0);
        let mut out = Vec::new();
        assert_eq!(reassemble_into(&bytes, &mut out), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn packet_parse_identity_response() {
        // Code=Response(2), Id=22, Length=12, Type=Identity(1), "spencer"
        let bytes = [2u8, 22, 0, 12, 1, b's', b'p', b'e', b'n', b'c', b'e', b'r'];
        let pkt = Packet::parse(&bytes).expect("ok");
        assert_eq!(pkt.code(), Code::RESPONSE);
        assert_eq!(pkt.identifier(), 22);
        assert_eq!(pkt.length(), 12);
        assert_eq!(pkt.typ(), Some(Type::IDENTITY));
        assert_eq!(pkt.type_data(), b"spencer");
    }

    #[test]
    fn packet_parse_success_has_no_type() {
        // Bare EAP-Success: Code=3, Id=7, Length=4.
        let bytes = [3u8, 7, 0, 4];
        let pkt = Packet::parse(&bytes).expect("ok");
        assert_eq!(pkt.code(), Code::SUCCESS);
        assert_eq!(pkt.identifier(), 7);
        assert_eq!(pkt.length(), 4);
        assert_eq!(pkt.typ(), None);
        assert_eq!(pkt.type_data(), b"");
    }

    #[test]
    fn packet_parse_ignores_trailing_bytes() {
        // Length=4 but buffer is longer — trailing bytes ignored.
        let bytes = [3u8, 7, 0, 4, 0xFF, 0xFF];
        let pkt = Packet::parse(&bytes).expect("ok");
        assert_eq!(pkt.length(), 4);
        assert_eq!(pkt.type_data(), b"");
    }

    #[test]
    fn packet_parse_md5_challenge_response() {
        // Response/MD5-Challenge: value-size(1)=16, value(16), name(0)
        let mut bytes = vec![2u8, 5, 0, 22, 4, 16];
        bytes.extend_from_slice(&[0xAA; 16]);
        let pkt = Packet::parse(&bytes).expect("ok");
        assert_eq!(pkt.code(), Code::RESPONSE);
        assert_eq!(pkt.typ(), Some(Type::MD5_CHALLENGE));
        // Type-Data starts at the value-size byte.
        assert_eq!(pkt.type_data().len(), 17);
        assert_eq!(pkt.type_data()[0], 16);
    }

    #[test]
    fn packet_parse_rejects_short_header() {
        assert!(matches!(
            Packet::parse(&[1, 2, 3]),
            Err(PacketError::ShortHeader)
        ));
    }

    #[test]
    fn packet_parse_rejects_length_below_four() {
        // Length=3 is illegal.
        assert!(matches!(
            Packet::parse(&[1, 0, 0, 3, 0]),
            Err(PacketError::LengthTooSmall)
        ));
    }

    #[test]
    fn packet_parse_rejects_length_past_buffer() {
        // Length=99 but only 5 bytes supplied.
        assert!(matches!(
            Packet::parse(&[1, 0, 0, 99, 1]),
            Err(PacketError::LengthExceedsBuffer)
        ));
    }

    #[test]
    fn packet_typ_none_on_truncated_request() {
        // Code=Request(1), Length=4 — protocol-illegal (Request must
        // carry a Type) but our parser surfaces it as typ()==None
        // rather than erroring; the consumer's match arm handles it
        // as an unknown / unsupported shape.
        let pkt = Packet::parse(&[1u8, 0, 0, 4]).expect("ok");
        assert_eq!(pkt.code(), Code::REQUEST);
        assert_eq!(pkt.typ(), None);
    }

    #[test]
    fn write_request_roundtrips_through_parse() {
        let mut buf = Vec::new();
        let n = write_request(&mut buf, 7, Type::MD5_CHALLENGE, &[16, 0xAA, 0xBB]).expect("ok");
        assert_eq!(n as usize, buf.len());
        let pkt = Packet::parse(&buf).expect("parses");
        assert_eq!(pkt.code(), Code::REQUEST);
        assert_eq!(pkt.identifier(), 7);
        assert_eq!(pkt.typ(), Some(Type::MD5_CHALLENGE));
        assert_eq!(pkt.type_data(), &[16, 0xAA, 0xBB]);
    }

    #[test]
    fn write_response_roundtrips_through_parse() {
        let mut buf = Vec::new();
        let n = write_response(&mut buf, 22, Type::IDENTITY, b"alice").expect("ok");
        assert_eq!(n as usize, buf.len());
        let pkt = Packet::parse(&buf).expect("parses");
        assert_eq!(pkt.code(), Code::RESPONSE);
        assert_eq!(pkt.identifier(), 22);
        assert_eq!(pkt.length() as usize, buf.len());
        assert_eq!(pkt.typ(), Some(Type::IDENTITY));
        assert_eq!(pkt.type_data(), b"alice");
    }

    #[test]
    fn write_request_appends_does_not_clear() {
        let mut buf = vec![0xDE, 0xAD];
        write_request(&mut buf, 1, Type::IDENTITY, b"").expect("ok");
        assert_eq!(&buf[..2], &[0xDE, 0xAD]);
        // Parse the EAP packet from the appended region.
        let pkt = Packet::parse(&buf[2..]).expect("parses");
        assert_eq!(pkt.code(), Code::REQUEST);
        assert_eq!(pkt.typ(), Some(Type::IDENTITY));
        assert_eq!(pkt.type_data(), b"");
    }

    #[test]
    fn write_request_rejects_oversized_payload() {
        // Payload of u16::MAX bytes would push total to u16::MAX + 5.
        let big = vec![0u8; usize::from(u16::MAX)];
        let mut buf = Vec::new();
        let err = write_request(&mut buf, 0, Type::TLS, &big).expect_err("must reject");
        assert!(matches!(err, PacketError::PayloadTooLong { .. }));
        assert!(buf.is_empty(), "no partial write on error");
    }

    #[test]
    fn write_success_and_failure_roundtrip() {
        let mut buf = Vec::new();
        assert_eq!(write_success(&mut buf, 11), 4);
        let pkt = Packet::parse(&buf).expect("ok");
        assert_eq!(pkt.code(), Code::SUCCESS);
        assert_eq!(pkt.identifier(), 11);
        assert_eq!(pkt.length(), 4);
        assert_eq!(pkt.typ(), None);

        let mut buf = Vec::new();
        assert_eq!(write_failure(&mut buf, 12), 4);
        let pkt = Packet::parse(&buf).expect("ok");
        assert_eq!(pkt.code(), Code::FAILURE);
        assert_eq!(pkt.identifier(), 12);
        assert_eq!(pkt.length(), 4);
    }
}
