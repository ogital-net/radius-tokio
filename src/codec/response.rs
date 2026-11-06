//! Verified owned responses shared by outgoing transports.

use super::attributes::{self, AttributesView};
use super::header::{Code, Header, MIN_PACKET_LEN};
use super::{authenticator, message_authenticator};

/// An owned response that passed correlation and integrity checks.
///
/// Access-Reject is a successful exchange, not a transport error. Inspect
/// `code()` to distinguish Accept, Reject, and Challenge outcomes.
#[derive(Debug)]
pub struct Response {
    header: Header,
    packet: Vec<u8>,
}

impl Response {
    /// Response packet code.
    #[must_use]
    pub fn code(&self) -> Code {
        self.header.code
    }

    /// Correlation identifier of the completed exchange.
    #[must_use]
    pub fn identifier(&self) -> u8 {
        self.header.identifier
    }

    /// The verified wire packet, excluding UDP padding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.packet
    }

    /// Borrow the response as an `AttributesView`.
    #[must_use]
    pub fn attributes(&self) -> &Self {
        self
    }

    pub(crate) fn verify(
        packet: &[u8],
        request_code: Code,
        identifier: u8,
        request_authenticator: &[u8; 16],
        secret: &[u8],
    ) -> Option<Self> {
        let (header, attrs) = Header::parse(packet).ok()?;
        if header.identifier != identifier
            || !matches_reply(request_code, header.code)
            || attributes::iter(attrs).any(|attribute| attribute.is_err())
        {
            return None;
        }
        let packet = &packet[..usize::from(header.length)];
        if !authenticator::verify_response(packet, request_authenticator, secret) {
            return None;
        }
        match message_authenticator::verify(packet, request_authenticator, secret) {
            message_authenticator::Verification::Valid => {}
            message_authenticator::Verification::Absent
                if request_code == Code::ACCOUNTING_REQUEST => {}
            _ => return None,
        }
        Some(Self {
            header,
            packet: packet.to_vec(),
        })
    }
}

impl<'a> AttributesView<'a> for &'a Response {
    fn raw_attributes(&self) -> &'a [u8] {
        &self.packet[MIN_PACKET_LEN..]
    }
}

fn matches_reply(request: Code, response: Code) -> bool {
    match request {
        Code::ACCESS_REQUEST => matches!(
            response,
            Code::ACCESS_ACCEPT | Code::ACCESS_REJECT | Code::ACCESS_CHALLENGE
        ),
        Code::ACCOUNTING_REQUEST => response == Code::ACCOUNTING_RESPONSE,
        Code::STATUS_SERVER => matches!(response, Code::ACCESS_ACCEPT | Code::ACCOUNTING_RESPONSE),
        Code::COA_REQUEST => matches!(response, Code::COA_ACK | Code::COA_NAK),
        Code::DISCONNECT_REQUEST => matches!(response, Code::DISCONNECT_ACK | Code::DISCONNECT_NAK),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode::Reply;

    #[test]
    fn verifies_challenge_attributes_and_ignores_padding() {
        let mut reply = Reply::new(Code::ACCESS_CHALLENGE, 7);
        reply.add_state(b"state").unwrap();
        let mut bytes = reply.seal_for(&[3; 16], b"secret").as_bytes().to_vec();
        let length = bytes.len();
        bytes.extend_from_slice(&[0xaa; 9]);
        let response =
            Response::verify(&bytes, Code::ACCESS_REQUEST, 7, &[3; 16], b"secret").unwrap();
        assert_eq!(response.code(), Code::ACCESS_CHALLENGE);
        assert_eq!(response.as_bytes().len(), length);
        assert_eq!(response.attributes().state(), Some(b"state".as_slice()));
    }

    #[test]
    fn rejects_wrong_code_identifier_secret_and_missing_mac() {
        let reply = Reply::new(Code::ACCESS_ACCEPT, 7).seal_for(&[3; 16], b"secret");
        assert!(Response::verify(
            reply.as_bytes(),
            Code::ACCOUNTING_REQUEST,
            7,
            &[3; 16],
            b"secret"
        )
        .is_none());
        assert!(Response::verify(
            reply.as_bytes(),
            Code::ACCESS_REQUEST,
            8,
            &[3; 16],
            b"secret"
        )
        .is_none());
        assert!(Response::verify(
            reply.as_bytes(),
            Code::ACCESS_REQUEST,
            7,
            &[3; 16],
            b"wrong"
        )
        .is_none());
        let legacy = Reply::new(Code::ACCESS_ACCEPT, 7)
            .without_message_authenticator()
            .seal_for(&[3; 16], b"secret");
        assert!(Response::verify(
            legacy.as_bytes(),
            Code::ACCESS_REQUEST,
            7,
            &[3; 16],
            b"secret"
        )
        .is_none());
        let accounting = Reply::new(Code::ACCOUNTING_RESPONSE, 7)
            .without_message_authenticator()
            .seal_for(&[3; 16], b"secret");
        assert!(Response::verify(
            accounting.as_bytes(),
            Code::ACCOUNTING_REQUEST,
            7,
            &[3; 16],
            b"secret"
        )
        .is_some());
    }
}
