//! Outgoing requests shared by client transports and the CoA originator.

use super::header::Code;
use super::typed::{Attr, IntoWire, VsaAttr, WireType};
use super::{authenticator, message_authenticator, CodecError, PacketBuffer, TlvWriter};
use crate::crypto::{password, ZeroizingBytes};

/// Builder for an outgoing RADIUS request.
///
/// Identifiers, authenticators, password hiding, and Message-Authenticator
/// are finalized by the transport. Every request emits Message-Authenticator.
pub struct Request {
    buf: PacketBuffer,
    password: Option<ZeroizingBytes>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Request")
            .field("code", &self.code())
            .field("has_password", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

impl Request {
    fn new(code: Code) -> Self {
        let mut buf = PacketBuffer::new(code, 0);
        message_authenticator::append_zeroed_slot(&mut buf)
            .expect("fresh request has room for Message-Authenticator");
        Self {
            buf,
            password: None,
        }
    }

    /// Begin an Access-Request.
    #[must_use]
    pub fn access() -> Self {
        Self::new(Code::ACCESS_REQUEST)
    }

    /// Begin an Accounting-Request.
    #[must_use]
    pub fn accounting() -> Self {
        Self::new(Code::ACCOUNTING_REQUEST)
    }

    /// Begin a Status-Server probe.
    #[must_use]
    pub fn status_server() -> Self {
        Self::new(Code::STATUS_SERVER)
    }

    /// Begin a CoA-Request.
    #[must_use]
    pub fn coa() -> Self {
        Self::new(Code::COA_REQUEST)
    }

    /// Begin a Disconnect-Request.
    #[must_use]
    pub fn disconnect() -> Self {
        Self::new(Code::DISCONNECT_REQUEST)
    }

    /// The outgoing packet code.
    #[must_use]
    pub fn code(&self) -> Code {
        self.buf.header().code
    }

    /// Set a PAP password, replacing any previous password.
    ///
    /// The owned plaintext is scrubbed on drop, including failed sends.
    ///
    /// # Errors
    /// Rejects non-Access requests and passwords longer than 128 bytes.
    pub fn user_password(&mut self, plaintext: &[u8]) -> Result<&mut Self, CodecError> {
        if self.code() != Code::ACCESS_REQUEST {
            return Err(CodecError::WrongPacketType);
        }
        if plaintext.len() > 128 {
            return Err(CodecError::PasswordTooLong {
                len: plaintext.len(),
            });
        }
        self.password = Some(ZeroizingBytes::new(plaintext.to_vec()));
        Ok(self)
    }

    fn check_attribute(typ: u8) -> Result<(), CodecError> {
        if typ == 2 || typ == message_authenticator::TYPE {
            return Err(CodecError::ReservedAttribute { typ });
        }
        Ok(())
    }

    /// Append a raw attribute. Use `user_password` for PAP credentials.
    ///
    /// # Errors
    /// Rejects builder-managed attributes and forwards codec limits.
    pub fn add_attribute(&mut self, typ: u8, value: &[u8]) -> Result<&mut Self, CodecError> {
        Self::check_attribute(typ)?;
        self.buf.add_attribute(typ, value)?;
        Ok(self)
    }

    /// Append a typed dictionary attribute.
    ///
    /// # Errors
    /// Rejects builder-managed attributes and forwards codec limits.
    pub fn add<T: WireType, V: IntoWire<T>>(
        &mut self,
        attr: Attr<T>,
        value: V,
    ) -> Result<&mut Self, CodecError> {
        Self::check_attribute(attr.code)?;
        self.buf.add(attr, value)?;
        Ok(self)
    }

    /// Append a typed vendor-specific attribute.
    ///
    /// # Errors
    /// Forwards attribute and packet length errors.
    pub fn add_vsa<T: WireType, V: IntoWire<T>>(
        &mut self,
        attr: VsaAttr<T>,
        value: V,
    ) -> Result<&mut Self, CodecError> {
        self.buf.add_vsa(attr, value)?;
        Ok(self)
    }

    /// Append a nested TLV attribute.
    ///
    /// # Errors
    /// Rejects builder-managed attributes and forwards codec errors.
    pub fn add_tlv<F>(&mut self, typ: u8, build: F) -> Result<&mut Self, CodecError>
    where
        F: FnOnce(&mut TlvWriter<'_>) -> Result<(), CodecError>,
    {
        Self::check_attribute(typ)?;
        self.buf.add_tlv(typ, build)?;
        Ok(self)
    }

    /// Echo an opaque State value from an Access-Challenge.
    ///
    /// # Errors
    /// Forwards attribute and packet length errors.
    pub fn add_state(&mut self, state: &[u8]) -> Result<&mut Self, CodecError> {
        self.add_attribute(24, state)
    }

    /// Fragment an EAP packet into consecutive EAP-Message attributes.
    ///
    /// # Errors
    /// Forwards packet length errors; failed appends are rolled back.
    pub fn add_eap_message(&mut self, packet: &[u8]) -> Result<&mut Self, CodecError> {
        let previous = self.buf.attributes().len();
        for chunk in packet.chunks(253) {
            if let Err(error) = self.buf.add_attribute(79, chunk) {
                self.buf.truncate_attributes_to(previous);
                return Err(error);
            }
        }
        Ok(self)
    }

    pub(crate) fn seal(
        mut self,
        identifier: u8,
        secret: &[u8],
    ) -> Result<PacketBuffer, CodecError> {
        self.buf.set_identifier(identifier);
        let auth = if matches!(self.code(), Code::ACCESS_REQUEST | Code::STATUS_SERVER) {
            authenticator::random_request_authenticator()
        } else {
            [0; 16]
        };
        if let Some(plaintext) = self.password.take() {
            let ciphertext = password::user_password_encrypt(plaintext.as_bytes(), secret, &auth);
            self.buf.add_attribute(2, &ciphertext)?;
        }
        self.buf.patch_length();
        let tag = message_authenticator::compute(self.buf.as_bytes(), &auth, secret);
        message_authenticator::patch(&mut self.buf, 22, &tag);
        let auth = if matches!(self.code(), Code::ACCESS_REQUEST | Code::STATUS_SERVER) {
            auth
        } else {
            authenticator::compute_zeroed_request(self.buf.as_bytes(), secret)
        };
        self.buf.set_authenticator(auth);
        Ok(self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_password_and_authenticators_round_trip() {
        let mut request = Request::access();
        request.user_password(b"hidden-credential").unwrap();
        assert!(!format!("{request:?}").contains("hidden-credential"));
        let packet = request.seal(42, b"secret").unwrap();
        let header = packet.header();
        assert_eq!(header.identifier, 42);
        assert_ne!(header.authenticator, [0; 16]);
        assert_eq!(
            message_authenticator::verify(packet.as_bytes(), &header.authenticator, b"secret"),
            message_authenticator::Verification::Valid
        );
        let credential = packet
            .attributes_iter()
            .map(Result::unwrap)
            .find(|attr| attr.attribute_type() == 2)
            .unwrap();
        assert_eq!(
            password::user_password_decrypt(credential.value(), b"secret", &header.authenticator)
                .unwrap()
                .as_bytes(),
            b"hidden-credential"
        );
    }

    #[test]
    fn zeroed_requests_are_signed_in_the_correct_order() {
        for request in [Request::accounting(), Request::coa(), Request::disconnect()] {
            let packet = request.seal(1, b"secret").unwrap();
            assert!(authenticator::verify_zeroed_request(
                packet.as_bytes(),
                b"secret"
            ));
            assert_eq!(
                message_authenticator::verify(packet.as_bytes(), &[0; 16], b"secret"),
                message_authenticator::Verification::Valid
            );
        }
    }

    #[test]
    fn managed_attributes_and_invalid_passwords_are_rejected() {
        assert!(Request::access().add_attribute(80, &[0; 16]).is_err());
        assert!(Request::access().add_attribute(2, b"plaintext").is_err());
        assert!(Request::access().user_password(&[0; 129]).is_err());
        assert!(Request::accounting().user_password(b"password").is_err());
    }
}
