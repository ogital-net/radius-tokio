use std::fmt;

/// Owned shared-secret bytes, scrubbed on drop and redacted in Debug output.
///
/// Share an `Arc<SecretBytes>` rather than copying the secret between tasks.
pub struct SecretBytes(Box<[u8]>);

impl SecretBytes {
    /// Take ownership of a shared secret.
    #[must_use]
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the shared-secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec().into_boxed_slice())
    }
}

impl<const N: usize> From<&[u8; N]> for SecretBytes {
    fn from(bytes: &[u8; N]) -> Self {
        Self::from(bytes.as_slice())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        crate::crypto::cleanse(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretBytes({} bytes)", self.0.len())
    }
}
