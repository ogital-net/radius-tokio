//! Crate-wide error type.
//!
//! Method-specific errors are folded into the variants below so
//! downstream consumers can pattern-match without depending on the
//! `radsec` / TLS feature being enabled.

/// Errors surfaced by the EAP method drivers and the shared
/// framing / reassembly machinery.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A TLS-EAP frame was malformed (short header, length field
    /// inconsistent with the L bit, fragment data shorter than the
    /// declared length, …). See [`crate::framing`] for the wire
    /// shape.
    Framing(&'static str),

    /// Inbound reassembly was asked to accept more bytes than the
    /// peer originally promised in the first fragment's `Length`
    /// field. Either the peer lied about the total length or the
    /// session was driven past the end of a complete TLS message
    /// without a reset.
    ReassemblyOverflow {
        /// Total length promised by the first fragment (L bit
        /// set).
        expected: u32,
        /// Number of bytes already buffered before the offending
        /// fragment.
        buffered: usize,
        /// Bytes the offending fragment is trying to add.
        attempted: usize,
    },

    /// The supplicant's first fragment did not advertise a total
    /// length (`L` bit unset on the first fragment of a multi-part
    /// message). Required by RFC 5216 §3.2.
    MissingTotalLength,

    /// EAP packet parsing surfaced an error. Forwarded verbatim
    /// from [`radius_tokio::eap`].
    Eap(radius_tokio::eap::PacketError),

    /// Wraps any error surfaced by the underlying TLS implementation
    /// (handshake failure, fatal alert, …). The string is for
    /// diagnostics only; programmatic callers should inspect the
    /// session state instead.
    Tls(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Framing(what) => write!(f, "EAP framing error: {what}"),
            Error::ReassemblyOverflow {
                expected,
                buffered,
                attempted,
            } => write!(
                f,
                "EAP reassembly overflow: expected {expected}, buffered {buffered}, attempted {attempted}",
            ),
            Error::MissingTotalLength => f.write_str(
                "EAP first fragment missing total-length (L bit unset on multi-part message)",
            ),
            Error::Eap(e) => write!(f, "EAP packet error: {e}"),
            Error::Tls(msg) => write!(f, "TLS error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Eap(e) => Some(e),
            _ => None,
        }
    }
}

impl From<radius_tokio::eap::PacketError> for Error {
    fn from(e: radius_tokio::eap::PacketError) -> Self {
        Error::Eap(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_covers_every_variant() {
        assert_eq!(
            Error::Framing("short header").to_string(),
            "EAP framing error: short header"
        );
        assert_eq!(
            Error::ReassemblyOverflow {
                expected: 100,
                buffered: 60,
                attempted: 50,
            }
            .to_string(),
            "EAP reassembly overflow: expected 100, buffered 60, attempted 50"
        );
        assert!(Error::MissingTotalLength
            .to_string()
            .contains("missing total-length"));
        assert_eq!(
            Error::Tls("bad alert".into()).to_string(),
            "TLS error: bad alert"
        );
    }

    #[test]
    fn source_returns_eap_inner_only() {
        // Drive a PacketError out of parse() on a too-short buffer.
        let inner = radius_tokio::eap::Packet::parse(&[]).unwrap_err();
        let wrapped: Error = inner.into();
        // Display passes through the inner error.
        assert!(wrapped.to_string().starts_with("EAP packet error:"));
        assert!(wrapped.source().is_some());

        assert!(Error::Framing("x").source().is_none());
        assert!(Error::MissingTotalLength.source().is_none());
        assert!(Error::Tls("x".into()).source().is_none());
        assert!(Error::ReassemblyOverflow {
            expected: 1,
            buffered: 0,
            attempted: 2
        }
        .source()
        .is_none());
    }
}
