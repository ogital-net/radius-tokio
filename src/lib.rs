#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod auth;
mod codec;
mod crypto;

/// Constant-time byte-slice equality, backed by `CRYPTO_memcmp`.
/// Use this in any handler or EAP inner method that compares a
/// peer-supplied secret (password, MAC, response hash) against an
/// expected value, to keep timing side-channels closed.
pub use crypto::ct_eq;
/// Owning byte buffer that scrubs its contents on drop via
/// `OPENSSL_cleanse`. Re-exported for use in handler-side identity
/// stores and credential plumbing.
pub use crypto::ZeroizingBytes;
/// FreeRADIUS dictionary types and compile-time generated attribute tables.
///
/// This re-exports the `radius-tokio-dict` crate so that consumers can use paths
/// such as `radius_tokio::dict::rfc::attrs::USER_NAME`.
pub use radius_tokio_dict as dict;
#[macro_use]
mod obs;
pub mod server;

// Re-export the TLS wrapper as a public submodule. Lives under
// `crypto/` because it shares the same `aws-lc-sys` boundary, but
// is consumer-visible because RadSec listeners need to configure it.
// Only available with the `radsec` feature, which turns on the
// `ssl` feature of `aws-lc-sys`.
#[cfg(feature = "radsec")]
pub use crypto::tls;

/// Sensible-defaults PKI helpers (CA + leaf issuance) for RadSec
/// onboarding. Only available with the `radsec` feature.
#[cfg(feature = "radsec")]
pub use crypto::pki;

/// Cryptographically secure random byte source backed by aws-lc's
/// `RAND_bytes`. Intended for nonces, EAP session identifiers, and
/// any other consumer-side keying material that must be
/// unpredictable.
pub use crypto::rand;

/// AES-128 / AES-256 block primitives and CBC helpers. Exposed for
/// EAP method drivers (notably EAP-AKA's `AT_ENCR_DATA` payload)
/// and any consumer that needs a vetted block cipher.
pub use crypto::aes;
/// HMAC-SHA-1 primitives. Required for EAP-AKA (`AT_MAC` =
/// HMAC-SHA1-128) and PBKDF2-HMAC-SHA1 callers that want streaming
/// access alongside the one-shot [`pbkdf2`] helpers.
pub use crypto::hmac_sha1;
/// HMAC-SHA-256 primitives. Required for EAP-AKA' (`AT_MAC` =
/// HMAC-SHA256-128, PRF' key derivation per RFC 5448 §3.3) and for
/// generic password-verification HMAC use.
pub use crypto::hmac_sha256;
/// PBKDF2-HMAC-SHA1 / PBKDF2-HMAC-SHA256 helpers. Primary use
/// case: WPA/WPA2-Personal `PMK = PBKDF2-HMAC-SHA1(passphrase,
/// SSID, 4096, 32)` derivation that PPSK / DPSK / MPSK schemes
/// reuse.
pub use crypto::pbkdf2;

// Re-export the consumer-visible codec surface. The receive- and
// reply-handling types are needed by anyone implementing a `Handler`.
pub use codec::encode::Reply;
pub use codec::header::Code;
pub use codec::typed;
pub use codec::{
    attributes, authenticator, dissect, eap, header, message_authenticator, CodecError,
    PacketBuffer, TlvWriter,
};
