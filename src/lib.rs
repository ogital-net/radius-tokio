#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub mod auth;
mod codec;
mod crypto;

/// Owning byte buffer that scrubs its contents on drop via
/// `OPENSSL_cleanse`. Re-exported for use in handler-side identity
/// stores and credential plumbing.
pub use crypto::ZeroizingBytes;
/// FreeRADIUS dictionary types and compile-time generated attribute tables.
///
/// This re-exports the `radius-dict` crate so that consumers can use paths
/// such as `radius_tokio::dict::generated::rfc::attrs::USER_NAME`.
pub use radius_dict as dict;
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

// Re-export the consumer-visible codec surface. The receive- and
// reply-handling types are needed by anyone implementing a `Handler`.
pub use codec::encode::Reply;
pub use codec::header::Code;
pub use codec::typed;
pub use codec::{
    attributes, authenticator, dissect, header, message_authenticator, CodecError, PacketBuffer,
    TlvWriter,
};
