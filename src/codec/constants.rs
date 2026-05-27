//! Well-known RADIUS attribute type codes (RFC 2865 / RFC 2866 / RFC 2868 /
//! RFC 3579 / RFC 5176).
//!
//! Centralising these here keeps the magic numbers out of the auth
//! helpers, the codec, and the server pipeline. They duplicate the
//! constants emitted by the dictionary codegen on purpose: the
//! handful of attributes referenced from the crate's *own* code
//! (rather than from a consumer's typed `Attr<T>` handle) need to be
//! available without depending on a specific dictionary feature
//! being enabled.

/// `User-Name` (RFC 2865 §5.1).
pub(crate) const USER_NAME: u8 = 1;

/// `User-Password` (RFC 2865 §5.2).
pub(crate) const USER_PASSWORD: u8 = 2;

/// `CHAP-Password` (RFC 2865 §5.3).
pub(crate) const CHAP_PASSWORD: u8 = 3;

/// `Reply-Message` (RFC 2865 §5.18).
pub(crate) const REPLY_MESSAGE: u8 = 18;

/// `Vendor-Specific` (RFC 2865 §5.26).
pub(crate) const VENDOR_SPECIFIC: u8 = 26;

/// `Acct-Status-Type` (RFC 2866 §5.1).
pub(crate) const ACCT_STATUS_TYPE: u8 = 40;

/// `CHAP-Challenge` (RFC 2865 §5.40).
pub(crate) const CHAP_CHALLENGE: u8 = 60;

/// `Tunnel-Password` (RFC 2868 §3.5).
pub(crate) const TUNNEL_PASSWORD: u8 = 69;

/// `Error-Cause` (RFC 5176 §3.5 / RFC 3576 §5.18).
pub(crate) const ERROR_CAUSE: u8 = 101;
