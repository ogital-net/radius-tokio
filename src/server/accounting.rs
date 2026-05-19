//! RFC 2866 / RFC 2867 Accounting helpers.
//!
//! The wire protocol for Accounting is already handled end-to-end by
//! the rest of the crate: the UDP pipeline verifies the
//! Accounting-Request Authenticator (RFC 2866 §3 — `MD5(packet ||
//! secret)` with the Authenticator field zeroed), the dedup cache
//! suppresses NAS retransmits keyed on
//! `(src, code, identifier, request-authenticator)` (RFC 5080 §2.2.2),
//! and [`crate::codec::encode::Reply`] seals
//! [`Code::ACCOUNTING_RESPONSE`](crate::Code::ACCOUNTING_RESPONSE)
//! the same way it seals every other reply.
//!
//! What this module adds is the small, typed surface a handler needs
//! to react to an Accounting-Request: an [`AcctStatusType`] enum
//! covering the values from RFC 2866 §5.1 (and the tunnel-related
//! additions from RFC 2867 §4) plus a convenience accessor on
//! [`Request`](crate::server::Request).
//!
//! # Interim-Update interval
//!
//! The library does *not* generate `Interim-Update` packets — those
//! are sent by the NAS, not the server. The server's role is to
//! accept the inbound update and (optionally) tell the NAS how often
//! to send them by including `Acct-Interim-Interval` (attribute 85)
//! on the original Access-Accept. Use
//! [`Reply::add`](crate::codec::encode::Reply::add) with the
//! generated `attrs::ACCT_INTERIM_INTERVAL` handle.
//!
//! Duplicate Interim-Update suppression rides on the same dedup
//! cache used for every other request type — there is no separate
//! Accounting cache. A NAS that retransmits an interim update before
//! its retry timer hears our previous reply will get the cached
//! response back without the handler running a second time.

/// Acct-Status-Type (attribute 40) values defined by RFC 2866 §5.1
/// and RFC 2867 §4.
///
/// Wire encoding is a 4-byte big-endian unsigned integer; conversion
/// is via [`AcctStatusType::from_u32`] / [`AcctStatusType::to_u32`].
/// Values not enumerated here round-trip as
/// [`AcctStatusType::Other`] so the type stays total over the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcctStatusType {
    /// Session is starting (RFC 2866 §5.1).
    Start,
    /// Session has ended (RFC 2866 §5.1).
    Stop,
    /// Mid-session update (RFC 2869 §5.6 — value 3, also spelled
    /// `Alive` in some dictionaries).
    InterimUpdate,
    /// NAS has come up; previous accounting state should be flushed
    /// (RFC 2866 §5.1).
    AccountingOn,
    /// NAS is going down (RFC 2866 §5.1).
    AccountingOff,
    /// Tunnel start (RFC 2867 §4).
    TunnelStart,
    /// Tunnel stop (RFC 2867 §4).
    TunnelStop,
    /// Tunnel reject (RFC 2867 §4).
    TunnelReject,
    /// Tunnel link start (RFC 2867 §4).
    TunnelLinkStart,
    /// Tunnel link stop (RFC 2867 §4).
    TunnelLinkStop,
    /// Tunnel link reject (RFC 2867 §4).
    TunnelLinkReject,
    /// Generic failure indicator (RFC 2866 §5.1, value 15).
    Failed,
    /// An Acct-Status-Type value the library does not enumerate. The
    /// raw integer is preserved so handlers can react to vendor or
    /// future-RFC values without losing fidelity.
    Other(u32),
}

impl AcctStatusType {
    /// Decode from the on-wire integer.
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Start,
            2 => Self::Stop,
            3 => Self::InterimUpdate,
            7 => Self::AccountingOn,
            8 => Self::AccountingOff,
            9 => Self::TunnelStart,
            10 => Self::TunnelStop,
            11 => Self::TunnelReject,
            12 => Self::TunnelLinkStart,
            13 => Self::TunnelLinkStop,
            14 => Self::TunnelLinkReject,
            15 => Self::Failed,
            other => Self::Other(other),
        }
    }

    /// Encode to the on-wire integer.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Start => 1,
            Self::Stop => 2,
            Self::InterimUpdate => 3,
            Self::AccountingOn => 7,
            Self::AccountingOff => 8,
            Self::TunnelStart => 9,
            Self::TunnelStop => 10,
            Self::TunnelReject => 11,
            Self::TunnelLinkStart => 12,
            Self::TunnelLinkStop => 13,
            Self::TunnelLinkReject => 14,
            Self::Failed => 15,
            Self::Other(v) => v,
        }
    }
}

/// Acct-Status-Type attribute code (RFC 2866 §5.1).
pub(crate) use crate::codec::constants::ACCT_STATUS_TYPE as ACCT_STATUS_TYPE_CODE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_values() {
        for raw in [1u32, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            assert_eq!(AcctStatusType::from_u32(raw).to_u32(), raw);
        }
    }

    #[test]
    fn unknown_values_round_trip_as_other() {
        assert_eq!(AcctStatusType::from_u32(99), AcctStatusType::Other(99));
        assert_eq!(AcctStatusType::Other(99).to_u32(), 99);
    }
}
