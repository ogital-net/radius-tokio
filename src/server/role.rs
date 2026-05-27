//! Per-listener role tag.
//!
//! Every UDP and `RadSec` bind point on a [`Server`](super::Server)
//! carries a [`ListenerRole`]. The role has two jobs:
//!
//! 1. **Admission filter.** [`ListenerRole::accepts`] is consulted
//!    immediately after the header parse and decides whether the
//!    inbound code is legal on this listener. Mismatched codes are
//!    dropped (UDP) or close the session (`RadSec`) before any
//!    cryptographic work — matches the per-socket type filter every
//!    production RADIUS server applies (FreeRADIUS' `Invalid packet
//!    code N sent to socket type auth`, `radsecproxy`'s separate
//!    `listenUDP` / `listenAccountingUDP` accept paths).
//! 2. **Status-Server reply code.** [`ListenerRole::status_reply_code`]
//!    tells the built-in [`status`](super::status) responder which
//!    code to return for an RFC 5997 probe.
//!
//! The role is **not** inferred from the bound port number — port
//! 1812/1813 is RFC convention, not guarantee, and operators
//! routinely bind to non-standard ports.

use crate::codec::header::Code;

/// Role the operator assigned to a listener.
///
/// See the [module-level docs](self) for the full description; the
/// short version is "what codes is this listener allowed to receive,
/// and what does its built-in Status-Server responder reply with?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerRole {
    /// Authentication listener. Accepts `Access-Request` (and
    /// `Status-Server`); Status-Server probes are answered with
    /// `Access-Accept` (code 2). Default for
    /// [`ServerBuilder::listen_udp`](super::ServerBuilder::listen_udp).
    Auth,
    /// Accounting listener. Accepts `Accounting-Request` (and
    /// `Status-Server`); Status-Server probes are answered with
    /// `Accounting-Response` (code 5).
    Acct,
    /// Multiplexed listener: accepts every request code the library
    /// knows how to dispatch. Default for
    /// [`ServerBuilder::listen_radsec`](super::ServerBuilder::listen_radsec),
    /// which runs a single TLS connection on port 2083 carrying
    /// auth, accounting, and CoA traffic interleaved — matches the
    /// `radsecproxy` and FreeRADIUS `proto_radius_tcp` posture.
    /// Status-Server probes are answered with `Access-Accept` (the
    /// conventional default when the probe can't be attributed to
    /// a single subsystem).
    Any,
}

impl ListenerRole {
    /// Reply code this role emits in response to a Status-Server
    /// (RFC 5997 §6).
    #[must_use]
    pub fn status_reply_code(self) -> Code {
        match self {
            Self::Auth | Self::Any => Code::ACCESS_ACCEPT,
            Self::Acct => Code::ACCOUNTING_RESPONSE,
        }
    }

    /// Whether `code` is permitted to be processed on a listener of
    /// this role.
    ///
    /// The library applies this filter immediately after header
    /// parse and drops any mismatched packet before authenticator
    /// validation, dedup, or handler dispatch. Prevents a
    /// misconfigured NAS — or a confused unified handler — from
    /// quietly processing an Accounting-Request on an auth socket
    /// and vice versa.
    ///
    /// Status-Server (RFC 5997, code 12) is accepted on **every**
    /// role: it is defined to be sent to either port and the reply
    /// code is derived from the role.
    ///
    /// | Role  | Accepted codes                                       |
    /// |-------|------------------------------------------------------|
    /// | `Auth` | `Access-Request` (1), `Status-Server` (12)          |
    /// | `Acct` | `Accounting-Request` (4), `Status-Server` (12)      |
    /// | `Any`  | every request code the library dispatches           |
    #[must_use]
    pub fn accepts(self, code: Code) -> bool {
        if code == Code::STATUS_SERVER {
            return true;
        }
        match self {
            Self::Auth => code == Code::ACCESS_REQUEST,
            Self::Acct => code == Code::ACCOUNTING_REQUEST,
            Self::Any => matches!(
                code,
                Code::ACCESS_REQUEST
                    | Code::ACCOUNTING_REQUEST
                    | Code::COA_REQUEST
                    | Code::DISCONNECT_REQUEST
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_maps_to_reply_code() {
        assert_eq!(ListenerRole::Auth.status_reply_code(), Code::ACCESS_ACCEPT);
        assert_eq!(
            ListenerRole::Acct.status_reply_code(),
            Code::ACCOUNTING_RESPONSE,
        );
        // Mixed listener has no canonical answer for Status-Server;
        // we follow the FreeRADIUS / radsecproxy default of
        // Access-Accept.
        assert_eq!(ListenerRole::Any.status_reply_code(), Code::ACCESS_ACCEPT);
    }

    #[test]
    fn role_accepts_matches_per_socket_code_filter() {
        // Auth listener: Access-Request + Status-Server only.
        assert!(ListenerRole::Auth.accepts(Code::ACCESS_REQUEST));
        assert!(ListenerRole::Auth.accepts(Code::STATUS_SERVER));
        assert!(!ListenerRole::Auth.accepts(Code::ACCOUNTING_REQUEST));
        assert!(!ListenerRole::Auth.accepts(Code::COA_REQUEST));
        assert!(!ListenerRole::Auth.accepts(Code::DISCONNECT_REQUEST));
        assert!(!ListenerRole::Auth.accepts(Code::ACCESS_ACCEPT));

        // Acct listener: Accounting-Request + Status-Server only.
        assert!(ListenerRole::Acct.accepts(Code::ACCOUNTING_REQUEST));
        assert!(ListenerRole::Acct.accepts(Code::STATUS_SERVER));
        assert!(!ListenerRole::Acct.accepts(Code::ACCESS_REQUEST));
        assert!(!ListenerRole::Acct.accepts(Code::COA_REQUEST));
        assert!(!ListenerRole::Acct.accepts(Code::DISCONNECT_REQUEST));
        assert!(!ListenerRole::Acct.accepts(Code::ACCOUNTING_RESPONSE));

        // Any (RadSec default): every request code, plus
        // Status-Server. Reply / response codes are still rejected
        // — only request-shaped packets traverse the dispatch path.
        assert!(ListenerRole::Any.accepts(Code::ACCESS_REQUEST));
        assert!(ListenerRole::Any.accepts(Code::ACCOUNTING_REQUEST));
        assert!(ListenerRole::Any.accepts(Code::COA_REQUEST));
        assert!(ListenerRole::Any.accepts(Code::DISCONNECT_REQUEST));
        assert!(ListenerRole::Any.accepts(Code::STATUS_SERVER));
        assert!(!ListenerRole::Any.accepts(Code::ACCESS_ACCEPT));
        assert!(!ListenerRole::Any.accepts(Code::ACCOUNTING_RESPONSE));
    }
}
