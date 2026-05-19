//! Status-Server (RFC 5997) responder.
//!
//! Status-Server is RADIUS code 12, used by NAS devices and proxies
//! as an application-layer keepalive. It is a small, self-contained
//! exchange: a single request whose only meaningful attribute is
//! `Message-Authenticator` (and optionally `NAS-Identifier`), and a
//! reply whose code depends on which port the request landed on
//! (auth → `Access-Accept`, acct → `Accounting-Response`).
//!
//! The server pipeline short-circuits Status-Server *before* dispatch
//! to the consumer's [`Handler`](super::Handler). Every production RADIUS server
//! (FreeRADIUS, radsecproxy) handles keepalives this way; routing
//! them through application code would put the keepalive path at the
//! mercy of arbitrary handler latency, which defeats the purpose.
//!
//! Consumers that want to surface internal health in the reply
//! (queue depth, build version, …) plug in a [`StatusResponder`]
//! via [`StatusServerPolicy::Custom`].
//!
//! # Wire shape
//!
//! Per RFC 5997 §6, the reply carries a `Message-Authenticator`
//! and may optionally carry a `Reply-Message`. Our reply builder
//! emits Message-Authenticator unconditionally (see
//! [`Reply`]), so the helpers below only need to manage the
//! optional `Reply-Message` and the reply code.
//!
//! # Security
//!
//! RFC 5997 §6 makes Message-Authenticator mandatory on both
//! request and reply. The receive pipeline enforces this
//! independently of [`crate::server::Client::require_message_authenticator`]
//! — a Status-Server packet without a valid M-A is silently
//! dropped, full stop.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::codec::constants::REPLY_MESSAGE as REPLY_MESSAGE_TYPE;
use crate::codec::encode::Reply;
use crate::codec::header::Code;

use super::client::Client;

/// Role the operator assigned to a listener.
///
/// The role determines which reply code the built-in Status-Server
/// responder emits (RFC 5997 §6): `Access-Accept` on an auth port,
/// `Accounting-Response` on an acct port. It is *not* inferred from
/// the bound port number — port 1812/1813 is convention, not
/// guarantee, and operators routinely bind to non-standard ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerRole {
    /// Authentication listener. Status-Server probes are answered
    /// with `Access-Accept` (code 2).
    Auth,
    /// Accounting listener. Status-Server probes are answered with
    /// `Accounting-Response` (code 5).
    Acct,
}

impl ListenerRole {
    /// Reply code this role emits in response to a Status-Server.
    #[must_use]
    pub fn status_reply_code(self) -> Code {
        match self {
            Self::Auth => Code::ACCESS_ACCEPT,
            Self::Acct => Code::ACCOUNTING_RESPONSE,
        }
    }
}

/// Transport the inbound Status-Server arrived on. Surfaced to a
/// custom [`StatusResponder`] for logging or per-transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusTransport {
    /// Plain UDP (RFC 2865 / RFC 5997).
    Udp,
    /// `RadSec` (RFC 6614 §2.6).
    Radsec,
}

/// Server-wide policy for handling inbound Status-Server packets.
///
/// Stored on the [`Server`](super::Server) and shared (via
/// [`Arc`]-wrapped clones) with every listener task. The default,
/// returned by [`StatusServerPolicy::default`], is
/// [`Self::Enabled`].
#[derive(Clone, Default)]
pub enum StatusServerPolicy {
    /// Built-in responder is off. Status-Server packets that pass
    /// authenticator + Message-Authenticator validation are
    /// silently discarded (RFC 5997 §3 explicitly permits a server
    /// to decline support).
    Disabled,
    /// Built-in responder replies with the listener's role-derived
    /// code (`Access-Accept` for auth, `Accounting-Response` for
    /// acct). No `Reply-Message` is included.
    #[default]
    Enabled,
    /// Built-in responder is on, but a consumer-supplied callback
    /// gets a chance to add or override attributes (typically
    /// `Reply-Message`) and may veto the reply by returning
    /// [`StatusAction::Drop`].
    Custom(Arc<dyn StatusResponder>),
}

impl std::fmt::Debug for StatusServerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("StatusServerPolicy::Disabled"),
            Self::Enabled => f.write_str("StatusServerPolicy::Enabled"),
            Self::Custom(_) => f.write_str("StatusServerPolicy::Custom(..)"),
        }
    }
}

/// Outcome of a [`StatusResponder`] invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAction {
    /// Send the (possibly mutated) reply.
    Send,
    /// Drop the request silently — no reply on the wire.
    Drop,
}

/// Context passed to a [`StatusResponder`] callback.
#[derive(Debug)]
pub struct StatusContext<'a> {
    /// Resolved client record for the probing peer.
    pub client: &'a Arc<Client>,
    /// Source address of the probe (UDP src, or peer addr for `RadSec`).
    pub src: SocketAddr,
    /// Role of the listener that received the probe.
    pub role: ListenerRole,
    /// Transport the probe arrived on.
    pub transport: StatusTransport,
    /// Identifier byte of the probe — already echoed in `reply`.
    pub identifier: u8,
}

/// Consumer-supplied hook invoked for each inbound Status-Server
/// when [`StatusServerPolicy::Custom`] is in effect.
///
/// The default reply (correct code, echoed identifier,
/// Message-Authenticator placeholder) has already been built; the
/// callback may append additional attributes — most commonly a
/// short status string in `Reply-Message` (attribute 18) — or
/// return [`StatusAction::Drop`] to suppress the reply entirely.
///
/// Implementations must be cheap and synchronous. Status-Server is
/// a keepalive: a slow responder defeats its own purpose.
pub trait StatusResponder: Send + Sync + 'static {
    /// Decide whether to send the reply, and optionally mutate it.
    fn respond(&self, ctx: StatusContext<'_>, reply: &mut Reply) -> StatusAction;
}

/// Append a `Reply-Message` (RFC 2865 §5.18) to `reply`. Returns
/// [`StatusAction::Drop`] if the message would exceed the per-attribute
/// length limit (253 bytes), so a misconfigured caller can't accidentally
/// produce an unsendable reply.
///
/// Convenience for [`StatusResponder`] implementations.
///
/// # Errors
///
/// Returns the underlying [`crate::codec::CodecError`] if `reply`
/// is already at the protocol's 4 KiB ceiling, which is not
/// reachable for a Status-Server reply in practice.
pub fn append_reply_message(
    reply: &mut Reply,
    message: &[u8],
) -> Result<(), crate::codec::CodecError> {
    reply.add_attribute(REPLY_MESSAGE_TYPE, message)?;
    Ok(())
}

/// Build the (unsealed) reply for a validated Status-Server probe,
/// running the consumer-supplied responder when one is installed.
///
/// Returns `None` if the active policy or the responder elects to
/// drop the request.
pub(crate) fn build_status_reply(
    policy: &StatusServerPolicy,
    role: ListenerRole,
    transport: StatusTransport,
    identifier: u8,
    client: &Arc<Client>,
    src: SocketAddr,
) -> Option<Reply> {
    let custom = match policy {
        StatusServerPolicy::Disabled => return None,
        StatusServerPolicy::Enabled => None,
        StatusServerPolicy::Custom(responder) => Some(Arc::clone(responder)),
    };

    let mut reply = Reply::new(role.status_reply_code(), identifier);

    if let Some(responder) = custom {
        let ctx = StatusContext {
            client,
            src,
            role,
            transport,
            identifier,
        };
        match responder.respond(ctx, &mut reply) {
            StatusAction::Send => {}
            StatusAction::Drop => return None,
        }
    }

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Header;
    use crate::codec::message_authenticator;
    use std::net::Ipv4Addr;

    fn fake_client() -> Arc<Client> {
        Arc::new(Client::new(b"shh".as_slice()))
    }

    fn fake_src() -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345)
    }

    #[test]
    fn role_maps_to_reply_code() {
        assert_eq!(ListenerRole::Auth.status_reply_code(), Code::ACCESS_ACCEPT);
        assert_eq!(
            ListenerRole::Acct.status_reply_code(),
            Code::ACCOUNTING_RESPONSE,
        );
    }

    #[test]
    fn policy_default_is_enabled() {
        assert!(matches!(
            StatusServerPolicy::default(),
            StatusServerPolicy::Enabled
        ));
    }

    #[test]
    fn disabled_policy_drops() {
        let reply = build_status_reply(
            &StatusServerPolicy::Disabled,
            ListenerRole::Auth,
            StatusTransport::Udp,
            7,
            &fake_client(),
            fake_src(),
        );
        assert!(reply.is_none());
    }

    #[test]
    fn enabled_policy_builds_auth_reply() {
        let reply = build_status_reply(
            &StatusServerPolicy::Enabled,
            ListenerRole::Auth,
            StatusTransport::Udp,
            42,
            &fake_client(),
            fake_src(),
        )
        .expect("reply built");
        let sealed = reply.seal_for(&[0u8; 16], b"shh");
        let bytes = sealed.as_bytes();
        let (header, _attrs) = Header::parse(bytes).expect("parse");
        assert_eq!(header.code, Code::ACCESS_ACCEPT);
        assert_eq!(header.identifier, 42);
    }

    #[test]
    fn enabled_policy_builds_acct_reply() {
        let reply = build_status_reply(
            &StatusServerPolicy::Enabled,
            ListenerRole::Acct,
            StatusTransport::Udp,
            9,
            &fake_client(),
            fake_src(),
        )
        .expect("reply built");
        let sealed = reply.seal_for(&[0u8; 16], b"shh");
        let bytes = sealed.as_bytes();
        let (header, _attrs) = Header::parse(bytes).expect("parse");
        assert_eq!(header.code, Code::ACCOUNTING_RESPONSE);
        assert_eq!(header.identifier, 9);
    }

    #[test]
    fn sealed_reply_carries_valid_message_authenticator() {
        // RFC 5997 §6: Message-Authenticator MUST be present and
        // valid in the reply. The codec installs it automatically;
        // round-trip the verifier to confirm.
        let secret = b"shh";
        let reply = build_status_reply(
            &StatusServerPolicy::Enabled,
            ListenerRole::Auth,
            StatusTransport::Udp,
            1,
            &fake_client(),
            fake_src(),
        )
        .unwrap();
        // Use a fixed request authenticator so the M-A check is
        // deterministic.
        let req_auth = [0xAAu8; 16];
        let sealed = reply.seal_for(&req_auth, secret);
        let bytes = sealed.as_bytes();
        // The reply's Authenticator field is the Response
        // Authenticator, computed over MD5(reply || req_auth ||
        // secret). Reply M-A is computed over the reply with the
        // req_auth substituted into the Authenticator slot.
        assert_eq!(
            message_authenticator::verify(bytes, &req_auth, secret),
            crate::codec::message_authenticator::Verification::Valid,
        );
    }

    struct StringResponder(&'static str);
    impl StatusResponder for StringResponder {
        fn respond(&self, _ctx: StatusContext<'_>, reply: &mut Reply) -> StatusAction {
            append_reply_message(reply, self.0.as_bytes()).unwrap();
            StatusAction::Send
        }
    }

    #[test]
    fn custom_responder_can_inject_reply_message() {
        let policy = StatusServerPolicy::Custom(Arc::new(StringResponder("ok q=0")));
        let reply = build_status_reply(
            &policy,
            ListenerRole::Auth,
            StatusTransport::Udp,
            3,
            &fake_client(),
            fake_src(),
        )
        .unwrap();
        let sealed = reply.seal_for(&[0u8; 16], b"shh");
        let bytes = sealed.as_bytes();
        // Naive scan: find an attribute with type 18 and value
        // "ok q=0".
        let (_h, attrs) = Header::parse(bytes).unwrap();
        let mut found = false;
        for raw in crate::codec::attributes::iter(attrs) {
            let raw = raw.unwrap();
            if raw.attribute_type() == REPLY_MESSAGE_TYPE && raw.value() == b"ok q=0" {
                found = true;
            }
        }
        assert!(found, "Reply-Message not present");
    }

    struct DropResponder;
    impl StatusResponder for DropResponder {
        fn respond(&self, _ctx: StatusContext<'_>, _reply: &mut Reply) -> StatusAction {
            StatusAction::Drop
        }
    }

    #[test]
    fn custom_responder_can_drop() {
        let policy = StatusServerPolicy::Custom(Arc::new(DropResponder));
        let reply = build_status_reply(
            &policy,
            ListenerRole::Auth,
            StatusTransport::Udp,
            1,
            &fake_client(),
            fake_src(),
        );
        assert!(reply.is_none());
    }
}
