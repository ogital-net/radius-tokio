//! Transport-agnostic packet pipeline.
//!
//! Both the UDP ([`super::udp`]) and RadSec ([`super::radsec`])
//! transports share the same per-packet validation + dispatch flow
//! once a peer has been resolved to a [`Client`]:
//!
//! 1. Parse the fixed 20-byte header.
//! 2. Verify the code-appropriate Request Authenticator
//!    (Accounting / CoA / Disconnect zeroed-request scheme;
//!    Access-Request is implicitly checked by the
//!    Message-Authenticator and the response auth on the reply).
//! 3. Verify the Message-Authenticator (RFC 3579 §3.2), honouring
//!    the per-client strict / legacy policy.
//! 4. Consult the dedup / retransmit cache. On a hit, replay the
//!    cached reply byte-for-byte.
//! 5. On a miss, build a [`Request`], invoke the handler, seal the
//!    reply, insert into the cache, and hand the bytes back to the
//!    transport.
//!
//! This module owns steps 1–5 as two pure functions:
//!
//! * [`validate`] performs steps 1–3 and returns a [`Validated`]
//!   verdict. It does **no** I/O, **no** tracing, and **no**
//!   allocation beyond what the codec internally needs.
//! * [`dispatch_validated`] performs steps 4–5 and returns a
//!   [`Dispatched`] action describing what the transport should
//!   send back.
//!
//! Each transport remains responsible for its own tracing strings
//! (UDP uses `event = "drop"` / `"dedup_hit"` / …, RadSec prefixes
//! the same names with `radsec_`) and for its own drop-vs-teardown
//! policy. UDP silently drops on every error verdict; RadSec
//! converts an authentication failure into a connection teardown
//! because a misbehaving peer that already passed mTLS must not be
//! allowed to keep streaming frames.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::codec::header::{Code, Header, HeaderError};
use crate::codec::message_authenticator::Verification;
use crate::codec::{authenticator, message_authenticator, PacketBuffer};

use super::client::Client;
use super::dedup::{DedupCache, Key as DedupKey};
use super::handler::{Handler, HandlerResult, Request};
use super::status::{self, ListenerRole, StatusServerPolicy, StatusTransport};

/// Verdict produced by [`validate`].
///
/// The error variants carry only the minimum context needed to
/// emit a meaningful drop event — the caller adds transport-specific
/// fields (source address, client id, …).
pub(crate) enum Validated<'a> {
    /// Header parsed and every authenticator check passed.
    Ok { header: Header, attrs: &'a [u8] },
    /// `Header::parse` rejected the packet.
    MalformedHeader(HeaderError),
    /// Code-appropriate Request Authenticator did not verify.
    BadRequestAuthenticator { code: Code, identifier: u8 },
    /// Strict policy in effect and the (Access-Request) packet did
    /// not carry a Message-Authenticator attribute.
    MissingMessageAuthenticator { code: Code, identifier: u8 },
    /// A Message-Authenticator was present but did not verify.
    BadMessageAuthenticator { code: Code, identifier: u8 },
}

/// Parse `packet` and run every authenticator check that does not
/// depend on the transport. Pure; safe to call on any thread.
pub(crate) fn validate<'a>(packet: &'a [u8], client: &Client) -> Validated<'a> {
    let (header, attrs) = match Header::parse(packet) {
        Ok(parsed) => parsed,
        Err(e) => return Validated::MalformedHeader(e),
    };

    if !verify_request_authenticator(header.code, packet, client.secret()) {
        return Validated::BadRequestAuthenticator {
            code: header.code,
            identifier: header.identifier,
        };
    }

    let substitute = ma_substitute(header.code, &header.authenticator);
    match message_authenticator::verify(packet, &substitute, client.secret()) {
        Verification::Valid => {}
        Verification::Absent => {
            // RFC 5080 §2.2.2 / RFC 3579 §3.2: Access-Request packets
            // must carry Message-Authenticator under the strict policy
            // (default — see [`Client::require_message_authenticator`]).
            // RFC 5997 §6: Status-Server packets MUST carry it,
            // unconditionally — the per-client legacy opt-out does
            // not apply.
            // Accounting-Request / CoA-Request / Disconnect-Request
            // are exempt: they authenticate via the Request
            // Authenticator over the packet body and have never been
            // required to carry M-A; forcing it would break the
            // installed base for no security gain.
            let strict_required = match header.code {
                Code::STATUS_SERVER => true,
                Code::ACCESS_REQUEST => client.require_message_authenticator(),
                _ => false,
            };
            if strict_required {
                return Validated::MissingMessageAuthenticator {
                    code: header.code,
                    identifier: header.identifier,
                };
            }
        }
        Verification::Invalid => {
            return Validated::BadMessageAuthenticator {
                code: header.code,
                identifier: header.identifier,
            };
        }
    }

    Validated::Ok { header, attrs }
}

/// Returns `true` if the packet's Authenticator field is acceptable
/// for its code. Access-Request authenticators are random and cannot
/// be checked on their own; for everything else we recompute
/// `MD5(packet-with-zeros || secret)` and compare.
pub(crate) fn verify_request_authenticator(code: Code, packet: &[u8], secret: &[u8]) -> bool {
    match code {
        // Accounting-Request (RFC 2866 §3), CoA-Request /
        // Disconnect-Request (RFC 5176): authenticator is
        // MD5(packet-with-zeros || secret) — verify in place.
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => {
            authenticator::verify_zeroed_request(packet, secret)
        }
        // Access-Request (RFC 2865 §3) carries a random authenticator;
        // its integrity is bound by the Message-Authenticator (when
        // present) and by the response auth on the reply.
        // Status-Server / Status-Client follow the same shape; defer
        // to the M-A check (which the pipeline runs unconditionally)
        // for integrity.
        _ => true,
    }
}

/// The 16-byte value substituted into the Authenticator field when
/// recomputing the Message-Authenticator over a request.
///
/// * Access-Request carries a random Request Authenticator; that
///   value IS what the NAS used when computing the M-A, so we
///   substitute the wire bytes back in.
/// * Accounting-Request / CoA-Request / Disconnect-Request derive
///   the Authenticator from the rest of the packet, so the NAS
///   computed M-A *before* the Authenticator existed — with the
///   field treated as 16 zero octets. The verifier must do the same.
pub(crate) fn ma_substitute(code: Code, header_auth: &[u8; 16]) -> [u8; 16] {
    match code {
        Code::ACCOUNTING_REQUEST | Code::COA_REQUEST | Code::DISCONNECT_REQUEST => [0u8; 16],
        _ => *header_auth,
    }
}

/// Listener context for the built-in Status-Server (RFC 5997)
/// responder. The transport supplies one of these to
/// [`dispatch_validated`] so the pipeline can short-circuit
/// Status-Server probes without dispatching to the consumer's
/// [`Handler`].
pub(crate) struct StatusServerContext<'a> {
    /// Role of the listener that received the probe — determines
    /// the reply code per RFC 5997 §6.
    pub role: ListenerRole,
    /// Transport the probe arrived on — surfaced to a custom
    /// [`StatusResponder`](super::status::StatusResponder).
    pub transport: StatusTransport,
    /// Server-wide Status-Server policy.
    pub policy: &'a StatusServerPolicy,
}

/// Action returned by [`dispatch_validated`]. The transport reads
/// off this enum to decide what (if anything) to put on the wire.
pub(crate) enum Dispatched {
    /// Dedup-cache hit — write these bytes back unchanged. Already
    /// in the cache; no re-insert needed.
    Replay {
        bytes: Arc<[u8]>,
        code: Code,
        identifier: u8,
    },
    /// Fresh handler reply. Already inserted into the dedup cache;
    /// the transport just needs to write the bytes.
    Reply {
        sealed: PacketBuffer,
        code: Code,
        identifier: u8,
    },
    /// Handler returned [`HandlerResult::Drop`]; produce no reply.
    HandlerDrop { code: Code, identifier: u8 },
    /// Built-in Status-Server reply produced by the listener's
    /// configured policy. Already inserted into the dedup cache.
    StatusServerReply {
        sealed: PacketBuffer,
        identifier: u8,
        role: ListenerRole,
    },
    /// Status-Server probe rejected because the resolved client
    /// has [`Client::status_server_enabled`] set to `false`.
    StatusServerDisabledPerClient { identifier: u8 },
    /// Status-Server probe dropped because the active
    /// [`StatusServerPolicy`] (or a custom
    /// [`StatusResponder`](super::status::StatusResponder))
    /// declined to produce a reply.
    StatusServerDisabled { identifier: u8 },
}

impl Dispatched {
    /// Borrow the bytes to send, if any.
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Replay { bytes, .. } => Some(bytes),
            Self::Reply { sealed, .. } | Self::StatusServerReply { sealed, .. } => {
                Some(sealed.as_bytes())
            }
            Self::HandlerDrop { .. }
            | Self::StatusServerDisabledPerClient { .. }
            | Self::StatusServerDisabled { .. } => None,
        }
    }
}

/// Look up the dedup cache; on a miss either (a) short-circuit
/// Status-Server probes through the built-in responder when
/// `status` is `Some`, or (b) invoke `handler`. In either case the
/// sealed reply is inserted into the cache before return.
///
/// Assumes the caller has already validated the packet via
/// [`validate`]; in particular `header` and `attrs` must refer to
/// the same packet bytes.
pub(crate) async fn dispatch_validated<H: Handler>(
    header: Header,
    attrs: &[u8],
    peer: SocketAddr,
    client: &Arc<Client>,
    handler: &H,
    cache: &DedupCache,
    status: Option<StatusServerContext<'_>>,
) -> Dispatched {
    let dedup_key = DedupKey {
        src: peer,
        code: header.code.0,
        identifier: header.identifier,
        request_authenticator: header.authenticator,
    };
    if let Some(cached) = cache.lookup(&dedup_key) {
        return Dispatched::Replay {
            bytes: cached,
            code: header.code,
            identifier: header.identifier,
        };
    }

    // Status-Server short-circuit (RFC 5997). Built-in responder
    // runs inline — no handler dispatch — so a keepalive flood can
    // never queue behind application logic. The reply is cached
    // for retransmit just like any other reply.
    if header.code == Code::STATUS_SERVER {
        if let Some(ctx) = status {
            if !client.status_server_enabled() {
                return Dispatched::StatusServerDisabledPerClient {
                    identifier: header.identifier,
                };
            }
            let Some(reply) = status::build_status_reply(
                ctx.policy,
                ctx.role,
                ctx.transport,
                header.identifier,
                client,
                peer,
            ) else {
                return Dispatched::StatusServerDisabled {
                    identifier: header.identifier,
                };
            };
            let sealed = reply.seal_for(&header.authenticator, client.secret());
            cache.insert(dedup_key, sealed.as_bytes());
            return Dispatched::StatusServerReply {
                sealed,
                identifier: header.identifier,
                role: ctx.role,
            };
        }
        // No status context (transport doesn't enable Status-Server
        // for this listener at all) — fall through to handler
        // dispatch so the consumer can decide.
    }

    let request = Request::new(
        header.code,
        header.identifier,
        header.authenticator,
        attrs,
        client,
        peer,
    );

    #[cfg(feature = "metrics")]
    let handler_t0 = std::time::Instant::now();
    let result = handler.handle(request).await;
    #[cfg(feature = "metrics")]
    observe!(
        crate::obs::metrics::HANDLER_DURATION_SECONDS,
        handler_t0.elapsed().as_secs_f64()
    );

    let reply = match result {
        HandlerResult::Reply(reply) => reply,
        HandlerResult::Drop => {
            return Dispatched::HandlerDrop {
                code: header.code,
                identifier: header.identifier,
            };
        }
    };

    let sealed = reply.seal_for(&header.authenticator, client.secret());
    cache.insert(dedup_key, sealed.as_bytes());
    Dispatched::Reply {
        sealed,
        code: header.code,
        identifier: header.identifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;

    #[test]
    fn ma_substitute_uses_zeros_for_accounting_family() {
        let auth = [0xAAu8; 16];
        assert_eq!(ma_substitute(Code::ACCOUNTING_REQUEST, &auth), [0u8; 16]);
        assert_eq!(ma_substitute(Code::COA_REQUEST, &auth), [0u8; 16]);
        assert_eq!(ma_substitute(Code::DISCONNECT_REQUEST, &auth), [0u8; 16]);
    }

    #[test]
    fn ma_substitute_uses_header_for_access_request() {
        let auth = [0xAAu8; 16];
        assert_eq!(ma_substitute(Code::ACCESS_REQUEST, &auth), auth);
        assert_eq!(ma_substitute(Code::STATUS_SERVER, &auth), auth);
    }

    #[test]
    fn verify_request_authenticator_is_noop_for_access_request() {
        // Access-Request has a random auth that can't be checked
        // in isolation; the helper must return `true` regardless of
        // the bytes.
        assert!(verify_request_authenticator(
            Code::ACCESS_REQUEST,
            &[0u8; 32],
            b"secret",
        ));
    }
}
