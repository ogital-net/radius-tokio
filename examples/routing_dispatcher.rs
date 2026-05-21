//! Example: a single root [`Handler`] that dispatches by inspecting
//! which authentication attribute the NAS sent — EAP, PAP, CHAP, or
//! none of the above.
//!
//! Run with:
//!
//! ```text
//! cargo run --example routing_dispatcher
//! ```
//!
//! ## Pattern
//!
//! `radius-tokio` deliberately does not ship a "presence bitmap"
//! helper. When a root handler needs to dispatch on the combined
//! presence of several attributes, the opinionated idiom is:
//!
//! 1. Walk [`Request::attributes_iter`] *once*.
//! 2. Fold the predicates you care about into local booleans using
//!    [`RawAttribute::matches`] / [`matches_vsa`] / [`matches_tlv`].
//! 3. Match on the resulting tuple and hand off to a sub-handler.
//!
//! This is one walk, zero allocation, and the only API surface you
//! need is already on `Request`. For a single-attribute presence
//! check use [`Request::contains`] instead — it short-circuits on
//! the first match.
//!
//! [`Handler`]: radius_tokio::server::Handler
//! [`Request::attributes_iter`]: radius_tokio::server::Request::attributes_iter
//! [`Request::contains`]: radius_tokio::server::Request::contains
//! [`RawAttribute::matches`]: radius_tokio::codec::attributes::RawAttribute::matches
//! [`matches_vsa`]: radius_tokio::codec::attributes::RawAttribute::matches_vsa
//! [`matches_tlv`]: radius_tokio::codec::attributes::RawAttribute::matches_tlv

use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::dict::generated::rfc::attrs;
use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server, StaticClients,
};
use radius_tokio::Code;

/// Which credential the NAS supplied, decided in one walk over the
/// request's attribute region.
#[derive(Debug, Clone, Copy)]
enum AuthType {
    Eap,
    Pap,
    Chap,
    /// Access-Request with no recognised credential — most NASes
    /// never send this, but it's a reply-Reject path worth keeping
    /// explicit rather than letting it fall through silently.
    Unknown,
}

/// Classify the request in one pass. Stops at the first malformed
/// attribute (the iterator yields `Err`), matching the rest of the
/// library's "halt on corruption" behaviour.
fn classify(req: &Request<'_>) -> AuthType {
    let (mut eap, mut pap, mut chap) = (false, false, false);
    for slot in req.attributes_iter() {
        let Ok(raw) = slot else { break };
        eap |= raw.matches(attrs::EAP_MESSAGE);
        pap |= raw.matches(attrs::USER_PASSWORD);
        chap |= raw.matches(attrs::CHAP_PASSWORD);
    }
    // EAP wins if present — an EAP-capable supplicant may also send
    // a dummy User-Password ("\0") per RFC 3579 §3.3, and routing on
    // PAP first would mis-dispatch those.
    match (eap, pap, chap) {
        (true, _, _) => AuthType::Eap,
        (_, true, _) => AuthType::Pap,
        (_, _, true) => AuthType::Chap,
        _ => AuthType::Unknown,
    }
}

struct Dispatcher;

impl Handler for Dispatcher {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        if request.code() != Code::ACCESS_REQUEST {
            // Accounting / Status-Server / CoA are handled elsewhere
            // in a real deployment; here we silently drop them so
            // the example stays focused on the dispatch pattern.
            return HandlerResult::Drop;
        }

        // In a real server each branch would call into its own
        // sub-handler (EAP state machine, PAP credential check,
        // CHAP MD5 verify, …). We illustrate the structure with
        // a flat reply so the example stays runnable end-to-end.
        let flavour = classify(&request);
        let reply_code = match flavour {
            AuthType::Eap | AuthType::Pap | AuthType::Chap => Code::ACCESS_ACCEPT,
            AuthType::Unknown => Code::ACCESS_REJECT,
        };

        println!(
            "dispatch: id={} src={} flavour={:?} -> {:?}",
            request.identifier(),
            request.src(),
            flavour,
            reply_code,
        );

        let mut reply = request.reply(reply_code);
        if matches!(reply_code, Code::ACCESS_ACCEPT) {
            // Trivial reply attribute so the example does something
            // observable on the wire.
            reply.add(attrs::SESSION_TIMEOUT, 3600u32).unwrap();
        }
        HandlerResult::Reply(reply)
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let client = Arc::new(Client::new(b"shared-secret".as_slice()));
    let store = StaticClients::builder()
        .add(IpCidr::host(Ipv4Addr::LOCALHOST.into()), client)
        .build();

    let server = Server::builder()
        .clients(store)
        .handler(Dispatcher)
        .listen_udp("127.0.0.1:1812".parse().unwrap())
        .listen_udp_with("127.0.0.1:1813".parse().unwrap(), ListenerRole::Acct)
        .build()?;

    println!("radius-tokio dispatcher listening on 127.0.0.1:1812 (auth)");
    println!("send an Access-Request and watch the classification line.");
    server.run().await
}
