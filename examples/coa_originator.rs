//! Example: a CoA / Disconnect originator.
//!
//! Run with:
//!
//! ```text
//! cargo run --example coa_originator
//! ```
//!
//! ## What this shows
//!
//! In `CoA` / `Disconnect` exchanges (RFC 5176) the AAA server is the
//! *client*: it builds a request, sends it to the NAS's `CoA`
//! listener (UDP/3799 by default), and waits for the NAS to reply
//! with `CoA-ACK` / `CoA-NAK` (or `Disconnect-ACK` / `Disconnect-NAK`).
//!
//! [`CoaOriginator`] owns one bound UDP socket and a small reader
//! task; it correlates inbound replies to outstanding requests by
//! `(peer, identifier)` and surfaces the result as a typed
//! [`CoaOutcome`].
//!
//! This example does **not** spin up a real NAS — running it against
//! `127.0.0.1:3799` will simply time out unless something is
//! listening. The point is to show the call shape; for an end-to-end
//! exchange against a mock NAS, see `tests/coa_originator.rs`.
//!
//! ## Authentication
//!
//! The originator does not need a `ClientStore`: every call takes
//! the per-target shared secret directly so consumers can route by
//! whatever identity model they have (NAS-IP-Address, source IP,
//! tenant, ...). The library handles the Authenticator field and
//! the Message-Authenticator attribute on every request and
//! verifies them on every reply.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use radius_tokio::server::{CoaConfig, CoaError, CoaOriginator, CoaOutcome};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind an ephemeral UDP socket. The reader task starts immediately.
    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        CoaConfig {
            initial_timeout: Duration::from_millis(500),
            max_retries: 2,
            backoff_multiplier: 2,
            max_in_flight_per_target: 8,
        },
    )
    .await?;

    println!("originator bound on {}", originator.local_addr()?);

    // The NAS this would be sent to. Replace with the real NAS
    // address for a live exchange.
    let nas: SocketAddr = "127.0.0.1:3799".parse()?;
    let secret: &[u8] = b"shared-secret-with-nas";

    // ─── CoA-Request ────────────────────────────────────────────────
    //
    // Build the attribute list inline. The closure receives a
    // `PacketBuffer` already preloaded with a header and the
    // Message-Authenticator placeholder; the originator seals the
    // packet (Authenticator + Message-Authenticator) on send.
    let coa_outcome = originator
        .send_coa(nas, secret, |buf| {
            // User-Name = "alice"
            buf.add_attribute(1, b"alice")?;
            // Acct-Session-Id = "sess-42"
            buf.add_attribute(44, b"sess-42")?;
            // Session-Timeout = 7200 seconds (re-authorize the session
            // for two more hours; a typical CoA use case).
            buf.add_attribute(27, &7200u32.to_be_bytes())?;
            Ok(())
        })
        .await;

    match coa_outcome {
        Ok(CoaOutcome::Ack { .. }) => println!("CoA accepted"),
        Ok(CoaOutcome::Nak { .. }) => println!("CoA rejected by NAS"),
        Err(CoaError::Timeout) => println!("CoA timed out (no NAS at {nas}?)"),
        Err(other) => println!("CoA failed: {other}"),
    }

    // ─── Disconnect-Request ─────────────────────────────────────────
    //
    // Same shape; the only differences are the request code (handled
    // by `send_disconnect`) and that consumers usually carry just
    // enough attributes for the NAS to identify the session
    // (User-Name + Acct-Session-Id, NAS-Port, ...).
    let disc_outcome = originator
        .send_disconnect(nas, secret, |buf| {
            buf.add_attribute(1, b"alice")?;
            buf.add_attribute(44, b"sess-42")?;
            Ok(())
        })
        .await;

    match disc_outcome {
        Ok(CoaOutcome::Ack { .. }) => println!("Disconnect accepted"),
        Ok(CoaOutcome::Nak { .. }) => println!("Disconnect rejected by NAS"),
        Err(CoaError::Timeout) => println!("Disconnect timed out"),
        Err(other) => println!("Disconnect failed: {other}"),
    }

    Ok(())
}
