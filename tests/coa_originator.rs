//! Mock-NAS integration tests for the `CoA` / Disconnect originator
//! (RFC 5176).
//!
//! Each test stands up a tiny "NAS" coroutine bound to an ephemeral
//! UDP port and drives a [`CoaOriginator`] against it. The mock NAS
//! validates the inbound request's Authenticator + M-A and replies
//! with whatever the test scenario requires (ACK, NAK, silence,
//! delayed reply, malformed M-A).

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use radius_tokio::dict::rfc::attrs;
use radius_tokio::server::{CoaConfig, CoaError, CoaOriginator, CoaOutcome};
use radius_tokio::{authenticator, message_authenticator, Code, Reply};

/// What the mock NAS should do with the next inbound request.
#[derive(Clone, Copy, Debug)]
enum Behaviour {
    /// Reply ACK.
    Ack,
    /// Reply NAK.
    Nak,
    /// Drop the first N requests, then ACK the next one. Used to
    /// exercise the originator's retry loop.
    DropThenAck { drop_count: usize },
    /// Never reply.
    Silent,
    /// ACK but with a deliberately corrupted Message-Authenticator.
    CorruptMa,
}

/// Spin up a mock NAS on `127.0.0.1:0` and run it until `shutdown`
/// fires. Returns the bound port and a join handle.
async fn spawn_mock_nas(
    secret: Vec<u8>,
    behaviour: Behaviour,
) -> (
    SocketAddr,
    Arc<Mutex<HashSet<u8>>>,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let identifiers_seen = Arc::new(Mutex::new(HashSet::new()));
    let ids_for_task = Arc::clone(&identifiers_seen);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let join = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut drops_remaining = match behaviour {
            Behaviour::DropThenAck { drop_count } => drop_count,
            _ => 0,
        };
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => return,
                res = sock.recv_from(&mut buf) => {
                    let Ok((len, src)) = res else { continue };
                    let datagram = &buf[..len];

                    // Validate the request: zeroed-request authenticator
                    // and Message-Authenticator (RFC 5176 §3.1). For
                    // CoA / Disconnect the M-A formula treats the
                    // Authenticator field as 16 zero octets — see the
                    // matching note in `src/server/udp.rs`.
                    if !authenticator::verify_zeroed_request(datagram, &secret) {
                        continue;
                    }
                    if message_authenticator::verify(datagram, &[0u8; 16], &secret)
                        != message_authenticator::Verification::Valid
                    {
                        continue;
                    }

                    let identifier = datagram[1];
                    let request_authenticator: [u8; 16] =
                        datagram[4..20].try_into().unwrap();
                    let request_code = Code(datagram[0]);

                    // Track every distinct identifier we observe, so
                    // tests can assert on retransmit / per-target reuse.
                    ids_for_task.lock().await.insert(identifier);

                    // Handle drop-then-ack behaviour.
                    let respond = match behaviour {
                        Behaviour::Silent => false,
                        Behaviour::DropThenAck { .. }
                            if drops_remaining > 0 => {
                                drops_remaining -= 1;
                                false
                            }
                        _ => true,
                    };
                    if !respond {
                        continue;
                    }

                    let reply_code = match (behaviour, request_code) {
                        (Behaviour::Nak, Code::COA_REQUEST) => Code::COA_NAK,
                        (Behaviour::Nak, Code::DISCONNECT_REQUEST) => Code::DISCONNECT_NAK,
                        (_, Code::COA_REQUEST) => Code::COA_ACK,
                        (_, Code::DISCONNECT_REQUEST) => Code::DISCONNECT_ACK,
                        _ => continue,
                    };

                    // Use the public reply builder to seal a
                    // properly-signed response. `Reply::seal_for`
                    // patches the length, computes the M-A, and the
                    // Response Authenticator in one shot.
                    let reply = Reply::new(reply_code, identifier);
                    let sealed = reply.seal_for(&request_authenticator, &secret);
                    let mut bytes = sealed.as_bytes().to_vec();
                    if matches!(behaviour, Behaviour::CorruptMa) {
                        // The Reply builder reserves the M-A as the
                        // first attribute, so its 16-byte value lives
                        // at offset 22 (20-byte header + 2-byte TLV
                        // header).
                        bytes[22] ^= 0xff;
                    }

                    let _ = sock.send_to(&bytes, src).await;
                }
            }
        }
    });

    (addr, identifiers_seen, join, shutdown_tx)
}

/// Helper: short-timeout originator config so tests don't sit on a
/// real 1-second wait when exercising failure paths.
fn quick_config() -> CoaConfig {
    CoaConfig {
        initial_timeout: Duration::from_millis(80),
        max_retries: 2,
        backoff_multiplier: 2,
        max_in_flight_per_target: 4,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn coa_request_round_trip_ack() {
    let secret = b"shared".to_vec();
    let (nas_addr, ids, _join, _shutdown) = spawn_mock_nas(secret.clone(), Behaviour::Ack).await;

    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        quick_config(),
    )
    .await
    .unwrap();

    let outcome = originator
        .send_coa(nas_addr, &secret, |buf| {
            buf.add(attrs::USER_NAME, "alice")?;
            Ok(())
        })
        .await
        .expect("ack");

    assert!(matches!(outcome, CoaOutcome::Ack { .. }));
    assert_eq!(ids.lock().await.len(), 1, "single send → one identifier");
}

#[tokio::test(flavor = "current_thread")]
async fn disconnect_request_round_trip_nak() {
    let secret = b"shared".to_vec();
    let (nas_addr, _ids, _join, _shutdown) = spawn_mock_nas(secret.clone(), Behaviour::Nak).await;

    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        quick_config(),
    )
    .await
    .unwrap();

    let outcome = originator
        .send_disconnect(nas_addr, &secret, |buf| {
            buf.add(attrs::ACCT_SESSION_ID, "sess-1")?;
            Ok(())
        })
        .await
        .expect("nak");

    match outcome {
        CoaOutcome::Nak { attributes } => {
            // RFC 5176 NAK replies typically carry no attributes
            // unless the NAS adds an Error-Cause; the mock NAS adds
            // none, so we just assert the slot exists.
            let _ = attributes;
        }
        other @ CoaOutcome::Ack { .. } => panic!("expected NAK, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn retransmits_on_packet_loss_then_succeeds() {
    let secret = b"shared".to_vec();
    let (nas_addr, ids, _join, _shutdown) =
        spawn_mock_nas(secret.clone(), Behaviour::DropThenAck { drop_count: 2 }).await;

    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        quick_config(),
    )
    .await
    .unwrap();

    let outcome = originator
        .send_coa(nas_addr, &secret, |buf| {
            buf.add_attribute(1, b"alice")?;
            Ok(())
        })
        .await
        .expect("ack after retries");

    assert!(matches!(outcome, CoaOutcome::Ack { .. }));
    // Same identifier on every retransmit (RFC 5080 §2.2.1) — so
    // even after three transmissions the NAS sees exactly one ID.
    assert_eq!(
        ids.lock().await.len(),
        1,
        "retransmits must reuse the original Identifier",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn timeout_when_nas_is_silent() {
    let secret = b"shared".to_vec();
    let (nas_addr, _ids, _join, _shutdown) =
        spawn_mock_nas(secret.clone(), Behaviour::Silent).await;

    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        quick_config(),
    )
    .await
    .unwrap();

    let err = originator
        .send_coa(nas_addr, &secret, |buf| {
            buf.add_attribute(1, b"alice")?;
            Ok(())
        })
        .await
        .expect_err("should time out");

    assert!(matches!(err, CoaError::Timeout), "got {err:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_reply_message_authenticator_is_rejected() {
    let secret = b"shared".to_vec();
    let (nas_addr, _ids, _join, _shutdown) =
        spawn_mock_nas(secret.clone(), Behaviour::CorruptMa).await;

    let originator = CoaOriginator::bind(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        quick_config(),
    )
    .await
    .unwrap();

    let err = originator
        .send_coa(nas_addr, &secret, |buf| {
            buf.add_attribute(1, b"alice")?;
            Ok(())
        })
        .await
        .expect_err("M-A mismatch must surface");

    // Corrupting the M-A bytes also breaks the Response Authenticator
    // (which hashes over them), so the originator may surface either
    // error first; both represent a correct silent-drop decision.
    assert!(
        matches!(
            err,
            CoaError::MessageAuthenticatorInvalid | CoaError::AuthenticatorMismatch,
        ),
        "got {err:?}",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn per_target_in_flight_limit_enforced() {
    // A NAS that never replies, with a tiny in-flight cap so the
    // second concurrent send hits the limiter immediately.
    let secret = b"shared".to_vec();
    let (nas_addr, _ids, _join, _shutdown) =
        spawn_mock_nas(secret.clone(), Behaviour::Silent).await;

    let mut config = quick_config();
    config.max_in_flight_per_target = 1;
    config.initial_timeout = Duration::from_millis(500);
    config.max_retries = 0;

    let originator = Arc::new(
        CoaOriginator::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), config)
            .await
            .unwrap(),
    );

    let blocking = {
        let originator = Arc::clone(&originator);
        let secret = secret.clone();
        tokio::spawn(async move {
            originator
                .send_coa(nas_addr, &secret, |buf| {
                    buf.add_attribute(1, b"alice")?;
                    Ok(())
                })
                .await
        })
    };

    // Give the first request time to acquire the permit.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let err = originator
        .send_coa(nas_addr, &secret, |buf| {
            buf.add_attribute(1, b"bob")?;
            Ok(())
        })
        .await
        .expect_err("limiter must reject");

    assert!(matches!(err, CoaError::InFlightLimit), "got {err:?}");

    // Drain the still-running first send (it will time out).
    let _ = blocking.await;
}
