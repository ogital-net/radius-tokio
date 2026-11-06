use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::codec::header::{Code, Header};
use crate::codec::response::Response;
use crate::{CodecError, PacketBuffer, SecretBytes};

/// Limits and deadlines for outgoing RADIUS exchanges.
#[derive(Debug, Clone, Copy)]
pub struct ClientConfig {
    /// First UDP response timeout, or the total RadSec response deadline.
    pub initial_timeout: Duration,
    /// UDP retransmissions after the initial send. Not used for RadSec.
    pub max_retries: u8,
    /// UDP timeout multiplier, clamped to at least one.
    pub backoff_multiplier: u32,
    /// Concurrent requests per UDP target or RadSec connection (at most 256).
    pub max_in_flight_per_target: usize,
    /// TCP connection and TLS handshake deadline.
    pub connect_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            initial_timeout: Duration::from_secs(1),
            max_retries: 2,
            backoff_multiplier: 2,
            max_in_flight_per_target: 16,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Failure to send or complete an outgoing exchange.
///
/// Invalid UDP replies are discarded until the deadline. Access-Reject and
/// CoA-NAK are verified responses, not errors.
#[derive(Debug)]
pub enum ClientError {
    /// Network or TLS failure. A request may have reached the peer.
    Io(io::Error),
    /// Request construction failed before transmission.
    Codec(CodecError),
    /// No valid response arrived before the deadline.
    Timeout,
    /// Configured per-peer concurrency limit reached.
    InFlightLimit,
    /// All 256 identifiers are occupied.
    IdentifierExhausted,
    /// The transport is closed.
    Closed,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "i/o: {error}"),
            Self::Codec(error) => write!(formatter, "codec: {error}"),
            Self::Timeout => formatter.write_str("no valid response within the request deadline"),
            Self::InFlightLimit => formatter.write_str("per-peer in-flight limit reached"),
            Self::IdentifierExhausted => {
                formatter.write_str("all RADIUS identifiers are in flight")
            }
            Self::Closed => formatter.write_str("transport closed"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CodecError> for ClientError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

struct Pending {
    sender: Option<oneshot::Sender<Result<Response, ClientError>>>,
    code: Code,
    authenticator: [u8; 16],
    secret: SecretBytes,
}

#[derive(Default)]
struct Peer {
    next_identifier: u8,
    pending: HashMap<u8, Pending>,
}

#[derive(Default)]
struct State {
    peers: HashMap<SocketAddr, Peer>,
    closed: bool,
}

#[derive(Default)]
pub(crate) struct Registry(Mutex<State>);

pub(crate) struct Registration {
    registry: Arc<Registry>,
    peer: SocketAddr,
    identifier: u8,
    pub(crate) receiver: oneshot::Receiver<Result<Response, ClientError>>,
    pub(crate) packet: PacketBuffer,
}

impl Registry {
    pub(crate) fn register<F>(
        self: &Arc<Self>,
        peer: SocketAddr,
        secret: &[u8],
        limit: usize,
        build: F,
    ) -> Result<Registration, ClientError>
    where
        F: FnOnce(u8) -> Result<PacketBuffer, CodecError>,
    {
        let mut state = self.0.lock().expect("exchange registry poisoned");
        if state.closed {
            return Err(ClientError::Closed);
        }
        let target = state.peers.entry(peer).or_default();
        if target.pending.len() >= limit {
            return Err(ClientError::InFlightLimit);
        }
        let identifier = (0..=u8::MAX)
            .map(|offset| target.next_identifier.wrapping_add(offset))
            .find(|identifier| !target.pending.contains_key(identifier))
            .ok_or(ClientError::IdentifierExhausted)?;
        let packet = build(identifier)?;
        let header = packet.header();
        target.next_identifier = identifier.wrapping_add(1);
        let (sender, receiver) = oneshot::channel();
        target.pending.insert(
            identifier,
            Pending {
                sender: Some(sender),
                code: header.code,
                authenticator: header.authenticator,
                secret: secret.into(),
            },
        );
        Ok(Registration {
            registry: Arc::clone(self),
            peer,
            identifier,
            receiver,
            packet,
        })
    }

    pub(crate) fn deliver(&self, peer: SocketAddr, packet: &[u8]) -> bool {
        let Ok((header, _)) = Header::parse(packet) else {
            return false;
        };
        let mut state = self.0.lock().expect("exchange registry poisoned");
        let Some(pending) = state
            .peers
            .get_mut(&peer)
            .and_then(|target| target.pending.get_mut(&header.identifier))
        else {
            return false;
        };
        if pending.sender.is_none() {
            return false;
        }
        let Some(response) = Response::verify(
            packet,
            pending.code,
            header.identifier,
            &pending.authenticator,
            pending.secret.as_bytes(),
        ) else {
            return false;
        };
        if let Some(sender) = pending.sender.take() {
            let _ = sender.send(Ok(response));
        }
        true
    }

    pub(crate) fn close(&self) {
        let mut state = self.0.lock().expect("exchange registry poisoned");
        state.closed = true;
        for target in state.peers.values_mut() {
            for pending in target.pending.values_mut() {
                if let Some(sender) = pending.sender.take() {
                    let _ = sender.send(Err(ClientError::Closed));
                }
            }
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self.registry.0.lock().expect("exchange registry poisoned");
        if let Some(peer) = state.peers.get_mut(&self.peer) {
            peer.pending.remove(&self.identifier);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::request::Request;

    #[test]
    fn identifier_exhaustion_cancellation_and_close() {
        let registry = Arc::new(Registry::default());
        let peer = "127.0.0.1:1812".parse().unwrap();
        let mut pending = Vec::new();
        for _ in 0..256 {
            pending.push(
                registry
                    .register(peer, b"secret", 300, |identifier| {
                        Request::access().seal(identifier, b"secret")
                    })
                    .unwrap(),
            );
        }
        assert!(matches!(
            registry.register(peer, b"secret", 300, |identifier| Request::access()
                .seal(identifier, b"secret")),
            Err(ClientError::IdentifierExhausted)
        ));
        pending.pop();
        assert!(registry
            .register(peer, b"secret", 300, |identifier| Request::access()
                .seal(identifier, b"secret"))
            .is_ok());
        registry.close();
        assert!(matches!(
            pending[0].receiver.try_recv(),
            Ok(Err(ClientError::Closed))
        ));
        assert!(matches!(
            registry.register(peer, b"secret", 300, |identifier| Request::access()
                .seal(identifier, b"secret")),
            Err(ClientError::Closed)
        ));
    }
}
