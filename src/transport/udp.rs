use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::codec::header::MAX_PACKET_LEN;
use crate::codec::request::Request;
use crate::codec::response::Response;
use crate::exchange::{ClientConfig, ClientError, Registry};
use crate::{CodecError, PacketBuffer};

/// Multiplexed RADIUS/UDP client owning one socket and reader task.
///
/// Share with `Arc`. Cancellation releases the pending identifier. UDP
/// retries resend identical bytes; invalid replies never complete a request.
pub struct UdpClient {
    socket: Arc<UdpSocket>,
    registry: Arc<Registry>,
    config: ClientConfig,
    reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for UdpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpClient")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl UdpClient {
    /// Bind a UDP socket and start its response reader.
    ///
    /// # Errors
    /// Returns socket binding errors.
    pub async fn bind(local: SocketAddr, config: ClientConfig) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let registry = Arc::new(Registry::default());
        let reader = tokio::spawn(read_replies(Arc::clone(&socket), Arc::clone(&registry)));
        Ok(Self {
            socket,
            registry,
            config,
            reader,
        })
    }

    /// Bound local endpoint.
    ///
    /// # Errors
    /// Forwards socket address lookup errors.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send a request and await a verified response.
    ///
    /// The shared secret is copied into scrubbed exchange-owned storage.
    /// Use a fresh request after Access-Challenge, echoing its State value.
    ///
    /// # Errors
    /// Returns encoding, concurrency, socket, deadline, or closure errors.
    pub async fn send(
        &self,
        target: SocketAddr,
        secret: &[u8],
        request: Request,
    ) -> Result<Response, ClientError> {
        self.send_with(target, secret, |identifier| {
            request.seal(identifier, secret)
        })
        .await
    }

    pub(crate) async fn send_with<F>(
        &self,
        target: SocketAddr,
        secret: &[u8],
        build: F,
    ) -> Result<Response, ClientError>
    where
        F: FnOnce(u8) -> Result<PacketBuffer, CodecError>,
    {
        let mut pending =
            self.registry
                .register(target, secret, self.config.max_in_flight_per_target, build)?;
        let mut wait = self.config.initial_timeout;
        for attempt in 0..=u16::from(self.config.max_retries) {
            self.socket
                .send_to(pending.packet.as_bytes(), target)
                .await?;
            match tokio::time::timeout(wait, &mut pending.receiver).await {
                Ok(Ok(response)) => return response,
                Ok(Err(_)) => return Err(ClientError::Closed),
                Err(_) if attempt < u16::from(self.config.max_retries) => {
                    wait = wait.saturating_mul(self.config.backoff_multiplier.max(1));
                }
                Err(_) => return Err(ClientError::Timeout),
            }
        }
        Err(ClientError::Timeout)
    }
}

impl Drop for UdpClient {
    fn drop(&mut self) {
        self.reader.abort();
        self.registry.close();
    }
}

async fn read_replies(socket: Arc<UdpSocket>, registry: Arc<Registry>) {
    let mut buffer = vec![0; MAX_PACKET_LEN + 1];
    loop {
        if let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            registry.deliver(peer, &buffer[..length]);
        } else {
            registry.close();
            return;
        }
    }
}
