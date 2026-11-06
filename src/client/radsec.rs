use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, timeout_at, Instant};

use crate::codec::attributes;
use crate::codec::header::Header;
use crate::exchange::{Lease, Registry};
use crate::tls::{PeerCertificate, TlsConnection, TlsContext};
use crate::transport::tls::{tls_to_io, AsyncTls, FrameReader};
use crate::{authenticator, message_authenticator, Code, Reply};

use super::{ClientConfig, ClientError, Request, Response};

const SECRET: &[u8] = b"radsec";

enum Command {
    Send {
        packet: Vec<u8>,
        lease: Arc<Lease>,
        deadline: Instant,
    },
    Close(oneshot::Sender<()>),
}

/// A persistent, mutually authenticated RADIUS/TLS client (RFC 6614).
///
/// Share with `Arc` for concurrent exchanges. The connection driver handles
/// out-of-order replies and sends NAK/Unsupported-Extension for incoming CoA
/// and Disconnect requests. The legacy packet secret is always `radsec`.
///
/// Requests are never retransmitted or automatically replayed on reconnect.
/// A timeout or disconnect does not imply the server did not process them.
pub struct RadsecClient {
    peer: SocketAddr,
    certificate: PeerCertificate,
    config: ClientConfig,
    registry: Arc<Registry>,
    commands: mpsc::Sender<Command>,
    driver: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for RadsecClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RadsecClient")
            .field("peer", &self.peer)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RadsecClient {
    /// Connect and verify the configured server identity before returning.
    ///
    /// `context` must come from `TlsContext::client`. `expected_name` is the
    /// server's DNS name or IP SAN, independently of its resolved endpoint.
    /// TCP establishment and TLS negotiation share `connect_timeout`.
    ///
    /// # Errors
    /// Returns connection, timeout, certificate, or TLS configuration errors.
    pub async fn connect(
        peer: SocketAddr,
        context: &TlsContext,
        expected_name: &str,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let mut connection = timeout(config.connect_timeout, async {
            let tls = TlsConnection::connect(context, expected_name).map_err(tls_to_io)?;
            let socket = TcpStream::connect(peer).await?;
            socket.set_nodelay(true)?;
            let mut connection = AsyncTls::new(socket, tls);
            connection
                .handshake_with_timeout(config.connect_timeout)
                .await?;
            Ok::<_, io::Error>(connection)
        })
        .await
        .map_err(|_| ClientError::Timeout)??;
        let certificate = connection
            .peer_certificate()
            .ok_or_else(|| io::Error::other("server certificate missing"))?;
        let registry = Arc::new(Registry::default());
        let (commands, receiver) = mpsc::channel(config.max_in_flight_per_target.clamp(1, 256));
        let driver_registry = Arc::clone(&registry);
        let driver = tokio::spawn(async move {
            let _guard = CloseRegistry(Arc::clone(&driver_registry));
            let _ = run_connection(&mut connection, peer, &driver_registry, receiver, config).await;
            driver_registry.close();
            let _ = connection.shutdown_clean().await;
        });
        Ok(Self {
            peer,
            certificate,
            config,
            registry,
            commands,
            driver,
        })
    }

    /// Remote TCP endpoint.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Authenticated server certificate for additional application policy.
    #[must_use]
    pub fn peer_certificate(&self) -> &PeerCertificate {
        &self.certificate
    }

    /// Send a request and await its verified response without retransmission.
    ///
    /// Cancellation releases the caller's slot; queued writes retain their
    /// identifier until discarded or sent. Already-started writes may finish.
    /// The deadline includes queueing and sending, not just response waiting.
    ///
    /// # Errors
    /// Returns encoding, concurrency, timeout, or closed-connection errors.
    pub async fn send(&self, request: Request) -> Result<Response, ClientError> {
        let deadline = Instant::now() + self.config.initial_timeout;
        let mut pending = self.registry.register(
            self.peer,
            SECRET,
            self.config.max_in_flight_per_target,
            |identifier| request.seal(identifier, SECRET),
        )?;
        let command = Command::Send {
            packet: pending.packet.as_bytes().to_vec(),
            lease: Arc::clone(&pending.lease),
            deadline,
        };
        timeout_at(deadline, async {
            self.commands
                .send(command)
                .await
                .map_err(|_| ClientError::Closed)?;
            (&mut pending.receiver)
                .await
                .map_err(|_| ClientError::Closed)?
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// Close this shared connection and send best-effort TLS close-notify.
    ///
    /// Pending and future requests fail with `ClientError::Closed`.
    /// Dropping without calling this method aborts the driver immediately.
    ///
    /// # Errors
    /// Returns a timeout if the connection task cannot finish in time.
    pub async fn close(&self) -> Result<(), ClientError> {
        self.registry.close();
        if self.driver.is_finished() {
            return Ok(());
        }
        let (finished, receiver) = oneshot::channel();
        timeout(self.config.connect_timeout, async {
            if self.commands.send(Command::Close(finished)).await.is_ok() {
                let _ = receiver.await;
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?;
        Ok(())
    }
}

impl Drop for RadsecClient {
    fn drop(&mut self) {
        self.driver.abort();
        self.registry.close();
    }
}

struct CloseRegistry(Arc<Registry>);

impl Drop for CloseRegistry {
    fn drop(&mut self) {
        self.0.close();
    }
}

async fn run_connection(
    connection: &mut AsyncTls,
    peer: SocketAddr,
    registry: &Registry,
    mut commands: mpsc::Receiver<Command>,
    config: ClientConfig,
) -> io::Result<()> {
    let mut frames = FrameReader::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Send { packet, lease, deadline }) => {
                    if lease.is_active() && Instant::now() < deadline {
                        timeout_at(deadline, connection.write_all(&packet)).await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RadSec write deadline elapsed"))??;
                    }
                }
                Some(Command::Close(finished)) => {
                    connection.shutdown_clean().await?;
                    let _ = finished.send(());
                    return Ok(());
                }
                None => return Ok(()),
            },
            frame = frames.read(connection) => {
                let Some(frame) = frame? else { return Ok(()); };
                if let Some(reply) = unsupported_dynamic_request(frame)? {
                    timeout(config.initial_timeout, connection.write_all(reply.as_bytes())).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RadSec NAK write timed out"))??;
                } else { registry.deliver(peer, frame); }
            }
        }
    }
}

fn unsupported_dynamic_request(packet: &[u8]) -> io::Result<Option<crate::PacketBuffer>> {
    let (header, attrs) =
        Header::parse(packet).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let code = match header.code {
        Code::COA_REQUEST => Code::COA_NAK,
        Code::DISCONNECT_REQUEST => Code::DISCONNECT_NAK,
        _ => return Ok(None),
    };
    if attributes::iter(attrs).any(|attribute| attribute.is_err())
        || !authenticator::verify_zeroed_request(packet, SECRET)
        || message_authenticator::verify(packet, &[0; 16], SECRET)
            == message_authenticator::Verification::Invalid
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid RadSec dynamic-authorization request",
        ));
    }
    let mut reply = Reply::new(code, header.identifier);
    reply
        .add_attribute(101, &406u32.to_be_bytes())
        .map_err(io::Error::other)?;
    Ok(Some(reply.seal_for(&header.authenticator, SECRET)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls::test_client::build_pki;
    use crate::AttributesView;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn contexts() -> (TlsContext, TlsContext) {
        let pki = build_pki();
        (
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap(),
            TlsContext::client(&pki.client_chain_pem, &pki.client_key_pem, &pki.ca_pem).unwrap(),
        )
    }

    fn config() -> ClientConfig {
        ClientConfig {
            initial_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            ..ClientConfig::default()
        }
    }

    async fn accept(listener: TcpListener, context: TlsContext) -> AsyncTls {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = AsyncTls::new(socket, TlsConnection::accept(&context).unwrap());
        connection
            .handshake_with_timeout(Duration::from_secs(2))
            .await
            .unwrap();
        connection
    }

    #[tokio::test]
    async fn concurrent_radsec_exchanges_complete_out_of_order() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = accept(listener, server_context).await;
            let mut frames = FrameReader::new();
            let mut replies = Vec::new();
            for _ in 0..8 {
                let packet = frames.read(&mut connection).await.unwrap().unwrap();
                let (header, _) = Header::parse(packet).unwrap();
                assert_eq!(
                    message_authenticator::verify(packet, &header.authenticator, SECRET),
                    message_authenticator::Verification::Valid
                );
                let mut reply = Reply::new(Code::ACCESS_CHALLENGE, header.identifier);
                reply.add_state(&[header.identifier]).unwrap();
                replies.push(reply.seal_for(&header.authenticator, SECRET));
            }
            let mut coalesced = Vec::new();
            for reply in replies.into_iter().rev() {
                coalesced.extend_from_slice(reply.as_bytes());
            }
            connection.write_all(&coalesced[..7]).await.unwrap();
            connection.write_all(&coalesced[7..]).await.unwrap();
            connection.shutdown_clean().await.unwrap();
        });
        let client = Arc::new(
            RadsecClient::connect(peer, &client_context, "radsec.test", config())
                .await
                .unwrap(),
        );
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let client = Arc::clone(&client);
            requests.spawn(async move {
                let reply = client.send(Request::access()).await.unwrap();
                assert_eq!(reply.code(), Code::ACCESS_CHALLENGE);
                assert_eq!(
                    reply.attributes().state(),
                    Some([reply.identifier()].as_slice())
                );
            });
        }
        while let Some(request) = requests.join_next().await {
            request.unwrap();
        }
        server.await.unwrap();
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn incoming_coa_gets_nak_without_stealing_response_identifiers() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = accept(listener, server_context).await;
            let coa = crate::PacketBuffer::new(Code::COA_REQUEST, 0).seal_as_zeroed_request(SECRET);
            connection.write_all(coa.as_bytes()).await.unwrap();
            let mut frames = FrameReader::new();
            let mut saw_nak = false;
            let mut saw_request = false;
            while !saw_nak || !saw_request {
                let frame = frames.read(&mut connection).await.unwrap().unwrap();
                let (header, attrs) = Header::parse(frame).unwrap();
                if header.code == Code::COA_NAK {
                    assert!(authenticator::verify_response(
                        frame,
                        &coa.header().authenticator,
                        SECRET
                    ));
                    assert!(attributes::iter(attrs)
                        .map(Result::unwrap)
                        .any(|attribute| attribute.attribute_type() == 101
                            && attribute.value() == 406u32.to_be_bytes()));
                    saw_nak = true;
                } else {
                    assert_eq!(header.code, Code::ACCESS_REQUEST);
                    let reply = Reply::new(Code::ACCESS_ACCEPT, header.identifier)
                        .seal_for(&header.authenticator, SECRET);
                    connection.write_all(reply.as_bytes()).await.unwrap();
                    saw_request = true;
                }
            }
        });
        let client = RadsecClient::connect(peer, &client_context, "radsec.test", config())
            .await
            .unwrap();
        assert_eq!(
            client.send(Request::access()).await.unwrap().code(),
            Code::ACCESS_ACCEPT
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn timeout_does_not_retransmit_or_close_connection() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = accept(listener, server_context).await;
            let mut frames = FrameReader::new();
            let first = Header::parse(frames.read(&mut connection).await.unwrap().unwrap())
                .unwrap()
                .0;
            let second = Header::parse(frames.read(&mut connection).await.unwrap().unwrap())
                .unwrap()
                .0;
            assert_ne!(
                first.identifier, second.identifier,
                "RadSec must not retransmit timed-out requests"
            );
            for header in [first, second] {
                let reply = Reply::new(Code::ACCESS_ACCEPT, header.identifier)
                    .seal_for(&header.authenticator, SECRET);
                connection.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let config = ClientConfig {
            initial_timeout: Duration::from_millis(100),
            max_retries: 255,
            max_in_flight_per_target: 1,
            ..config()
        };
        let client = RadsecClient::connect(peer, &client_context, "radsec.test", config)
            .await
            .unwrap();
        assert!(matches!(
            client.send(Request::access()).await,
            Err(ClientError::Timeout)
        ));
        assert_eq!(
            client.send(Request::access()).await.unwrap().code(),
            Code::ACCESS_ACCEPT
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_requests_release_radsec_identifiers() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let config = ClientConfig {
            max_in_flight_per_target: 1,
            ..config()
        };
        let (client, mut server) = tokio::join!(
            RadsecClient::connect(peer, &client_context, "radsec.test", config),
            accept(listener, server_context)
        );
        let client = client.unwrap();
        let mut frames = FrameReader::new();
        for _ in 0..=256u16 {
            let request = client.send(Request::access());
            tokio::pin!(request);
            timeout(Duration::from_secs(2), async {
                tokio::select! {
                    result = &mut request => panic!("request ended before cancellation: {result:?}"),
                    frame = frames.read(&mut server) => { frame.unwrap().unwrap(); }
                }
            }).await.unwrap();
        }
    }

    #[tokio::test]
    async fn wrong_server_name_is_rejected() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(accept(listener, server_context));
        assert!(
            RadsecClient::connect(peer, &client_context, "wrong.test", config())
                .await
                .is_err()
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn closed_connection_fails_pending_and_future_requests() {
        let (server_context, client_context) = contexts();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut connection = accept(listener, server_context).await;
            FrameReader::new()
                .read(&mut connection)
                .await
                .unwrap()
                .unwrap();
            connection.shutdown_clean().await.unwrap();
        });
        let client = RadsecClient::connect(peer, &client_context, "radsec.test", config())
            .await
            .unwrap();
        assert!(matches!(
            client.send(Request::access()).await,
            Err(ClientError::Closed)
        ));
        assert!(matches!(
            client.send(Request::access()).await,
            Err(ClientError::Closed)
        ));
        server.await.unwrap();
    }
}
