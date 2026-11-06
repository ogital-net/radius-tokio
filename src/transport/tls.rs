use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};

use crate::codec::header::{MAX_PACKET_LEN, MIN_PACKET_LEN};
use crate::tls::{HandshakeState, PeerCertificate, TlsConnection, TlsError};

pub(crate) const TLS_READ_CHUNK: usize = 16 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) fn tls_to_io(error: TlsError) -> io::Error {
    io::Error::other(error)
}

pub(crate) struct AsyncTls {
    stream: TcpStream,
    pub(crate) tls: TlsConnection,
    input: Vec<u8>,
    flushed: usize,
    eof: bool,
}

impl AsyncTls {
    pub(crate) fn new(stream: TcpStream, tls: TlsConnection) -> Self {
        Self {
            stream,
            tls,
            input: vec![0; TLS_READ_CHUNK],
            flushed: 0,
            eof: false,
        }
    }

    pub(crate) fn peer_certificate(&self) -> Option<PeerCertificate> {
        self.tls.peer_certificate()
    }

    pub(crate) async fn handshake(&mut self) -> io::Result<()> {
        self.handshake_with_timeout(Duration::from_secs(30)).await
    }

    pub(crate) async fn handshake_with_timeout(&mut self, deadline: Duration) -> io::Result<()> {
        timeout(deadline, async {
            loop {
                let state = self.tls.process().map_err(tls_to_io)?;
                self.flush_tls_output().await?;
                if state == HandshakeState::Established {
                    return Ok(());
                }
                if self.receive().await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed during TLS handshake",
                    ));
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
    }

    async fn receive(&mut self) -> io::Result<usize> {
        let length = self.stream.read(&mut self.input).await?;
        if length == 0 {
            self.eof = true;
        } else {
            self.tls
                .feed_input(&self.input[..length])
                .map_err(tls_to_io)?;
        }
        Ok(length)
    }

    async fn read_some(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            self.flush_tls_output().await?;
            let length = self.tls.read(output).map_err(tls_to_io)?;
            if length > 0 {
                return Ok(length);
            }
            if self.eof || self.tls.received_close_notify() {
                return Ok(0);
            }
            self.flush_tls_output().await?;
            self.receive().await?;
        }
    }

    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.flush_tls_output().await?;
        let mut written = 0;
        while written < bytes.len() {
            let length = self.tls.write(&bytes[written..]).map_err(tls_to_io)?;
            self.flush_tls_output().await?;
            if length == 0 {
                if self.receive().await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed during TLS write",
                    ));
                }
            } else {
                written += length;
            }
        }
        Ok(())
    }

    async fn flush_tls_output(&mut self) -> io::Result<()> {
        loop {
            let pending = self.tls.pending_output();
            if self.flushed == pending.len() {
                break;
            }
            let length = self.stream.write(&pending[self.flushed..]).await?;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS socket write returned zero",
                ));
            }
            self.flushed += length;
        }
        self.tls.consume_output().map_err(tls_to_io)?;
        self.flushed = 0;
        Ok(())
    }

    pub(crate) async fn shutdown_clean(&mut self) -> io::Result<()> {
        let _ = self.tls.shutdown();
        let _ = timeout(Duration::from_secs(1), self.flush_tls_output()).await;
        Ok(())
    }
}

pub(crate) struct FrameReader {
    buffer: Vec<u8>,
    filled: usize,
    target: usize,
    deadline: Instant,
}

impl FrameReader {
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0; MAX_PACKET_LEN],
            filled: 0,
            target: 4,
            deadline: Instant::now() + IDLE_TIMEOUT,
        }
    }

    pub(crate) async fn read<'a>(
        &'a mut self,
        connection: &mut AsyncTls,
    ) -> io::Result<Option<&'a [u8]>> {
        loop {
            let length = timeout_at(
                self.deadline,
                connection.read_some(&mut self.buffer[self.filled..self.target]),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "RadSec read idle timeout"))??;
            if length == 0 {
                return if self.filled == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed mid-frame",
                    ))
                };
            }
            self.filled += length;
            self.deadline = Instant::now() + IDLE_TIMEOUT;
            if self.filled < self.target {
                continue;
            }
            if self.target == 4 {
                self.target = usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
                if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&self.target) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RADIUS stream frame length",
                    ));
                }
                continue;
            }
            let length = self.target;
            self.filled = 0;
            self.target = 4;
            return Ok(Some(&self.buffer[..length]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls::test_client::build_pki;
    use crate::{tls::TlsContext, Code, PacketBuffer};

    async fn pair() -> (AsyncTls, AsyncTls) {
        let pki = build_pki();
        let server_context =
            TlsContext::server(&pki.server_chain_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let client_context =
            TlsContext::client(&pki.client_chain_pem, &pki.client_key_pem, &pki.ca_pem).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection =
                AsyncTls::new(socket, TlsConnection::accept(&server_context).unwrap());
            connection.handshake().await.unwrap();
            connection
        };
        let client = async {
            let socket = TcpStream::connect(address).await.unwrap();
            let mut connection = AsyncTls::new(
                socket,
                TlsConnection::connect(&client_context, "radsec.test").unwrap(),
            );
            connection.handshake().await.unwrap();
            connection
        };
        tokio::join!(server, client)
    }

    #[tokio::test]
    async fn fragmented_and_coalesced_frames() {
        let (mut writer, mut reader) = pair().await;
        let packet = PacketBuffer::new(Code::ACCESS_REQUEST, 9);
        writer.write_all(&packet.as_bytes()[..2]).await.unwrap();
        writer.write_all(&packet.as_bytes()[2..11]).await.unwrap();
        let mut rest = packet.as_bytes()[11..].to_vec();
        rest.extend_from_slice(packet.as_bytes());
        writer.write_all(&rest).await.unwrap();
        let mut frames = FrameReader::new();
        for _ in 0..2 {
            assert_eq!(
                frames.read(&mut reader).await.unwrap().unwrap(),
                packet.as_bytes()
            );
        }
        writer.shutdown_clean().await.unwrap();
        assert!(timeout(Duration::from_secs(1), frames.read(&mut reader))
            .await
            .unwrap()
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cancelled_read_preserves_partial_frame() {
        let (mut writer, mut reader) = pair().await;
        let packet = PacketBuffer::new(Code::ACCESS_REQUEST, 9);
        writer.write_all(&packet.as_bytes()[..10]).await.unwrap();
        let mut frames = FrameReader::new();
        assert!(timeout(Duration::from_millis(50), frames.read(&mut reader))
            .await
            .is_err());
        assert_eq!(frames.filled, 10);
        writer.write_all(&packet.as_bytes()[10..]).await.unwrap();
        assert_eq!(
            frames.read(&mut reader).await.unwrap().unwrap(),
            packet.as_bytes()
        );
    }

    #[tokio::test]
    async fn close_mid_frame_is_an_error() {
        let (mut writer, mut reader) = pair().await;
        writer.write_all(&[1, 0, 0, 20, 0]).await.unwrap();
        writer.shutdown_clean().await.unwrap();
        let error = timeout(Duration::from_secs(1), FrameReader::new().read(&mut reader))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
