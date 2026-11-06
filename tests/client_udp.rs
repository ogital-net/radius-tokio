//! In-process integration tests for the multiplexed UDP client.

use std::sync::Arc;
use std::time::Duration;

use radius_tokio::client::{ClientConfig, ClientError, Request, UdpClient};
use radius_tokio::{AttributesView, Code, Reply};
use tokio::net::UdpSocket;

fn config() -> ClientConfig {
    ClientConfig {
        initial_timeout: Duration::from_millis(50),
        max_retries: 1,
        max_in_flight_per_target: 64,
        ..ClientConfig::default()
    }
}

#[tokio::test]
async fn concurrent_requests_accept_out_of_order_replies() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut requests = Vec::new();
        let mut packet = [0; 4096];
        for _ in 0..32 {
            let (length, source) = server.recv_from(&mut packet).await.unwrap();
            let auth = packet[4..20].try_into().unwrap();
            assert_eq!(
                radius_tokio::message_authenticator::verify(&packet[..length], &auth, b"secret"),
                radius_tokio::message_authenticator::Verification::Valid
            );
            requests.push((packet[1], auth, source));
        }
        for (identifier, auth, source) in requests.into_iter().rev() {
            let mut reply = Reply::new(Code::ACCESS_CHALLENGE, identifier);
            reply.add_state(&[identifier]).unwrap();
            server
                .send_to(reply.seal_for(&auth, b"secret").as_bytes(), source)
                .await
                .unwrap();
        }
    });
    let client = Arc::new(
        UdpClient::bind("127.0.0.1:0".parse().unwrap(), config())
            .await
            .unwrap(),
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let client = Arc::clone(&client);
        tasks.spawn(async move {
            let reply = client
                .send(target, b"secret", Request::access())
                .await
                .unwrap();
            assert_eq!(reply.code(), Code::ACCESS_CHALLENGE);
            assert_eq!(
                reply.attributes().state(),
                Some([reply.identifier()].as_slice())
            );
        });
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
        mock.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_reply_then_padded_reject_still_completes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut packet = [0; 4096];
        let (_, source) = server.recv_from(&mut packet).await.unwrap();
        let auth = packet[4..20].try_into().unwrap();
        let invalid = Reply::new(Code::ACCESS_ACCEPT, packet[1]).seal_for(&auth, b"wrong");
        server.send_to(invalid.as_bytes(), source).await.unwrap();
        let valid = Reply::new(Code::ACCESS_REJECT, packet[1]).seal_for(&auth, b"secret");
        let mut bytes = valid.as_bytes().to_vec();
        bytes.extend_from_slice(&[0xaa; 5]);
        server.send_to(&bytes, source).await.unwrap();
    });
    let client = UdpClient::bind("127.0.0.1:0".parse().unwrap(), config())
        .await
        .unwrap();
    let reply = client
        .send(target, b"secret", Request::access())
        .await
        .unwrap();
    assert_eq!(reply.code(), Code::ACCESS_REJECT);
    mock.await.unwrap();
}

#[tokio::test]
async fn timeout_retransmits_identical_bytes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut packet = [0; 4096];
        let (length, _) = server.recv_from(&mut packet).await.unwrap();
        let first = packet[..length].to_vec();
        let (length, _) = server.recv_from(&mut packet).await.unwrap();
        assert_eq!(first, packet[..length]);
    });
    let client = UdpClient::bind("127.0.0.1:0".parse().unwrap(), config())
        .await
        .unwrap();
    assert!(matches!(
        client.send(target, b"secret", Request::accounting()).await,
        Err(ClientError::Timeout)
    ));
    mock.await.unwrap();
}
