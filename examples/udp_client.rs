//! PAP authentication over UDP.
//!
//! Run with `--features client --example udp_client -- 127.0.0.1:1812 alice`.
//! Set `RADIUS_SECRET` and `RADIUS_PASSWORD` in the process environment.

use radius_tokio::client::{ClientConfig, Request, UdpClient};
use radius_tokio::{SecretBytes, ZeroizingBytes};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let target: std::net::SocketAddr = arguments.next().ok_or("missing server address")?.parse()?;
    let username = arguments.next().ok_or("missing user name")?;
    let secret = SecretBytes::new(std::env::var("RADIUS_SECRET")?.into_bytes());
    let password = ZeroizingBytes::new(std::env::var("RADIUS_PASSWORD")?.into_bytes());
    let local = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let client = UdpClient::bind(local.parse()?, ClientConfig::default()).await?;
    let mut request = Request::access();
    request.add_attribute(1, username.as_bytes())?;
    request.user_password(password.as_bytes())?;
    let response = client.send(target, secret.as_bytes(), request).await?;
    println!("{}", response.code());
    Ok(())
}
