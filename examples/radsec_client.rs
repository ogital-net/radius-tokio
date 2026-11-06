//! PAP authentication over mutually authenticated `RadSec`.
//!
//! Run with `--features client,radsec --example radsec_client --
//! 127.0.0.1:2083 radius.example.com alice`.
//! Set `RADIUS_CA_FILE`, `RADIUS_CERT_FILE`, `RADIUS_KEY_FILE`, and `RADIUS_PASSWORD`.

use radius_tokio::client::{ClientConfig, RadsecClient, Request};
use radius_tokio::{tls::TlsContext, ZeroizingBytes};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let target = arguments.next().ok_or("missing server address")?.parse()?;
    let expected_name = arguments.next().ok_or("missing server certificate name")?;
    let username = arguments.next().ok_or("missing user name")?;
    let ca = std::fs::read(std::env::var("RADIUS_CA_FILE")?)?;
    let certificate = std::fs::read(std::env::var("RADIUS_CERT_FILE")?)?;
    let key = ZeroizingBytes::new(std::fs::read(std::env::var("RADIUS_KEY_FILE")?)?);
    let context = TlsContext::client(&certificate, key.as_bytes(), &ca)?;
    let client =
        RadsecClient::connect(target, &context, &expected_name, ClientConfig::default()).await?;
    let password = ZeroizingBytes::new(std::env::var("RADIUS_PASSWORD")?.into_bytes());
    let mut request = Request::access();
    request.add_attribute(1, username.as_bytes())?;
    request.user_password(password.as_bytes())?;
    let response = client.send(request).await?;
    println!("{}", response.code());
    client.close().await?;
    Ok(())
}
