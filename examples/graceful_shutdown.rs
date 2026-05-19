//! Example: graceful shutdown driven by
//! [`Server::shutdown_handle`](radius_tokio::server::Server::shutdown_handle).
//!
//! Run with:
//!
//! ```text
//! cargo run --example graceful_shutdown
//! ```
//!
//! Press Ctrl-C to trigger a clean drain.
//!
//! ## Pattern
//!
//! [`Server::run`](radius_tokio::server::Server::run) owns the accept
//! loops and only returns once every listener task has exited.
//! Because `run` takes `self` by value, you cannot call any method on
//! the `Server` once it is running — including asking it to stop.
//! That is what [`ShutdownHandle`] is for: grab one *before* moving
//! the server into a task, then signal it from anywhere.
//!
//! The handle is `Clone + Send + Sync`, so it composes naturally with
//! signal handlers, admin HTTP endpoints, watchdogs, or any other
//! out-of-band control plane the consumer wires up.
//!
//! Dropping every clone of the handle does *not* trigger shutdown —
//! the server keeps running until something explicitly calls
//! [`shutdown`](ShutdownHandle::shutdown). Wrap the handle in your
//! own RAII type if you want drop-to-shutdown semantics.
//!
//! [`ShutdownHandle`]: radius_tokio::server::ShutdownHandle

use std::net::Ipv4Addr;
use std::sync::Arc;

use radius_tokio::server::{
    Client, Handler, HandlerResult, IpCidr, ListenerRole, Request, Server, StaticClients,
};
use radius_tokio::Code;

/// Trivial handler: accept every Access-Request.
struct AcceptAll;

impl Handler for AcceptAll {
    async fn handle(&self, request: Request<'_>) -> HandlerResult {
        HandlerResult::Reply(request.reply(Code::ACCESS_ACCEPT))
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
        .handler(AcceptAll)
        .listen_udp("127.0.0.1:1812".parse().unwrap())
        .listen_udp_with("127.0.0.1:1813".parse().unwrap(), ListenerRole::Acct)
        .build()?;

    // Grab the shutdown handle *before* moving the server into the
    // task. The handle is cloneable, so you can hand copies to as
    // many control-plane components as you like (signal handler,
    // admin endpoint, supervisor, …).
    let shutdown = server.shutdown_handle();

    let run = tokio::spawn(server.run());

    println!("radius-tokio listening on 127.0.0.1:1812 (auth) and 127.0.0.1:1813 (acct)");
    println!("press Ctrl-C to drain and exit");

    // Any async source can drive shutdown. Here we use Ctrl-C; in
    // production you would typically combine SIGINT, SIGTERM, an
    // admin RPC, and/or a health-check failure with `tokio::select!`.
    tokio::signal::ctrl_c().await?;
    println!("\nshutdown signal received, draining...");

    // `shutdown` is idempotent — calling it twice is a no-op, and
    // calling it after the server has already exited is also a no-op.
    shutdown.shutdown();

    // `run` resolves once every listener task has drained.
    run.await.expect("server task panicked")?;
    println!("server exited cleanly");
    Ok(())
}
