//! Server runtime: client identification, request dispatch, and the
//! UDP / `RadSec` transports.

pub mod accounting;
pub mod cache;
pub mod client;
pub mod coa;
mod dedup;
pub mod handler;
mod pipeline;
#[cfg(feature = "radsec")]
mod radsec;
pub mod role;
mod runtime;
pub mod status;
pub mod store;
mod udp;

pub use accounting::AcctStatusType;
pub use cache::{CacheConfig, CachedStore};
pub use client::{Client, ClientId, SecretBytes};
pub use coa::{CoaAction, CoaConfig, CoaError, CoaOriginator, CoaOutcome, ErrorCause};
#[cfg(any(feature = "test-util", test))]
pub use handler::test_support;
pub use handler::{Handler, HandlerError, HandlerResult, Request};
pub use role::ListenerRole;
pub use runtime::{Server, ServerBuilder, ShutdownHandle};
pub use status::{
    StatusAction, StatusContext, StatusResponder, StatusServerPolicy, StatusTransport,
};
pub use store::{CidrError, ClientStore, IpCidr, StaticClients, StaticClientsBuilder};

#[cfg(feature = "radsec")]
pub use runtime::RadSecRevoker;
