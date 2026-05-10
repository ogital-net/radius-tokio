//! Server runtime: client identification, request dispatch, and the
//! UDP / `RadSec` transports.

pub mod accounting;
pub mod cache;
pub mod client;
pub mod coa;
mod dedup;
pub mod handler;
#[cfg(feature = "radsec")]
mod radsec;
mod runtime;
pub mod store;
mod udp;

pub use accounting::AcctStatusType;
pub use cache::{CacheConfig, CachedStore};
pub use client::{Client, ClientId, SecretBytes};
pub use coa::{CoaConfig, CoaError, CoaOriginator, CoaOutcome};
pub use handler::{Handler, HandlerError, HandlerResult, Request};
pub use runtime::{Server, ServerBuilder, ShutdownHandle};
pub use store::{CidrError, ClientStore, IpCidr, StaticClients, StaticClientsBuilder};

#[cfg(feature = "radsec")]
pub use runtime::RadSecRevoker;
