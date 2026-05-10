//! Compile-time-typed handles for known dictionary attributes.
//!
//! The build-time codegen emits one `const` per `ATTRIBUTE` line: an
//! [`Attr<T>`] for top-level attributes or a [`VsaAttr<T>`] for those
//! living inside a `BEGIN-VENDOR` block. The marker type `T` records
//! the wire type so the value decoder is selected at the call site —
//! no runtime dispatch, no allocation, fully inlinable.
//!
//! Callers use these handles via
//! [`RawAttribute::get`](super::attributes::RawAttribute::get) (per-attribute
//! match in an iterator) or the free functions
//! [`first`](super::attributes::first) /
//! [`first_vsa`](super::attributes::first_vsa) (find-first by code).
//!
//! ```ignore
//! use radius_tokio::dict::generated::rfc::attrs;
//!
//! for attr in packet.attributes_iter() {
//!     if let Some(name) = attr.get(attrs::USER_NAME) {
//!         // name: &str
//!     }
//! }
//! ```
//!
//! The types themselves live in `radius-dict` and are re-exported here so
//! codec consumers can reference them via the familiar `codec::typed` path.

pub use radius_dict::typed::*;
