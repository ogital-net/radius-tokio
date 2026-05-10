//! FreeRADIUS dictionary parser and Rust code generator.
//!
//! This crate is intended for use as a **build-dependency only**. It parses
//! FreeRADIUS-format dictionary files and renders Rust source that is
//! `include!`-ed by `radius-dict` at compile time.

#![warn(missing_docs)]

pub mod codegen;
pub mod model;
pub mod parser;

pub use model::{Attribute, Dictionary, Error, ErrorKind, Flags, Oid, Type, Value, Vendor};
pub use parser::{FsLoader, Loader, MapLoader, Parser};
