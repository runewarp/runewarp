//! HTTP/3 client and server
#![deny(missing_docs, clippy::self_named_module_files)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod client;

mod config;
//pub mod error;
pub mod ext;
pub mod quic;

pub mod server;

//pub use error::Error;

mod buf;

mod shared_state;

pub use shared_state::{ConnectionState, SharedState};

pub mod error;

#[allow(missing_docs)]
pub mod connection;
#[allow(missing_docs)]
pub mod frame;
#[allow(missing_docs)]
pub mod proto;
#[allow(dead_code, missing_docs)]
pub mod qpack;
#[allow(missing_docs)]
pub mod stream;
#[allow(missing_docs)]
pub mod webtransport;

#[cfg(not(all()))]
mod connection;
#[cfg(not(all()))]
mod frame;
#[cfg(not(all()))]
mod proto;
#[cfg(not(all()))]
#[allow(dead_code)]
mod qpack;
#[cfg(not(all()))]
mod stream;
#[cfg(not(all()))]
mod webtransport;

#[cfg(any())]
mod tests;
