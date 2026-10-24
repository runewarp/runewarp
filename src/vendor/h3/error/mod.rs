//! This module contains the error handling logic and types for the h3 crate.

mod codes;

pub mod connection_error_creators;
#[cfg(not(all()))]
pub mod connection_error_creators;

pub mod internal_error;
#[cfg(not(all()))]
pub(crate) mod internal_error;

// Todo better module names
#[allow(clippy::module_inception)]
mod error;

pub use codes::Code;
pub use error::{ConnectionError, LocalError, StreamError};
