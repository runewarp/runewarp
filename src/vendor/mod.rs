//! THROWAWAY vendored HTTP/3 stack. MIT notices accompany each module.
#![allow(clippy::collapsible_if)]
#![forbid(unsafe_code)]
pub mod h3;
pub mod h3_datagram;
pub mod h3_quinn;
pub mod h3_webtransport;
