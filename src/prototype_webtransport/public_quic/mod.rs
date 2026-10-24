//! THROWAWAY comparison of unified WT, split WT and dedicated UDP CONNECT.
mod association;
mod experiment;
mod forwarder;
mod measure;
mod network;

use super::{Error, Result, SERVER, STEP};
pub use experiment::run;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Unified,
    SplitWt,
    Dedicated,
}
impl Profile {
    const ALL: [Self; 3] = [Self::Unified, Self::SplitWt, Self::Dedicated];
    fn udp_id(self) -> u64 {
        if self == Self::Unified { 4 } else { 8 }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Unified => "unified-wt",
            Self::SplitWt => "split-wt",
            Self::Dedicated => "dedicated-connect",
        }
    }
}
