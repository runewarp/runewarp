//! Shared Client Visitor-capacity configuration policy.
pub(crate) const DEFAULT_VISITOR_CAPACITY: usize = 16_384;
pub(crate) const MIN_VISITOR_CAPACITY: usize = crate::tunnel_h3::MAX_IDLE_VISITOR_CREDIT;
pub(crate) const MAX_VISITOR_CAPACITY: usize = 1_048_576;
