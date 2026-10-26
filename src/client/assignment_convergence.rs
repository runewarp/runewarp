//! Assignment convergence for managed Client Server-address maintenance.
//!
//! Convergence is separate from applied revision. Retiring connections are
//! excluded: only currently assigned addresses contribute to the aggregate.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::ServerAddress;
use crate::tunnel::ServerRuntimeGeneration;

/// Aggregate progress of the current managed Client assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentConvergence {
    /// None of a non-empty assignment are connected.
    Unconverged,
    /// Some, but not all, assigned addresses are connected.
    PartiallyConverged,
    /// Every assigned address is connected, or the assignment is empty.
    Converged,
}

impl AssignmentConvergence {
    /// Derive convergence from assigned and connected counts.
    ///
    /// `connected` must count only assigned addresses that are currently
    /// Connected. Retiring connections must not be included.
    pub fn from_counts(assigned: usize, connected: usize) -> Self {
        if assigned == 0 {
            return Self::Converged;
        }
        if connected == 0 {
            Self::Unconverged
        } else if connected >= assigned {
            Self::Converged
        } else {
            Self::PartiallyConverged
        }
    }
}

#[derive(Debug, Default)]
struct ConvergenceState {
    assigned: HashSet<ServerAddress>,
    /// Addresses that currently have a live Connected tunnel, including Retiring
    /// ones. Aggregate convergence intersects this with `assigned` so Retiring
    /// connections are excluded until re-adopted.
    connected: HashSet<ServerAddress>,
    /// Generations of the connections carrying Visitor credit, keyed by a per-connection token.
    carrying_credit: HashMap<ServerAddress, Vec<(u64, ServerRuntimeGeneration)>>,
    next_connection: u64,
}

impl ConvergenceState {
    fn assigned_connected_count(&self) -> usize {
        self.connected
            .iter()
            .filter(|address| self.assigned.contains(address))
            .count()
    }

    fn current(&self) -> AssignmentConvergence {
        AssignmentConvergence::from_counts(self.assigned.len(), self.assigned_connected_count())
    }
}

/// Shared tracker updated when assignment intent changes or address workers
/// gain/lose Connected status.
#[derive(Clone, Debug, Default)]
pub(crate) struct AssignmentConvergenceTracker {
    inner: Arc<Mutex<ConvergenceState>>,
    /// Signals the Managed state reporter that the assignment or a connection changed.
    reported_state_changed: Arc<Notify>,
}

/// Records one connection carrying Visitor credit until dropped.
#[derive(Debug)]
pub(crate) struct CarryingCredit {
    tracker: AssignmentConvergenceTracker,
    address: ServerAddress,
    token: u64,
}

impl Drop for CarryingCredit {
    fn drop(&mut self) {
        {
            let mut state = self.tracker.lock();
            if let Some(connections) = state.carrying_credit.get_mut(&self.address) {
                connections.retain(|(token, _)| *token != self.token);
                if connections.is_empty() {
                    state.carrying_credit.remove(&self.address);
                }
            }
        }
        self.tracker.reported_state_changed.notify_one();
    }
}

impl AssignmentConvergenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConvergenceState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record a connection to `address` on `generation` that carries Visitor credit, until the
    /// returned guard drops.
    pub fn carrying_credit(
        &self,
        address: &ServerAddress,
        generation: ServerRuntimeGeneration,
    ) -> CarryingCredit {
        let token = {
            let mut state = self.lock();
            let token = state.next_connection;
            state.next_connection = token.wrapping_add(1);
            state
                .carrying_credit
                .entry(address.clone())
                .or_default()
                .push((token, generation));
            token
        };
        self.reported_state_changed.notify_one();
        CarryingCredit {
            tracker: self.clone(),
            address: address.clone(),
            token,
        }
    }

    /// Each assigned address, as `host:port`, with the sorted generations of its connections
    /// carrying credit. Retiring addresses are not assigned and are not reported.
    pub fn reported_servers(&self) -> BTreeMap<String, Vec<String>> {
        let state = self.lock();
        state
            .assigned
            .iter()
            .map(|address| {
                let mut generations: Vec<String> = state
                    .carrying_credit
                    .get(address)
                    .into_iter()
                    .flatten()
                    .map(|(_, generation)| generation.to_string())
                    .collect();
                generations.sort_unstable();
                (
                    format!("{}:{}", address.hostname().as_str(), address.port()),
                    generations,
                )
            })
            .collect()
    }

    pub fn reported_state_changed(&self) -> Arc<Notify> {
        self.reported_state_changed.clone()
    }

    pub fn current(&self) -> AssignmentConvergence {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .current()
    }

    /// Replace the assigned address set. Retiring connections remain tracked as
    /// Connected but are excluded from aggregate convergence until re-adopted.
    /// Returns the new status when it changed.
    pub fn set_assigned(&self, addresses: &[ServerAddress]) -> Option<AssignmentConvergence> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = state.current();
        state.assigned = addresses.iter().cloned().collect();
        let next = state.current();
        self.reported_state_changed.notify_one();
        (next != previous).then_some(next)
    }

    /// Record that an address reached Connected. Returns the new convergence
    /// when it changed. Connected Retiring addresses are recorded so a later
    /// re-adopt can restore them without waiting for a new dial.
    pub fn mark_connected(&self, address: &ServerAddress) -> Option<AssignmentConvergence> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = state.current();
        state.connected.insert(address.clone());
        let next = state.current();
        (next != previous).then_some(next)
    }

    /// Record that an address is no longer Connected. Returns the new
    /// convergence when it changed.
    pub fn mark_disconnected(&self, address: &ServerAddress) -> Option<AssignmentConvergence> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = state.current();
        if !state.connected.remove(address) {
            return None;
        }
        let next = state.current();
        (next != previous).then_some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{AssignmentConvergence, AssignmentConvergenceTracker};
    use crate::ServerAddress;

    fn address(value: &str) -> ServerAddress {
        ServerAddress::parse(value).expect("test server address should parse")
    }

    #[test]
    fn empty_assignment_is_converged() {
        assert_eq!(
            AssignmentConvergence::from_counts(0, 0),
            AssignmentConvergence::Converged
        );
    }

    #[test]
    fn non_empty_with_no_connections_is_unconverged() {
        assert_eq!(
            AssignmentConvergence::from_counts(2, 0),
            AssignmentConvergence::Unconverged
        );
    }

    #[test]
    fn some_connected_is_partially_converged() {
        assert_eq!(
            AssignmentConvergence::from_counts(3, 1),
            AssignmentConvergence::PartiallyConverged
        );
    }

    #[test]
    fn all_assigned_connected_is_converged() {
        assert_eq!(
            AssignmentConvergence::from_counts(2, 2),
            AssignmentConvergence::Converged
        );
    }

    #[test]
    fn set_assigned_empty_is_converged_and_excludes_retiring_connected() {
        let tracker = AssignmentConvergenceTracker::new();
        let a = address("a.example.test");
        let b = address("b.example.test");
        assert_eq!(
            tracker.set_assigned(&[a.clone(), b.clone()]),
            Some(AssignmentConvergence::Unconverged)
        );
        assert_eq!(
            tracker.mark_connected(&a),
            Some(AssignmentConvergence::PartiallyConverged)
        );
        assert_eq!(
            tracker.set_assigned(&[]),
            Some(AssignmentConvergence::Converged)
        );
        assert_eq!(tracker.current(), AssignmentConvergence::Converged);
        // Still Connected but Retiring: excluded until re-adopted.
        assert_eq!(tracker.mark_connected(&a), None);
        assert_eq!(tracker.current(), AssignmentConvergence::Converged);
        // Re-adopt restores Converged without a status change from empty Converged.
        assert_eq!(tracker.set_assigned(std::slice::from_ref(&a)), None);
        assert_eq!(tracker.current(), AssignmentConvergence::Converged);
    }

    #[test]
    fn connected_transitions_follow_assignment() {
        let tracker = AssignmentConvergenceTracker::new();
        let a = address("a.example.test");
        let b = address("b.example.test");
        assert_eq!(
            tracker.set_assigned(&[a.clone(), b.clone()]),
            Some(AssignmentConvergence::Unconverged)
        );
        assert_eq!(
            tracker.mark_connected(&a),
            Some(AssignmentConvergence::PartiallyConverged)
        );
        assert_eq!(
            tracker.mark_connected(&b),
            Some(AssignmentConvergence::Converged)
        );
        assert_eq!(
            tracker.mark_disconnected(&a),
            Some(AssignmentConvergence::PartiallyConverged)
        );
        assert_eq!(
            tracker.mark_disconnected(&b),
            Some(AssignmentConvergence::Unconverged)
        );
    }
}
