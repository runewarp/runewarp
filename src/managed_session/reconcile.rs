//! Latest-state, non-preemptive reconciliation helpers.
//!
//! While an apply is in flight, newer snapshots collapse to a single pending
//! candidate. Equal applied revisions are skipped when idle. Previously applied
//! but non-current revisions remain valid rollback candidates because equality
//! is checked only against the current applied revision.

/// Memory-only applied revision retained by one Managed-session process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppliedRevision {
    revision: Option<String>,
}

impl AppliedRevision {
    pub fn new() -> Self {
        Self { revision: None }
    }

    pub fn get(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    pub fn matches(&self, revision: &str) -> bool {
        self.revision.as_deref() == Some(revision)
    }

    pub fn set(&mut self, revision: impl Into<String>) {
        self.revision = Some(revision.into());
    }
}

/// A validated snapshot ready for role-adapter apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedSnapshot<I> {
    pub revision: String,
    pub input: I,
}

/// Collapse queue for non-preemptive latest-state reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotQueue<I> {
    pending: Option<QueuedSnapshot<I>>,
    applying: bool,
}

impl<I> Default for SnapshotQueue<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> SnapshotQueue<I> {
    pub fn new() -> Self {
        Self {
            pending: None,
            applying: false,
        }
    }

    /// Retain only the newest candidate while an apply is in flight.
    pub fn note_while_applying(&mut self, snapshot: QueuedSnapshot<I>) {
        debug_assert!(self.applying);
        self.pending = Some(snapshot);
    }

    /// Retain a candidate while idle. Later [`take_next`] starts the apply.
    pub fn note_when_idle(&mut self, snapshot: QueuedSnapshot<I>) {
        debug_assert!(!self.applying);
        self.pending = Some(snapshot);
    }

    /// Take the newest pending candidate and mark apply in flight.
    pub fn take_next(&mut self) -> Option<QueuedSnapshot<I>> {
        if self.applying {
            return None;
        }
        let next = self.pending.take()?;
        self.applying = true;
        Some(next)
    }

    /// Mark the active apply finished so a pending candidate can start.
    pub fn finish_apply(&mut self) {
        self.applying = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{AppliedRevision, QueuedSnapshot, SnapshotQueue};

    fn snapshot(revision: &str) -> QueuedSnapshot<&'static str> {
        QueuedSnapshot {
            revision: revision.to_owned(),
            input: "input",
        }
    }

    #[test]
    fn equal_applied_revision_is_detectable_and_memory_only() {
        let mut applied = AppliedRevision::new();
        assert!(!applied.matches("rev-1"));
        applied.set("rev-1");
        assert!(applied.matches("rev-1"));
        assert!(!applied.matches("rev-2"));
        // A fresh process has no retained revision.
        assert_eq!(AppliedRevision::new().get(), None);
    }

    #[test]
    fn previously_applied_revision_remains_a_rollback_candidate() {
        let mut applied = AppliedRevision::new();
        applied.set("rev-a");
        applied.set("rev-b");
        // Equality is only against the current applied revision.
        assert!(!applied.matches("rev-a"));
        assert!(applied.matches("rev-b"));
    }

    #[test]
    fn queue_is_non_preemptive_and_keeps_only_latest_pending() {
        let mut queue = SnapshotQueue::new();
        queue.note_when_idle(snapshot("rev-1"));
        let first = queue.take_next().expect("idle take starts apply");
        assert_eq!(first.revision, "rev-1");
        assert!(
            queue.take_next().is_none(),
            "cannot start another apply while one is in flight"
        );

        queue.note_while_applying(snapshot("rev-2"));
        queue.note_while_applying(snapshot("rev-3"));
        queue.finish_apply();

        let next = queue.take_next().expect("pending newest remains");
        assert_eq!(next.revision, "rev-3");
        queue.finish_apply();
        assert!(queue.take_next().is_none());
    }
}
