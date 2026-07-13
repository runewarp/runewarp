//! Managed-session timing windows.

use std::time::Duration;

use tokio::time::Instant;

/// Deadline for the first valid snapshot on a new connection. Keepalive
/// comments do not extend this window.
pub const FIRST_SNAPSHOT_DEADLINE: Duration = Duration::from_secs(60);

/// Maximum silence between any SSE bytes before the session is replaced.
pub const SILENCE_TIMEOUT: Duration = Duration::from_secs(60);

/// Cadence for repeating the last successfully applied revision to Control.
pub const STATE_HEARTBEAT: Duration = Duration::from_secs(20);

/// Clock used by the Managed-session loop so tests can pause Tokio time.
pub trait SessionClock {
    fn now(&self) -> Instant;
}

/// Tokio-time [`SessionClock`] backed by [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSessionClock;

impl SessionClock for SystemSessionClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionDeadlines {
    pub(crate) first_snapshot_deadline: Instant,
    pub(crate) silence_deadline: Instant,
    received_first_snapshot: bool,
}

impl SessionDeadlines {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            first_snapshot_deadline: now + FIRST_SNAPSHOT_DEADLINE,
            silence_deadline: now + SILENCE_TIMEOUT,
            received_first_snapshot: false,
        }
    }

    pub(crate) fn note_bytes(&mut self, now: Instant) {
        self.silence_deadline = now + SILENCE_TIMEOUT;
    }

    pub(crate) fn note_valid_snapshot(&mut self, now: Instant) {
        self.received_first_snapshot = true;
        self.note_bytes(now);
    }

    pub(crate) fn expired(&self, now: Instant) -> bool {
        if !self.received_first_snapshot && now >= self.first_snapshot_deadline {
            return true;
        }
        now >= self.silence_deadline
    }

    pub(crate) fn next_deadline(&self) -> Instant {
        if self.received_first_snapshot {
            self.silence_deadline
        } else {
            self.first_snapshot_deadline.min(self.silence_deadline)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{FIRST_SNAPSHOT_DEADLINE, SILENCE_TIMEOUT, SessionDeadlines};

    #[test]
    fn comments_extend_silence_but_not_first_snapshot_deadline() {
        let start = Instant::now();
        let mut deadlines = SessionDeadlines::new(start);
        let after_comment = start + Duration::from_secs(30);
        deadlines.note_bytes(after_comment);

        assert_eq!(
            deadlines.first_snapshot_deadline,
            start + FIRST_SNAPSHOT_DEADLINE
        );
        assert_eq!(deadlines.silence_deadline, after_comment + SILENCE_TIMEOUT);
        // Comments cannot push the first-snapshot deadline past 60s from connect.
        assert!(!deadlines.expired(start + Duration::from_secs(59)));
        assert!(deadlines.expired(start + FIRST_SNAPSHOT_DEADLINE));
    }

    #[test]
    fn valid_snapshot_clears_first_snapshot_deadline_pressure() {
        let start = Instant::now();
        let mut deadlines = SessionDeadlines::new(start);
        let snapshot_at = start + Duration::from_secs(10);
        deadlines.note_valid_snapshot(snapshot_at);

        assert!(!deadlines.expired(start + FIRST_SNAPSHOT_DEADLINE));
        assert!(deadlines.expired(snapshot_at + SILENCE_TIMEOUT));
    }
}
