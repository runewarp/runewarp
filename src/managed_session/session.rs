//! Managed-session reconnect loop.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use rand::rngs::StdRng;

use super::connection::{ConnectionError, ManagedSessionConnection};
use super::role::ManagedSessionRole;
use super::snapshot::{SnapshotEnvelope, SnapshotError, parse_snapshot_event};
use super::sse::{SseParseError, SseParseItem, SseParser};
use super::timing::{SessionClock, SessionDeadlines, SystemSessionClock};
use super::tls::{ControlTlsMaterialError, SessionMaterial, load_control_tls_material};
use crate::ControlAddress;
use crate::reconnect_policy::ReconnectPolicy;

/// Events emitted by the Managed-session downlink loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedSessionEvent {
    /// A validated snapshot envelope was received on the active downlink.
    Snapshot(SnapshotEnvelope),
    /// The session is waiting before replacing a failed connection.
    Reconnecting { display_delay_secs: u64 },
}

#[derive(Debug)]
pub enum ManagedSessionError {
    TlsMaterial(ControlTlsMaterialError),
    Connection(ConnectionError),
    Sse(SseParseError),
    Snapshot(SnapshotError),
    SilenceTimeout,
    FirstSnapshotTimeout,
    StreamEnded,
}

impl fmt::Display for ManagedSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsMaterial(error) => write!(formatter, "{error}"),
            Self::Connection(error) => write!(formatter, "{error}"),
            Self::Sse(error) => write!(formatter, "{error}"),
            Self::Snapshot(error) => write!(formatter, "{error}"),
            Self::SilenceTimeout => {
                formatter.write_str("managed session timed out waiting for SSE bytes")
            }
            Self::FirstSnapshotTimeout => {
                formatter.write_str("managed session timed out waiting for the first snapshot")
            }
            Self::StreamEnded => formatter.write_str("managed session SSE stream ended"),
        }
    }
}

impl std::error::Error for ManagedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TlsMaterial(error) => Some(error),
            Self::Connection(error) => Some(error),
            Self::Sse(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::SilenceTimeout | Self::FirstSnapshotTimeout | Self::StreamEnded => None,
        }
    }
}

/// Role-neutral Managed-session downlink runner.
pub struct ManagedSession<C = SystemSessionClock> {
    address: ControlAddress,
    role: ManagedSessionRole,
    material: SessionMaterial,
    clock: C,
    reconnect: ReconnectPolicy<StdRng>,
}

impl ManagedSession<SystemSessionClock> {
    pub fn new(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
    ) -> Self {
        Self {
            address,
            role,
            material,
            clock: SystemSessionClock,
            reconnect: ReconnectPolicy::new(),
        }
    }
}

impl<C: SessionClock> ManagedSession<C> {
    pub fn with_clock(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
        clock: C,
    ) -> Self {
        Self {
            address,
            role,
            material,
            clock,
            reconnect: ReconnectPolicy::new(),
        }
    }

    /// Run until `shutdown` completes, emitting downlink events to `on_event`.
    pub async fn run<F, Fut, S, Shut>(&mut self, mut on_event: F, shutdown: S)
    where
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
        S: Future<Output = Shut>,
    {
        tokio::pin!(shutdown);
        loop {
            let outcome = tokio::select! {
                biased;
                _ = &mut shutdown => return,
                outcome = self.run_one_connection(&mut on_event) => outcome,
            };

            match outcome {
                Ok(()) => {
                    // Clean shutdown from inside the connection is unexpected;
                    // treat it like a stream end and reconnect.
                }
                Err(error) => {
                    tracing::warn!(error = %error, "managed session downlink failed");
                }
            }

            let retry = self.reconnect.next_retry();
            on_event(ManagedSessionEvent::Reconnecting {
                display_delay_secs: retry.display_delay_secs,
            })
            .await;

            tokio::select! {
                biased;
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(retry.delay) => {}
            }
        }
    }

    async fn run_one_connection<F, Fut>(
        &mut self,
        on_event: &mut F,
    ) -> Result<(), ManagedSessionError>
    where
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        let tls =
            load_control_tls_material(&self.material).map_err(ManagedSessionError::TlsMaterial)?;
        let mut connection = ManagedSessionConnection::connect(&self.address, &tls, self.role)
            .await
            .map_err(ManagedSessionError::Connection)?;

        let mut parser = SseParser::new();
        let mut deadlines = SessionDeadlines::new(self.clock.now());
        let mut received_valid_snapshot = false;

        loop {
            let wait = deadlines
                .next_deadline()
                .saturating_duration_since(self.clock.now());
            let wait = if wait.is_zero() {
                Duration::from_millis(1)
            } else {
                wait
            };

            let chunk = tokio::select! {
                chunk = connection.next_chunk() => chunk,
                _ = tokio::time::sleep(wait) => {
                    let now = self.clock.now();
                    if deadlines.expired(now) {
                        if !received_valid_snapshot
                            && now >= deadlines.first_snapshot_deadline
                        {
                            return Err(ManagedSessionError::FirstSnapshotTimeout);
                        }
                        return Err(ManagedSessionError::SilenceTimeout);
                    }
                    continue;
                }
            };

            let Some(bytes) = chunk.map_err(ManagedSessionError::Connection)? else {
                return Err(ManagedSessionError::StreamEnded);
            };
            if bytes.is_empty() {
                continue;
            }

            let now = self.clock.now();
            deadlines.note_bytes(now);

            let items = parser.push(&bytes).map_err(ManagedSessionError::Sse)?;
            for item in items {
                match item {
                    SseParseItem::Comment => {
                        // Comments refresh silence via note_bytes above but do
                        // not extend the first-snapshot deadline.
                    }
                    SseParseItem::Event(event) => {
                        if event.event_type.is_none() && event.data.is_empty() {
                            // Standard SSE discards empty events; a blank
                            // dispatch after comments or ignored fields is not
                            // a session failure.
                            continue;
                        }
                        let envelope =
                            parse_snapshot_event(event.event_type.as_deref(), &event.data)
                                .map_err(ManagedSessionError::Snapshot)?;
                        deadlines.note_valid_snapshot(now);
                        if !received_valid_snapshot {
                            received_valid_snapshot = true;
                            self.reconnect.reset();
                        }
                        on_event(ManagedSessionEvent::Snapshot(envelope)).await;
                    }
                }
            }
        }
    }
}
