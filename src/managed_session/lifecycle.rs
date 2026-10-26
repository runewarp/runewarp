//! One Managed-session connection lifecycle.
//!
//! Owns the absolute first-snapshot deadline, authenticated connection, SSE
//! parser, reconciliation queue, apply progress, state reporting, and timers.

use std::fmt;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::adapter::{ApplyError, RoleAdapter};
use super::connection::{ConnectionError, ManagedSessionConnection};
use super::input::InputError;
use super::limits::{ManagedSessionLimitKind, ManagedSessionLimits};
use super::reconcile::{AppliedRevision, QueuedSnapshot, SnapshotQueue};
use super::role::ManagedSessionRole;
use super::session::ManagedSessionEvent;
use super::snapshot::{SnapshotEnvelope, SnapshotError, parse_snapshot_event};
use super::state::RoleState;
use super::timing::{FIRST_SNAPSHOT_DEADLINE, SessionDeadlines};
use super::tls::ControlTlsMaterial;
use crate::ControlAddress;
use crate::sse::{SseParseError, SseParseItem, SseParser};

#[derive(Debug)]
pub(super) enum ManagedSessionError {
    Connection(ConnectionError),
    Sse(SseParseError),
    Snapshot(SnapshotError),
    SilenceTimeout,
    FirstSnapshotTimeout,
    StateAcknowledgmentTimeout,
    InputLimit(InputError),
    StreamEnded,
}

impl fmt::Display for ManagedSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(error) => write!(formatter, "{error}"),
            Self::Sse(error) => write!(formatter, "{error}"),
            Self::Snapshot(error) => write!(formatter, "{error}"),
            Self::SilenceTimeout => {
                formatter.write_str("managed session timed out waiting for SSE bytes")
            }
            Self::FirstSnapshotTimeout => {
                formatter.write_str("managed session timed out waiting for the first snapshot")
            }
            Self::StateAcknowledgmentTimeout => {
                formatter.write_str("managed session timed out waiting for state acknowledgment")
            }
            Self::InputLimit(error) => write!(formatter, "{error}"),
            Self::StreamEnded => formatter.write_str("managed session SSE stream ended"),
        }
    }
}

impl std::error::Error for ManagedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Sse(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::InputLimit(error) => Some(error),
            Self::SilenceTimeout
            | Self::FirstSnapshotTimeout
            | Self::StateAcknowledgmentTimeout
            | Self::StreamEnded => None,
        }
    }
}

pub(super) struct ConnectionRun {
    pub(super) result: Result<(), ManagedSessionError>,
    pub(super) received_valid_snapshot: bool,
}

pub(super) struct ConnectionLifecycle<I> {
    connection: ManagedSessionConnection,
    parser: SseParser,
    deadlines: SessionDeadlines,
    received_valid_snapshot: bool,
    queue: SnapshotQueue<I>,
    report: ReportState,
    role_state: Option<Arc<dyn RoleState>>,
    limits: ManagedSessionLimits,
}

impl<I> ConnectionLifecycle<I> {
    pub(super) async fn connect(
        address: &ControlAddress,
        tls: &ControlTlsMaterial,
        role: ManagedSessionRole,
        limits: ManagedSessionLimits,
    ) -> Result<Self, ManagedSessionError> {
        let connection_started_at = Instant::now();
        let first_snapshot_deadline = connection_started_at + FIRST_SNAPSHOT_DEADLINE;
        let connection = tokio::time::timeout_at(
            first_snapshot_deadline,
            ManagedSessionConnection::connect(address, tls, role),
        )
        .await
        .map_err(|_| ManagedSessionError::FirstSnapshotTimeout)?
        .map_err(ManagedSessionError::Connection)?;

        Ok(Self {
            connection,
            parser: SseParser::new(limits.sse_limits()),
            deadlines: SessionDeadlines::new(connection_started_at),
            received_valid_snapshot: false,
            queue: SnapshotQueue::new(),
            report: ReportState::default(),
            role_state: None,
            limits,
        })
    }

    pub(super) async fn run<A, F, Fut>(
        mut self,
        adapter: &mut A,
        applied: &mut AppliedRevision,
        on_event: &mut F,
    ) -> ConnectionRun
    where
        A: RoleAdapter<Input = I>,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        self.role_state = adapter.role_state();
        let result = self.run_state_machine(adapter, applied, on_event).await;
        ConnectionRun {
            result,
            received_valid_snapshot: self.received_valid_snapshot,
        }
    }

    async fn run_state_machine<A, F, Fut>(
        &mut self,
        adapter: &mut A,
        applied: &mut AppliedRevision,
        on_event: &mut F,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter<Input = I>,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            let mut no_apply = pending::<Result<(), ApplyError>>();
            let snapshot = match self
                .drive_until_transition::<A, _, _, _>(
                    ConnectionPhase::Idle,
                    Pin::new(&mut no_apply),
                    applied,
                    on_event,
                )
                .await?
            {
                ConnectionTransition::Apply(snapshot) => snapshot,
                ConnectionTransition::Applied(_) => unreachable!("idle phase cannot finish apply"),
            };

            let QueuedSnapshot { revision, input } = snapshot;
            on_event(ManagedSessionEvent::Applying {
                revision: revision.clone(),
            })
            .await;
            let apply = adapter.apply(input);
            tokio::pin!(apply);
            let apply_result = match self
                .drive_until_transition::<A, _, _, _>(
                    ConnectionPhase::Applying,
                    apply.as_mut(),
                    applied,
                    on_event,
                )
                .await?
            {
                ConnectionTransition::Applied(result) => result,
                ConnectionTransition::Apply(_) => {
                    unreachable!("applying phase cannot start another apply")
                }
            };

            match apply_result {
                Ok(()) => {
                    applied.set(revision.clone());
                    on_event(ManagedSessionEvent::Applied {
                        revision: revision.clone(),
                    })
                    .await;
                    self.schedule_report(revision);
                }
                Err(error) => {
                    tracing::warn!(error = %error, "managed session role input rejected");
                    on_event(ManagedSessionEvent::Rejected { revision }).await;
                }
            }
            self.queue.finish_apply();
        }
    }

    async fn drive_until_transition<A, F, Fut, Apply>(
        &mut self,
        phase: ConnectionPhase,
        mut apply: Pin<&mut Apply>,
        applied: &AppliedRevision,
        on_event: &mut F,
    ) -> Result<ConnectionTransition<I>, ManagedSessionError>
    where
        A: RoleAdapter<Input = I>,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
        Apply: Future<Output = Result<(), ApplyError>>,
    {
        loop {
            self.drive_report();
            self.handle_timer()?;

            if phase == ConnectionPhase::Idle
                && let Some(pending) = self.queue.take_next()
            {
                if applied.matches(&pending.revision) {
                    self.queue.finish_apply();
                    self.schedule_report(pending.revision);
                    continue;
                }
                return Ok(ConnectionTransition::Apply(pending));
            }

            let wait = next_wait(&self.deadlines, Instant::now());
            let spacing_wait = self.report.spacing_wait();
            let role_state = self.role_state.clone();
            tokio::select! {
                biased;
                result = apply.as_mut(), if phase == ConnectionPhase::Applying => {
                    return Ok(ConnectionTransition::Applied(result));
                }
                _ = tokio::time::sleep(wait) => {
                    self.handle_timer()?;
                }
                chunk = self.connection.next_chunk() => {
                    self.ingest_chunk::<A, _, _>(
                        chunk,
                        on_event,
                        phase == ConnectionPhase::Applying,
                        applied,
                    )
                    .await?;
                }
                result = wait_for_report(&mut self.report.in_flight) => {
                    self.report.in_flight = None;
                    self.on_report_finished(result)?;
                }
                _ = async {
                    if let Some(start_at) = spacing_wait {
                        tokio::time::sleep_until(start_at).await;
                    }
                }, if spacing_wait.is_some() => {}
                _ = async {
                    if let Some(role_state) = &role_state {
                        role_state.changed().await;
                    }
                }, if role_state.is_some() => {
                    self.note_role_state_changed();
                }
            }
        }
    }

    async fn ingest_chunk<A, F, Fut>(
        &mut self,
        chunk: Result<Option<bytes::Bytes>, ConnectionError>,
        on_event: &mut F,
        applying: bool,
        applied: &AppliedRevision,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter<Input = I>,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        let Some(bytes) = chunk.map_err(ManagedSessionError::Connection)? else {
            return Err(ManagedSessionError::StreamEnded);
        };
        if bytes.is_empty() {
            return Ok(());
        }

        let now = Instant::now();
        self.deadlines.note_bytes(now);
        let items = self.parser.push(&bytes).map_err(|error| {
            if let SseParseError::LimitExceeded { limit, value, max } = error {
                log_limit_exceeded(limit.into(), value, max);
            }
            ManagedSessionError::Sse(error)
        })?;

        for item in items {
            match item {
                SseParseItem::Comment => {}
                SseParseItem::Event(event) => {
                    if event.event_type.is_none() && event.data.is_empty() {
                        continue;
                    }
                    let envelope = parse_snapshot_event(
                        event.event_type.as_deref(),
                        &event.data,
                        &self.limits,
                    )
                    .map_err(|error| {
                        if let SnapshotError::LimitExceeded { limit, value, max } = error {
                            log_limit_exceeded(limit, value, max);
                        }
                        ManagedSessionError::Snapshot(error)
                    })?;
                    let snapshot_received_at = Instant::now();
                    if !self.deadlines.try_note_valid_snapshot(snapshot_received_at) {
                        return Err(ManagedSessionError::FirstSnapshotTimeout);
                    }
                    if !self.received_valid_snapshot {
                        self.received_valid_snapshot = true;
                    }
                    on_event(ManagedSessionEvent::Snapshot {
                        revision: envelope.revision.clone(),
                    })
                    .await;
                    self.accept_envelope::<A, _, _>(envelope, on_event, applying, applied)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn accept_envelope<A, F, Fut>(
        &mut self,
        envelope: SnapshotEnvelope,
        on_event: &mut F,
        applying: bool,
        applied: &AppliedRevision,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter<Input = I>,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        if !applying && applied.matches(&envelope.revision) {
            self.schedule_report(envelope.revision);
            return Ok(());
        }

        let SnapshotEnvelope { revision, input } = envelope;
        let input = match A::parse_input(input, &self.limits) {
            Ok(input) => input,
            Err(error @ InputError::LimitExceeded { limit, value, max }) => {
                log_limit_exceeded(limit, value, max);
                return Err(ManagedSessionError::InputLimit(error));
            }
            Err(error) => {
                tracing::warn!(error = %error, "managed session role input invalid");
                on_event(ManagedSessionEvent::Rejected { revision }).await;
                return Ok(());
            }
        };

        let queued = QueuedSnapshot { revision, input };
        let superseded = if applying {
            self.queue.note_while_applying(queued)
        } else {
            self.queue.note_when_idle(queued)
        };
        if let Some(revision) = superseded {
            on_event(ManagedSessionEvent::Superseded { revision }).await;
        }
        Ok(())
    }

    fn handle_timer(&self) -> Result<(), ManagedSessionError> {
        let now = Instant::now();
        if self.deadlines.expired(now) {
            if !self.received_valid_snapshot && now >= self.deadlines.first_snapshot_deadline {
                return Err(ManagedSessionError::FirstSnapshotTimeout);
            }
            return Err(ManagedSessionError::SilenceTimeout);
        }
        Ok(())
    }

    /// Queue a state document for `revision`. It replaces any unsent one and starts once no
    /// request is in flight and the per-second spacing allows.
    fn schedule_report(&mut self, revision: String) {
        self.report.revision = Some(revision);
        self.report.pending = true;
        self.drive_report();
    }

    /// Queue a state document for a role fact change. Before this connection reports a revision
    /// there is nothing to send; its first snapshot will report the full document.
    fn note_role_state_changed(&mut self) {
        if self.report.revision.is_some() {
            self.report.pending = true;
            self.drive_report();
        }
    }

    fn drive_report(&mut self) {
        if self.report.in_flight.is_some() || !self.report.pending {
            return;
        }
        let Some(revision) = self.report.revision.clone() else {
            return;
        };
        let now = Instant::now();
        if self
            .report
            .next_start_at()
            .is_some_and(|start_at| now < start_at)
        {
            return;
        }
        self.report.pending = false;
        self.report.last_started = Some(now);
        self.report.in_flight = Some(self.connection.begin_put_state(
            revision,
            self.role_state.clone(),
            &self.limits,
        ));
    }

    fn on_report_finished(
        &mut self,
        result: Result<(), ConnectionError>,
    ) -> Result<(), ManagedSessionError> {
        match result {
            Ok(()) => {
                self.drive_report();
                Ok(())
            }
            Err(ConnectionError::StateRequestTimeout | ConnectionError::StateResponseTimeout) => {
                Err(ManagedSessionError::StateAcknowledgmentTimeout)
            }
            Err(error) => Err(ManagedSessionError::Connection(error)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionPhase {
    Idle,
    Applying,
}

enum ConnectionTransition<I> {
    Apply(QueuedSnapshot<I>),
    Applied(Result<(), ApplyError>),
}

type StateReportFuture = Pin<Box<dyn Future<Output = Result<(), ConnectionError>> + Send>>;

/// Minimum spacing between the starts of two state requests on one connection.
const STATE_REQUEST_SPACING: Duration = Duration::from_secs(1);

/// One in-flight state request and at most one pending document. A pending document is rendered
/// when it starts, so a newer change always replaces an unsent one.
#[derive(Default)]
struct ReportState {
    in_flight: Option<StateReportFuture>,
    pending: bool,
    /// Revision this connection last scheduled; every document reports it.
    revision: Option<String>,
    last_started: Option<Instant>,
}

impl ReportState {
    fn next_start_at(&self) -> Option<Instant> {
        self.last_started
            .map(|started| started + STATE_REQUEST_SPACING)
    }

    /// When a pending document waits only for request spacing, the instant it may start.
    fn spacing_wait(&self) -> Option<Instant> {
        (self.pending && self.in_flight.is_none() && self.revision.is_some())
            .then(|| self.next_start_at())
            .flatten()
    }
}

async fn wait_for_report(report: &mut Option<StateReportFuture>) -> Result<(), ConnectionError> {
    match report {
        Some(report) => report.await,
        None => pending().await,
    }
}

fn next_wait(deadlines: &SessionDeadlines, now: Instant) -> Duration {
    let wait = deadlines.next_deadline().saturating_duration_since(now);
    if wait.is_zero() {
        Duration::from_millis(1)
    } else {
        wait
    }
}

fn log_limit_exceeded(limit: ManagedSessionLimitKind, value: usize, max: usize) {
    tracing::warn!(
        limit = limit.as_str(),
        value,
        max,
        "managed session input limit exceeded"
    );
}
