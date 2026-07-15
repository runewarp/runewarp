//! Managed-session reconnect, reconciliation, and applied-revision acknowledgment.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use rand::rngs::StdRng;
use tokio::time::Instant;

use super::adapter::RoleAdapter;
use super::connection::{ConnectionError, ManagedSessionConnection};
use super::input::InputError;
use super::limits::{ManagedSessionLimitKind, ManagedSessionLimits};
use super::reconcile::{AppliedRevision, QueuedSnapshot, SnapshotQueue};
use super::role::ManagedSessionRole;
use super::snapshot::{SnapshotEnvelope, SnapshotError, parse_snapshot_event};
use super::sse::{SseParseError, SseParseItem, SseParser};
use super::timing::{FIRST_SNAPSHOT_DEADLINE, SessionDeadlines};
use super::tls::{ControlTlsMaterialError, SessionMaterial, load_control_tls_material};
use crate::ControlAddress;
use crate::reconnect_policy::ReconnectPolicy;

/// Events emitted by the Managed-session engine for local observability.
///
/// Server reconciliation surfaces as Received (`Snapshot`), `Applying`,
/// `Applied`, `Rejected`, and `Superseded` without a separate status endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedSessionEvent {
    /// A validated snapshot envelope was received on the active downlink.
    Snapshot { revision: String },
    /// Role-adapter apply has started for this revision.
    Applying { revision: String },
    /// A revision was successfully applied through the role adapter.
    Applied { revision: String },
    /// Role input was rejected or invalid; prior applied revision is retained.
    Rejected { revision: String },
    /// A queued snapshot was discarded because a newer complete snapshot arrived.
    Superseded { revision: String },
    /// The session is waiting before replacing a failed connection.
    Reconnecting { display_delay_secs: u64 },
}

#[derive(Debug)]
pub(crate) enum ManagedSessionError {
    TlsMaterial(ControlTlsMaterialError),
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
            Self::TlsMaterial(error) => Some(error),
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

/// Role-neutral Managed-session engine.
pub struct ManagedSession {
    address: ControlAddress,
    role: ManagedSessionRole,
    material: SessionMaterial,
    limits: ManagedSessionLimits,
    reconnect: ReconnectPolicy<StdRng>,
    applied: AppliedRevision,
}

impl ManagedSession {
    pub fn new(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
    ) -> Result<Self, ControlTlsMaterialError> {
        Self::with_limits(address, role, material, ManagedSessionLimits::default())
    }

    pub fn with_limits(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
        limits: ManagedSessionLimits,
    ) -> Result<Self, ControlTlsMaterialError> {
        // Initial local material is a startup invariant. Later connection
        // attempts reload the same paths so post-start replacement failures
        // remain recoverable through the reconnect loop.
        load_control_tls_material(&material)?;
        Ok(Self {
            address,
            role,
            material,
            limits,
            reconnect: ReconnectPolicy::new(),
            applied: AppliedRevision::new(),
        })
    }

    /// Last successfully applied revision retained in this process only.
    pub fn applied_revision(&self) -> Option<&str> {
        self.applied.get()
    }

    /// Injected limits for this session (production defaults unless overridden).
    pub fn limits(&self) -> ManagedSessionLimits {
        self.limits
    }

    /// Run until `shutdown` completes, driving the role adapter and acknowledgments.
    pub async fn run<A, F, Fut, S, Shut>(
        &mut self,
        adapter: &mut A,
        mut on_event: F,
        shutdown: S,
    ) -> Shut
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
        S: Future<Output = Shut>,
    {
        tokio::pin!(shutdown);
        loop {
            let outcome = tokio::select! {
                biased;
                shutdown_result = &mut shutdown => return shutdown_result,
                outcome = self.run_one_connection(adapter, &mut on_event) => outcome,
            };

            match outcome {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "managed session failed");
                }
            }

            let retry = self.reconnect.next_retry();
            on_event(ManagedSessionEvent::Reconnecting {
                display_delay_secs: retry.display_delay_secs,
            })
            .await;

            tokio::select! {
                biased;
                shutdown_result = &mut shutdown => return shutdown_result,
                _ = tokio::time::sleep(retry.delay) => {}
            }
        }
    }

    async fn run_one_connection<A, F, Fut>(
        &mut self,
        adapter: &mut A,
        on_event: &mut F,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        let tls =
            load_control_tls_material(&self.material).map_err(ManagedSessionError::TlsMaterial)?;
        let connection = tokio::time::timeout(
            FIRST_SNAPSHOT_DEADLINE,
            ManagedSessionConnection::connect(&self.address, &tls, self.role),
        )
        .await
        .map_err(|_| ManagedSessionError::FirstSnapshotTimeout)?
        .map_err(ManagedSessionError::Connection)?;
        let mut loop_state = ConnectionLoop::<A::Input> {
            connection,
            parser: SseParser::new(self.limits),
            deadlines: SessionDeadlines::new(Instant::now()),
            received_valid_snapshot: false,
            queue: SnapshotQueue::new(),
            report: ReportState::default(),
        };

        loop {
            let snapshot = self
                .wait_for_apply_candidate::<A, _, _>(&mut loop_state, on_event)
                .await?;
            self.apply_while_reading(adapter, snapshot, &mut loop_state, on_event)
                .await?;
        }
    }

    async fn wait_for_apply_candidate<A, F, Fut>(
        &mut self,
        loop_state: &mut ConnectionLoop<A::Input>,
        on_event: &mut F,
    ) -> Result<QueuedSnapshot<A::Input>, ManagedSessionError>
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            self.drive_report(loop_state)?;

            if let Some(pending) = loop_state.queue.take_next() {
                if self.applied.matches(&pending.revision) {
                    loop_state.queue.finish_apply();
                    self.schedule_report(loop_state, pending.revision);
                    continue;
                }
                return Ok(pending);
            }

            let wait = next_wait(&loop_state.deadlines, Instant::now());
            if let Some(report) = loop_state.report.in_flight.as_mut() {
                tokio::select! {
                    chunk = loop_state.connection.next_chunk() => {
                        self.ingest_chunk::<A, _, _>(chunk, loop_state, on_event, false)
                            .await?;
                    }
                    result = report.as_mut() => {
                        loop_state.report.in_flight = None;
                        self.on_report_finished(loop_state, result)?;
                    }
                    _ = tokio::time::sleep(wait) => {
                        self.handle_timer(loop_state).await?;
                    }
                }
            } else {
                tokio::select! {
                    chunk = loop_state.connection.next_chunk() => {
                        self.ingest_chunk::<A, _, _>(chunk, loop_state, on_event, false)
                            .await?;
                    }
                    _ = tokio::time::sleep(wait) => {
                        self.handle_timer(loop_state).await?;
                    }
                }
            }
        }
    }

    async fn apply_while_reading<A, F, Fut>(
        &mut self,
        adapter: &mut A,
        snapshot: QueuedSnapshot<A::Input>,
        loop_state: &mut ConnectionLoop<A::Input>,
        on_event: &mut F,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        let QueuedSnapshot { revision, input } = snapshot;
        on_event(ManagedSessionEvent::Applying {
            revision: revision.clone(),
        })
        .await;
        let apply = adapter.apply(input);
        tokio::pin!(apply);

        let apply_result = loop {
            self.drive_report(loop_state)?;
            let wait = next_wait(&loop_state.deadlines, Instant::now());
            if let Some(report) = loop_state.report.in_flight.as_mut() {
                tokio::select! {
                    result = &mut apply => break result,
                    chunk = loop_state.connection.next_chunk() => {
                        self.ingest_chunk::<A, _, _>(chunk, loop_state, on_event, true)
                            .await?;
                    }
                    result = report.as_mut() => {
                        loop_state.report.in_flight = None;
                        self.on_report_finished(loop_state, result)?;
                    }
                    _ = tokio::time::sleep(wait) => {
                        self.handle_timer(loop_state).await?;
                    }
                }
            } else {
                tokio::select! {
                    result = &mut apply => break result,
                    chunk = loop_state.connection.next_chunk() => {
                        self.ingest_chunk::<A, _, _>(chunk, loop_state, on_event, true)
                            .await?;
                    }
                    _ = tokio::time::sleep(wait) => {
                        self.handle_timer(loop_state).await?;
                    }
                }
            }
        };

        match apply_result {
            Ok(()) => {
                self.applied.set(revision.clone());
                on_event(ManagedSessionEvent::Applied {
                    revision: revision.clone(),
                })
                .await;
                self.schedule_report(loop_state, revision);
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "managed session role input rejected"
                );
                on_event(ManagedSessionEvent::Rejected { revision }).await;
            }
        }
        loop_state.queue.finish_apply();
        Ok(())
    }

    async fn ingest_chunk<A, F, Fut>(
        &mut self,
        chunk: Result<Option<bytes::Bytes>, ConnectionError>,
        loop_state: &mut ConnectionLoop<A::Input>,
        on_event: &mut F,
        applying: bool,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter,
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
        loop_state.deadlines.note_bytes(now);

        let items = loop_state.parser.push(&bytes).map_err(|error| {
            if let SseParseError::LimitExceeded { limit, value, max } = error {
                log_limit_exceeded(limit, value, max);
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
                    loop_state.deadlines.note_valid_snapshot(now);
                    if !loop_state.received_valid_snapshot {
                        loop_state.received_valid_snapshot = true;
                        self.reconnect.reset();
                    }
                    on_event(ManagedSessionEvent::Snapshot {
                        revision: envelope.revision.clone(),
                    })
                    .await;
                    self.accept_envelope::<A, _, _>(envelope, loop_state, on_event, applying)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn accept_envelope<A, F, Fut>(
        &mut self,
        envelope: SnapshotEnvelope,
        loop_state: &mut ConnectionLoop<A::Input>,
        on_event: &mut F,
        applying: bool,
    ) -> Result<(), ManagedSessionError>
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        if !applying && self.applied.matches(&envelope.revision) {
            self.schedule_report(loop_state, envelope.revision);
            return Ok(());
        }

        // Validate through the role adapter before queueing so invalid or
        // adapter-rejected candidates never displace a newer valid pending
        // snapshot. The parsed input is retained so apply does not re-parse.
        let SnapshotEnvelope { revision, input } = envelope;
        let input = match A::parse_input(input, &self.limits) {
            Ok(input) => input,
            Err(error @ InputError::LimitExceeded { limit, value, max }) => {
                log_limit_exceeded(limit, value, max);
                return Err(ManagedSessionError::InputLimit(error));
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "managed session role input invalid"
                );
                on_event(ManagedSessionEvent::Rejected { revision }).await;
                return Ok(());
            }
        };

        let queued = QueuedSnapshot { revision, input };
        let superseded = if applying {
            loop_state.queue.note_while_applying(queued)
        } else {
            loop_state.queue.note_when_idle(queued)
        };
        if let Some(revision) = superseded {
            on_event(ManagedSessionEvent::Superseded { revision }).await;
        }
        Ok(())
    }

    async fn handle_timer<I>(
        &self,
        loop_state: &mut ConnectionLoop<I>,
    ) -> Result<(), ManagedSessionError> {
        let now = Instant::now();
        if loop_state.deadlines.expired(now) {
            if !loop_state.received_valid_snapshot
                && now >= loop_state.deadlines.first_snapshot_deadline
            {
                return Err(ManagedSessionError::FirstSnapshotTimeout);
            }
            return Err(ManagedSessionError::SilenceTimeout);
        }
        Ok(())
    }

    fn schedule_report<I>(&self, loop_state: &mut ConnectionLoop<I>, revision: String) {
        if loop_state.report.in_flight.is_some() {
            // Newer successful applies replace any older pending report.
            loop_state.report.pending = Some(revision);
            return;
        }
        let future = loop_state
            .connection
            .begin_put_applied_revision(&revision, &self.limits);
        loop_state.report.in_flight = Some(future);
    }

    fn drive_report<I>(
        &self,
        loop_state: &mut ConnectionLoop<I>,
    ) -> Result<(), ManagedSessionError> {
        if loop_state.report.in_flight.is_some() {
            return Ok(());
        }
        if let Some(revision) = loop_state.report.pending.take() {
            let future = loop_state
                .connection
                .begin_put_applied_revision(&revision, &self.limits);
            loop_state.report.in_flight = Some(future);
        }
        Ok(())
    }

    fn on_report_finished<I>(
        &self,
        loop_state: &mut ConnectionLoop<I>,
        result: Result<(), ConnectionError>,
    ) -> Result<(), ManagedSessionError> {
        match result {
            Ok(()) => {
                // Start the coalesced latest pending revision, if any.
                self.drive_report(loop_state)?;
                Ok(())
            }
            Err(ConnectionError::StateRequestTimeout | ConnectionError::StateResponseTimeout) => {
                Err(ManagedSessionError::StateAcknowledgmentTimeout)
            }
            Err(error) => Err(ManagedSessionError::Connection(error)),
        }
    }
}

struct ConnectionLoop<I> {
    connection: ManagedSessionConnection,
    parser: SseParser,
    deadlines: SessionDeadlines,
    received_valid_snapshot: bool,
    queue: SnapshotQueue<I>,
    report: ReportState,
}

type StateReportFuture = Pin<Box<dyn Future<Output = Result<(), ConnectionError>> + Send>>;

#[derive(Default)]
struct ReportState {
    in_flight: Option<StateReportFuture>,
    pending: Option<String>,
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
