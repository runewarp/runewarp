use quinn::ConnectionError;
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use time::format_description::{self, OwnedFormatItem};
use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt as tracing_fmt, reload};

use crate::client_hello::ClientHelloError;
use crate::shutdown::ShutdownMode;
use crate::{ClientIdentity, LogLevel, ManagedSessionEvent, ManagedSessionRole};

static LOGGER: OnceLock<InstalledLogger> = OnceLock::new();

type RuntimeSubscriber = Box<dyn Subscriber + Send + Sync>;
type ReloadFilter = Box<dyn Fn(LogLevel) -> Result<(), InstallError> + Send + Sync>;

struct InstalledLogger {
    reload_filter: ReloadFilter,
    level: Mutex<LogLevel>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTunnelAttemptKind {
    Initial,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTunnelPhase {
    Establishing,
    Reconnecting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallOutcome {
    Installed,
    Updated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerRouteOutcome {
    Forwarded,
    RejectedServerHostname,
    RejectedUnauthorized,
    NoActiveTunnelConnection,
    AcmeChallenge,
    MissingAcmeTlsConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRouteOutcome<'a> {
    Passthrough { backend_address: &'a str },
    Terminated { backend_address: &'a str },
    RejectedNoMatchingService,
    BackendConnectFailed { backend_address: &'a str },
    BackendWriteFailed { backend_address: &'a str },
    MissingTlsConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeRole<'a> {
    Server { server_hostname: &'a str },
    Client { public_hostname: &'a str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeEvent<'a> {
    CachedCertificateReady {
        remaining_validity: &'a str,
        renewal_due: bool,
    },
    FirstIssuanceStarting {
        reason: &'a str,
    },
    RenewalStarting {
        reason: &'a str,
    },
    CertificateIssued,
    CertificateRenewed,
    ChallengeHandled,
    ChallengeFailed {
        error: &'a str,
    },
    RecoverableFailure {
        error: &'a str,
    },
    ManagerStopped,
    NonStandardPublicBind {
        bind_address: SocketAddr,
    },
}

#[derive(Debug)]
pub enum InstallError {
    SetGlobalDefault(tracing::dispatcher::SetGlobalDefaultError),
    Reload(String),
}

impl fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetGlobalDefault(error) => {
                write!(formatter, "failed to install runtime logger: {error}")
            }
            Self::Reload(error) => write!(formatter, "failed to update runtime log level: {error}"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SetGlobalDefault(error) => Some(error),
            Self::Reload(_) => None,
        }
    }
}

impl InstalledLogger {
    fn set_level(&self, level: LogLevel) -> Result<(), InstallError> {
        (self.reload_filter)(level)?;
        *self.level.lock().expect("runtime logger mutex poisoned") = level;
        Ok(())
    }
}

pub fn install(level: LogLevel) -> Result<InstallOutcome, InstallError> {
    if let Some(logger) = LOGGER.get() {
        logger.set_level(level)?;
        return Ok(InstallOutcome::Updated);
    }

    let use_ansi = io::stderr().is_terminal();
    let (subscriber, reload_filter) = build_subscriber(level, io::stderr, use_ansi);
    tracing::subscriber::set_global_default(subscriber).map_err(InstallError::SetGlobalDefault)?;

    let logger = InstalledLogger {
        reload_filter,
        level: Mutex::new(level),
    };

    match LOGGER.set(logger) {
        Ok(()) => Ok(InstallOutcome::Installed),
        Err(_) => {
            let logger = LOGGER
                .get()
                .expect("runtime logger missing after global subscriber install");
            logger.set_level(level)?;
            Ok(InstallOutcome::Updated)
        }
    }
}

pub fn emit(level: EventLevel, message: &str) {
    match level {
        EventLevel::Error => tracing::error!("{message}"),
        EventLevel::Warn => tracing::warn!("{message}"),
        EventLevel::Info => tracing::info!("{message}"),
        EventLevel::Debug => tracing::debug!("{message}"),
        EventLevel::Trace => tracing::trace!("{message}"),
    }
}

pub fn server_route(public_hostname: &str, outcome: ServerRouteOutcome) {
    let (level, message) = server_route_event(public_hostname, outcome);
    emit(level, &message);
}

pub fn server_route_rejected_client_hello(error: &ClientHelloError) {
    let (level, message) = server_route_rejected_client_hello_event(error);
    emit(level, &message);
}

pub fn client_route(public_hostname: &str, outcome: ClientRouteOutcome<'_>) {
    let (level, message) = client_route_event(public_hostname, outcome);
    emit(level, &message);
}

pub fn server_tunnel_connection_accepted(client_identity: &ClientIdentity) {
    emit(
        EventLevel::Info,
        &server_tunnel_connection_accepted_line(client_identity),
    );
}

pub fn server_tunnel_connection_terminated(
    client_identity: &ClientIdentity,
    error: &ConnectionError,
) {
    match error {
        ConnectionError::ApplicationClosed(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::LocallyClosed => emit(
            EventLevel::Info,
            &server_tunnel_connection_closed_line(client_identity),
        ),
        _ => emit_server_tunnel_connection_dropped(client_identity, &error.to_string()),
    }
}

pub fn server_tunnel_connection_failed(error: &str) {
    emit(
        EventLevel::Warn,
        &server_tunnel_connection_failed_line(error),
    );
}

pub fn warning(role: &str, message: &str) {
    emit(EventLevel::Warn, &warning_line(role, message));
}

pub fn client_tunnel_connecting(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
) {
    emit(
        EventLevel::Info,
        &client_tunnel_connecting_line(
            phase,
            attempt_kind,
            configured_server_addr,
            resolved_server_addr,
        ),
    );
}

pub fn client_tunnel_connect_failed(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        client_tunnel_startup_failure_level(phase, attempt_kind),
        &client_tunnel_connect_failed_line(
            phase,
            attempt_kind,
            configured_server_addr,
            resolved_server_addr,
            next_retry_delay_secs,
            error,
        ),
        client_tunnel_connect_failed_detail_line(
            phase,
            attempt_kind,
            configured_server_addr,
            resolved_server_addr,
            error,
        ),
        error,
    );
}

pub fn client_tunnel_resolution_failed(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    next_retry_delay_secs: u64,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        client_tunnel_startup_failure_level(phase, attempt_kind),
        &client_tunnel_resolution_failed_line(
            phase,
            attempt_kind,
            configured_server_addr,
            next_retry_delay_secs,
            error,
        ),
        client_tunnel_resolution_failed_detail_line(
            phase,
            attempt_kind,
            configured_server_addr,
            error,
        ),
        error,
    );
}

pub fn client_tunnel_connected(
    phase: ClientTunnelPhase,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
) {
    emit(
        EventLevel::Info,
        &client_tunnel_connected_line(phase, configured_server_addr, resolved_server_addr),
    );
}

pub fn client_ready(configured_server_addr: &str) {
    emit(EventLevel::Info, &client_ready_line(configured_server_addr));
}

pub fn client_assignment_convergence(status: crate::AssignmentConvergence) {
    emit(
        EventLevel::Info,
        &client_assignment_convergence_line(status),
    );
}

pub fn client_tunnel_disconnected(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &client_tunnel_disconnected_line(
            configured_server_addr,
            resolved_server_addr,
            next_retry_delay_secs,
            error,
        ),
        client_tunnel_disconnected_detail_line(configured_server_addr, resolved_server_addr, error),
        error,
    );
}

pub fn client_tunnel_closed(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
) {
    emit(
        EventLevel::Info,
        &client_tunnel_closed_line(
            configured_server_addr,
            resolved_server_addr,
            next_retry_delay_secs,
        ),
    );
}

pub fn client_tunnel_unauthorized(
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    next_retry_delay_secs: u64,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &client_tunnel_unauthorized_line(
            attempt_kind,
            configured_server_addr,
            next_retry_delay_secs,
        ),
        client_tunnel_unauthorized_detail_line(
            attempt_kind,
            configured_server_addr,
            next_retry_delay_secs,
            error,
        ),
        error,
    );
}

pub fn client_trust_store_warning(errors: usize) {
    emit(
        EventLevel::Warn,
        &format!(
            "{errors} system trust-store certificate(s) could not be loaded; continuing with the successfully loaded trust anchors"
        ),
    );
}

pub fn server_public_listener_ready(bind_address: SocketAddr) {
    emit(
        EventLevel::Info,
        &event_line(
            "server public listener ready",
            [("bind-address", Cow::Owned(bind_address.to_string()))],
        ),
    );
}

pub fn server_tunnel_listener_ready(bind_address: SocketAddr) {
    emit(
        EventLevel::Info,
        &event_line(
            "server tunnel listener ready",
            [("bind-address", Cow::Owned(bind_address.to_string()))],
        ),
    );
}

pub fn server_readiness_listener_enabled(bind_address: SocketAddr) {
    emit(
        EventLevel::Info,
        &event_line(
            "server readiness listener enabled",
            [
                ("bind-address", Cow::Owned(bind_address.to_string())),
                ("kind", Cow::Borrowed("tcp-probe-only")),
            ],
        ),
    );
}

pub fn server_readiness_gained(bind_address: SocketAddr) {
    emit(
        EventLevel::Info,
        &event_line(
            "server readiness gained",
            [("bind-address", Cow::Owned(bind_address.to_string()))],
        ),
    );
}

pub fn server_readiness_lost(bind_address: SocketAddr) {
    emit(
        EventLevel::Info,
        &event_line(
            "server readiness lost",
            [("bind-address", Cow::Owned(bind_address.to_string()))],
        ),
    );
}

pub fn server_orderly_shutdown_started(mode: ShutdownMode, effective_graceful_duration: Duration) {
    emit(
        EventLevel::Info,
        &event_line(
            "server orderly shutdown started",
            [
                ("mode", Cow::Borrowed(shutdown_mode_label(mode))),
                (
                    "effective-graceful-duration",
                    Cow::Owned(format_duration(effective_graceful_duration)),
                ),
            ],
        ),
    );
}

pub fn server_orderly_shutdown_escalated() {
    emit(
        EventLevel::Warn,
        "server orderly shutdown escalated: mode=fast",
    );
}

pub fn server_graceful_shutdown_deadline_expired(active_connections: usize) {
    emit(
        EventLevel::Warn,
        &event_line(
            "server graceful shutdown deadline expired",
            [(
                "active-tunnel-connections",
                Cow::Owned(active_connections.to_string()),
            )],
        ),
    );
}

pub fn server_orderly_shutdown_closing_tunnel_connections(
    mode: ShutdownMode,
    active_connections: usize,
) {
    emit(
        EventLevel::Info,
        &event_line(
            "server orderly shutdown closing tunnel connections",
            [
                ("mode", Cow::Borrowed(shutdown_mode_label(mode))),
                (
                    "active-tunnel-connections",
                    Cow::Owned(active_connections.to_string()),
                ),
            ],
        ),
    );
}

pub fn client_graceful_shutdown_started() {
    emit(
        EventLevel::Info,
        "client instance graceful shutdown started",
    );
}

pub fn client_graceful_shutdown_closing_tunnel_connection() {
    emit(
        EventLevel::Info,
        "client instance graceful shutdown closing tunnel connection",
    );
}

pub fn managed_session_event(role: ManagedSessionRole, event: &ManagedSessionEvent) {
    let role = match role {
        ManagedSessionRole::Server => "server",
        ManagedSessionRole::Client => "client",
    };
    match event {
        ManagedSessionEvent::Snapshot(_) => emit(
            EventLevel::Info,
            &event_line(
                "managed session snapshot received",
                [("role", Cow::Borrowed(role))],
            ),
        ),
        ManagedSessionEvent::Applying { revision: _ } => emit(
            EventLevel::Info,
            &event_line(
                "managed session revision applying",
                [("role", Cow::Borrowed(role))],
            ),
        ),
        ManagedSessionEvent::Applied { revision: _ } => emit(
            EventLevel::Info,
            &event_line(
                "managed session revision applied",
                [("role", Cow::Borrowed(role))],
            ),
        ),
        ManagedSessionEvent::Rejected { revision: _ } => emit(
            EventLevel::Warn,
            &event_line(
                "managed session revision rejected",
                [("role", Cow::Borrowed(role))],
            ),
        ),
        ManagedSessionEvent::Superseded { revision: _ } => emit(
            EventLevel::Info,
            &event_line(
                "managed session revision superseded",
                [("role", Cow::Borrowed(role))],
            ),
        ),
        ManagedSessionEvent::Reconnecting { display_delay_secs } => emit(
            EventLevel::Warn,
            &event_line(
                "managed session reconnecting",
                [
                    ("role", Cow::Borrowed(role)),
                    (
                        "next-retry-delay",
                        Cow::Owned(format!("{display_delay_secs}s")),
                    ),
                ],
            ),
        ),
    }
}

fn shutdown_mode_label(mode: ShutdownMode) -> &'static str {
    match mode {
        ShutdownMode::Graceful => "graceful",
        ShutdownMode::Fast => "fast",
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub fn server_tunnel_connection_unauthorized(client_identity: &ClientIdentity) {
    emit(
        EventLevel::Warn,
        &server_tunnel_connection_unauthorized_line(client_identity),
    );
}

pub fn acme(role: AcmeRole<'_>, event: AcmeEvent<'_>) {
    let (level, message) = acme_event(role, event);
    emit(level, &message);
}

#[cfg(test)]
pub(crate) fn installed_level() -> Option<LogLevel> {
    LOGGER
        .get()
        .map(|logger| *logger.level.lock().expect("runtime logger mutex poisoned"))
}

fn build_subscriber<W>(
    level: LogLevel,
    writer: W,
    use_ansi: bool,
) -> (RuntimeSubscriber, ReloadFilter)
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let (filter_layer, reload_handle) = reload::Layer::new(level_filter(level));
    let subscriber = tracing_subscriber::registry().with(filter_layer).with(
        tracing_fmt::layer()
            .with_writer(writer)
            .with_timer(UtcTime::new(log_timestamp_format()))
            .with_ansi(use_ansi)
            .with_target(false),
    );

    let reload_filter = Box::new(move |level| {
        reload_handle
            .reload(level_filter(level))
            .map_err(|error| InstallError::Reload(error.to_string()))
    });

    (Box::new(subscriber), reload_filter)
}

fn log_timestamp_format() -> OwnedFormatItem {
    static FORMAT: OnceLock<OwnedFormatItem> = OnceLock::new();
    FORMAT
        .get_or_init(|| {
            format_description::parse_owned::<2>(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
            )
            .expect("runtime log timestamp format must stay valid")
        })
        .clone()
}

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Off => LevelFilter::OFF,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

fn event_line<'a, I>(event: &str, fields: I) -> String
where
    I: IntoIterator<Item = (&'a str, Cow<'a, str>)>,
{
    let mut line = String::from(event);
    let mut fields = fields.into_iter().peekable();
    if fields.peek().is_none() {
        return line;
    }
    line.push(':');
    for (field, value) in fields {
        line.push(' ');
        line.push_str(field);
        line.push('=');
        line.push_str(value.as_ref());
    }
    line
}

fn event_line_with_summary<'a, I>(event: &str, fields: I, summary: &str) -> String
where
    I: IntoIterator<Item = (&'a str, Cow<'a, str>)>,
{
    let mut line = event_line(event, fields);
    line.push_str(": ");
    line.push_str(summary);
    line
}

fn server_route_event(public_hostname: &str, outcome: ServerRouteOutcome) -> (EventLevel, String) {
    let (level, line) = match outcome {
        ServerRouteOutcome::Forwarded => (
            EventLevel::Debug,
            event_line(
                "server route forwarded",
                [("public-hostname", Cow::Borrowed(public_hostname))],
            ),
        ),
        ServerRouteOutcome::RejectedServerHostname => (
            EventLevel::Debug,
            event_line(
                "server route rejected",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("non-acme-server-hostname")),
                ],
            ),
        ),
        ServerRouteOutcome::RejectedUnauthorized => (
            EventLevel::Debug,
            event_line(
                "server route rejected",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("unauthorized-public-hostname")),
                ],
            ),
        ),
        ServerRouteOutcome::NoActiveTunnelConnection => (
            EventLevel::Warn,
            event_line(
                "server route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("no-active-tunnel-connection")),
                ],
            ),
        ),
        ServerRouteOutcome::AcmeChallenge => (
            EventLevel::Debug,
            event_line(
                "server route acme-challenge",
                [("public-hostname", Cow::Borrowed(public_hostname))],
            ),
        ),
        ServerRouteOutcome::MissingAcmeTlsConfig => (
            EventLevel::Warn,
            event_line(
                "server route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("acme-tls-config-missing")),
                ],
            ),
        ),
    };
    (level, line)
}

fn server_route_rejected_client_hello_event(error: &ClientHelloError) -> (EventLevel, String) {
    let reason = match error {
        ClientHelloError::InvalidTls => "non-tls-client-hello",
        ClientHelloError::MissingSni => "missing-sni-client-hello",
        ClientHelloError::InvalidSni => "invalid-sni-client-hello",
        ClientHelloError::TooLong { .. } => "oversized-client-hello",
        ClientHelloError::UnexpectedEof => "incomplete-client-hello",
        ClientHelloError::Io(_) => "client-hello-io-error",
    };
    (
        EventLevel::Debug,
        event_line("server route rejected", [("reason", Cow::Borrowed(reason))]),
    )
}

fn client_route_event(
    public_hostname: &str,
    outcome: ClientRouteOutcome<'_>,
) -> (EventLevel, String) {
    let (level, line) = match outcome {
        ClientRouteOutcome::Passthrough { backend_address } => (
            EventLevel::Debug,
            event_line(
                "client route passthrough",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("backend-address", Cow::Borrowed(backend_address)),
                ],
            ),
        ),
        ClientRouteOutcome::Terminated { backend_address } => (
            EventLevel::Debug,
            event_line(
                "client route terminate",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("backend-address", Cow::Borrowed(backend_address)),
                ],
            ),
        ),
        ClientRouteOutcome::RejectedNoMatchingService => (
            EventLevel::Warn,
            event_line(
                "client route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("no-matching-service")),
                ],
            ),
        ),
        ClientRouteOutcome::BackendConnectFailed { backend_address } => (
            EventLevel::Warn,
            event_line(
                "client route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("backend-address", Cow::Borrowed(backend_address)),
                    ("reason", Cow::Borrowed("backend-connect-failed")),
                ],
            ),
        ),
        ClientRouteOutcome::BackendWriteFailed { backend_address } => (
            EventLevel::Warn,
            event_line(
                "client route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("backend-address", Cow::Borrowed(backend_address)),
                    ("reason", Cow::Borrowed("backend-write-failed")),
                ],
            ),
        ),
        ClientRouteOutcome::MissingTlsConfig => (
            EventLevel::Warn,
            event_line(
                "client route unavailable",
                [
                    ("public-hostname", Cow::Borrowed(public_hostname)),
                    ("reason", Cow::Borrowed("tls-config-missing")),
                ],
            ),
        ),
    };
    (level, line)
}

fn acme_event(role: AcmeRole<'_>, event: AcmeEvent<'_>) -> (EventLevel, String) {
    let (event_name_prefix, hostname_field, hostname_value) = match role {
        AcmeRole::Server { server_hostname } => (
            "server acme",
            "server-hostname",
            Cow::Borrowed(server_hostname),
        ),
        AcmeRole::Client { public_hostname } => (
            "client acme",
            "public-hostname",
            Cow::Borrowed(public_hostname),
        ),
    };
    match event {
        AcmeEvent::CachedCertificateReady {
            remaining_validity,
            renewal_due,
        } => (
            EventLevel::Info,
            event_line(
                &format!("{event_name_prefix} cached certificate ready"),
                [
                    (hostname_field, hostname_value),
                    ("remaining-validity", Cow::Borrowed(remaining_validity)),
                    (
                        "renewal",
                        Cow::Borrowed(if renewal_due { "due" } else { "not-due" }),
                    ),
                ],
            ),
        ),
        AcmeEvent::FirstIssuanceStarting { reason } => (
            EventLevel::Info,
            event_line(
                &format!("{event_name_prefix} first issuance starting"),
                [
                    (hostname_field, hostname_value),
                    ("reason", Cow::Borrowed(reason)),
                ],
            ),
        ),
        AcmeEvent::RenewalStarting { reason } => (
            EventLevel::Info,
            event_line(
                &format!("{event_name_prefix} renewal starting"),
                [
                    (hostname_field, hostname_value),
                    ("reason", Cow::Borrowed(reason)),
                ],
            ),
        ),
        AcmeEvent::CertificateIssued => (
            EventLevel::Info,
            event_line(
                &format!("{event_name_prefix} certificate issued"),
                [(hostname_field, hostname_value)],
            ),
        ),
        AcmeEvent::CertificateRenewed => (
            EventLevel::Info,
            event_line(
                &format!("{event_name_prefix} certificate renewed"),
                [(hostname_field, hostname_value)],
            ),
        ),
        AcmeEvent::ChallengeHandled => (
            EventLevel::Debug,
            event_line(
                &format!("{event_name_prefix} challenge handled"),
                [(hostname_field, hostname_value)],
            ),
        ),
        AcmeEvent::ChallengeFailed { error } => (
            EventLevel::Warn,
            event_line(
                &format!("{event_name_prefix} challenge failed"),
                [
                    (hostname_field, hostname_value),
                    ("error", Cow::Borrowed(error)),
                ],
            ),
        ),
        AcmeEvent::RecoverableFailure { error } => (
            EventLevel::Warn,
            event_line_with_summary(
                &format!("{event_name_prefix} failed"),
                [(hostname_field, hostname_value)],
                error,
            ),
        ),
        AcmeEvent::ManagerStopped => (
            EventLevel::Error,
            event_line_with_summary(
                &format!("{event_name_prefix} stopped"),
                [(hostname_field, hostname_value)],
                "automatic certificate management stopped unexpectedly",
            ),
        ),
        AcmeEvent::NonStandardPublicBind { bind_address } => (
            EventLevel::Warn,
            event_line_with_summary(
                "server acme challenge reachability",
                [("bind-address", Cow::Owned(bind_address.to_string()))],
                "TLS-ALPN-01 still requires public TCP 443 reachability; non-443 internal binds can still work behind NAT or container port mapping",
            ),
        ),
    }
}

fn warning_line(role: &str, message: &str) -> String {
    format!("{role} warning: {message}")
}

fn server_tunnel_connection_accepted_line(client_identity: &ClientIdentity) -> String {
    format!("server tunnel connection accepted: client-identity={client_identity}")
}

fn server_tunnel_connection_closed_line(client_identity: &ClientIdentity) -> String {
    format!("server tunnel connection closed: client-identity={client_identity}")
}

fn server_tunnel_connection_unauthorized_line(client_identity: &ClientIdentity) -> String {
    event_line(
        "server tunnel connection unauthorized",
        [("client-identity", Cow::Owned(client_identity.to_string()))],
    )
}

fn server_tunnel_connection_failed_line(error: &str) -> String {
    format!(
        "server tunnel connection failed: {}",
        summarize_live_connection_error(error)
    )
}

fn emit_server_tunnel_connection_dropped(client_identity: &ClientIdentity, error: &str) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &server_tunnel_connection_dropped_line(client_identity, error),
        server_tunnel_connection_dropped_detail_line(client_identity, error),
        error,
    );
}

fn server_tunnel_connection_dropped_line(client_identity: &ClientIdentity, error: &str) -> String {
    format!(
        "server tunnel connection dropped: client-identity={client_identity}: {}",
        summarize_live_connection_error(error)
    )
}

fn server_tunnel_connection_dropped_detail_line(
    client_identity: &ClientIdentity,
    error: &str,
) -> String {
    format!("server tunnel connection dropped detail: client-identity={client_identity}: {error}")
}

fn client_tunnel_connecting_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
) -> String {
    let event = match (phase, attempt_kind) {
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::Initial) => {
            "client tunnel connection connecting"
        }
        (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::Initial) => {
            "client tunnel connection reconnecting"
        }
        (_, ClientTunnelAttemptKind::Retry) => "client tunnel connection retrying",
    };
    let retry = client_tunnel_retry_field(attempt_kind);
    event_line(
        event,
        [
            ("server-address", Cow::Borrowed(configured_server_addr)),
            (
                "resolved-address",
                Cow::Owned(resolved_server_addr.to_string()),
            ),
        ]
        .into_iter()
        .chain(retry),
    )
}

fn client_tunnel_connect_failed_line(
    _phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
    error: &str,
) -> String {
    event_line_with_summary(
        "client tunnel connection failed",
        [
            ("server-address", Cow::Borrowed(configured_server_addr)),
            (
                "resolved-address",
                Cow::Owned(resolved_server_addr.to_string()),
            ),
        ]
        .into_iter()
        .chain(client_tunnel_attempt_field(attempt_kind))
        .chain(next_retry_delay_field(next_retry_delay_secs)),
        summarize_error(error),
    )
}

fn client_tunnel_resolution_failed_line(
    _phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    next_retry_delay_secs: u64,
    error: &str,
) -> String {
    event_line_with_summary(
        "client tunnel resolution failed",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(client_tunnel_attempt_field(attempt_kind))
            .chain(next_retry_delay_field(next_retry_delay_secs)),
        summarize_error(error),
    )
}

fn client_tunnel_connected_line(
    phase: ClientTunnelPhase,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
) -> String {
    let _ = phase;
    let _ = resolved_server_addr;
    event_line(
        "client tunnel connection connected",
        [("server-address", Cow::Borrowed(configured_server_addr))],
    )
}

fn client_tunnel_disconnected_line(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
    error: &str,
) -> String {
    let _ = resolved_server_addr;
    event_line_with_summary(
        "client tunnel connection dropped",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(next_retry_delay_field(next_retry_delay_secs)),
        summarize_live_connection_error(error),
    )
}

fn client_tunnel_closed_line(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    next_retry_delay_secs: u64,
) -> String {
    let _ = resolved_server_addr;
    event_line(
        "client tunnel connection closed",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(next_retry_delay_field(next_retry_delay_secs)),
    )
}

fn client_ready_line(configured_server_addr: &str) -> String {
    event_line(
        "client ready",
        [("server-address", Cow::Borrowed(configured_server_addr))],
    )
}

fn client_assignment_convergence_line(status: crate::AssignmentConvergence) -> String {
    let status = match status {
        crate::AssignmentConvergence::Unconverged => "unconverged",
        crate::AssignmentConvergence::PartiallyConverged => "partially-converged",
        crate::AssignmentConvergence::Converged => "converged",
    };
    event_line(
        "client assignment convergence",
        [("status", Cow::Borrowed(status))],
    )
}

fn client_tunnel_disconnected_detail_line(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) -> String {
    let _ = resolved_server_addr;
    event_line_with_summary(
        "client tunnel connection dropped detail",
        [("server-address", Cow::Borrowed(configured_server_addr))],
        error,
    )
}

fn client_tunnel_unauthorized_line(
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    next_retry_delay_secs: u64,
) -> String {
    event_line(
        "client tunnel connection unauthorized",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(client_tunnel_attempt_field(attempt_kind))
            .chain(next_retry_delay_field(next_retry_delay_secs)),
    )
}

fn client_tunnel_unauthorized_detail_line(
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    next_retry_delay_secs: u64,
    error: &str,
) -> String {
    event_line_with_summary(
        "client tunnel connection unauthorized detail",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(client_tunnel_attempt_field(attempt_kind))
            .chain(next_retry_delay_field(next_retry_delay_secs)),
        error,
    )
}

fn emit_runtime_failure_with_debug_detail(
    level: EventLevel,
    summary_line: &str,
    detail_line: String,
    error: &str,
) {
    emit(level, summary_line);
    if has_nested_error_detail(error) {
        emit(EventLevel::Debug, &detail_line);
    }
}

fn client_tunnel_connect_failed_detail_line(
    _phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) -> String {
    event_line_with_summary(
        "client tunnel connection failed detail",
        [
            ("server-address", Cow::Borrowed(configured_server_addr)),
            (
                "resolved-address",
                Cow::Owned(resolved_server_addr.to_string()),
            ),
        ]
        .into_iter()
        .chain(client_tunnel_attempt_field(attempt_kind)),
        error,
    )
}

fn client_tunnel_resolution_failed_detail_line(
    _phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    error: &str,
) -> String {
    event_line_with_summary(
        "client tunnel resolution failed detail",
        [("server-address", Cow::Borrowed(configured_server_addr))]
            .into_iter()
            .chain(client_tunnel_attempt_field(attempt_kind)),
        error,
    )
}

fn client_tunnel_retry_field(
    attempt_kind: ClientTunnelAttemptKind,
) -> Option<(&'static str, Cow<'static, str>)> {
    match attempt_kind {
        ClientTunnelAttemptKind::Initial => None,
        ClientTunnelAttemptKind::Retry => Some(("retry", Cow::Borrowed("retry"))),
    }
}

fn client_tunnel_startup_failure_level(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
) -> EventLevel {
    if matches!(phase, ClientTunnelPhase::Establishing)
        && matches!(attempt_kind, ClientTunnelAttemptKind::Initial)
    {
        EventLevel::Error
    } else {
        EventLevel::Warn
    }
}

fn client_tunnel_attempt_field(
    attempt_kind: ClientTunnelAttemptKind,
) -> Option<(&'static str, Cow<'static, str>)> {
    match attempt_kind {
        ClientTunnelAttemptKind::Initial => Some(("retry", Cow::Borrowed("initial"))),
        ClientTunnelAttemptKind::Retry => Some(("retry", Cow::Borrowed("retry"))),
    }
}

fn next_retry_delay_field(next_retry_delay_secs: u64) -> Option<(&'static str, Cow<'static, str>)> {
    Some((
        "next-retry-delay",
        Cow::Owned(format!("{next_retry_delay_secs}s")),
    ))
}

fn has_nested_error_detail(error: &str) -> bool {
    summarize_error(error) != error
}

fn summarize_live_connection_error(error: &str) -> &str {
    match error.rsplit_once(": ") {
        Some((_, cause)) => cause,
        None => error,
    }
}

fn summarize_error(error: &str) -> &str {
    match error.split_once(": ") {
        Some((summary, _)) => summary,
        None => error,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use quinn::ConnectionError;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use tracing_subscriber::fmt::writer::MakeWriter;

    use super::{
        AcmeEvent, AcmeRole, ClientRouteOutcome, ClientTunnelAttemptKind, ClientTunnelPhase,
        EventLevel, InstallOutcome, ServerRouteOutcome, acme, build_subscriber,
        client_graceful_shutdown_closing_tunnel_connection, client_graceful_shutdown_started,
        client_ready, client_route, client_trust_store_warning, client_tunnel_closed,
        client_tunnel_connect_failed, client_tunnel_connected, client_tunnel_connecting,
        client_tunnel_disconnected, client_tunnel_resolution_failed, client_tunnel_unauthorized,
        emit, emit_server_tunnel_connection_dropped, install, installed_level,
        managed_session_event, server_graceful_shutdown_deadline_expired,
        server_orderly_shutdown_closing_tunnel_connections, server_orderly_shutdown_escalated,
        server_orderly_shutdown_started, server_public_listener_ready, server_readiness_gained,
        server_readiness_listener_enabled, server_readiness_lost, server_route,
        server_route_rejected_client_hello, server_tunnel_connection_accepted,
        server_tunnel_connection_failed, server_tunnel_connection_terminated,
        server_tunnel_connection_unauthorized, server_tunnel_listener_ready, warning,
    };
    use crate::{
        ClientHelloError, ClientIdentity, LogLevel, ManagedSessionEvent, ManagedSessionRole,
        ShutdownMode, SnapshotEnvelope,
    };

    static INSTALL_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(SharedBuffer);

    impl SharedBuffer {
        fn read(&self) -> String {
            String::from_utf8(self.0.lock().expect("buffer mutex poisoned").clone())
                .expect("runtime log output must be valid UTF-8")
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .0
                .lock()
                .expect("buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(self.clone())
        }
    }

    fn capture(level: LogLevel, emit_logs: impl FnOnce()) -> String {
        capture_with_ansi(level, false, emit_logs)
    }

    fn capture_with_ansi(level: LogLevel, ansi: bool, emit_logs: impl FnOnce()) -> String {
        let buffer = SharedBuffer::default();
        let (subscriber, _) = build_subscriber(level, buffer.clone(), ansi);
        tracing::subscriber::with_default(subscriber, emit_logs);
        buffer.read()
    }

    #[test]
    fn off_level_suppresses_runtime_events() {
        let output = capture(LogLevel::Off, || {
            emit(
                EventLevel::Info,
                "server route app.example.test -> forwarded",
            );
            warning("client", "tunnel connection lost");
        });

        assert!(output.is_empty());
    }

    #[test]
    fn info_level_filters_out_debug_routing_events_but_keeps_warn_routes() {
        let output = capture(LogLevel::Info, || {
            emit(EventLevel::Debug, "debug detail");
            client_route(
                "app.example.test",
                ClientRouteOutcome::Passthrough {
                    backend_address: "127.0.0.1:8443",
                },
            );
            client_route(
                "api.example.test",
                ClientRouteOutcome::RejectedNoMatchingService,
            );
            warning("client", "tunnel connection lost");
        });

        assert!(!output.contains("debug detail"));
        assert!(!output.contains(
            "client route passthrough: public-hostname=app.example.test backend-address=127.0.0.1:8443"
        ));
        assert!(output.contains(
            "WARN client route unavailable: public-hostname=api.example.test reason=no-matching-service"
        ));
        assert!(output.contains("client warning: tunnel connection lost"));
    }

    #[test]
    fn debug_level_keeps_debug_routing_events() {
        let output = capture(LogLevel::Debug, || {
            emit(EventLevel::Debug, "debug detail");
            server_route("app.example.test", ServerRouteOutcome::Forwarded);
        });

        assert!(output.contains("debug detail"));
        assert!(output.contains("server route forwarded: public-hostname=app.example.test"));
    }

    #[test]
    fn managed_session_snapshot_logs_role_without_opaque_revision() {
        let output = capture(LogLevel::Info, || {
            managed_session_event(
                ManagedSessionRole::Client,
                &ManagedSessionEvent::Snapshot(SnapshotEnvelope {
                    revision: "control-supplied-secret".to_owned(),
                    input: serde_json::json!({}),
                }),
            );
        });

        assert!(output.contains("INFO managed session snapshot received: role=client"));
        assert!(!output.contains("control-supplied-secret"));
        assert!(!output.contains("revision="));
    }

    #[test]
    fn debug_level_emits_client_hello_reject_reasons() {
        let output = capture(LogLevel::Debug, || {
            server_route_rejected_client_hello(&ClientHelloError::InvalidTls);
            server_route_rejected_client_hello(&ClientHelloError::MissingSni);
        });

        assert!(output.contains("DEBUG server route rejected: reason=non-tls-client-hello"));
        assert!(output.contains("DEBUG server route rejected: reason=missing-sni-client-hello"));
    }

    #[test]
    fn warn_level_keeps_client_routing_availability_failures() {
        let output = capture(LogLevel::Warn, || {
            client_route(
                "app.example.test",
                ClientRouteOutcome::BackendConnectFailed {
                    backend_address: "127.0.0.1:8443",
                },
            );
            client_route(
                "app.example.test",
                ClientRouteOutcome::BackendWriteFailed {
                    backend_address: "127.0.0.1:8443",
                },
            );
            client_route("app.example.test", ClientRouteOutcome::MissingTlsConfig);
        });

        assert!(output.contains(
            "WARN client route unavailable: public-hostname=app.example.test backend-address=127.0.0.1:8443 reason=backend-connect-failed"
        ));
        assert!(output.contains(
            "WARN client route unavailable: public-hostname=app.example.test backend-address=127.0.0.1:8443 reason=backend-write-failed"
        ));
        assert!(output.contains(
            "WARN client route unavailable: public-hostname=app.example.test reason=tls-config-missing"
        ));
    }

    #[test]
    fn formatter_includes_fixed_width_utc_rfc3339_timestamp_level_and_message() {
        let output = capture(LogLevel::Warn, || {
            client_route(
                "app.example.test",
                ClientRouteOutcome::RejectedNoMatchingService,
            );
        });
        let line = output
            .lines()
            .next()
            .expect("expected a formatted log line");
        let parts = line.split_whitespace().collect::<Vec<_>>();

        assert!(OffsetDateTime::parse(parts[0], &Rfc3339).is_ok());
        assert!(parts[0].ends_with('Z'));
        let (_, time_and_zone) = parts[0]
            .split_once('T')
            .expect("timestamp should separate date and time");
        let (time_part, _) = time_and_zone
            .split_once('Z')
            .expect("timestamp should end with Z");
        let (_, fractional) = time_part
            .split_once('.')
            .expect("timestamp should include fractional seconds");
        assert_eq!(fractional.len(), 6);
        assert_eq!(parts[1], "WARN");
        assert_eq!(
            parts[2..].join(" "),
            "client route unavailable: public-hostname=app.example.test reason=no-matching-service"
        );
    }

    #[test]
    fn formatter_disables_ansi_when_not_requested() {
        let output = capture_with_ansi(LogLevel::Warn, false, || {
            emit(
                EventLevel::Warn,
                "client route: public-hostname=app.example.test",
            );
        });

        assert!(!output.contains("\u{1b}["));
    }

    #[test]
    fn formatter_can_enable_ansi_when_requested() {
        let output = capture_with_ansi(LogLevel::Warn, true, || {
            emit(
                EventLevel::Warn,
                "client route: public-hostname=app.example.test",
            );
        });

        assert!(output.contains("\u{1b}["));
    }

    #[test]
    fn install_is_safe_to_repeat_for_current_process_model() {
        let _guard = INSTALL_LOCK.lock().expect("install mutex poisoned");

        let first = install(LogLevel::Info).expect("first install should succeed");
        assert!(matches!(
            first,
            InstallOutcome::Installed | InstallOutcome::Updated
        ));
        assert_eq!(installed_level(), Some(LogLevel::Info));

        let second = install(LogLevel::Debug).expect("second install should succeed");
        assert_eq!(second, InstallOutcome::Updated);
        assert_eq!(installed_level(), Some(LogLevel::Debug));
    }

    #[test]
    fn client_tunnel_lifecycle_logs_use_shared_field_style_and_trim_resolved_addresses() {
        let configured_server_addr = "tunnel.example.test:443";
        let resolved_server_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = capture(LogLevel::Info, || {
            client_tunnel_connecting(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                5,
                "DNS timeout",
            );
            client_tunnel_connecting(
                ClientTunnelPhase::Reconnecting,
                ClientTunnelAttemptKind::Retry,
                configured_server_addr,
                resolved_server_addr,
            );
            client_tunnel_connected(
                ClientTunnelPhase::Reconnecting,
                configured_server_addr,
                resolved_server_addr,
            );
            client_ready(configured_server_addr);
            client_tunnel_closed(configured_server_addr, resolved_server_addr, 5);
            client_tunnel_disconnected(
                configured_server_addr,
                resolved_server_addr,
                5,
                "connection reset by peer",
            );
            client_trust_store_warning(2);
        });

        assert!(output.contains(
            "INFO client tunnel connection connecting: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443"
        ));
        assert!(output.contains(
            "ERROR client tunnel connection failed: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443 retry=initial next-retry-delay=5s: DNS timeout"
        ));
        assert!(output.contains(
            "INFO client tunnel connection retrying: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443 retry=retry"
        ));
        assert!(output.contains(
            "INFO client tunnel connection connected: server-address=tunnel.example.test:443"
        ));
        assert!(output.contains("INFO client ready: server-address=tunnel.example.test:443"));
        assert!(output.contains(
            "INFO client tunnel connection closed: server-address=tunnel.example.test:443 next-retry-delay=5s"
        ));
        assert!(output.contains(
            "WARN client tunnel connection dropped: server-address=tunnel.example.test:443 next-retry-delay=5s: connection reset by peer"
        ));
        assert!(!output.contains(
            "INFO client tunnel connection connected: server-address=tunnel.example.test:443 resolved-address="
        ));
        assert!(!output.contains(
            "INFO client tunnel connection closed: server-address=tunnel.example.test:443 resolved-address="
        ));
        assert!(!output.contains(
            "WARN client tunnel connection dropped: server-address=tunnel.example.test:443 resolved-address="
        ));
        assert!(output.contains(
            "WARN 2 system trust-store certificate(s) could not be loaded; continuing with the successfully loaded trust anchors"
        ));
    }

    #[test]
    fn server_listener_ready_logs_render_distinct_lines() {
        let output = capture(LogLevel::Info, || {
            server_public_listener_ready("127.0.0.1:443".parse().unwrap());
            server_tunnel_listener_ready("127.0.0.1:443".parse().unwrap());
        });

        assert!(output.contains("INFO server public listener ready: bind-address=127.0.0.1:443"));
        assert!(output.contains("INFO server tunnel listener ready: bind-address=127.0.0.1:443"));
    }

    #[test]
    fn orderly_shutdown_and_readiness_logs_render_explicit_runtime_lines() {
        let output = capture(LogLevel::Info, || {
            server_readiness_listener_enabled("127.0.0.1:9000".parse().unwrap());
            server_readiness_gained("127.0.0.1:9000".parse().unwrap());
            server_orderly_shutdown_started(ShutdownMode::Graceful, Duration::from_secs(60));
            server_orderly_shutdown_escalated();
            server_readiness_lost("127.0.0.1:9000".parse().unwrap());
            server_graceful_shutdown_deadline_expired(2);
            server_orderly_shutdown_closing_tunnel_connections(ShutdownMode::Fast, 2);
            client_graceful_shutdown_started();
            client_graceful_shutdown_closing_tunnel_connection();
        });

        assert!(output.contains(
            "INFO server readiness listener enabled: bind-address=127.0.0.1:9000 kind=tcp-probe-only"
        ));
        assert!(output.contains("INFO server readiness gained: bind-address=127.0.0.1:9000"));
        assert!(output.contains(
            "INFO server orderly shutdown started: mode=graceful effective-graceful-duration=60s"
        ));
        assert!(output.contains("WARN server orderly shutdown escalated: mode=fast"));
        assert!(output.contains("INFO server readiness lost: bind-address=127.0.0.1:9000"));
        assert!(output.contains(
            "WARN server graceful shutdown deadline expired: active-tunnel-connections=2"
        ));
        assert!(output.contains(
            "INFO server orderly shutdown closing tunnel connections: mode=fast active-tunnel-connections=2"
        ));
        assert!(output.contains("INFO client instance graceful shutdown started"));
        assert!(
            output.contains("INFO client instance graceful shutdown closing tunnel connection")
        );
    }

    #[test]
    fn acme_lifecycle_logs_use_role_specific_wording_and_levels() {
        let output = capture(LogLevel::Debug, || {
            acme(
                AcmeRole::Server {
                    server_hostname: "tunnel.example.test",
                },
                AcmeEvent::CachedCertificateReady {
                    remaining_validity: "89d",
                    renewal_due: false,
                },
            );
            acme(
                AcmeRole::Client {
                    public_hostname: "app.example.test",
                },
                AcmeEvent::FirstIssuanceStarting {
                    reason: "no-ready-cached-certificate",
                },
            );
            acme(
                AcmeRole::Client {
                    public_hostname: "api.example.test",
                },
                AcmeEvent::RenewalStarting {
                    reason: "expired-cached-certificate",
                },
            );
            acme(
                AcmeRole::Client {
                    public_hostname: "app.example.test",
                },
                AcmeEvent::RecoverableFailure {
                    error: "order: authorization for app.example.test failed too many times",
                },
            );
            acme(
                AcmeRole::Server {
                    server_hostname: "tunnel.example.test",
                },
                AcmeEvent::ManagerStopped,
            );
            acme(
                AcmeRole::Server {
                    server_hostname: "tunnel.example.test",
                },
                AcmeEvent::NonStandardPublicBind {
                    bind_address: "127.0.0.1:8443".parse().unwrap(),
                },
            );
            acme(
                AcmeRole::Client {
                    public_hostname: "app.example.test",
                },
                AcmeEvent::ChallengeHandled,
            );
        });

        assert!(output.contains(
            "INFO server acme cached certificate ready: server-hostname=tunnel.example.test remaining-validity=89d renewal=not-due"
        ));
        assert!(output.contains(
            "INFO client acme first issuance starting: public-hostname=app.example.test reason=no-ready-cached-certificate"
        ));
        assert!(output.contains(
            "INFO client acme renewal starting: public-hostname=api.example.test reason=expired-cached-certificate"
        ));
        assert!(output.contains(
            "WARN client acme failed: public-hostname=app.example.test: order: authorization for app.example.test failed too many times"
        ));
        assert!(output.contains(
            "ERROR server acme stopped: server-hostname=tunnel.example.test: automatic certificate management stopped unexpectedly"
        ));
        assert!(output.contains(
            "WARN server acme challenge reachability: bind-address=127.0.0.1:8443: TLS-ALPN-01 still requires public TCP 443 reachability; non-443 internal binds can still work behind NAT or container port mapping"
        ));
        assert!(
            output
                .contains("DEBUG client acme challenge handled: public-hostname=app.example.test")
        );
    }

    #[test]
    fn client_tunnel_failure_logs_drop_nested_error_detail() {
        let configured_server_addr = "tunnel.example.test:443";
        let resolved_server_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = capture(LogLevel::Info, || {
            client_tunnel_resolution_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                5,
                "failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known",
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                5,
                "client QUIC handshake failed: timed out",
            );
            client_tunnel_resolution_failed(
                ClientTunnelPhase::Reconnecting,
                ClientTunnelAttemptKind::Retry,
                configured_server_addr,
                5,
                "failed to resolve the Server hostname: temporary failure in name resolution",
            );
        });

        assert!(output.contains(
            "ERROR client tunnel resolution failed: server-address=tunnel.example.test:443 retry=initial next-retry-delay=5s: failed to resolve the Server hostname"
        ));
        assert!(output.contains(
            "ERROR client tunnel connection failed: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443 retry=initial next-retry-delay=5s: client QUIC handshake failed"
        ));
        assert!(output.contains(
            "WARN client tunnel resolution failed: server-address=tunnel.example.test:443 retry=retry next-retry-delay=5s: failed to resolve the Server hostname"
        ));
        assert!(!output.contains("after waiting 5s"));
        assert!(!output.contains("timed out"));
        assert!(!output.contains("failed to lookup address information"));
    }

    #[test]
    fn debug_level_keeps_full_client_tunnel_failure_detail_on_separate_lines() {
        let configured_server_addr = "tunnel.example.test:443";
        let resolved_server_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = capture(LogLevel::Debug, || {
            client_tunnel_resolution_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                5,
                "failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known",
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                5,
                "client QUIC handshake failed: timed out",
            );
        });

        assert!(output.contains(
            "ERROR client tunnel resolution failed: server-address=tunnel.example.test:443 retry=initial next-retry-delay=5s: failed to resolve the Server hostname"
        ));
        assert!(output.contains(
            "DEBUG client tunnel resolution failed detail: server-address=tunnel.example.test:443 retry=initial: failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known"
        ));
        assert!(output.contains(
            "ERROR client tunnel connection failed: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443 retry=initial next-retry-delay=5s: client QUIC handshake failed"
        ));
        assert!(output.contains(
            "DEBUG client tunnel connection failed detail: server-address=tunnel.example.test:443 resolved-address=203.0.113.10:443 retry=initial: client QUIC handshake failed: timed out"
        ));
    }

    #[test]
    fn live_tunnel_failure_logs_keep_short_causes_and_debug_detail() {
        let configured_server_addr = "tunnel.example.test:443";
        let resolved_server_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let client_identity = ClientIdentity::from_str(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let remote_addr: SocketAddr = "203.0.113.11:443".parse().unwrap();

        let info_output = capture(LogLevel::Info, || {
            client_tunnel_disconnected(
                configured_server_addr,
                resolved_server_addr,
                5,
                "closed by peer: transport error: timed out",
            );
            emit_server_tunnel_connection_dropped(
                &client_identity,
                "aborted by peer: transport error: peer sent malformed frame",
            );
        });

        assert!(info_output.contains(
            "WARN client tunnel connection dropped: server-address=tunnel.example.test:443 next-retry-delay=5s: timed out"
        ));
        assert!(info_output.contains(format!(
            "WARN server tunnel connection dropped: client-identity={client_identity}: peer sent malformed frame"
        ).as_str()));
        assert!(!info_output.contains("closed by peer: transport error: timed out"));
        assert!(
            !info_output.contains("aborted by peer: transport error: peer sent malformed frame")
        );

        let debug_output = capture(LogLevel::Debug, || {
            client_tunnel_disconnected(
                configured_server_addr,
                resolved_server_addr,
                5,
                "closed by peer: transport error: timed out",
            );
            emit_server_tunnel_connection_dropped(
                &client_identity,
                "aborted by peer: transport error: peer sent malformed frame",
            );
        });

        assert!(debug_output.contains(
            "DEBUG client tunnel connection dropped detail: server-address=tunnel.example.test:443: closed by peer: transport error: timed out"
        ));
        assert!(debug_output.contains(format!(
            "DEBUG server tunnel connection dropped detail: client-identity={client_identity}: aborted by peer: transport error: peer sent malformed frame"
        ).as_str()));
        assert!(!debug_output.contains(remote_addr.to_string().as_str()));
    }

    #[test]
    fn server_tunnel_lifecycle_logs_keep_remote_addresses_out_of_info_and_warn_lines() {
        let client_identity = ClientIdentity::from_str(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let first_remote_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = capture(LogLevel::Info, || {
            server_tunnel_connection_accepted(&client_identity);
            server_tunnel_connection_terminated(&client_identity, &ConnectionError::TimedOut);
            server_tunnel_connection_failed("handshake timed out");
        });

        assert!(
            output.contains(
                format!(
                    "INFO server tunnel connection accepted: client-identity={client_identity}"
                )
                .as_str()
            )
        );
        assert!(output.contains(format!(
            "WARN server tunnel connection dropped: client-identity={client_identity}: timed out"
        ).as_str()));
        assert!(output.contains("WARN server tunnel connection failed: handshake timed out"));
        assert!(!output.contains(first_remote_addr.to_string().as_str()));
    }

    #[test]
    fn unauthorized_tunnel_diagnostics_stay_concise_at_warn_and_keep_debug_detail() {
        let configured_server_addr = "tunnel.example.test:443";
        let client_identity = ClientIdentity::from_str(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        let info_output = capture(LogLevel::Info, || {
            client_tunnel_unauthorized(
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                1,
                "client QUIC handshake failed: peer doesn't support any known protocol",
            );
            server_tunnel_connection_unauthorized(&client_identity);
        });

        assert!(info_output.contains(
            "WARN client tunnel connection unauthorized: server-address=tunnel.example.test:443 retry=initial next-retry-delay=1s"
        ));
        assert!(
            info_output.contains(
                format!(
                    "WARN server tunnel connection unauthorized: client-identity={client_identity}"
                )
                .as_str()
            )
        );
        assert!(!info_output.contains("peer doesn't support any known protocol"));

        let debug_output = capture(LogLevel::Debug, || {
            client_tunnel_unauthorized(
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                1,
                "client QUIC handshake failed: invalid peer certificate: ApplicationVerificationFailure",
            );
        });

        assert!(debug_output.contains(
            "DEBUG client tunnel connection unauthorized detail: server-address=tunnel.example.test:443 retry=initial next-retry-delay=1s: client QUIC handshake failed: invalid peer certificate: ApplicationVerificationFailure"
        ));
    }
}
