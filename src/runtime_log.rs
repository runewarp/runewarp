use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use quinn::ConnectionError;
use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt as tracing_fmt, reload};

use crate::client_hello::ClientHelloError;
use crate::{ClientIdentity, LogLevel};

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
    ImmediateRetry,
    IntervalRetry,
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

    let (subscriber, reload_filter) = build_subscriber(level, io::stderr);
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

pub fn server_tunnel_connection_accepted(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
) {
    emit(
        EventLevel::Info,
        &server_tunnel_connection_accepted_line(client_identity, remote_addr),
    );
}

pub fn server_tunnel_connection_replaced(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    previous_remote_addr: SocketAddr,
) {
    emit(
        EventLevel::Info,
        &server_tunnel_connection_replaced_line(client_identity, remote_addr, previous_remote_addr),
    );
}

pub fn server_tunnel_connection_terminated(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    error: &ConnectionError,
) {
    match error {
        ConnectionError::ApplicationClosed(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::LocallyClosed => emit(
            EventLevel::Info,
            &server_tunnel_connection_closed_line(client_identity, remote_addr),
        ),
        _ => {
            emit_server_tunnel_connection_dropped(client_identity, remote_addr, &error.to_string())
        }
    }
}

pub fn warning(role: &str, message: &str) {
    emit(EventLevel::Warn, &warning_line(role, message));
}

pub fn client_tunnel_connecting(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    retry_interval: Duration,
) {
    emit(
        EventLevel::Info,
        &client_tunnel_connecting_line(
            phase,
            attempt_kind,
            configured_server_addr,
            resolved_server_addr,
            retry_interval,
        ),
    );
}

pub fn client_tunnel_connect_failed(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    retry_interval: Duration,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &client_tunnel_connect_failed_line(
            phase,
            attempt_kind,
            configured_server_addr,
            resolved_server_addr,
            retry_interval,
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
    retry_interval: Duration,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &client_tunnel_resolution_failed_line(
            phase,
            attempt_kind,
            configured_server_addr,
            retry_interval,
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

pub fn client_tunnel_disconnected(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &client_tunnel_disconnected_line(configured_server_addr, resolved_server_addr, error),
        client_tunnel_disconnected_detail_line(configured_server_addr, resolved_server_addr, error),
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

#[cfg(test)]
pub(crate) fn installed_level() -> Option<LogLevel> {
    LOGGER
        .get()
        .map(|logger| *logger.level.lock().expect("runtime logger mutex poisoned"))
}

fn build_subscriber<W>(level: LogLevel, writer: W) -> (RuntimeSubscriber, ReloadFilter)
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let (filter_layer, reload_handle) = reload::Layer::new(level_filter(level));
    let subscriber = tracing_subscriber::registry().with(filter_layer).with(
        tracing_fmt::layer()
            .with_writer(writer)
            .with_timer(UtcTime::rfc_3339())
            .with_ansi(false)
            .with_target(false),
    );

    let reload_filter = Box::new(move |level| {
        reload_handle
            .reload(level_filter(level))
            .map_err(|error| InstallError::Reload(error.to_string()))
    });

    (Box::new(subscriber), reload_filter)
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

fn server_route_line(public_hostname: &str, outcome: &str) -> String {
    format!("server route {public_hostname} -> {outcome}")
}

fn client_route_line(public_hostname: &str, outcome: &str) -> String {
    format!("client route {public_hostname} -> {outcome}")
}

fn server_route_rejected_client_hello_line(reason: &str) -> String {
    format!("server route rejected -> {reason}")
}

fn server_route_event(public_hostname: &str, outcome: ServerRouteOutcome) -> (EventLevel, String) {
    let (level, outcome) = match outcome {
        ServerRouteOutcome::Forwarded => (
            EventLevel::Debug,
            "forwarded to active tunnel connection".to_owned(),
        ),
        ServerRouteOutcome::RejectedServerHostname => (
            EventLevel::Debug,
            "rejected non-ACME traffic for server hostname".to_owned(),
        ),
        ServerRouteOutcome::RejectedUnauthorized => (
            EventLevel::Debug,
            "rejected unauthorized public hostname".to_owned(),
        ),
        ServerRouteOutcome::NoActiveTunnelConnection => (
            EventLevel::Warn,
            "unavailable (no active tunnel connection)".to_owned(),
        ),
        ServerRouteOutcome::AcmeChallenge => (
            EventLevel::Debug,
            "handled ACME TLS-ALPN-01 challenge".to_owned(),
        ),
        ServerRouteOutcome::MissingAcmeTlsConfig => (
            EventLevel::Warn,
            "ACME challenge unavailable (TLS config missing)".to_owned(),
        ),
    };
    (level, server_route_line(public_hostname, &outcome))
}

fn server_route_rejected_client_hello_event(error: &ClientHelloError) -> (EventLevel, String) {
    let reason = match error {
        ClientHelloError::InvalidTls => "rejected non-TLS client hello",
        ClientHelloError::MissingSni => "rejected TLS client hello without SNI",
        ClientHelloError::InvalidSni => "rejected TLS client hello with invalid SNI",
        ClientHelloError::TooLong { .. } => "rejected oversized TLS client hello",
        ClientHelloError::UnexpectedEof => "rejected incomplete or non-TLS client hello",
        ClientHelloError::Io(_) => "rejected client hello after IO error",
    };
    (
        EventLevel::Debug,
        server_route_rejected_client_hello_line(reason),
    )
}

fn client_route_event(
    public_hostname: &str,
    outcome: ClientRouteOutcome<'_>,
) -> (EventLevel, String) {
    let (level, outcome) = match outcome {
        ClientRouteOutcome::Passthrough { backend_address } => (
            EventLevel::Debug,
            format!("passthrough to {backend_address}"),
        ),
        ClientRouteOutcome::Terminated { backend_address } => (
            EventLevel::Debug,
            format!("terminated TLS and forwarded to {backend_address}"),
        ),
        ClientRouteOutcome::RejectedNoMatchingService => (
            EventLevel::Warn,
            "unavailable (no matching client service)".to_owned(),
        ),
        ClientRouteOutcome::BackendConnectFailed { backend_address } => (
            EventLevel::Warn,
            format!("backend connect failed for {backend_address}"),
        ),
        ClientRouteOutcome::BackendWriteFailed { backend_address } => (
            EventLevel::Warn,
            format!("backend write failed for {backend_address}"),
        ),
        ClientRouteOutcome::MissingTlsConfig => (
            EventLevel::Warn,
            "terminate mode unavailable (TLS config missing)".to_owned(),
        ),
    };
    (level, client_route_line(public_hostname, outcome.as_ref()))
}

fn warning_line(role: &str, message: &str) -> String {
    format!("{role} warning: {message}")
}

fn server_tunnel_connection_accepted_line(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
) -> String {
    format!(
        "server tunnel connection accepted: client-identity={client_identity} remote-address={remote_addr}"
    )
}

fn server_tunnel_connection_replaced_line(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    previous_remote_addr: SocketAddr,
) -> String {
    format!(
        "server tunnel connection replaced: client-identity={client_identity} remote-address={remote_addr} previous-remote-address={previous_remote_addr}"
    )
}

fn server_tunnel_connection_closed_line(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
) -> String {
    format!(
        "server tunnel connection closed: client-identity={client_identity} remote-address={remote_addr}"
    )
}

fn emit_server_tunnel_connection_dropped(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    error: &str,
) {
    emit_runtime_failure_with_debug_detail(
        EventLevel::Warn,
        &server_tunnel_connection_dropped_line(client_identity, remote_addr, error),
        server_tunnel_connection_dropped_detail_line(client_identity, remote_addr, error),
        error,
    );
}

fn server_tunnel_connection_dropped_line(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    error: &str,
) -> String {
    format!(
        "server tunnel connection dropped: client-identity={client_identity} remote-address={remote_addr}: {}",
        summarize_live_connection_error(error)
    )
}

fn server_tunnel_connection_dropped_detail_line(
    client_identity: &ClientIdentity,
    remote_addr: SocketAddr,
    error: &str,
) -> String {
    format!(
        "server tunnel connection dropped detail: client-identity={client_identity} remote-address={remote_addr}: {error}"
    )
}

fn client_tunnel_connecting_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    _retry_interval: Duration,
) -> String {
    let action = match (phase, attempt_kind) {
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::Initial) => {
            "client tunnel connecting".to_owned()
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::ImmediateRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::ImmediateRetry) => {
            "retrying client tunnel connection immediately".to_owned()
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::IntervalRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::IntervalRetry) => {
            "retrying client tunnel connection".to_owned()
        }
        (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::Initial) => {
            "client tunnel reconnecting".to_owned()
        }
    };
    format!("{action} to {configured_server_addr} (resolved {resolved_server_addr})")
}

fn client_tunnel_connect_failed_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    _retry_interval: Duration,
    error: &str,
) -> String {
    let attempt_label = client_tunnel_connect_attempt_label(phase, attempt_kind);
    format!(
        "{attempt_label} to {configured_server_addr} (resolved {resolved_server_addr}): {}",
        summarize_error(error)
    )
}

fn client_tunnel_resolution_failed_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    _retry_interval: Duration,
    error: &str,
) -> String {
    let attempt_label = client_tunnel_resolution_attempt_label(phase, attempt_kind);
    format!(
        "{attempt_label} for {configured_server_addr}: {}",
        summarize_error(error)
    )
}

fn client_tunnel_connected_line(
    phase: ClientTunnelPhase,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
) -> String {
    let action = match phase {
        ClientTunnelPhase::Establishing => "client tunnel connected",
        ClientTunnelPhase::Reconnecting => "client tunnel reconnected",
    };
    format!("{action} to {configured_server_addr} (resolved {resolved_server_addr})")
}

fn client_tunnel_disconnected_line(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) -> String {
    format!(
        "client tunnel disconnected from {configured_server_addr} (resolved {resolved_server_addr}): {}",
        summarize_live_connection_error(error)
    )
}

fn client_tunnel_disconnected_detail_line(
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) -> String {
    format!(
        "client tunnel disconnected detail from {configured_server_addr} (resolved {resolved_server_addr}): {error}"
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

fn client_tunnel_connect_attempt_label(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
) -> &'static str {
    match (phase, attempt_kind) {
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::Initial) => {
            "initial client tunnel connection failed"
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::ImmediateRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::ImmediateRetry) => {
            "immediate client tunnel retry failed"
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::IntervalRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::IntervalRetry) => {
            "client tunnel retry failed"
        }
        (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::Initial) => {
            "client tunnel reconnect failed"
        }
    }
}

fn client_tunnel_resolution_attempt_label(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
) -> &'static str {
    match (phase, attempt_kind) {
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::Initial) => {
            "initial client tunnel resolution failed"
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::ImmediateRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::ImmediateRetry) => {
            "immediate client tunnel retry resolution failed"
        }
        (ClientTunnelPhase::Establishing, ClientTunnelAttemptKind::IntervalRetry)
        | (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::IntervalRetry) => {
            "client tunnel retry resolution failed"
        }
        (ClientTunnelPhase::Reconnecting, ClientTunnelAttemptKind::Initial) => {
            "client tunnel reconnect resolution failed"
        }
    }
}

fn client_tunnel_connect_failed_detail_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    resolved_server_addr: SocketAddr,
    error: &str,
) -> String {
    format!(
        "{} detail to {configured_server_addr} (resolved {resolved_server_addr}): {error}",
        client_tunnel_connect_attempt_label(phase, attempt_kind)
    )
}

fn client_tunnel_resolution_failed_detail_line(
    phase: ClientTunnelPhase,
    attempt_kind: ClientTunnelAttemptKind,
    configured_server_addr: &str,
    error: &str,
) -> String {
    format!(
        "{} detail for {configured_server_addr}: {error}",
        client_tunnel_resolution_attempt_label(phase, attempt_kind)
    )
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
        ClientRouteOutcome, ClientTunnelAttemptKind, ClientTunnelPhase, EventLevel, InstallOutcome,
        ServerRouteOutcome, build_subscriber, client_route, client_trust_store_warning,
        client_tunnel_connect_failed, client_tunnel_connected, client_tunnel_connecting,
        client_tunnel_disconnected, client_tunnel_resolution_failed, emit,
        emit_server_tunnel_connection_dropped, install, installed_level, server_route,
        server_route_rejected_client_hello, server_tunnel_connection_accepted,
        server_tunnel_connection_replaced, server_tunnel_connection_terminated, warning,
    };
    use crate::{ClientHelloError, ClientIdentity, LogLevel};

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
        let buffer = SharedBuffer::default();
        let (subscriber, _) = build_subscriber(level, buffer.clone());
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
        assert!(!output.contains("client route app.example.test -> passthrough to 127.0.0.1:8443"));
        assert!(output.contains(
            "WARN client route api.example.test -> unavailable (no matching client service)"
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
        assert!(
            output
                .contains("server route app.example.test -> forwarded to active tunnel connection")
        );
    }

    #[test]
    fn debug_level_emits_client_hello_reject_reasons() {
        let output = capture(LogLevel::Debug, || {
            server_route_rejected_client_hello(&ClientHelloError::InvalidTls);
            server_route_rejected_client_hello(&ClientHelloError::MissingSni);
        });

        assert!(output.contains("DEBUG server route rejected -> rejected non-TLS client hello"));
        assert!(
            output.contains("DEBUG server route rejected -> rejected TLS client hello without SNI")
        );
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
            "WARN client route app.example.test -> backend connect failed for 127.0.0.1:8443"
        ));
        assert!(output.contains(
            "WARN client route app.example.test -> backend write failed for 127.0.0.1:8443"
        ));
        assert!(output.contains(
            "WARN client route app.example.test -> terminate mode unavailable (TLS config missing)"
        ));
    }

    #[test]
    fn formatter_includes_utc_rfc3339_timestamp_level_and_message() {
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
        assert_eq!(parts[1], "WARN");
        assert_eq!(
            parts[2..].join(" "),
            "client route app.example.test -> unavailable (no matching client service)"
        );
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
    fn client_tunnel_lifecycle_logs_include_addresses_and_expected_levels() {
        let configured_server_addr = "tunnel.example.test:443";
        let resolved_server_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = capture(LogLevel::Info, || {
            client_tunnel_connecting(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                Duration::from_secs(5),
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                Duration::from_secs(5),
                "DNS timeout",
            );
            client_tunnel_connecting(
                ClientTunnelPhase::Reconnecting,
                ClientTunnelAttemptKind::IntervalRetry,
                configured_server_addr,
                resolved_server_addr,
                Duration::from_secs(5),
            );
            client_tunnel_connected(
                ClientTunnelPhase::Reconnecting,
                configured_server_addr,
                resolved_server_addr,
            );
            client_tunnel_disconnected(
                configured_server_addr,
                resolved_server_addr,
                "connection reset by peer",
            );
            client_trust_store_warning(2);
        });

        assert!(output.contains(
            "INFO client tunnel connecting to tunnel.example.test:443 (resolved 203.0.113.10:443)"
        ));
        assert!(output.contains(
            "WARN initial client tunnel connection failed to tunnel.example.test:443 (resolved 203.0.113.10:443): DNS timeout"
        ));
        assert!(output.contains(
            "INFO retrying client tunnel connection to tunnel.example.test:443 (resolved 203.0.113.10:443)"
        ));
        assert!(output.contains(
            "INFO client tunnel reconnected to tunnel.example.test:443 (resolved 203.0.113.10:443)"
        ));
        assert!(output.contains(
            "WARN client tunnel disconnected from tunnel.example.test:443 (resolved 203.0.113.10:443): connection reset by peer"
        ));
        assert!(output.contains(
            "WARN 2 system trust-store certificate(s) could not be loaded; continuing with the successfully loaded trust anchors"
        ));
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
                Duration::from_secs(5),
                "failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known",
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                Duration::from_secs(5),
                "client QUIC handshake failed: timed out",
            );
            client_tunnel_resolution_failed(
                ClientTunnelPhase::Reconnecting,
                ClientTunnelAttemptKind::IntervalRetry,
                configured_server_addr,
                Duration::from_secs(5),
                "failed to resolve the Server hostname: temporary failure in name resolution",
            );
        });

        assert!(output.contains(
            "WARN initial client tunnel resolution failed for tunnel.example.test:443: failed to resolve the Server hostname"
        ));
        assert!(output.contains(
            "WARN initial client tunnel connection failed to tunnel.example.test:443 (resolved 203.0.113.10:443): client QUIC handshake failed"
        ));
        assert!(output.contains(
            "WARN client tunnel retry resolution failed for tunnel.example.test:443: failed to resolve the Server hostname"
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
                Duration::from_secs(5),
                "failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known",
            );
            client_tunnel_connect_failed(
                ClientTunnelPhase::Establishing,
                ClientTunnelAttemptKind::Initial,
                configured_server_addr,
                resolved_server_addr,
                Duration::from_secs(5),
                "client QUIC handshake failed: timed out",
            );
        });

        assert!(output.contains(
            "WARN initial client tunnel resolution failed for tunnel.example.test:443: failed to resolve the Server hostname"
        ));
        assert!(output.contains(
            "DEBUG initial client tunnel resolution failed detail for tunnel.example.test:443: failed to resolve the Server hostname: failed to lookup address information: nodename nor servname provided, or not known"
        ));
        assert!(output.contains(
            "WARN initial client tunnel connection failed to tunnel.example.test:443 (resolved 203.0.113.10:443): client QUIC handshake failed"
        ));
        assert!(output.contains(
            "DEBUG initial client tunnel connection failed detail to tunnel.example.test:443 (resolved 203.0.113.10:443): client QUIC handshake failed: timed out"
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
                "closed by peer: transport error: timed out",
            );
            emit_server_tunnel_connection_dropped(
                &client_identity,
                remote_addr,
                "aborted by peer: transport error: peer sent malformed frame",
            );
        });

        assert!(info_output.contains(
            "WARN client tunnel disconnected from tunnel.example.test:443 (resolved 203.0.113.10:443): timed out"
        ));
        assert!(info_output.contains(format!(
            "WARN server tunnel connection dropped: client-identity={client_identity} remote-address={remote_addr}: peer sent malformed frame"
        ).as_str()));
        assert!(!info_output.contains("closed by peer: transport error: timed out"));
        assert!(
            !info_output.contains("aborted by peer: transport error: peer sent malformed frame")
        );

        let debug_output = capture(LogLevel::Debug, || {
            client_tunnel_disconnected(
                configured_server_addr,
                resolved_server_addr,
                "closed by peer: transport error: timed out",
            );
            emit_server_tunnel_connection_dropped(
                &client_identity,
                remote_addr,
                "aborted by peer: transport error: peer sent malformed frame",
            );
        });

        assert!(debug_output.contains(
            "DEBUG client tunnel disconnected detail from tunnel.example.test:443 (resolved 203.0.113.10:443): closed by peer: transport error: timed out"
        ));
        assert!(debug_output.contains(format!(
            "DEBUG server tunnel connection dropped detail: client-identity={client_identity} remote-address={remote_addr}: aborted by peer: transport error: peer sent malformed frame"
        ).as_str()));
    }

    #[test]
    fn server_tunnel_lifecycle_logs_include_identity_addresses_and_levels() {
        let client_identity = ClientIdentity::from_str(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let first_remote_addr: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let second_remote_addr: SocketAddr = "203.0.113.11:443".parse().unwrap();
        let output = capture(LogLevel::Info, || {
            server_tunnel_connection_accepted(&client_identity, first_remote_addr);
            server_tunnel_connection_replaced(
                &client_identity,
                second_remote_addr,
                first_remote_addr,
            );
            server_tunnel_connection_terminated(
                &client_identity,
                second_remote_addr,
                &ConnectionError::TimedOut,
            );
        });

        assert!(output.contains(format!(
            "INFO server tunnel connection accepted: client-identity={client_identity} remote-address={first_remote_addr}"
        ).as_str()));
        assert!(output.contains(format!(
            "INFO server tunnel connection replaced: client-identity={client_identity} remote-address={second_remote_addr} previous-remote-address={first_remote_addr}"
        ).as_str()));
        assert!(output.contains(format!(
            "WARN server tunnel connection dropped: client-identity={client_identity} remote-address={second_remote_addr}: timed out"
        ).as_str()));
    }
}
