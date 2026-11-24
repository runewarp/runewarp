//! Optional OTLP/HTTP span export for one Server or Client process.
//!
//! Runewarp creates a few spans under [`TARGET`]: the Server `visitor` span and its `intake`,
//! `route` and `stream_open` children, `tunnel_connection.handshake`, the Client
//! `client.tunnel_connect` and `client.visitor` spans, and `managed.apply` on both roles. With
//! no `otlp-traces-endpoint`, no layer enables that target, so the span macros are disabled at
//! their callsites and cost one cached interest check.
//!
//! Span attributes come only from code-enumerated values and runtime generations or Control
//! revisions. Hostnames, IP addresses, Client identities and Tunnel IDs never become attributes,
//! and log events are never attached to spans. JSON log lines inside a sampled span carry its
//! trace and span IDs, through [`log_ids`].

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use opentelemetry::KeyValue;
use opentelemetry::trace::{SpanId, TraceContextExt as _, TraceId, TracerProvider as _};
use opentelemetry_http::{HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider, SpanData, SpanExporter,
};
use tracing::{Dispatch, Event, Metadata, Span, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::registry::LookupSpan;

/// `tracing` target of every exported span. The log formatter never shows spans with it.
pub(crate) const TARGET: &str = "runewarp::trace";

/// Span attribute recording how a root span ended.
pub(crate) const OUTCOME: &str = "runewarp.outcome";

/// Default path appended when `otlp-traces-endpoint` has no path.
const DEFAULT_TRACES_PATH: &str = "/v1/traces";

/// At most this many finished spans wait for export. Further spans are dropped.
const MAX_QUEUE_SIZE: usize = 2048;
const MAX_EXPORT_BATCH_SIZE: usize = 512;
const SCHEDULED_DELAY: Duration = Duration::from_secs(5);
/// Bounds one HTTP attempt, including connect and the response body. The SDK may retry a failed
/// batch with backoff, and each attempt gets its own timeout.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Collectors answer with a small protobuf or status body.
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
/// At most one export-failure debug line per interval.
const EXPORT_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Which runtime exports spans. Sets the `service.name` resource attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceRole {
    /// A Server runtime. Its generation becomes the `service.instance.id` resource attribute,
    /// matching the `target_info` metric, so every exported span carries it.
    Server(crate::ServerRuntimeGeneration),
    /// A Client runtime. Its resource has no `service.instance.id`.
    Client,
}

impl TraceRole {
    fn service_name(self) -> &'static str {
        match self {
            Self::Server(_) => "runewarp-server",
            Self::Client => "runewarp-client",
        }
    }

    pub(crate) fn log_role(self) -> &'static str {
        match self {
            Self::Server(_) => "server",
            Self::Client => "client",
        }
    }
}

/// Validated `otlp-traces-endpoint` and `trace-sample-ratio`.
#[derive(Clone, Debug, PartialEq)]
pub struct TraceExportConfig {
    endpoint: http::Uri,
    sample_ratio: f64,
}

// `sample_ratio` is always finite, so equality is total.
impl Eq for TraceExportConfig {}

impl TraceExportConfig {
    /// The default `trace-sample-ratio`: export every Visitor.
    pub const DEFAULT_SAMPLE_RATIO: f64 = 1.0;

    /// Validate an `http` or `https` endpoint and a ratio from 0 to 1. An endpoint whose path is
    /// empty or `/` gets `/v1/traces`, keeping any query. Errors never repeat the endpoint, which
    /// may carry credentials.
    pub fn new(endpoint: &str, sample_ratio: Option<f64>) -> Result<Self, String> {
        let sample_ratio = sample_ratio.unwrap_or(Self::DEFAULT_SAMPLE_RATIO);
        if !(0.0..=1.0).contains(&sample_ratio) {
            return Err(format!(
                "trace-sample-ratio must be between 0 and 1, got {sample_ratio}"
            ));
        }
        let invalid = |reason: &str| format!("invalid otlp-traces-endpoint: {reason}");
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|error: http::uri::InvalidUri| invalid(&error.to_string()))?;
        // `InvalidUri` messages describe the failure without quoting the input.
        match uri.scheme_str() {
            Some("http" | "https") => {}
            _ => return Err(invalid("scheme must be http or https")),
        }
        let Some(authority) = uri.authority() else {
            return Err(invalid("missing host"));
        };
        if authority.as_str().contains('@') {
            return Err(invalid("credentials are not allowed in the URL"));
        }
        // `http::Uri` reads an omitted path as `/`, so the two cannot be told apart.
        let uri = if matches!(uri.path(), "" | "/") {
            let path_and_query = match uri.query() {
                Some(query) => format!("{DEFAULT_TRACES_PATH}?{query}"),
                None => DEFAULT_TRACES_PATH.to_owned(),
            };
            let mut parts = uri.into_parts();
            parts.path_and_query = Some(
                path_and_query
                    .parse()
                    .map_err(|error: http::uri::InvalidUri| invalid(&error.to_string()))?,
            );
            http::Uri::from_parts(parts).map_err(|error| invalid(&error.to_string()))?
        } else {
            uri
        };
        Ok(Self {
            endpoint: uri,
            sample_ratio,
        })
    }

    pub fn endpoint(&self) -> &http::Uri {
        &self.endpoint
    }

    pub fn sample_ratio(&self) -> f64 {
        self.sample_ratio
    }

    /// The endpoint without its query, for logs.
    fn display_endpoint(&self) -> String {
        format!(
            "{}://{}{}",
            self.endpoint.scheme_str().unwrap_or("http"),
            self.endpoint.authority().map_or("", |a| a.as_str()),
            self.endpoint.path()
        )
    }
}

/// A root span that records [`OUTCOME`] once. Dropping it unfinished records `cancelled`.
pub(crate) struct TracedStage {
    span: Span,
    finished: bool,
}

impl TracedStage {
    pub(crate) fn new(span: Span) -> Self {
        Self {
            span,
            finished: false,
        }
    }

    pub(crate) fn span(&self) -> &Span {
        &self.span
    }

    /// Record `outcome` and end the span, unless child spans still hold it open.
    pub(crate) fn finish(mut self, outcome: &'static str) {
        self.span.record(OUTCOME, outcome);
        self.finished = true;
    }

    /// Like [`Self::finish`], and set ERROR status so error ratios count the span. The status
    /// has no description, so no error text leaves the process.
    pub(crate) fn fail(self, outcome: &'static str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        self.span
            .set_status(opentelemetry::trace::Status::error(""));
        self.finish(outcome);
    }
}

impl Drop for TracedStage {
    fn drop(&mut self) {
        if !self.finished {
            self.span.record(OUTCOME, "cancelled");
        }
    }
}

/// Exported spans have [`TARGET`]. Every other span and every event stays local.
fn is_trace_span(metadata: &Metadata<'_>) -> bool {
    metadata.is_span() && metadata.target() == TARGET
}

/// `tracing` target prefix of the HTTP client that only the exporter uses. Its per-connection
/// diagnostics would repeat on every export retry, bypassing the rate-limited failure line.
const EXPORTER_HTTP_TARGET: &str = "hyper_util::client";

/// Whether the log formatter may see `metadata`. Runewarp trace spans and the exporter's HTTP
/// client diagnostics never appear in log lines.
pub(crate) fn visible_to_logs(metadata: &Metadata<'_>) -> bool {
    !is_trace_span(metadata) && !metadata.target().starts_with(EXPORTER_HTTP_TARGET)
}

/// The trace and span IDs of the Runewarp trace span nearest `event`, for log correlation. The
/// search starts at the event's explicit parent, else the current span, and skips spans from
/// other targets. `None` outside every trace span, for a sampled-out span, which is never
/// exported, or when `dispatch` has no trace layer.
pub(crate) fn log_ids(dispatch: &Dispatch, event: &Event<'_>) -> Option<(TraceId, SpanId)> {
    if event.is_root() {
        return None;
    }
    let registry = dispatch.downcast_ref::<tracing_subscriber::Registry>()?;
    let id = match event.parent() {
        Some(id) => id.clone(),
        None => registry.current_span().id()?.clone(),
    };
    let span = registry
        .span(&id)?
        .scope()
        .find(|span| is_trace_span(span.metadata()))?;
    let context = tracing_opentelemetry::get_otel_context(&span.id(), dispatch)?;
    let span = context.span();
    let span_context = span.span_context();
    span_context
        .is_sampled()
        .then(|| (span_context.trace_id(), span_context.span_id()))
}

/// The `tracing` layer that turns Runewarp trace spans into OpenTelemetry spans.
pub(crate) fn layer<S>(provider: &SdkTracerProvider) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("runewarp"))
        .with_location(false)
        .with_threads(false)
        .with_target(false)
        .with_tracked_inactivity(false)
        .with_context_activation(false)
        .with_filter(filter_fn(is_trace_span))
}

/// Build the process tracer provider: parent-based ratio sampling, a bounded batch queue that
/// drops when full, and OTLP/HTTP protobuf export through a client driven by `runtime`.
pub(crate) fn otlp_provider(
    config: &TraceExportConfig,
    role: TraceRole,
    runtime: tokio::runtime::Handle,
) -> Result<SdkTracerProvider, String> {
    let http_client = TokioHttpClient::new(runtime, config.endpoint.scheme_str() == Some("https"))?;
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.endpoint.to_string())
        .with_timeout(EXPORT_TIMEOUT)
        .with_http_client(http_client)
        .build()
        .map_err(|error| format!("trace exporter setup failed: {error}"))?;
    Ok(provider_builder(config.sample_ratio, role)
        .with_span_processor(batch_processor(exporter, role))
        .build())
}

/// The bounded batch processor: at most [`MAX_QUEUE_SIZE`] finished spans wait, and further
/// spans are dropped while the exporter is busy.
fn batch_processor<E>(exporter: E, role: TraceRole) -> BatchSpanProcessor
where
    E: SpanExporter + 'static,
{
    let batch = BatchConfigBuilder::default()
        .with_max_queue_size(MAX_QUEUE_SIZE)
        .with_max_export_batch_size(MAX_EXPORT_BATCH_SIZE)
        .with_scheduled_delay(SCHEDULED_DELAY)
        .build();
    BatchSpanProcessor::builder(ReportingExporter::new(exporter, role.log_role()))
        .with_batch_config(batch)
        .build()
}

fn provider_builder(
    sample_ratio: f64,
    role: TraceRole,
) -> opentelemetry_sdk::trace::TracerProviderBuilder {
    SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio,
        ))))
        .with_resource(resource(role))
}

/// Process resource: `service.name`, `service.version` and, for a Server, `service.instance.id`.
fn resource(role: TraceRole) -> Resource {
    let resource = Resource::builder_empty()
        .with_service_name(role.service_name())
        .with_attribute(KeyValue::new(
            "service.version",
            crate::metrics::SERVICE_VERSION,
        ));
    match role {
        TraceRole::Server(generation) => {
            resource.with_attribute(KeyValue::new("service.instance.id", generation.to_string()))
        }
        TraceRole::Client => resource,
    }
    .build()
}

/// Log the enabled exporter once at startup.
pub(crate) fn log_enabled(config: &TraceExportConfig, role: TraceRole) {
    crate::runtime_log::emit(
        crate::runtime_log::EventLevel::Info,
        &format!(
            "{} trace export enabled: endpoint={} sample-ratio={}",
            role.log_role(),
            config.display_endpoint(),
            config.sample_ratio
        ),
    );
}

/// Flush queued spans and stop the exporter thread, bounded by a timeout.
pub(crate) fn shutdown(provider: &SdkTracerProvider) {
    let _ = provider.shutdown_with_timeout(SHUTDOWN_TIMEOUT);
}

/// Wraps an exporter to report failures at debug, at most once per interval.
#[derive(Debug)]
struct ReportingExporter<E> {
    inner: E,
    role: &'static str,
    reporter: ExportErrorReporter,
}

impl<E> ReportingExporter<E> {
    fn new(inner: E, role: &'static str) -> Self {
        Self {
            inner,
            role,
            reporter: ExportErrorReporter::new(EXPORT_ERROR_LOG_INTERVAL),
        }
    }
}

impl<E: SpanExporter> SpanExporter for ReportingExporter<E> {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let result = self.inner.export(batch).await;
        if let Err(error) = &result
            && let Some(suppressed) = self.reporter.should_report(Instant::now())
        {
            crate::runtime_log::emit(
                crate::runtime_log::EventLevel::Debug,
                &format!(
                    "{} trace export failed: {error} suppressed={suppressed}",
                    self.role
                ),
            );
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// Rate limit for export-failure logs. Counts failures suppressed since the last report.
#[derive(Debug)]
struct ExportErrorReporter {
    interval: Duration,
    last_report: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
}

impl ExportErrorReporter {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_report: Mutex::new(None),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(suppressed)` when this failure should be logged.
    fn should_report(&self, now: Instant) -> Option<u64> {
        let mut last = self
            .last_report
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if last.is_some_and(|last| now.duration_since(last) < self.interval) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *last = Some(now);
        Some(self.suppressed.swap(0, Ordering::Relaxed))
    }
}

type HyperClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// OTLP HTTP client on the runtime's Tokio executor. The SDK exports from its own thread, so each
/// request runs as a Tokio task and the exporter thread only waits for it.
struct TokioHttpClient {
    runtime: tokio::runtime::Handle,
    client: HyperClient,
}

impl fmt::Debug for TokioHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioHttpClient")
            .finish_non_exhaustive()
    }
}

impl TokioHttpClient {
    fn new(runtime: tokio::runtime::Handle, https: bool) -> Result<Self, String> {
        let roots = if https {
            system_roots()
        } else {
            rustls::RootCertStore::empty()
        };
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("trace exporter TLS setup failed: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        Ok(Self { runtime, client })
    }
}

fn system_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    roots
}

#[async_trait::async_trait]
impl HttpClient for TokioHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let client = self.client.clone();
        let task = self.runtime.spawn(async move {
            let (parts, body) = request.into_parts();
            let request = Request::from_parts(parts, Full::new(body));
            let send = async {
                let response = client.request(request).await?;
                let (parts, body) = response.into_parts();
                let body = Limited::new(body, MAX_RESPONSE_BODY_BYTES)
                    .collect()
                    .await?
                    .to_bytes();
                Ok::<_, HttpError>(Response::from_parts(parts, body))
            };
            match tokio::time::timeout(EXPORT_TIMEOUT, send).await {
                Ok(result) => result,
                Err(_) => Err("OTLP request timed out".into()),
            }
        });
        task.await?
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::trace::{
        InMemorySpanExporter, SdkTracerProvider, SpanData, SpanExporter,
    };

    /// In-memory exporter that also keeps the provider's resource, which
    /// [`InMemorySpanExporter`] does not expose.
    #[derive(Clone, Debug, Default)]
    struct ResourceExporter {
        spans: InMemorySpanExporter,
        resource: Arc<Mutex<Option<Resource>>>,
    }

    impl SpanExporter for ResourceExporter {
        async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
            self.spans.export(batch).await
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            self.spans.shutdown_with_timeout(timeout)
        }

        fn set_resource(&mut self, resource: &Resource) {
            *self.resource.lock().expect("resource lock") = Some(resource.clone());
            self.spans.set_resource(resource);
        }
    }

    /// Captures exported spans synchronously for tests.
    pub(crate) struct CapturedSpans {
        provider: SdkTracerProvider,
        exporter: InMemorySpanExporter,
        resource: Arc<Mutex<Option<Resource>>>,
    }

    impl CapturedSpans {
        /// Capture as a Server with a fresh generation.
        pub(crate) fn new(sample_ratio: f64) -> Self {
            Self::with_role(
                sample_ratio,
                super::TraceRole::Server(crate::ServerRuntimeGeneration::generate()),
            )
        }

        pub(crate) fn with_role(sample_ratio: f64, role: super::TraceRole) -> Self {
            let exporter = ResourceExporter::default();
            let provider = super::provider_builder(sample_ratio, role)
                .with_simple_exporter(exporter.clone())
                .build();
            Self {
                provider,
                exporter: exporter.spans,
                resource: exporter.resource,
            }
        }

        /// A resource attribute every exported span carries.
        pub(crate) fn resource_attribute(&self, key: &str) -> Option<String> {
            self.resource
                .lock()
                .expect("resource lock")
                .as_ref()?
                .get(&opentelemetry::Key::from(key.to_owned()))
                .map(|value| value.to_string())
        }

        pub(crate) fn provider(&self) -> &SdkTracerProvider {
            &self.provider
        }

        pub(crate) fn finished(&self) -> Vec<SpanData> {
            self.exporter.get_finished_spans().unwrap_or_default()
        }

        pub(crate) fn names(&self) -> Vec<String> {
            self.finished()
                .into_iter()
                .map(|span| span.name.into_owned())
                .collect()
        }

        /// Install a thread-default subscriber with only the trace layer.
        pub(crate) fn set_default(&self) -> tracing::subscriber::DefaultGuard {
            use tracing_subscriber::layer::SubscriberExt;
            tracing::subscriber::set_default(
                tracing_subscriber::registry().with(super::layer(&self.provider)),
            )
        }

        pub(crate) fn span(&self, name: &str) -> Option<SpanData> {
            self.finished().into_iter().find(|span| span.name == name)
        }
    }

    /// Run the calling test alone in a child process and return whether this is that child.
    ///
    /// Callsite interest is process-wide. While only one scoped subscriber is live, `tracing`
    /// computes a new callsite's interest from the registering thread's own subscriber, so a
    /// parallel test can permanently disable spans another test captures.
    pub(crate) fn isolated(module_path: &str, test: &str) -> bool {
        const CHILD: &str = "RUNEWARP_TRACE_TEST_CHILD";
        let name = format!(
            "{}::{test}",
            module_path
                .strip_prefix("runewarp::")
                .unwrap_or(module_path)
        );
        if std::env::var(CHILD).is_ok_and(|child| child == name) {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", &name, "--test-threads=1"])
            .env(CHILD, &name)
            .output()
            .expect("run isolated test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated {name} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    /// Every attribute key Runewarp may export.
    pub(crate) const ALLOWED_ATTRIBUTES: &[&str] = &[
        super::OUTCOME,
        "runewarp.role",
        "runewarp.revision",
        "runewarp.server_generation",
        "runewarp.candidate",
    ];

    pub(crate) fn attribute(span: &SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .map(|attribute| attribute.value.to_string())
    }

    /// Assert that every attribute is allowlisted and none contains a forbidden value.
    pub(crate) fn assert_safe_attributes(spans: &[SpanData], forbidden: &[&str]) {
        for span in spans {
            for attribute in &span.attributes {
                assert!(
                    ALLOWED_ATTRIBUTES.contains(&attribute.key.as_str()),
                    "span {} exports unexpected attribute {}",
                    span.name,
                    attribute.key
                );
                let value = attribute.value.to_string();
                for forbidden in forbidden {
                    assert!(
                        !value.contains(forbidden),
                        "span {} attribute {} exports {forbidden}",
                        span.name,
                        attribute.key
                    );
                }
            }
            assert!(span.events.is_empty(), "span {} exports events", span.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{CapturedSpans, attribute};
    use super::*;

    #[test]
    fn config_accepts_http_and_https_and_defaults_the_path_and_ratio() {
        let config = TraceExportConfig::new("http://127.0.0.1:4318", None).expect("config");
        assert_eq!(
            config.endpoint().to_string(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(config.sample_ratio(), 1.0);

        let config = TraceExportConfig::new("https://otel.example.test/custom/traces", Some(0.25))
            .expect("config");
        assert_eq!(
            config.endpoint().to_string(),
            "https://otel.example.test/custom/traces"
        );
        assert_eq!(config.sample_ratio(), 0.25);

        for (endpoint, expected) in [
            ("http://h:4318/", "http://h:4318/v1/traces"),
            ("http://h:4318?tenant=a", "http://h:4318/v1/traces?tenant=a"),
            (
                "http://h:4318/?tenant=a",
                "http://h:4318/v1/traces?tenant=a",
            ),
            (
                "http://h:4318/custom?tenant=a",
                "http://h:4318/custom?tenant=a",
            ),
        ] {
            let config = TraceExportConfig::new(endpoint, None).expect("config");
            assert_eq!(config.endpoint().to_string(), expected, "{endpoint}");
        }
    }

    #[test]
    fn config_errors_never_repeat_the_endpoint() {
        for endpoint in [
            "http://user:secret-marker@otel.example.test/v1/traces",
            "grpc://otel.example.test/secret-marker",
            "http://otel.example.test/secret-marker with spaces",
        ] {
            let error = TraceExportConfig::new(endpoint, None).expect_err(endpoint);
            assert!(
                error.starts_with("invalid otlp-traces-endpoint: "),
                "{error}"
            );
            assert!(!error.contains("secret-marker"), "{error}");
        }
    }

    #[test]
    fn config_rejects_bad_endpoints_and_ratios() {
        for endpoint in [
            "otel.example.test:4318",
            "grpc://otel.example.test",
            "http://user:secret@otel.example.test/v1/traces",
            "/v1/traces",
            "not a url",
        ] {
            assert!(
                TraceExportConfig::new(endpoint, None).is_err(),
                "{endpoint} should be rejected"
            );
        }
        for ratio in [-0.1, 1.5, f64::NAN, f64::INFINITY] {
            assert!(
                TraceExportConfig::new("http://127.0.0.1:4318", Some(ratio)).is_err(),
                "{ratio} should be rejected"
            );
        }
    }

    #[test]
    fn logs_hide_only_runewarp_trace_spans() {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "logs_hide_only_runewarp_trace_spans",
        ) {
            return;
        }
        let captured = CapturedSpans::new(1.0);
        let _guard = captured.set_default();
        let trace_span = tracing::info_span!(target: TARGET, "probe");
        let other_span = tracing::info_span!("other");
        let trace_metadata = trace_span.metadata().expect("trace span is enabled");
        assert!(!visible_to_logs(trace_metadata));
        assert!(other_span.metadata().is_none_or(visible_to_logs));
    }

    #[test]
    fn server_resource_carries_the_runtime_generation_and_client_resource_has_no_instance() {
        let generation = crate::ServerRuntimeGeneration::generate();
        let server = CapturedSpans::with_role(1.0, TraceRole::Server(generation));
        assert_eq!(
            server.resource_attribute("service.instance.id"),
            Some(generation.to_string())
        );
        assert_eq!(
            server.resource_attribute("service.name").as_deref(),
            Some("runewarp-server")
        );

        let client = CapturedSpans::with_role(1.0, TraceRole::Client);
        assert_eq!(client.resource_attribute("service.instance.id"), None);
        assert_eq!(
            client.resource_attribute("service.name").as_deref(),
            Some("runewarp-client")
        );
    }

    #[test]
    fn exports_only_trace_target_spans_without_events() {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "exports_only_trace_target_spans_without_events",
        ) {
            return;
        }
        let captured = CapturedSpans::new(1.0);
        {
            let _guard = captured.set_default();
            let stage = TracedStage::new(tracing::info_span!(
                target: TARGET,
                "probe",
                runewarp.outcome = tracing::field::Empty
            ));
            let _entered = stage.span().clone().entered();
            tracing::info!("server routed Visitor stream: public-hostname=app.example.test");
            tracing::info_span!("untargeted").in_scope(|| {});
            drop(_entered);
            stage.finish("placed");
        }
        let spans = captured.finished();
        assert_eq!(captured.names(), vec!["probe".to_owned()]);
        assert_eq!(attribute(&spans[0], OUTCOME).as_deref(), Some("placed"));
        super::test_support::assert_safe_attributes(&spans, &["app.example.test"]);
    }

    #[test]
    fn dropped_stage_records_cancelled() {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "dropped_stage_records_cancelled",
        ) {
            return;
        }
        let captured = CapturedSpans::new(1.0);
        {
            let _guard = captured.set_default();
            drop(TracedStage::new(tracing::info_span!(
                target: TARGET,
                "probe",
                runewarp.outcome = tracing::field::Empty
            )));
        }
        let span = captured.span("probe").expect("probe span");
        assert_eq!(attribute(&span, OUTCOME).as_deref(), Some("cancelled"));
    }

    #[test]
    fn zero_ratio_samples_out_roots_and_their_children() {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "zero_ratio_samples_out_roots_and_their_children",
        ) {
            return;
        }
        let captured = CapturedSpans::new(0.0);
        {
            let _guard = captured.set_default();
            let root = tracing::info_span!(target: TARGET, "root");
            tracing::info_span!(target: TARGET, parent: &root, "child").in_scope(|| {});
        }
        assert!(captured.finished().is_empty());
    }

    /// Accept one HTTP/1 request and return its request line, content type and body length.
    async fn collector_once(
        listener: tokio::net::TcpListener,
    ) -> std::io::Result<(String, String, usize)> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let (socket, _) = listener.accept().await?;
        let mut reader = BufReader::new(socket);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
        let (mut content_type, mut length) = (String::new(), 0);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "content-type" => content_type = value.trim().to_owned(),
                    "content-length" => length = value.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await?;
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await?;
        Ok((request_line.trim_end().to_owned(), content_type, body.len()))
    }

    fn export_one_span(provider: &SdkTracerProvider) {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer(provider));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!(target: TARGET, "probe").in_scope(|| {});
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_provider_posts_protobuf_spans_to_the_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let collector = tokio::spawn(collector_once(listener));
        let config = TraceExportConfig::new(&endpoint, None)?;
        let provider = otlp_provider(
            &config,
            TraceRole::Client,
            tokio::runtime::Handle::current(),
        )?;

        export_one_span(&provider);
        let flushed = provider.clone();
        tokio::task::spawn_blocking(move || flushed.force_flush()).await??;
        let (request_line, content_type, length) =
            tokio::time::timeout(Duration::from_secs(5), collector).await???;

        assert_eq!(request_line, "POST /v1/traces HTTP/1.1");
        assert_eq!(content_type, "application/x-protobuf");
        assert!(length > 0);
        tokio::task::spawn_blocking(move || shutdown(&provider)).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unreachable_endpoint_fails_the_export_without_blocking_callers()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        drop(listener);
        let config = TraceExportConfig::new(&endpoint, None)?;
        let provider = otlp_provider(
            &config,
            TraceRole::Server(crate::ServerRuntimeGeneration::generate()),
            tokio::runtime::Handle::current(),
        )?;

        let started = Instant::now();
        for _ in 0..(MAX_QUEUE_SIZE * 2) {
            export_one_span(&provider);
        }
        // Span creation only enqueues; a full queue drops instead of waiting.
        assert!(started.elapsed() < Duration::from_secs(2));
        let flushed = provider.clone();
        // The SDK reports a flushed batch even when its export failed; it must still finish.
        tokio::time::timeout(
            EXPORT_TIMEOUT * 2,
            tokio::task::spawn_blocking(move || flushed.force_flush()),
        )
        .await??
        .ok();
        tokio::task::spawn_blocking(move || shutdown(&provider)).await?;
        Ok(())
    }

    /// Blocks its first export until released, and counts every exported span.
    #[derive(Debug)]
    struct BlockingExporter {
        exported: std::sync::Arc<AtomicU64>,
        started: std::sync::mpsc::SyncSender<()>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl SpanExporter for BlockingExporter {
        async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
            let release = self.release.lock().expect("release").take();
            if let Some(release) = release {
                let _ = self.started.send(());
                let _ = release.recv();
            }
            self.exported
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn a_busy_exporter_drops_spans_beyond_the_queue() {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "a_busy_exporter_drops_spans_beyond_the_queue",
        ) {
            return;
        }
        let exported = std::sync::Arc::new(AtomicU64::new(0));
        let (started, export_started) = std::sync::mpsc::sync_channel(1);
        let (release_export, release) = std::sync::mpsc::channel();
        let exporter = BlockingExporter {
            exported: exported.clone(),
            started,
            release: Mutex::new(Some(release)),
        };
        let role = TraceRole::Server(crate::ServerRuntimeGeneration::generate());
        let provider = provider_builder(1.0, role)
            .with_span_processor(batch_processor(exporter, role))
            .build();
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(layer(&provider));
        let emitted = MAX_EXPORT_BATCH_SIZE + 4 * MAX_QUEUE_SIZE;
        tracing::subscriber::with_default(subscriber, || {
            // A full batch starts an export, which then holds the exporter busy.
            for _ in 0..MAX_EXPORT_BATCH_SIZE {
                tracing::info_span!(target: TARGET, "probe").in_scope(|| {});
            }
            export_started
                .recv_timeout(Duration::from_secs(10))
                .expect("first export started");
            let started = Instant::now();
            for _ in MAX_EXPORT_BATCH_SIZE..emitted {
                tracing::info_span!(target: TARGET, "probe").in_scope(|| {});
            }
            assert!(started.elapsed() < Duration::from_secs(2));
        });
        release_export.send(()).expect("release");
        shutdown(&provider);

        let exported = exported.load(Ordering::Relaxed) as usize;
        assert!(
            (MAX_QUEUE_SIZE..=MAX_EXPORT_BATCH_SIZE * 2 + MAX_QUEUE_SIZE).contains(&exported),
            "exported {exported} of {emitted}"
        );
    }

    #[derive(Debug)]
    struct FailingExporter;

    impl SpanExporter for FailingExporter {
        async fn export(&self, _batch: Vec<SpanData>) -> OTelSdkResult {
            Err(opentelemetry_sdk::error::OTelSdkError::InternalFailure(
                "collector unreachable".to_owned(),
            ))
        }
    }

    #[test]
    fn export_failures_log_one_rate_limited_debug_line() {
        #[derive(Clone, Default)]
        struct Buffer(std::sync::Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish();
        let exporter = ReportingExporter::new(FailingExporter, "server");
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                let result = futures_util::FutureExt::now_or_never(exporter.export(Vec::new()));
                assert!(matches!(result, Some(Err(_))));
            }
        });
        let output = String::from_utf8(buffer.0.lock().expect("buffer").clone()).expect("utf8");
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "{output}");
        assert!(lines[0].contains("DEBUG"), "{output}");
        assert!(
            lines[0].ends_with(
                "server trace export failed: Operation failed: collector unreachable suppressed=0"
            ),
            "{output}"
        );
    }

    #[test]
    fn export_errors_report_once_per_interval_with_the_suppressed_count() {
        let reporter = ExportErrorReporter::new(Duration::from_secs(60));
        let start = Instant::now();
        assert_eq!(reporter.should_report(start), Some(0));
        assert_eq!(reporter.should_report(start + Duration::from_secs(1)), None);
        assert_eq!(reporter.should_report(start + Duration::from_secs(2)), None);
        assert_eq!(
            reporter.should_report(start + Duration::from_secs(61)),
            Some(2)
        );
    }
}
