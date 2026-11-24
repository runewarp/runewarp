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
//! and log events are never attached to spans.
//!
//! The exporter is the `otel` Cargo feature's only seam. This module holds what both builds
//! share: span names and attributes, [`TracedStage`], config validation and the log filter.
//! The backend behind [`Provider`], [`otlp_provider`], [`layer`] and [`shutdown`] is the
//! OpenTelemetry exporter with the feature, and an uninhabited stub without it. No other module
//! checks the feature.

use tracing::{Metadata, Span};

#[cfg(feature = "otel")]
#[path = "otel.rs"]
mod backend;
#[cfg(not(feature = "otel"))]
#[path = "disabled.rs"]
mod backend;

pub(crate) use backend::{Provider, layer, otlp_provider, shutdown};

/// `tracing` target of every exported span. The log formatter never shows spans with it.
pub(crate) const TARGET: &str = "runewarp::trace";

/// Span attribute recording how a root span ended.
pub(crate) const OUTCOME: &str = "runewarp.outcome";

/// Default path appended when `otlp-traces-endpoint` has no path.
const DEFAULT_TRACES_PATH: &str = "/v1/traces";

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

    /// Validate the top-level `otlp-traces-endpoint` and `trace-sample-ratio` keys. `None` when
    /// neither is set. Without the `otel` feature, setting either fails with a fixed error.
    pub(crate) fn from_config_keys(
        endpoint: Option<&str>,
        sample_ratio: Option<f64>,
    ) -> Result<Option<Self>, String> {
        let key = match (endpoint, sample_ratio) {
            (None, None) => return Ok(None),
            (Some(_), _) => "otlp-traces-endpoint",
            (None, Some(_)) => "trace-sample-ratio",
        };
        backend::require_feature(key)?;
        match endpoint {
            Some(endpoint) => Self::new(endpoint, sample_ratio).map(Some),
            None => Err("trace-sample-ratio requires otlp-traces-endpoint".to_owned()),
        }
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

#[cfg(test)]
pub(crate) mod test_support {
    #[cfg(feature = "otel")]
    pub(crate) use super::backend::test_support::*;

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
}

#[cfg(test)]
mod tests {
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
}
