//! The trace export stub for builds without the `otel` feature. Config loading rejects both
//! trace keys, so no [`Provider`] is ever built and no layer enables Runewarp trace spans.

use tracing_subscriber::layer::Identity;

use super::{TraceExportConfig, TraceRole};

/// No tracer provider exists without the `otel` feature.
#[derive(Clone, Debug)]
pub(crate) enum Provider {}

/// Fixed startup error for a trace key set in a build without the exporter.
pub(super) fn require_feature(key: &str) -> Result<(), String> {
    Err(format!(
        "{key} requires the otel feature, which this build does not include; rebuild with --features otel"
    ))
}

pub(crate) fn otlp_provider(
    _config: &TraceExportConfig,
    _role: TraceRole,
    _runtime: tokio::runtime::Handle,
) -> Result<Provider, String> {
    Err("this build does not include the otel feature".to_owned())
}

pub(crate) fn layer(provider: &Provider) -> Identity {
    match *provider {}
}

pub(crate) fn shutdown(provider: &Provider) {
    match *provider {}
}
