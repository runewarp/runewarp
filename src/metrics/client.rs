//! Client runtime metrics: `runewarp_client_*`, build and target info.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::DescriptorEncoder;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Unit;

use super::server::{LATENCY_BUCKETS, label_enum};
use super::{
    AtomicHistogram, LabelValue, LabelledCounter, RuntimeIdentity, encode_counter, encode_gauge,
};

label_enum!(ClientTunnelAttemptOutcome, "outcome", {
    Connected => "connected",
    ResolutionFailed => "resolution_failed",
    Unauthorized => "unauthorized",
    WrongGeneration => "wrong_generation",
    Failed => "failed",
});

label_enum!(ClientVisitorRejectReason, "reason", {
    NoService => "no_service",
    IntakeTimeout => "intake_timeout",
    ParseFailed => "parse_failed",
    Saturated => "saturated",
    NoCredit => "no_credit",
});

label_enum!(BackendDirection, "direction", {
    ToBackend => "to_backend",
    FromBackend => "from_backend",
});

/// Shared handle for one Client instance; clones update the same series.
#[derive(Clone, Debug)]
pub(crate) struct ClientMetrics(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    identity: RuntimeIdentity,
    tunnel_connections: Gauge,
    tunnel_connection_attempts: LabelledCounter<ClientTunnelAttemptOutcome>,
    credit: CreditGauges,
    visitors_active: Gauge,
    backend_connect_duration: AtomicHistogram,
    backend_connect_failures: Counter,
    backend_bytes: LabelledCounter<BackendDirection>,
}

/// Visitor credit state across every Tunnel connection of one Client instance.
#[derive(Clone, Debug, Default)]
pub(crate) struct CreditGauges {
    /// Idle permit-backed credit currently offered to Servers.
    pub(crate) available: Gauge,
    /// Visitor streams holding a permit, from stream accept until both stream halves drop.
    pub(crate) active: Gauge,
    /// Every Visitor stream a Server opened that reached this Client instance.
    visitors_handled: Counter,
    visitors_rejected: Arc<LabelledCounter<ClientVisitorRejectReason>>,
}

impl CreditGauges {
    /// A Visitor stream reset before any handler took it, such as for missing capacity.
    pub(crate) fn reject_unassigned(&self, reason: ClientVisitorRejectReason) {
        self.visitors_handled.inc();
        self.visitors_rejected.inc(reason);
    }
}

impl ClientMetrics {
    pub(crate) fn new(managed: bool) -> Self {
        Self(Arc::new(Inner {
            identity: RuntimeIdentity {
                role: "client",
                mode: super::admission_mode(managed),
                service_name: "runewarp-client",
                // A Client instance has no Server-issued generation; mint a per-process one.
                instance_id: uuid::Uuid::now_v7().to_string(),
            },
            tunnel_connections: Gauge::default(),
            tunnel_connection_attempts: LabelledCounter::default(),
            credit: CreditGauges::default(),
            visitors_active: Gauge::default(),
            backend_connect_duration: AtomicHistogram::new(LATENCY_BUCKETS),
            backend_connect_failures: Counter::default(),
            backend_bytes: LabelledCounter::default(),
        }))
    }

    /// Count a Visitor stream handed to a stream handler, active until the guard drops.
    pub(crate) fn visitor_handled(&self) -> ClientVisitor {
        self.0.credit.visitors_handled.inc();
        self.0.visitors_active.inc();
        ClientVisitor(self.clone())
    }

    pub(crate) fn backend_connected(&self, elapsed: Duration) {
        self.0
            .backend_connect_duration
            .observe(elapsed.as_secs_f64());
    }

    pub(crate) fn backend_connect_failed(&self) {
        self.0.backend_connect_failures.inc();
    }

    /// Counter for bytes moved through the backend socket in `direction`.
    pub(crate) fn backend_bytes(&self, direction: BackendDirection) -> Counter {
        self.0.backend_bytes.get(direction)
    }

    pub(crate) fn collector(&self) -> Arc<dyn Collector> {
        self.0.clone()
    }

    pub(crate) fn credit_gauges(&self) -> CreditGauges {
        self.0.credit.clone()
    }

    pub(crate) fn active_stream_handlers(&self) -> usize {
        usize::try_from(self.0.credit.active.get()).unwrap_or_default()
    }

    pub(crate) fn tunnel_connection_attempt(&self, outcome: ClientTunnelAttemptOutcome) {
        self.0.tunnel_connection_attempts.inc(outcome);
    }

    /// Count a live Tunnel connection until the returned guard drops.
    pub(crate) fn tunnel_connection_opened(&self) -> ClientTunnelConnectionGuard {
        self.0.tunnel_connections.inc();
        ClientTunnelConnectionGuard(self.0.tunnel_connections.clone())
    }

    #[cfg(test)]
    pub(crate) fn render(&self) -> String {
        super::render(self.collector())
    }
}

/// One Visitor stream inside a stream handler.
pub(crate) struct ClientVisitor(ClientMetrics);

impl ClientVisitor {
    pub(crate) fn reject(self, reason: ClientVisitorRejectReason) {
        self.0.0.credit.visitors_rejected.inc(reason);
    }
}

impl Drop for ClientVisitor {
    fn drop(&mut self) {
        self.0.0.visitors_active.dec();
    }
}

pub(crate) struct ClientTunnelConnectionGuard(Gauge);

impl Drop for ClientTunnelConnectionGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl Collector for Inner {
    fn encode(&self, mut encoder: DescriptorEncoder) -> fmt::Result {
        let e = &mut encoder;
        self.identity.encode(e)?;
        encode_gauge(
            e,
            "runewarp_client_tunnel_connections",
            "Live established Tunnel connections, including candidates.",
            None,
            self.tunnel_connections.get(),
        )?;
        self.tunnel_connection_attempts.encode(
            e,
            "runewarp_client_tunnel_connection_attempts",
            "Tunnel connection attempts, by outcome.",
        )?;
        encode_gauge(
            e,
            "runewarp_client_visitor_credit_available",
            "Idle Visitor credit offered to Servers.",
            None,
            self.credit.available.get(),
        )?;
        encode_gauge(
            e,
            "runewarp_client_stream_handlers_active",
            "Visitor streams currently holding a stream-handler permit.",
            None,
            self.credit.active.get(),
        )?;
        encode_counter(
            e,
            "runewarp_client_visitors_handled",
            "Visitor streams that reached this Client instance.",
            &self.credit.visitors_handled,
        )?;
        self.credit.visitors_rejected.encode(
            e,
            "runewarp_client_visitors_rejected",
            "Visitor streams dropped before reaching a backend, by reason.",
        )?;
        encode_gauge(
            e,
            "runewarp_client_visitors_active",
            "Visitor streams inside a stream handler.",
            None,
            self.visitors_active.get(),
        )?;
        self.backend_connect_duration.encode(
            e,
            "runewarp_client_backend_connect_duration",
            "Time to connect to the Local backend, for successful connects.",
            &Unit::Seconds,
        )?;
        encode_counter(
            e,
            "runewarp_client_backend_connect_failures",
            "Local backend connects that failed or timed out.",
            &self.backend_connect_failures,
        )?;
        self.backend_bytes.encode(
            e,
            "runewarp_client_backend_bytes",
            "Bytes moved through the Local backend socket, by direction.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{label_values, sample};
    use super::*;

    #[test]
    fn attempt_outcomes_expose_exactly_their_code_enumerated_values() {
        let metrics = ClientMetrics::new(false);
        metrics.tunnel_connection_attempt(ClientTunnelAttemptOutcome::Unauthorized);
        let text = metrics.render();
        assert_eq!(
            label_values(
                &text,
                "runewarp_client_tunnel_connection_attempts_total",
                "outcome"
            ),
            [
                "connected",
                "resolution_failed",
                "unauthorized",
                "wrong_generation",
                "failed"
            ]
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_client_tunnel_connection_attempts_total{outcome="unauthorized"}"#
            ),
            Some(1.0)
        );
    }

    #[test]
    fn visitor_series_expose_exactly_their_code_enumerated_values() {
        let text = ClientMetrics::new(false).render();
        assert_eq!(
            label_values(&text, "runewarp_client_visitors_rejected_total", "reason"),
            [
                "no_service",
                "intake_timeout",
                "parse_failed",
                "saturated",
                "no_credit"
            ]
        );
        assert_eq!(
            label_values(&text, "runewarp_client_backend_bytes_total", "direction"),
            ["to_backend", "from_backend"]
        );
        assert_eq!(
            label_values(
                &text,
                "runewarp_client_backend_connect_duration_seconds_bucket",
                "le"
            ),
            [
                "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25",
                "0.5", "1.0", "2.5", "5.0", "+Inf"
            ]
        );
        assert_eq!(
            sample(&text, "runewarp_client_backend_connect_failures_total"),
            Some(0.0)
        );
    }

    #[test]
    fn visitor_guard_counts_handled_and_active_until_dropped() {
        let metrics = ClientMetrics::new(false);
        let visitor = metrics.visitor_handled();
        assert_eq!(
            sample(&metrics.render(), "runewarp_client_visitors_active"),
            Some(1.0)
        );
        visitor.reject(ClientVisitorRejectReason::NoService);
        let text = metrics.render();
        assert_eq!(sample(&text, "runewarp_client_visitors_active"), Some(0.0));
        assert_eq!(
            sample(&text, "runewarp_client_visitors_handled_total"),
            Some(1.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_client_visitors_rejected_total{reason="no_service"}"#
            ),
            Some(1.0)
        );
    }

    #[test]
    fn credit_rejections_count_as_handled_and_rejected() {
        let metrics = ClientMetrics::new(false);
        let credit = metrics.credit_gauges();
        credit.reject_unassigned(ClientVisitorRejectReason::Saturated);
        credit.reject_unassigned(ClientVisitorRejectReason::NoCredit);
        let text = metrics.render();
        assert_eq!(
            sample(&text, "runewarp_client_visitors_handled_total"),
            Some(2.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_client_visitors_rejected_total{reason="saturated"}"#
            ),
            Some(1.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_client_visitors_rejected_total{reason="no_credit"}"#
            ),
            Some(1.0)
        );
        assert_eq!(sample(&text, "runewarp_client_visitors_active"), Some(0.0));
    }

    #[test]
    fn tunnel_connection_guard_counts_until_dropped() {
        let metrics = ClientMetrics::new(true);
        let series = "runewarp_client_tunnel_connections";
        let first = metrics.tunnel_connection_opened();
        let second = metrics.tunnel_connection_opened();
        assert_eq!(sample(&metrics.render(), series), Some(2.0));
        drop(first);
        assert_eq!(sample(&metrics.render(), series), Some(1.0));
        drop(second);
        assert_eq!(sample(&metrics.render(), series), Some(0.0));
    }

    #[test]
    fn identity_series_name_the_client_role() {
        let text = ClientMetrics::new(true).render();
        assert!(text.contains(r#"role="client""#), "{text}");
        assert!(text.contains(r#"mode="managed""#), "{text}");
        assert!(text.contains(r#"service_name="runewarp-client""#), "{text}");
    }
}
