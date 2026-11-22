//! Client runtime metrics: `runewarp_client_*`, build and target info.

use std::fmt;
use std::sync::Arc;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::DescriptorEncoder;
use prometheus_client::metrics::gauge::Gauge;

use super::server::label_enum;
use super::{LabelValue, LabelledCounter, RuntimeIdentity, encode_gauge};

label_enum!(ClientTunnelAttemptOutcome, "outcome", {
    Connected => "connected",
    ResolutionFailed => "resolution_failed",
    Unauthorized => "unauthorized",
    WrongGeneration => "wrong_generation",
    Failed => "failed",
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
}

/// Visitor credit state across every Tunnel connection of one Client instance.
#[derive(Clone, Debug, Default)]
pub(crate) struct CreditGauges {
    /// Idle permit-backed credit currently offered to Servers.
    pub(crate) available: Gauge,
    /// Visitor streams holding a permit, from stream accept until both stream halves drop.
    pub(crate) active: Gauge,
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
        }))
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
