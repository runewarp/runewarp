//! Server runtime metrics: `runewarp_server_*`, ACME events, build and target info.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use prometheus_client::collector::Collector;
use prometheus_client::encoding::DescriptorEncoder;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Unit;
use tokio::sync::Semaphore;

use super::{
    AtomicHistogram, LabelValue, LabelledCounter, RuntimeIdentity, encode_counter, encode_gauge,
    encode_gauge_family, gauge_value, set_flag,
};
use crate::ManagedSessionEvent;

/// Tunnel connection lifetimes span seconds (flapping) to days (healthy).
const TUNNEL_CONNECTION_DURATION_BUCKETS: &[f64] = &[
    1.0, 10.0, 60.0, 300.0, 1_800.0, 3_600.0, 21_600.0, 86_400.0, 604_800.0,
];
const UNKNOWN_EXPIRY: i64 = i64::MIN;

macro_rules! label_enum {
    ($name:ident, $key:literal, { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum $name { $($variant),+ }

        impl LabelValue for $name {
            const KEY: &'static str = $key;
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
            fn index(self) -> usize {
                self as usize
            }
        }
    };
}
pub(crate) use label_enum;

label_enum!(TunnelRejectReason, "reason", {
    Unauthorized => "unauthorized",
    HandshakeFailed => "handshake_failed",
    PoolFull => "pool_full",
    Shutdown => "shutdown",
});

label_enum!(TunnelCloseReason, "reason", {
    Closed => "closed",
    Dropped => "dropped",
    Replaced => "replaced",
    Shutdown => "shutdown",
});

label_enum!(ManagedEventLabel, "event", {
    Snapshot => "snapshot",
    Applying => "applying",
    Applied => "applied",
    Rejected => "rejected",
    Superseded => "superseded",
    Reconnecting => "reconnecting",
});

label_enum!(AcmeMetricEvent, "event", {
    OwnershipAcquired => "ownership_acquired",
    CertificateInstalled => "certificate_installed",
    Failure => "failure",
    MaintenanceStarted => "maintenance_started",
    ChallengeHandled => "challenge_handled",
});

/// Lock-free views of Server admission state. Per-source, per-Tunnel and per-identity limits
/// have no in-use series: their usage is per key, and keys are never labels.
#[derive(Debug, Default)]
pub(crate) struct ServerAdmissionGauges {
    /// Every limit, by label value, in a fixed order.
    pub(crate) limits: Vec<(&'static str, usize)>,
    pub(crate) in_use: Vec<(&'static str, AdmissionInUse)>,
}

#[derive(Debug)]
pub(crate) enum AdmissionInUse {
    /// `limit - available_permits`. Tokio reads available permits with one atomic load.
    Permits {
        semaphore: Arc<Semaphore>,
        limit: usize,
    },
    Count(Arc<AtomicUsize>),
}

impl AdmissionInUse {
    fn value(&self) -> usize {
        match self {
            Self::Permits { semaphore, limit } => {
                limit.saturating_sub(semaphore.available_permits())
            }
            Self::Count(count) => count.load(Ordering::Relaxed),
        }
    }
}

/// Shared handle for one Server runtime; clones update the same series.
#[derive(Clone, Debug)]
pub(crate) struct ServerMetrics(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    identity: RuntimeIdentity,
    managed: bool,
    admission: ServerAdmissionGauges,
    ready: Gauge,
    draining: Gauge,
    tunnel_connections: Gauge,
    tunnels_connected: Gauge,
    tunnel_connections_accepted: Counter,
    tunnel_connections_rejected: LabelledCounter<TunnelRejectReason>,
    tunnel_connections_closed: LabelledCounter<TunnelCloseReason>,
    tunnel_connection_duration: AtomicHistogram,
    managed_session_connected: Gauge,
    managed_session_events: LabelledCounter<ManagedEventLabel>,
    certificate_expiry: AtomicI64,
    acme_events: LabelledCounter<AcmeMetricEvent>,
}

impl ServerMetrics {
    /// `generation` is the Server runtime generation, exported as `service.instance.id`.
    pub(crate) fn new(
        generation: impl fmt::Display,
        managed: bool,
        admission: ServerAdmissionGauges,
    ) -> Self {
        Self(Arc::new(Inner {
            identity: RuntimeIdentity {
                role: "server",
                mode: super::admission_mode(managed),
                service_name: "runewarp-server",
                instance_id: generation.to_string(),
            },
            managed,
            admission,
            ready: Gauge::default(),
            draining: Gauge::default(),
            tunnel_connections: Gauge::default(),
            tunnels_connected: Gauge::default(),
            tunnel_connections_accepted: Counter::default(),
            tunnel_connections_rejected: LabelledCounter::default(),
            tunnel_connections_closed: LabelledCounter::default(),
            tunnel_connection_duration: AtomicHistogram::new(TUNNEL_CONNECTION_DURATION_BUCKETS),
            managed_session_connected: Gauge::default(),
            managed_session_events: LabelledCounter::default(),
            certificate_expiry: AtomicI64::new(UNKNOWN_EXPIRY),
            acme_events: LabelledCounter::default(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::new("test-generation", false, ServerAdmissionGauges::default())
    }

    pub(crate) fn collector(&self) -> Arc<dyn Collector> {
        self.0.clone()
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        set_flag(&self.0.ready, ready);
    }

    pub(crate) fn set_draining(&self) {
        set_flag(&self.0.draining, true);
    }

    pub(crate) fn tunnel_connection_accepted(&self) {
        self.0.tunnel_connections_accepted.inc();
        self.0.tunnel_connections.inc();
    }

    pub(crate) fn tunnel_connection_rejected(&self, reason: TunnelRejectReason) {
        self.0.tunnel_connections_rejected.inc(reason);
    }

    pub(crate) fn tunnel_connection_closed(&self, reason: TunnelCloseReason, lifetime: Duration) {
        self.0.tunnel_connections_closed.inc(reason);
        self.0.tunnel_connections.dec();
        self.0
            .tunnel_connection_duration
            .observe(lifetime.as_secs_f64());
    }

    /// A Tunnel pool's live member count moved from `before` to `after`.
    pub(crate) fn tunnel_pool_resized(&self, before: usize, after: usize) {
        match (before, after) {
            (0, 1..) => {
                self.0.tunnels_connected.inc();
            }
            (1.., 0) => {
                self.0.tunnels_connected.dec();
            }
            _ => {}
        }
    }

    pub(crate) fn managed_session_event(&self, event: &ManagedSessionEvent) {
        let label = match event {
            ManagedSessionEvent::Snapshot { .. } => ManagedEventLabel::Snapshot,
            ManagedSessionEvent::Applying { .. } => ManagedEventLabel::Applying,
            ManagedSessionEvent::Applied { .. } => ManagedEventLabel::Applied,
            ManagedSessionEvent::Rejected { .. } => ManagedEventLabel::Rejected,
            ManagedSessionEvent::Superseded { .. } => ManagedEventLabel::Superseded,
            ManagedSessionEvent::Reconnecting { .. } => ManagedEventLabel::Reconnecting,
        };
        self.0.managed_session_events.inc(label);
        // A validated snapshot proves an active downlink; reconnecting proves its loss.
        match label {
            ManagedEventLabel::Snapshot => set_flag(&self.0.managed_session_connected, true),
            ManagedEventLabel::Reconnecting => {
                set_flag(&self.0.managed_session_connected, false);
            }
            _ => {}
        }
    }

    pub(crate) fn set_certificate_expiry(&self, expires_at: SystemTime) {
        let seconds = match expires_at.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
        };
        self.0.certificate_expiry.store(seconds, Ordering::Relaxed);
    }

    pub(crate) fn acme_event(&self, event: AcmeMetricEvent) {
        self.0.acme_events.inc(event);
    }

    #[cfg(test)]
    pub(crate) fn render(&self) -> String {
        super::render(self.collector())
    }
}

impl Collector for Inner {
    fn encode(&self, mut encoder: DescriptorEncoder) -> fmt::Result {
        let e = &mut encoder;
        self.identity.encode(e)?;
        encode_gauge(
            e,
            "runewarp_server_ready",
            "1 while the Server admits new ingress.",
            None,
            self.ready.get(),
        )?;
        encode_gauge(
            e,
            "runewarp_server_draining",
            "1 once orderly shutdown or a Managed drain has started.",
            None,
            self.draining.get(),
        )?;
        encode_gauge(
            e,
            "runewarp_server_tunnel_connections",
            "Live accepted Tunnel connections.",
            None,
            self.tunnel_connections.get(),
        )?;
        encode_gauge(
            e,
            "runewarp_server_tunnels_connected",
            "Tunnels with at least one live Tunnel connection.",
            None,
            self.tunnels_connected.get(),
        )?;
        encode_counter(
            e,
            "runewarp_server_tunnel_connections_accepted",
            "Tunnel connections registered in a Tunnel pool.",
            &self.tunnel_connections_accepted,
        )?;
        self.tunnel_connections_rejected.encode(
            e,
            "runewarp_server_tunnel_connections_rejected",
            "Tunnel connections refused before registration, by reason.",
        )?;
        self.tunnel_connections_closed.encode(
            e,
            "runewarp_server_tunnel_connections_closed",
            "Accepted Tunnel connections that ended, by reason.",
        )?;
        self.tunnel_connection_duration.encode(
            e,
            "runewarp_server_tunnel_connection_duration",
            "Lifetime of accepted Tunnel connections.",
            &Unit::Seconds,
        )?;
        let in_use: Vec<_> = self
            .admission
            .in_use
            .iter()
            .map(|(limit, source)| (*limit, gauge_value(source.value())))
            .collect();
        encode_gauge_family(
            e,
            "runewarp_server_admission_in_use",
            "Work currently holding an aggregate admission limit.",
            "limit",
            &in_use,
        )?;
        let limits: Vec<_> = self
            .admission
            .limits
            .iter()
            .map(|(limit, value)| (*limit, gauge_value(*value)))
            .collect();
        encode_gauge_family(
            e,
            "runewarp_server_admission_limit",
            "Effective admission limits.",
            "limit",
            &limits,
        )?;
        if self.managed {
            encode_gauge(
                e,
                "runewarp_server_managed_session_connected",
                "1 while the Managed session has an active downlink.",
                None,
                self.managed_session_connected.get(),
            )?;
            self.managed_session_events.encode(
                e,
                "runewarp_server_managed_session_events",
                "Managed-session events, by event.",
            )?;
        }
        let expiry = self.certificate_expiry.load(Ordering::Relaxed);
        if expiry != UNKNOWN_EXPIRY {
            encode_gauge(
                e,
                "runewarp_server_certificate_expiry_timestamp",
                "Expiry of the serving Server certificate, as a Unix timestamp.",
                Some(&Unit::Seconds),
                expiry,
            )?;
        }
        self.acme_events.encode(
            e,
            "runewarp_acme_events",
            "Server certificate ACME events, by event.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{label_values, sample};
    use super::*;

    fn all<L: LabelValue>() -> Vec<String> {
        L::ALL
            .iter()
            .map(|label| label.as_str().to_owned())
            .collect()
    }

    #[test]
    fn labelled_series_expose_exactly_their_code_enumerated_values() {
        let metrics = ServerMetrics::new("generation", true, ServerAdmissionGauges::default());
        let text = metrics.render();
        assert_eq!(
            label_values(
                &text,
                "runewarp_server_tunnel_connections_rejected_total",
                "reason"
            ),
            ["unauthorized", "handshake_failed", "pool_full", "shutdown"]
        );
        assert_eq!(
            label_values(
                &text,
                "runewarp_server_tunnel_connections_closed_total",
                "reason"
            ),
            ["closed", "dropped", "replaced", "shutdown"]
        );
        assert_eq!(
            label_values(
                &text,
                "runewarp_server_managed_session_events_total",
                "event"
            ),
            [
                "snapshot",
                "applying",
                "applied",
                "rejected",
                "superseded",
                "reconnecting"
            ]
        );
        assert_eq!(
            label_values(&text, "runewarp_acme_events_total", "event"),
            [
                "ownership_acquired",
                "certificate_installed",
                "failure",
                "maintenance_started",
                "challenge_handled"
            ]
        );
        assert_eq!(all::<TunnelCloseReason>().len(), 4);
    }

    #[test]
    fn identity_series_carry_role_mode_and_generation() {
        let text = ServerMetrics::new("0193-gen", true, ServerAdmissionGauges::default()).render();
        let build = text
            .lines()
            .find(|line| line.starts_with("runewarp_build_info{"))
            .expect("build info");
        assert!(build.contains(r#"role="server""#), "{build}");
        assert!(build.contains(r#"mode="managed""#), "{build}");
        assert!(
            build.contains(&format!(r#"version="{}""#, env!("CARGO_PKG_VERSION"))),
            "{build}"
        );
        let target = text
            .lines()
            .find(|line| line.starts_with("target_info{"))
            .expect("target info");
        assert!(
            target.contains(r#"service_name="runewarp-server""#),
            "{target}"
        );
        assert!(
            target.contains(r#"service_instance_id="0193-gen""#),
            "{target}"
        );
        assert!(
            target.contains(&format!(
                r#"service_version="{}""#,
                env!("RUNEWARP_CLI_VERSION")
            )),
            "{target}"
        );
    }

    #[test]
    fn managed_series_are_absent_in_static_mode() {
        let text = ServerMetrics::for_test().render();
        assert!(!text.contains("managed_session"), "{text}");
        assert!(text.contains(r#"mode="static""#), "{text}");
    }

    #[test]
    fn managed_session_connected_follows_snapshot_and_reconnect() {
        let metrics = ServerMetrics::new("generation", true, ServerAdmissionGauges::default());
        let connected = "runewarp_server_managed_session_connected";
        assert_eq!(sample(&metrics.render(), connected), Some(0.0));
        metrics.managed_session_event(&ManagedSessionEvent::Snapshot {
            revision: "r1".to_owned(),
        });
        metrics.managed_session_event(&ManagedSessionEvent::Applied {
            revision: "r1".to_owned(),
        });
        let text = metrics.render();
        assert_eq!(sample(&text, connected), Some(1.0));
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_managed_session_events_total{event="applied"}"#
            ),
            Some(1.0)
        );
        metrics.managed_session_event(&ManagedSessionEvent::Reconnecting {
            display_delay_secs: 1,
        });
        assert_eq!(sample(&metrics.render(), connected), Some(0.0));
    }

    #[test]
    fn tunnels_connected_counts_pools_with_live_members() {
        let metrics = ServerMetrics::for_test();
        let series = "runewarp_server_tunnels_connected";
        metrics.tunnel_pool_resized(0, 1);
        metrics.tunnel_pool_resized(1, 2);
        metrics.tunnel_pool_resized(0, 1);
        assert_eq!(sample(&metrics.render(), series), Some(2.0));
        metrics.tunnel_pool_resized(2, 0);
        assert_eq!(sample(&metrics.render(), series), Some(1.0));
    }

    #[test]
    fn certificate_expiry_appears_once_known() {
        let metrics = ServerMetrics::for_test();
        let series = "runewarp_server_certificate_expiry_timestamp_seconds";
        assert_eq!(sample(&metrics.render(), series), None);
        metrics.set_certificate_expiry(SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000));
        assert_eq!(sample(&metrics.render(), series), Some(1_800_000_000.0));
    }

    #[test]
    fn admission_gauges_read_permits_and_counts_at_scrape() {
        let semaphore = Arc::new(Semaphore::new(4));
        let count = Arc::new(AtomicUsize::new(0));
        let metrics = ServerMetrics::new(
            "generation",
            false,
            ServerAdmissionGauges {
                limits: vec![("pending", 4), ("connections", 9)],
                in_use: vec![
                    (
                        "pending",
                        AdmissionInUse::Permits {
                            semaphore: semaphore.clone(),
                            limit: 4,
                        },
                    ),
                    ("connections", AdmissionInUse::Count(count.clone())),
                ],
            },
        );
        let _held = semaphore
            .clone()
            .try_acquire_many_owned(3)
            .expect("permits");
        count.store(2, Ordering::Relaxed);
        let text = metrics.render();
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_admission_in_use{limit="pending"}"#
            ),
            Some(3.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_admission_in_use{limit="connections"}"#
            ),
            Some(2.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_admission_limit{limit="connections"}"#
            ),
            Some(9.0)
        );
    }
}
