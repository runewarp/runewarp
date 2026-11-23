//! Opt-in Prometheus/OpenMetrics instrumentation for one Server or Client runtime.
//!
//! Each runtime owns its own metric handles, so embedders and tests can run several runtimes in
//! one process without merging series. Every value is an atomic updated where state changes;
//! a scrape only loads atomics and never takes a lock or walks Tunnel pools. Labels come from
//! code-enumerated values only, so the series count is fixed per role. See `docs/metrics.md`.

mod client;
mod counted_io;
mod endpoint;
mod server;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric, NoLabelSet};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::{Registry, Unit};

pub(crate) use self::client::{
    BackendDirection, ClientMetrics, ClientTunnelAttemptOutcome, ClientVisitorRejectReason,
    CreditGauges,
};
pub(crate) use self::counted_io::CountedIo;
pub(crate) use self::endpoint::MetricsEndpoint;
pub(crate) use self::server::{
    AcmeMetricEvent, AdmissionInUse, ServerAdmissionGauges, ServerMetrics, TunnelCloseReason,
    TunnelRejectReason, VisitorCloseOutcome, VisitorDirection, VisitorRejectReason, VisitorTracker,
};

/// Crate version plus the short build commit for `-dev` builds, as `--version` prints it.
const SERVICE_VERSION: &str = env!("RUNEWARP_CLI_VERSION");
const BUILD_REVISION: &str = env!("RUNEWARP_BUILD_REVISION");

/// A code-enumerated label value set. `ALL` lists every value in index order.
pub(crate) trait LabelValue: Copy + Send + Sync + fmt::Debug + 'static {
    const KEY: &'static str;
    const ALL: &'static [Self];
    fn as_str(self) -> &'static str;
    fn index(self) -> usize;
}

/// One counter per label value, created up front so increments never touch a map or lock.
#[derive(Debug)]
pub(crate) struct LabelledCounter<L: LabelValue> {
    counters: Box<[Counter]>,
    _label: std::marker::PhantomData<L>,
}

impl<L: LabelValue> Default for LabelledCounter<L> {
    fn default() -> Self {
        Self {
            counters: L::ALL.iter().map(|_| Counter::default()).collect(),
            _label: std::marker::PhantomData,
        }
    }
}

impl<L: LabelValue> LabelledCounter<L> {
    pub(crate) fn inc(&self, label: L) {
        self.counters[label.index()].inc();
    }

    /// A handle on one label's counter, for hot paths that add without a lookup.
    pub(crate) fn get(&self, label: L) -> Counter {
        self.counters[label.index()].clone()
    }

    fn encode(&self, encoder: &mut DescriptorEncoder<'_>, name: &str, help: &str) -> fmt::Result {
        let mut metric = encoder.encode_descriptor(name, help, None, MetricType::Counter)?;
        for label in L::ALL {
            let labels = [(L::KEY, label.as_str())];
            let family = metric.encode_family(&labels)?;
            self.counters[label.index()].encode(family)?;
        }
        Ok(())
    }
}

/// Fixed-bucket histogram over atomics. Observation and scrape are lock-free; a scrape that
/// races an observation can see the bucket before the sum, which Prometheus tolerates.
#[derive(Debug)]
pub(crate) struct AtomicHistogram {
    upper_bounds: &'static [f64],
    buckets: Box<[AtomicU64]>,
    count: AtomicU64,
    sum_bits: AtomicU64,
}

impl AtomicHistogram {
    pub(crate) fn new(upper_bounds: &'static [f64]) -> Self {
        Self {
            upper_bounds,
            buckets: upper_bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_bits: AtomicU64::new(0_f64.to_bits()),
        }
    }

    pub(crate) fn observe(&self, value: f64) {
        if let Some(index) = self.upper_bounds.iter().position(|upper| value <= *upper) {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        // A CAS loop builds on every supported toolchain; `fetch_update` is deprecated on newer ones.
        let mut current = self.sum_bits.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(current) + value).to_bits();
            match self.sum_bits.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn encode(
        &self,
        encoder: &mut DescriptorEncoder<'_>,
        name: &str,
        help: &str,
        unit: &Unit,
    ) -> fmt::Result {
        // The encoder accumulates per-bucket counts itself.
        let mut bucketed = 0;
        let mut buckets = Vec::with_capacity(self.upper_bounds.len() + 1);
        for (upper, bucket) in self.upper_bounds.iter().zip(self.buckets.iter()) {
            let count = bucket.load(Ordering::Relaxed);
            bucketed += count;
            buckets.push((*upper, count));
        }
        // A racing observation may show in a bucket before `count`; never report fewer.
        let count = self.count.load(Ordering::Relaxed).max(bucketed);
        buckets.push((f64::INFINITY, count - bucketed));
        let sum = f64::from_bits(self.sum_bits.load(Ordering::Relaxed));
        encoder
            .encode_descriptor(name, help, Some(unit), MetricType::Histogram)?
            .encode_histogram::<NoLabelSet>(sum, count, &buckets, None)
    }
}

fn encode_counter(
    encoder: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    counter: &Counter,
) -> fmt::Result {
    counter.encode(encoder.encode_descriptor(name, help, None, MetricType::Counter)?)
}

fn encode_gauge(
    encoder: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    unit: Option<&Unit>,
    value: i64,
) -> fmt::Result {
    encoder
        .encode_descriptor(name, help, unit, MetricType::Gauge)?
        .encode_gauge(&value)
}

fn encode_gauge_family(
    encoder: &mut DescriptorEncoder<'_>,
    name: &str,
    help: &str,
    label_key: &str,
    values: &[(&str, i64)],
) -> fmt::Result {
    let mut metric = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
    for (label, value) in values {
        let labels = [(label_key, *label)];
        metric.encode_family(&labels)?.encode_gauge(value)?;
    }
    Ok(())
}

/// Runtime identity shared by both roles: `runewarp_build_info` and OpenTelemetry `target_info`.
#[derive(Debug)]
struct RuntimeIdentity {
    role: &'static str,
    mode: &'static str,
    service_name: &'static str,
    instance_id: String,
}

impl RuntimeIdentity {
    fn encode(&self, encoder: &mut DescriptorEncoder<'_>) -> fmt::Result {
        let build = [
            ("version", env!("CARGO_PKG_VERSION")),
            ("revision", BUILD_REVISION),
            ("role", self.role),
            ("mode", self.mode),
        ];
        encoder
            .encode_descriptor(
                "runewarp_build",
                "Runewarp build and runtime shape.",
                None,
                MetricType::Info,
            )?
            .encode_info(&build)?;
        let target = [
            ("service_name", self.service_name),
            ("service_version", SERVICE_VERSION),
            ("service_instance_id", self.instance_id.as_str()),
        ];
        encoder
            .encode_descriptor(
                "target",
                "OpenTelemetry resource attributes for this runtime.",
                None,
                MetricType::Info,
            )?
            .encode_info(&target)
    }
}

fn admission_mode(managed: bool) -> &'static str {
    if managed { "managed" } else { "static" }
}

/// Render `collector` as OpenMetrics text. Only reads atomics.
pub(crate) fn render(collector: Arc<dyn Collector>) -> String {
    let mut registry = Registry::default();
    registry.register_collector(Box::new(SharedCollector(collector)));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)
        .expect("writing metrics to a String cannot fail");
    output
}

#[derive(Debug)]
struct SharedCollector(Arc<dyn Collector>);

impl Collector for SharedCollector {
    fn encode(&self, encoder: DescriptorEncoder) -> fmt::Result {
        self.0.encode(encoder)
    }
}

/// Clamp a count into a gauge value.
pub(crate) fn gauge_value(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Gauge handle convenience: set from a bool.
fn set_flag(gauge: &Gauge, value: bool) {
    gauge.set(i64::from(value));
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Value of the first sample whose name and labels match `series` exactly, e.g.
    /// `runewarp_server_tunnel_connections_closed_total{reason="closed"}`.
    pub(crate) fn sample(text: &str, series: &str) -> Option<f64> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.rsplit_once(' ')?;
                (name == series).then(|| value.parse().ok()).flatten()
            })
    }

    /// Every label value present for `metric`'s `key` label, in output order.
    pub(crate) fn label_values(text: &str, metric: &str, key: &str) -> Vec<String> {
        let prefix = format!("{metric}{{");
        let needle = format!("{key}=\"");
        text.lines()
            .filter(|line| line.starts_with(&prefix))
            .filter_map(|line| {
                let start = line.find(&needle)? + needle.len();
                let end = line[start..].find('"')? + start;
                Some(line[start..end].to_owned())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::sample;
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Colour {
        Red,
        Blue,
    }

    impl LabelValue for Colour {
        const KEY: &'static str = "colour";
        const ALL: &'static [Self] = &[Self::Red, Self::Blue];
        fn as_str(self) -> &'static str {
            match self {
                Self::Red => "red",
                Self::Blue => "blue",
            }
        }
        fn index(self) -> usize {
            self as usize
        }
    }

    #[derive(Debug, Default)]
    struct Fixture {
        colours: LabelledCounter<Colour>,
    }

    #[derive(Debug)]
    struct HistogramFixture(AtomicHistogram);

    impl Collector for Fixture {
        fn encode(&self, mut encoder: DescriptorEncoder) -> fmt::Result {
            self.colours
                .encode(&mut encoder, "test_colours", "Colours.")
        }
    }

    impl Collector for HistogramFixture {
        fn encode(&self, mut encoder: DescriptorEncoder) -> fmt::Result {
            self.0
                .encode(&mut encoder, "test_duration", "Duration.", &Unit::Seconds)
        }
    }

    #[test]
    fn labelled_counter_emits_every_value_from_zero() {
        let fixture = Arc::new(Fixture::default());
        fixture.colours.inc(Colour::Blue);
        fixture.colours.inc(Colour::Blue);
        let text = render(fixture);
        assert_eq!(
            sample(&text, r#"test_colours_total{colour="red"}"#),
            Some(0.0)
        );
        assert_eq!(
            sample(&text, r#"test_colours_total{colour="blue"}"#),
            Some(2.0)
        );
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_end_at_count() {
        let histogram = AtomicHistogram::new(&[1.0, 10.0]);
        histogram.observe(0.5);
        histogram.observe(5.0);
        histogram.observe(50.0);
        let text = render(Arc::new(HistogramFixture(histogram)));
        assert_eq!(
            sample(&text, r#"test_duration_seconds_bucket{le="1.0"}"#),
            Some(1.0)
        );
        assert_eq!(
            sample(&text, r#"test_duration_seconds_bucket{le="10.0"}"#),
            Some(2.0)
        );
        assert_eq!(
            sample(&text, r#"test_duration_seconds_bucket{le="+Inf"}"#),
            Some(3.0)
        );
        assert_eq!(sample(&text, "test_duration_seconds_count"), Some(3.0));
        assert_eq!(sample(&text, "test_duration_seconds_sum"), Some(55.5));
    }
}
