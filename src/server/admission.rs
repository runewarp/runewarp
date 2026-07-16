use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::ClientIdentity;

const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const SATURATION_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ServerAdmissionLimits {
    pub(crate) client_hello_timeout: Duration,
    pub(crate) open_bi_timeout: Duration,
    pub(crate) max_pending_visitors: usize,
    pub(crate) max_pending_visitors_per_source: usize,
    pub(crate) max_pending_handshakes: usize,
    pub(crate) max_pending_stream_opens: usize,
    pub(crate) max_active_routed_streams: usize,
    pub(crate) max_tunnel_connections: usize,
    pub(crate) max_tunnel_connections_per_tunnel: usize,
    pub(crate) max_tunnel_connections_per_identity: usize,
}

impl Default for ServerAdmissionLimits {
    fn default() -> Self {
        Self {
            client_hello_timeout: Duration::from_secs(5),
            open_bi_timeout: Duration::from_secs(5),
            max_pending_visitors: 4_096,
            max_pending_visitors_per_source: 256,
            max_pending_handshakes: 256,
            max_pending_stream_opens: 1_024,
            max_active_routed_streams: 4_096,
            max_tunnel_connections: 4_096,
            max_tunnel_connections_per_tunnel: 256,
            max_tunnel_connections_per_identity: 64,
        }
    }
}

impl ServerAdmissionLimits {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            client_hello_timeout: Duration::from_millis(50),
            open_bi_timeout: Duration::from_millis(50),
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum AdmissionLimit {
    VisitorsGlobal,
    VisitorSource,
    Handshakes,
    PendingStreamOpens,
    ActiveRoutedStreams,
    TunnelConnectionsGlobal,
    TunnelConnectionsPerTunnel,
    TunnelConnectionsPerIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionRejection {
    pub(crate) limit: AdmissionLimit,
    pub(crate) active_work: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AdmissionLogOutcome {
    Saturation(AdmissionLimit),
    PublicAcceptRetry,
    TunnelHandshakeFailure,
}

#[derive(Clone)]
pub(crate) struct ServerAdmissionPolicy {
    limits: ServerAdmissionLimits,
    pending_visitors: Arc<Semaphore>,
    pending_visitors_by_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pending_handshakes: Arc<Semaphore>,
    pending_stream_opens: Arc<Semaphore>,
    active_routed_streams: Arc<Semaphore>,
    tunnel_connections: TunnelConnectionAdmission,
    log_gate: AdmissionLogGate,
}

impl ServerAdmissionPolicy {
    pub(crate) fn new(limits: ServerAdmissionLimits) -> Self {
        Self {
            pending_visitors: Arc::new(Semaphore::new(limits.max_pending_visitors)),
            pending_visitors_by_source: Arc::new(Mutex::new(HashMap::new())),
            pending_handshakes: Arc::new(Semaphore::new(limits.max_pending_handshakes)),
            pending_stream_opens: Arc::new(Semaphore::new(limits.max_pending_stream_opens)),
            active_routed_streams: Arc::new(Semaphore::new(limits.max_active_routed_streams)),
            tunnel_connections: TunnelConnectionAdmission::new(limits),
            log_gate: AdmissionLogGate::default(),
            limits,
        }
    }

    pub(crate) fn limits(&self) -> ServerAdmissionLimits {
        self.limits
    }

    #[cfg(test)]
    pub(crate) fn try_admit_visitor(
        &self,
        source: IpAddr,
    ) -> Result<VisitorAdmissionPermit, AdmissionRejection> {
        let mut permit = self.try_admit_visitor_global()?;
        permit.use_canonical_source(source, self.limits.max_pending_visitors_per_source)?;
        Ok(permit)
    }

    pub(crate) fn try_admit_visitor_global(
        &self,
    ) -> Result<VisitorAdmissionPermit, AdmissionRejection> {
        let global_permit = self
            .pending_visitors
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRejection {
                limit: AdmissionLimit::VisitorsGlobal,
                active_work: self.limits.max_pending_visitors
                    - self.pending_visitors.available_permits(),
            })?;
        Ok(VisitorAdmissionPermit {
            _global_permit: global_permit,
            source: None,
            pending_visitors_by_source: self.pending_visitors_by_source.clone(),
        })
    }

    pub(crate) fn try_admit_handshake(&self) -> Result<OwnedSemaphorePermit, AdmissionRejection> {
        self.pending_handshakes
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRejection {
                limit: AdmissionLimit::Handshakes,
                active_work: self.limits.max_pending_handshakes
                    - self.pending_handshakes.available_permits(),
            })
    }

    pub(crate) fn try_admit_pending_stream_open(
        &self,
    ) -> Result<OwnedSemaphorePermit, AdmissionRejection> {
        self.pending_stream_opens
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRejection {
                limit: AdmissionLimit::PendingStreamOpens,
                active_work: self.limits.max_pending_stream_opens
                    - self.pending_stream_opens.available_permits(),
            })
    }

    pub(crate) fn try_admit_active_routed_stream(
        &self,
    ) -> Result<OwnedSemaphorePermit, AdmissionRejection> {
        self.active_routed_streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRejection {
                limit: AdmissionLimit::ActiveRoutedStreams,
                active_work: self.limits.max_active_routed_streams
                    - self.active_routed_streams.available_permits(),
            })
    }

    pub(crate) fn tunnel_connections(&self) -> TunnelConnectionAdmission {
        self.tunnel_connections.clone()
    }

    pub(crate) fn should_log_saturation(&self, limit: AdmissionLimit) -> bool {
        self.log_gate
            .should_log(AdmissionLogOutcome::Saturation(limit), Instant::now())
    }

    pub(crate) fn take_recovered(&self, limit: AdmissionLimit) -> bool {
        self.log_gate
            .take_recovered(AdmissionLogOutcome::Saturation(limit))
    }

    pub(crate) fn should_log_public_accept_retry(&self) -> bool {
        self.log_gate
            .should_log(AdmissionLogOutcome::PublicAcceptRetry, Instant::now())
    }

    pub(crate) fn should_log_tunnel_handshake_failure(&self) -> bool {
        self.log_gate
            .should_log(AdmissionLogOutcome::TunnelHandshakeFailure, Instant::now())
    }

    pub(crate) fn take_tunnel_handshake_failure_recovered(&self) -> bool {
        self.log_gate
            .take_recovered(AdmissionLogOutcome::TunnelHandshakeFailure)
    }

    pub(crate) fn limit_value(&self, limit: AdmissionLimit) -> Option<usize> {
        match limit {
            AdmissionLimit::VisitorsGlobal => Some(self.limits.max_pending_visitors),
            AdmissionLimit::VisitorSource => Some(self.limits.max_pending_visitors_per_source),
            AdmissionLimit::Handshakes => Some(self.limits.max_pending_handshakes),
            AdmissionLimit::PendingStreamOpens => Some(self.limits.max_pending_stream_opens),
            AdmissionLimit::ActiveRoutedStreams => Some(self.limits.max_active_routed_streams),
            AdmissionLimit::TunnelConnectionsGlobal => Some(self.limits.max_tunnel_connections),
            AdmissionLimit::TunnelConnectionsPerTunnel => {
                Some(self.limits.max_tunnel_connections_per_tunnel)
            }
            AdmissionLimit::TunnelConnectionsPerIdentity => {
                Some(self.limits.max_tunnel_connections_per_identity)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct VisitorAdmissionPermit {
    _global_permit: OwnedSemaphorePermit,
    source: Option<IpAddr>,
    pending_visitors_by_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl VisitorAdmissionPermit {
    pub(crate) fn use_canonical_source(
        &mut self,
        source: IpAddr,
        maximum: usize,
    ) -> Result<(), AdmissionRejection> {
        if Some(source) == self.source {
            return Ok(());
        }
        let mut sources = self
            .pending_visitors_by_source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active = sources.get(&source).copied().unwrap_or_default();
        if active >= maximum {
            return Err(AdmissionRejection {
                limit: AdmissionLimit::VisitorSource,
                active_work: active,
            });
        }
        if let Some(previous_source) = self.source
            && let Some(previous) = sources.get_mut(&previous_source)
        {
            *previous -= 1;
            if *previous == 0 {
                sources.remove(&previous_source);
            }
        }
        *sources.entry(source).or_default() += 1;
        self.source = Some(source);
        Ok(())
    }
}

impl Drop for VisitorAdmissionPermit {
    fn drop(&mut self) {
        let mut sources = self
            .pending_visitors_by_source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(source) = self.source else {
            return;
        };
        let Some(active) = sources.get_mut(&source) else {
            return;
        };
        *active -= 1;
        if *active == 0 {
            sources.remove(&source);
        }
    }
}

#[derive(Clone)]
pub(crate) struct TunnelConnectionAdmission {
    limits: ServerAdmissionLimits,
    state: Arc<Mutex<TunnelConnectionAdmissionState>>,
}

#[derive(Default)]
struct TunnelConnectionAdmissionState {
    active: usize,
    active_by_identity: HashMap<ClientIdentity, usize>,
}

impl TunnelConnectionAdmission {
    pub(crate) fn new(limits: ServerAdmissionLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(TunnelConnectionAdmissionState::default())),
        }
    }

    pub(crate) fn max_per_tunnel(&self) -> usize {
        self.limits.max_tunnel_connections_per_tunnel
    }

    pub(crate) fn try_acquire(
        &self,
        client_identity: &ClientIdentity,
    ) -> Result<TunnelConnectionPermit, AdmissionRejection> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.active >= self.limits.max_tunnel_connections {
            return Err(AdmissionRejection {
                limit: AdmissionLimit::TunnelConnectionsGlobal,
                active_work: state.active,
            });
        }
        let identity_active = state
            .active_by_identity
            .get(client_identity)
            .copied()
            .unwrap_or(0);
        if identity_active >= self.limits.max_tunnel_connections_per_identity {
            return Err(AdmissionRejection {
                limit: AdmissionLimit::TunnelConnectionsPerIdentity,
                active_work: identity_active,
            });
        }
        state.active += 1;
        *state
            .active_by_identity
            .entry(client_identity.clone())
            .or_default() += 1;
        drop(state);

        Ok(TunnelConnectionPermit {
            admission: self.clone(),
            client_identity: client_identity.clone(),
        })
    }
}

pub(crate) struct TunnelConnectionPermit {
    admission: TunnelConnectionAdmission,
    client_identity: ClientIdentity,
}

impl Drop for TunnelConnectionPermit {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active -= 1;
        let Some(active) = state.active_by_identity.get_mut(&self.client_identity) else {
            return;
        };
        *active -= 1;
        if *active == 0 {
            state.active_by_identity.remove(&self.client_identity);
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct AdmissionLogGate {
    last_logged: Arc<Mutex<HashMap<AdmissionLogOutcome, Instant>>>,
    active: Arc<Mutex<HashSet<AdmissionLogOutcome>>>,
}

impl AdmissionLogGate {
    fn should_log(&self, outcome: AdmissionLogOutcome, now: Instant) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(outcome);
        let mut last_logged = self
            .last_logged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last_logged
            .get(&outcome)
            .is_some_and(|last| now.saturating_duration_since(*last) < SATURATION_LOG_INTERVAL)
        {
            return false;
        }
        last_logged.insert(outcome, now);
        true
    }

    fn take_recovered(&self, outcome: AdmissionLogOutcome) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&outcome)
    }
}

pub(crate) struct AcceptBackoff {
    next_delay: Duration,
    recovering: bool,
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self {
            next_delay: ACCEPT_BACKOFF_INITIAL,
            recovering: false,
        }
    }
}

impl AcceptBackoff {
    pub(crate) fn on_error(&mut self, error: &io::Error) -> Option<Duration> {
        if !is_transient_accept_error(error) {
            return None;
        }
        let delay = self.next_delay;
        self.next_delay = self.next_delay.saturating_mul(2).min(ACCEPT_BACKOFF_MAX);
        self.recovering = true;
        Some(delay)
    }

    pub(crate) fn on_success(&mut self) -> bool {
        let recovered = self.recovering;
        self.next_delay = ACCEPT_BACKOFF_INITIAL;
        self.recovering = false;
        recovered
    }
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::OutOfMemory
    ) || matches!(error.raw_os_error(), Some(12 | 23 | 24 | 55 | 105))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{
        AcceptBackoff, AdmissionLimit, AdmissionLogGate, AdmissionLogOutcome,
        ServerAdmissionLimits, ServerAdmissionPolicy,
    };

    #[test]
    fn production_limits_match_the_documented_policy() {
        let limits = ServerAdmissionLimits::default();

        assert_eq!(limits.client_hello_timeout, Duration::from_secs(5));
        assert_eq!(limits.open_bi_timeout, Duration::from_secs(5));
        assert_eq!(limits.max_pending_visitors, 4_096);
        assert_eq!(limits.max_pending_visitors_per_source, 256);
        assert_eq!(limits.max_pending_handshakes, 256);
        assert_eq!(limits.max_pending_stream_opens, 1_024);
        assert_eq!(limits.max_active_routed_streams, 4_096);
        assert_eq!(limits.max_tunnel_connections, 4_096);
        assert_eq!(limits.max_tunnel_connections_per_tunnel, 256);
        assert_eq!(limits.max_tunnel_connections_per_identity, 64);
    }

    #[test]
    fn pending_stream_open_admission_releases_capacity_after_completion() {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_stream_opens: 1,
            ..ServerAdmissionLimits::for_test()
        });

        let permit = policy
            .try_admit_pending_stream_open()
            .expect("first pending open should fit");
        assert_eq!(
            policy.try_admit_pending_stream_open().unwrap_err().limit,
            AdmissionLimit::PendingStreamOpens
        );
        drop(permit);
        assert!(policy.try_admit_pending_stream_open().is_ok());
    }

    #[test]
    fn active_routed_stream_admission_releases_capacity_after_completion() {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_active_routed_streams: 1,
            ..ServerAdmissionLimits::for_test()
        });

        let permit = policy
            .try_admit_active_routed_stream()
            .expect("first active stream should fit");
        assert_eq!(
            policy.try_admit_active_routed_stream().unwrap_err().limit,
            AdmissionLimit::ActiveRoutedStreams
        );
        drop(permit);
        assert!(policy.try_admit_active_routed_stream().is_ok());
    }

    #[test]
    fn visitor_admission_enforces_global_and_per_source_limits_then_recovers() {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_visitors: 2,
            max_pending_visitors_per_source: 1,
            max_pending_handshakes: 1,
            max_tunnel_connections: 2,
            max_tunnel_connections_per_tunnel: 2,
            max_tunnel_connections_per_identity: 2,
            ..ServerAdmissionLimits::for_test()
        });
        let first_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        let first = policy
            .try_admit_visitor(first_source)
            .expect("first source should fit");
        assert_eq!(
            policy.try_admit_visitor(first_source).unwrap_err().limit,
            AdmissionLimit::VisitorSource
        );
        let second = policy
            .try_admit_visitor(second_source)
            .expect("second source should fit");
        assert_eq!(
            policy
                .try_admit_visitor(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
                .unwrap_err()
                .limit,
            AdmissionLimit::VisitorsGlobal
        );

        drop(first);
        assert!(policy.try_admit_visitor(first_source).is_ok());
        drop(second);
    }

    #[test]
    fn handshake_admission_releases_capacity_after_completion() {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_handshakes: 1,
            ..ServerAdmissionLimits::for_test()
        });

        let permit = policy
            .try_admit_handshake()
            .expect("first handshake should fit");
        assert_eq!(
            policy.try_admit_handshake().unwrap_err().limit,
            AdmissionLimit::Handshakes
        );
        drop(permit);
        assert!(policy.try_admit_handshake().is_ok());
    }

    #[test]
    fn tunnel_connection_admission_enforces_global_and_identity_limits_then_recovers() {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_tunnel_connections: 2,
            max_tunnel_connections_per_tunnel: 2,
            max_tunnel_connections_per_identity: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let first_identity = crate::ClientIdentity::from_subject_public_key_info(b"first");
        let second_identity = crate::ClientIdentity::from_subject_public_key_info(b"second");
        let admission = policy.tunnel_connections();

        let first = admission
            .try_acquire(&first_identity)
            .expect("first identity should fit");
        assert!(matches!(
            admission.try_acquire(&first_identity),
            Err(super::AdmissionRejection {
                limit: AdmissionLimit::TunnelConnectionsPerIdentity,
                active_work: 1,
            })
        ));
        let second = admission
            .try_acquire(&second_identity)
            .expect("second identity should fit");
        let third_identity = crate::ClientIdentity::from_subject_public_key_info(b"third");
        assert!(matches!(
            admission.try_acquire(&third_identity),
            Err(super::AdmissionRejection {
                limit: AdmissionLimit::TunnelConnectionsGlobal,
                active_work: 2,
            })
        ));

        drop(first);
        assert!(admission.try_acquire(&first_identity).is_ok());
        drop(second);
    }

    #[test]
    fn transient_accept_errors_back_off_and_success_resets_the_sequence() {
        let mut backoff = AcceptBackoff::default();

        let transient = io::Error::from(io::ErrorKind::Interrupted);
        for expected_millis in [10, 20, 40, 80, 160, 320, 640, 1_000, 1_000] {
            assert_eq!(
                backoff.on_error(&transient),
                Some(Duration::from_millis(expected_millis))
            );
        }
        assert!(backoff.on_success());
        assert_eq!(
            backoff.on_error(&io::Error::from(io::ErrorKind::WouldBlock)),
            Some(Duration::from_millis(10))
        );
        assert_eq!(
            backoff.on_error(&io::Error::from(io::ErrorKind::InvalidInput)),
            None
        );
    }

    #[test]
    fn repeated_saturation_is_logged_at_most_once_per_ten_seconds() {
        let gate = AdmissionLogGate::default();
        let start = Instant::now();

        let visitor_saturation = AdmissionLogOutcome::Saturation(AdmissionLimit::VisitorsGlobal);
        assert!(gate.should_log(visitor_saturation, start));
        assert!(!gate.should_log(visitor_saturation, start + Duration::from_secs(9)));
        assert!(gate.should_log(visitor_saturation, start + Duration::from_secs(10)));
        assert!(gate.should_log(
            AdmissionLogOutcome::Saturation(AdmissionLimit::Handshakes),
            start + Duration::from_secs(1)
        ));
        assert!(gate.take_recovered(visitor_saturation));
        assert!(!gate.take_recovered(visitor_saturation));
        assert!(gate.should_log(AdmissionLogOutcome::TunnelHandshakeFailure, start));
        assert!(!gate.should_log(
            AdmissionLogOutcome::TunnelHandshakeFailure,
            start + Duration::from_secs(9)
        ));
    }
}
