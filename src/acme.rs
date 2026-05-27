use std::convert::Infallible;
use std::io;
use std::io::Cursor;
use std::path::Path;

use futures_util::StreamExt;
use rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, AcmeState, CertCache, EventError, EventOk};
use rustls_pemfile::{Item, read_one};
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_parser::parse_x509_certificate;

use crate::runtime_log::{self, AcmeEvent, AcmeRole};

pub(crate) const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

pub(crate) type ManagedAcmeState = AcmeState<io::Error>;

pub(crate) fn build_acme_state(
    server_hostname: &str,
    email: &str,
    state_directory: &Path,
) -> ManagedAcmeState {
    AcmeConfig::new([server_hostname])
        .contact_push(format!("mailto:{email}"))
        .directory_lets_encrypt(true)
        .cache(DirCache::new(state_directory.to_path_buf()))
        .state()
}

/// Builds an ACME state that manages certificates for all of the given hostnames.
/// All hostnames share a single Let's Encrypt account and state directory.
pub(crate) fn build_client_acme_state(
    hostnames: &[String],
    email: &str,
    state_directory: &Path,
) -> ManagedAcmeState {
    AcmeConfig::new(hostnames)
        .contact_push(format!("mailto:{email}"))
        .directory_lets_encrypt(true)
        .cache(DirCache::new(state_directory.to_path_buf()))
        .state()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcmeLifecycle {
    Server {
        server_hostname: String,
        first_issuance_pending: bool,
    },
    Client {
        public_hostnames: Vec<String>,
        first_issuance_pending: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CachedCertificateInspection {
    Ready {
        remaining_validity: String,
        renewal_due: bool,
    },
    Missing,
    Unavailable(String),
}

impl AcmeLifecycle {
    pub(crate) async fn server(server_hostname: &str, state_directory: &Path) -> Self {
        let inspection = inspect_cached_certificate(
            &[server_hostname.to_owned()],
            state_directory,
            OffsetDateTime::now_utc(),
        )
        .await;
        emit_startup_inspection(
            std::iter::once(AcmeRole::Server { server_hostname }),
            &inspection,
        );
        Self::Server {
            server_hostname: server_hostname.to_owned(),
            first_issuance_pending: !matches!(
                inspection,
                CachedCertificateInspection::Ready { .. }
            ),
        }
    }

    pub(crate) async fn client(public_hostnames: &[String], state_directory: &Path) -> Self {
        let inspection = inspect_cached_certificate(
            public_hostnames,
            state_directory,
            OffsetDateTime::now_utc(),
        )
        .await;
        emit_startup_inspection(
            public_hostnames
                .iter()
                .map(|public_hostname| AcmeRole::Client { public_hostname }),
            &inspection,
        );
        Self::Client {
            public_hostnames: public_hostnames.to_vec(),
            first_issuance_pending: !matches!(
                inspection,
                CachedCertificateInspection::Ready { .. }
            ),
        }
    }

    fn handle_ok(&mut self, event: EventOk) {
        match event {
            EventOk::DeployedCachedCert | EventOk::CertCacheStore | EventOk::AccountCacheStore => {}
            EventOk::DeployedNewCert => {
                let acme_event = if self.first_issuance_pending() {
                    AcmeEvent::CertificateIssued
                } else {
                    AcmeEvent::CertificateRenewed
                };
                self.emit(acme_event);
                self.set_first_issuance_pending(false);
            }
        }
    }

    fn handle_error(&self, error: &EventError<io::Error, io::Error>) {
        let error = error.to_string();
        self.emit(AcmeEvent::RecoverableFailure { error: &error });
    }

    fn handle_manager_stopped(&self) {
        self.emit(AcmeEvent::ManagerStopped);
    }

    fn emit(&self, event: AcmeEvent<'_>) {
        match self {
            Self::Server {
                server_hostname, ..
            } => runtime_log::acme(
                AcmeRole::Server {
                    server_hostname: server_hostname.as_str(),
                },
                event,
            ),
            Self::Client {
                public_hostnames, ..
            } => {
                for public_hostname in public_hostnames {
                    runtime_log::acme(
                        AcmeRole::Client {
                            public_hostname: public_hostname.as_str(),
                        },
                        event,
                    );
                }
            }
        }
    }

    fn first_issuance_pending(&self) -> bool {
        match self {
            Self::Server {
                first_issuance_pending,
                ..
            }
            | Self::Client {
                first_issuance_pending,
                ..
            } => *first_issuance_pending,
        }
    }

    fn set_first_issuance_pending(&mut self, pending: bool) {
        match self {
            Self::Server {
                first_issuance_pending,
                ..
            }
            | Self::Client {
                first_issuance_pending,
                ..
            } => *first_issuance_pending = pending,
        }
    }
}

pub(crate) async fn run_acme_state(
    mut state: ManagedAcmeState,
    mut lifecycle: AcmeLifecycle,
) -> io::Result<Infallible> {
    loop {
        match state.next().await {
            Some(Ok(event)) => lifecycle.handle_ok(event),
            Some(Err(error)) => {
                lifecycle.handle_error(&error);
            }
            None => {
                lifecycle.handle_manager_stopped();
                return Err(io::Error::other(
                    "ACME certificate manager stopped unexpectedly",
                ));
            }
        }
    }
}

async fn inspect_cached_certificate(
    domains: &[String],
    state_directory: &Path,
    now: OffsetDateTime,
) -> CachedCertificateInspection {
    let cache = DirCache::new(state_directory.to_path_buf());
    match cache
        .load_cert(domains, LETS_ENCRYPT_PRODUCTION_DIRECTORY)
        .await
    {
        Ok(Some(pem)) => inspect_cached_certificate_pem(&pem, now),
        Ok(None) => CachedCertificateInspection::Missing,
        Err(error) => CachedCertificateInspection::Unavailable(format!("cert cache load: {error}")),
    }
}

fn inspect_cached_certificate_pem(pem: &[u8], now: OffsetDateTime) -> CachedCertificateInspection {
    match parse_cached_certificate_freshness(pem, now) {
        Ok(Some((remaining_validity, renewal_due))) => CachedCertificateInspection::Ready {
            remaining_validity,
            renewal_due,
        },
        Ok(None) => CachedCertificateInspection::Missing,
        Err(error) => CachedCertificateInspection::Unavailable(error),
    }
}

fn parse_cached_certificate_freshness(
    pem: &[u8],
    now: OffsetDateTime,
) -> Result<Option<(String, bool)>, String> {
    let mut reader = Cursor::new(pem);
    while let Some(item) =
        read_one(&mut reader).map_err(|error| format!("cached cert parse: {error}"))?
    {
        let Item::X509Certificate(certificate) = item else {
            continue;
        };
        let (_, certificate) = parse_x509_certificate(certificate.as_ref())
            .map_err(|error| format!("cached cert parse: X509 parsing error: {error}"))?;
        let validity = certificate.validity();
        let not_before = OffsetDateTime::from_unix_timestamp(validity.not_before.timestamp())
            .map_err(|error| format!("cached cert parse: {error}"))?;
        let not_after = OffsetDateTime::from_unix_timestamp(validity.not_after.timestamp())
            .map_err(|error| format!("cached cert parse: {error}"))?;
        let remaining = not_after - now;
        if remaining.is_negative() || remaining.is_zero() {
            return Ok(None);
        }
        let validity_window = not_after - not_before;
        let renewal_due = now >= not_after - validity_window / 3;
        return Ok(Some((format_remaining_validity(remaining), renewal_due)));
    }
    Err("cached cert parse: no certificate PEM found".to_owned())
}

fn format_remaining_validity(remaining: TimeDuration) -> String {
    let days = remaining.whole_days();
    if days >= 1 {
        return format!("{days}d");
    }
    let hours = remaining.whole_hours();
    if hours >= 1 {
        return format!("{hours}h");
    }
    let minutes = remaining.whole_minutes();
    if minutes >= 1 {
        return format!("{minutes}m");
    }
    format!("{}s", remaining.whole_seconds().max(0))
}

fn emit_startup_inspection<'a>(
    roles: impl IntoIterator<Item = AcmeRole<'a>>,
    inspection: &CachedCertificateInspection,
) {
    match inspection {
        CachedCertificateInspection::Ready {
            remaining_validity,
            renewal_due,
        } => {
            for role in roles {
                runtime_log::acme(
                    role,
                    AcmeEvent::CachedCertificateReady {
                        remaining_validity,
                        renewal_due: *renewal_due,
                    },
                );
            }
        }
        CachedCertificateInspection::Missing => {
            for role in roles {
                runtime_log::acme(role, AcmeEvent::FirstIssuanceStarting);
            }
        }
        CachedCertificateInspection::Unavailable(error) => {
            for role in roles {
                runtime_log::acme(role, AcmeEvent::RecoverableFailure { error });
                runtime_log::acme(role, AcmeEvent::FirstIssuanceStarting);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, date_time_ymd};

    use super::{
        AcmeLifecycle, inspect_cached_certificate_pem, parse_cached_certificate_freshness,
    };

    fn build_cached_certificate_pem(
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(vec!["app.example.test".to_owned()]).unwrap();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "app.example.test");
        params.distinguished_name = distinguished_name;
        params.not_before = not_before;
        params.not_after = not_after;
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        format!("{}\n{}\n", key_pair.serialize_pem(), cert.pem()).into_bytes()
    }

    #[test]
    fn cached_certificate_freshness_reports_ready_and_not_due_state() {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 4, 1));
        let now = date_time_ymd(2026, 1, 10);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert!(matches!(
            inspection,
            super::CachedCertificateInspection::Ready {
                remaining_validity,
                renewal_due: false,
            } if remaining_validity == "81d"
        ));
    }

    #[test]
    fn cached_certificate_freshness_reports_renewal_due_state() {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 4, 1));
        let now = date_time_ymd(2026, 3, 10);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert!(matches!(
            inspection,
            super::CachedCertificateInspection::Ready {
                remaining_validity,
                renewal_due: true,
            } if remaining_validity == "22d"
        ));
    }

    #[test]
    fn cached_certificate_freshness_treats_expired_cache_as_not_ready() {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 2, 1));
        let now = date_time_ymd(2026, 2, 2);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert_eq!(inspection, super::CachedCertificateInspection::Missing);
    }

    #[test]
    fn deployed_new_certificate_switches_from_first_issuance_to_renewal() {
        let mut lifecycle = AcmeLifecycle::Server {
            server_hostname: "tunnel.example.test".to_owned(),
            first_issuance_pending: true,
        };

        lifecycle.handle_ok(rustls_acme::EventOk::DeployedNewCert);

        assert_eq!(
            lifecycle,
            AcmeLifecycle::Server {
                server_hostname: "tunnel.example.test".to_owned(),
                first_issuance_pending: false,
            }
        );
    }

    #[test]
    fn cached_certificate_parser_rejects_missing_certificates() {
        let key_pair = KeyPair::generate().unwrap();
        let error = parse_cached_certificate_freshness(
            key_pair.serialize_pem().as_bytes(),
            date_time_ymd(2026, 1, 1),
        )
        .unwrap_err();

        assert_eq!(error, "cached cert parse: no certificate PEM found");
    }
}
