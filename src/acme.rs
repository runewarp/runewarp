use std::convert::Infallible;
use std::io;
use std::path::Path;

use futures_util::StreamExt;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, AcmeState, CertCache, EventError, EventOk};
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

/// Builds an ACME state for the given hostname set.
/// Runewarp reuses the same state directory so the Let's Encrypt account cache can
/// still be shared across independently managed hostnames.
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
pub(crate) enum NextDeployment {
    FirstIssuance,
    Renewal,
}

#[derive(Debug)]
pub(crate) struct ManagedAcmeRuntime {
    pub(crate) state: ManagedAcmeState,
    pub(crate) lifecycle: AcmeLifecycle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcmeLifecycle {
    Server {
        server_hostname: String,
        next_deployment: NextDeployment,
    },
    Client {
        public_hostname: String,
        next_deployment: NextDeployment,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CachedCertificateInspection {
    Ready {
        remaining_validity: String,
        renewal_due: bool,
    },
    Missing,
    Expired,
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
            next_deployment: next_deployment_for_inspection(&inspection),
        }
    }

    pub(crate) async fn client(public_hostname: &str, state_directory: &Path) -> Self {
        let inspection = inspect_cached_certificate(
            &[public_hostname.to_owned()],
            state_directory,
            OffsetDateTime::now_utc(),
        )
        .await;
        emit_startup_inspection(
            std::iter::once(AcmeRole::Client { public_hostname }),
            &inspection,
        );
        Self::Client {
            public_hostname: public_hostname.to_owned(),
            next_deployment: next_deployment_for_inspection(&inspection),
        }
    }

    fn handle_ok(&mut self, event: EventOk) {
        match event {
            EventOk::DeployedCachedCert | EventOk::CertCacheStore | EventOk::AccountCacheStore => {}
            EventOk::DeployedNewCert => {
                let acme_event = if matches!(self.next_deployment(), NextDeployment::FirstIssuance)
                {
                    AcmeEvent::CertificateIssued
                } else {
                    AcmeEvent::CertificateRenewed
                };
                self.emit(acme_event);
                self.set_next_deployment(NextDeployment::Renewal);
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
                public_hostname, ..
            } => runtime_log::acme(
                AcmeRole::Client {
                    public_hostname: public_hostname.as_str(),
                },
                event,
            ),
        }
    }

    fn next_deployment(&self) -> NextDeployment {
        match self {
            Self::Server {
                next_deployment, ..
            }
            | Self::Client {
                next_deployment, ..
            } => next_deployment.clone(),
        }
    }

    fn set_next_deployment(&mut self, next: NextDeployment) {
        match self {
            Self::Server {
                next_deployment, ..
            }
            | Self::Client {
                next_deployment, ..
            } => *next_deployment = next,
        }
    }
}

fn next_deployment_for_inspection(inspection: &CachedCertificateInspection) -> NextDeployment {
    match inspection {
        CachedCertificateInspection::Missing => NextDeployment::FirstIssuance,
        CachedCertificateInspection::Ready { .. }
        | CachedCertificateInspection::Expired
        | CachedCertificateInspection::Unavailable(_) => NextDeployment::Renewal,
    }
}

pub(crate) async fn run_acme_state(
    mut state: ManagedAcmeState,
    mut lifecycle: AcmeLifecycle,
) -> io::Result<Infallible> {
    loop {
        match state.next().await {
            Some(Ok(event)) => lifecycle.handle_ok(event),
            Some(Err(error)) => lifecycle.handle_error(&error),
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
        Ok(None) => CachedCertificateInspection::Expired,
        Err(error) => CachedCertificateInspection::Unavailable(error),
    }
}

fn parse_cached_certificate_freshness(
    pem: &[u8],
    now: OffsetDateTime,
) -> Result<Option<(String, bool)>, String> {
    let Some(certificate) = CertificateDer::pem_slice_iter(pem).next() else {
        return Err("cached cert parse: no certificate PEM found".to_owned());
    };
    let certificate = certificate.map_err(|error| format!("cached cert parse: {error}"))?;
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
    Ok(Some((format_remaining_validity(remaining), renewal_due)))
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
                runtime_log::acme(
                    role,
                    AcmeEvent::FirstIssuanceStarting {
                        reason: "no-ready-cached-certificate",
                    },
                );
            }
        }
        CachedCertificateInspection::Expired => {
            for role in roles {
                runtime_log::acme(
                    role,
                    AcmeEvent::RenewalStarting {
                        reason: "expired-cached-certificate",
                    },
                );
            }
        }
        CachedCertificateInspection::Unavailable(error) => {
            for role in roles {
                runtime_log::acme(role, AcmeEvent::RecoverableFailure { error });
                runtime_log::acme(
                    role,
                    AcmeEvent::RenewalStarting {
                        reason: "unreadable-cached-certificate",
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
        date_time_ymd,
    };

    use super::{
        AcmeLifecycle, CachedCertificateInspection, NextDeployment, inspect_cached_certificate_pem,
        parse_cached_certificate_freshness,
    };

    fn build_cached_certificate_pem(
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut params = CertificateParams::new(vec!["app.example.test".to_owned()])?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "app.example.test");
        params.distinguished_name = distinguished_name;
        params.not_before = not_before;
        params.not_after = not_after;
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;
        Ok(format!("{}\n{}\n", key_pair.serialize_pem(), cert.pem()).into_bytes())
    }

    #[test]
    fn cached_certificate_freshness_reports_ready_and_not_due_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 4, 1))?;
        let now = date_time_ymd(2026, 1, 10);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert!(matches!(
            inspection,
            CachedCertificateInspection::Ready {
                remaining_validity,
                renewal_due: false,
            } if remaining_validity == "81d"
        ));
        Ok(())
    }

    #[test]
    fn cached_certificate_freshness_reports_renewal_due_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 4, 1))?;
        let now = date_time_ymd(2026, 3, 10);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert!(matches!(
            inspection,
            CachedCertificateInspection::Ready {
                remaining_validity,
                renewal_due: true,
            } if remaining_validity == "22d"
        ));
        Ok(())
    }

    #[test]
    fn cached_certificate_freshness_treats_expired_cache_as_expired()
    -> Result<(), Box<dyn std::error::Error>> {
        let pem =
            build_cached_certificate_pem(date_time_ymd(2026, 1, 1), date_time_ymd(2026, 2, 1))?;
        let now = date_time_ymd(2026, 2, 2);

        let inspection = inspect_cached_certificate_pem(&pem, now);

        assert_eq!(inspection, CachedCertificateInspection::Expired);
        Ok(())
    }

    #[test]
    fn deployed_new_certificate_switches_from_first_issuance_to_renewal() {
        let mut lifecycle = AcmeLifecycle::Server {
            server_hostname: "tunnel.example.test".to_owned(),
            next_deployment: NextDeployment::FirstIssuance,
        };

        lifecycle.handle_ok(rustls_acme::EventOk::DeployedNewCert);

        assert_eq!(
            lifecycle,
            AcmeLifecycle::Server {
                server_hostname: "tunnel.example.test".to_owned(),
                next_deployment: NextDeployment::Renewal,
            }
        );
    }

    #[test]
    fn cached_certificate_parser_rejects_missing_certificates()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let error = parse_cached_certificate_freshness(
            key_pair.serialize_pem().as_bytes(),
            date_time_ymd(2026, 1, 1),
        )
        .unwrap_err();

        assert_eq!(error, "cached cert parse: no certificate PEM found");
        Ok(())
    }
}
