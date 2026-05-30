use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use crate::{PublicHostname, ServiceConfig};

#[derive(Clone)]
pub(crate) struct ServiceSelector {
    services: Arc<[ServiceConfig]>,
}

impl ServiceSelector {
    pub(crate) fn new(services: Vec<ServiceConfig>) -> Self {
        Self {
            services: services.into(),
        }
    }

    pub(crate) fn select(&self, public_hostname: &PublicHostname) -> Option<&ServiceConfig> {
        if let [service] = &*self.services
            && service.public_hostnames.is_none()
        {
            return Some(service);
        }

        self.services.iter().find(|service| {
            service.public_hostnames.as_ref().is_some_and(|hostnames| {
                hostnames.iter().any(|hostname| hostname == public_hostname)
            })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientServiceValidationError {
    CatchAllRequiresSingleService,
    EmptyPublicHostnameList,
    DuplicatePublicHostname(PublicHostname),
}

impl fmt::Display for ClientServiceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatchAllRequiresSingleService => formatter.write_str(
                "client.services[].public-hostnames may be omitted only when there is exactly one service",
            ),
            Self::EmptyPublicHostnameList => {
                formatter.write_str("client.services[].public-hostnames must not be empty")
            }
            Self::DuplicatePublicHostname(hostname) => write!(
                formatter,
                "client.services[].public-hostnames must be unique after normalization: {hostname}"
            ),
        }
    }
}

impl std::error::Error for ClientServiceValidationError {}

pub(crate) fn validate_services(
    services: &[ServiceConfig],
) -> Result<Vec<ServiceConfig>, ClientServiceValidationError> {
    let multiple_services = services.len() > 1;
    let mut seen_hostnames = HashSet::new();
    let mut validated_services = Vec::with_capacity(services.len());

    for service in services {
        let public_hostnames = match &service.public_hostnames {
            Some(public_hostnames) => {
                if public_hostnames.is_empty() {
                    return Err(ClientServiceValidationError::EmptyPublicHostnameList);
                }
                let mut normalized_hostnames = Vec::with_capacity(public_hostnames.len());
                for hostname in public_hostnames {
                    if !seen_hostnames.insert(hostname.clone()) {
                        return Err(ClientServiceValidationError::DuplicatePublicHostname(
                            hostname.clone(),
                        ));
                    }
                    normalized_hostnames.push(hostname.clone());
                }
                Some(normalized_hostnames)
            }
            None => {
                if multiple_services {
                    return Err(ClientServiceValidationError::CatchAllRequiresSingleService);
                }
                None
            }
        };

        validated_services.push(ServiceConfig {
            public_hostnames,
            backend_address: service.backend_address.clone(),
            tls_mode: service.tls_mode.clone(),
        });
    }

    Ok(validated_services)
}

#[cfg(test)]
mod tests {
    use crate::{ClientTlsMode, PublicHostname, ServiceConfig};

    use super::{ClientServiceValidationError, ServiceSelector, validate_services};

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).unwrap()
    }

    #[test]
    fn rejects_multi_service_catch_all_shapes() {
        let services = vec![
            ServiceConfig {
                public_hostnames: None,
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "127.0.0.1:8443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ];

        assert_eq!(
            validate_services(&services).unwrap_err(),
            ClientServiceValidationError::CatchAllRequiresSingleService
        );
    }

    #[test]
    fn rejects_duplicate_hostnames_after_normalization() {
        let services = vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("App.Example.Test.")]),
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "127.0.0.1:8443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ];

        assert_eq!(
            validate_services(&services).unwrap_err(),
            ClientServiceValidationError::DuplicatePublicHostname(public_hostname(
                "app.example.test",
            ))
        );
    }

    #[test]
    fn selects_the_catch_all_service_when_it_is_the_only_service() {
        let selector = ServiceSelector::new(vec![ServiceConfig {
            public_hostnames: None,
            backend_address: "127.0.0.1:443".to_owned(),
            tls_mode: ClientTlsMode::Passthrough,
        }]);

        let selected = selector.select(&public_hostname("app.example.test"));

        assert_eq!(
            selected.map(|service| service.backend_address.as_str()),
            Some("127.0.0.1:443")
        );
    }

    #[test]
    fn selects_the_service_with_the_matching_public_hostname() {
        let selector = ServiceSelector::new(vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("api.example.test")]),
                backend_address: "127.0.0.1:8443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ]);

        let selected = selector.select(&public_hostname("api.example.test"));

        assert_eq!(
            selected.map(|service| service.backend_address.as_str()),
            Some("127.0.0.1:8443")
        );
    }

    #[test]
    fn returns_none_when_no_service_matches_the_public_hostname() {
        let selector = ServiceSelector::new(vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "127.0.0.1:443".to_owned(),
            tls_mode: ClientTlsMode::Passthrough,
        }]);

        let selected = selector.select(&public_hostname("api.example.test"));

        assert!(selected.is_none());
    }
}
