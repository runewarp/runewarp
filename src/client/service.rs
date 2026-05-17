use std::collections::HashSet;
use std::fmt;

use crate::ClientServiceSettings;
use crate::hostname::{PublicHostnameError, validate_public_hostname};

pub(crate) fn select_service<'a>(
    services: &'a [ClientServiceSettings],
    public_hostname: &str,
) -> Option<&'a ClientServiceSettings> {
    if let [service] = services
        && service.public_hostnames.is_none()
    {
        return Some(service);
    }

    services.iter().find(|service| {
        service
            .public_hostnames
            .as_ref()
            .is_some_and(|hostnames| hostnames.iter().any(|hostname| hostname == public_hostname))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientServiceValidationError {
    CatchAllRequiresSingleService,
    EmptyPublicHostnameList,
    InvalidPublicHostname {
        hostname: String,
        source: PublicHostnameError,
    },
    DuplicatePublicHostname(String),
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
            Self::InvalidPublicHostname { hostname, source } => write!(
                formatter,
                "client.services[].public-hostnames contains invalid hostname `{hostname}`: {source}"
            ),
            Self::DuplicatePublicHostname(hostname) => write!(
                formatter,
                "client.services[].public-hostnames must be unique after normalization: {hostname}"
            ),
        }
    }
}

impl std::error::Error for ClientServiceValidationError {}

pub(crate) fn validate_services(
    services: &[ClientServiceSettings],
) -> Result<Vec<ClientServiceSettings>, ClientServiceValidationError> {
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
                    let normalized_hostname =
                        validate_public_hostname(hostname).map_err(|source| {
                            ClientServiceValidationError::InvalidPublicHostname {
                                hostname: hostname.clone(),
                                source,
                            }
                        })?;
                    if !seen_hostnames.insert(normalized_hostname.clone()) {
                        return Err(ClientServiceValidationError::DuplicatePublicHostname(
                            normalized_hostname,
                        ));
                    }
                    normalized_hostnames.push(normalized_hostname);
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

        validated_services.push(ClientServiceSettings {
            public_hostnames,
            backend_address: service.backend_address.clone(),
        });
    }

    Ok(validated_services)
}

#[cfg(test)]
mod tests {
    use crate::ClientServiceSettings;

    use super::{ClientServiceValidationError, select_service, validate_services};

    #[test]
    fn catch_all_service_matches_when_it_is_the_only_service() {
        let services = vec![ClientServiceSettings {
            public_hostnames: None,
            backend_address: "127.0.0.1:443".to_owned(),
        }];

        let service = select_service(&services, "app.example.test").unwrap();

        assert_eq!(service.backend_address, "127.0.0.1:443");
    }

    #[test]
    fn exact_match_services_select_by_public_hostname() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["api.example.test".to_owned()]),
                backend_address: "127.0.0.1:8443".to_owned(),
            },
        ];

        let service = select_service(&services, "api.example.test").unwrap();

        assert_eq!(service.backend_address, "127.0.0.1:8443");
    }

    #[test]
    fn rejects_multi_service_catch_all_shapes() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: None,
                backend_address: "127.0.0.1:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:8443".to_owned(),
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
            ClientServiceSettings {
                public_hostnames: Some(vec!["App.Example.Test.".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:8443".to_owned(),
            },
        ];

        assert_eq!(
            validate_services(&services).unwrap_err(),
            ClientServiceValidationError::DuplicatePublicHostname("app.example.test".to_owned())
        );
    }
}
