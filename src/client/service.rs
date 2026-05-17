use crate::ClientServiceSettings;

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

#[cfg(test)]
mod tests {
    use crate::ClientServiceSettings;

    use super::select_service;

    #[test]
    fn catch_all_service_matches_when_it_is_the_only_service() {
        let services = vec![ClientServiceSettings {
            public_hostnames: None,
            backend_addr: "127.0.0.1:443".to_owned(),
        }];

        let service = select_service(&services, "app.example.test").unwrap();

        assert_eq!(service.backend_addr, "127.0.0.1:443");
    }

    #[test]
    fn exact_match_services_select_by_public_hostname() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_addr: "127.0.0.1:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["api.example.test".to_owned()]),
                backend_addr: "127.0.0.1:8443".to_owned(),
            },
        ];

        let service = select_service(&services, "api.example.test").unwrap();

        assert_eq!(service.backend_addr, "127.0.0.1:8443");
    }
}
