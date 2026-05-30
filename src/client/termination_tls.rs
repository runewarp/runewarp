use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Default)]
pub(crate) struct TerminationTlsConfigs {
    default_server_configs: Arc<HashMap<String, Arc<rustls::ServerConfig>>>,
    acme_challenge_server_configs: Arc<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl TerminationTlsConfigs {
    pub(crate) fn new(
        default_server_configs: HashMap<String, Arc<rustls::ServerConfig>>,
        acme_challenge_server_configs: HashMap<String, Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            default_server_configs: Arc::new(default_server_configs),
            acme_challenge_server_configs: Arc::new(acme_challenge_server_configs),
        }
    }

    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn default_server_config(
        &self,
        public_hostname: &str,
    ) -> Option<&Arc<rustls::ServerConfig>> {
        self.default_server_configs.get(public_hostname)
    }

    pub(crate) fn acme_challenge_server_config(
        &self,
        public_hostname: &str,
    ) -> Option<&Arc<rustls::ServerConfig>> {
        self.acme_challenge_server_configs.get(public_hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::TerminationTlsConfigs;
    use std::collections::HashMap;
    use std::io;
    use std::sync::Arc;

    use rcgen::generate_simple_self_signed;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn keeps_default_and_acme_challenge_lookup_independent() -> io::Result<()> {
        let default_config = Arc::new(make_server_config("app.example.test")?);
        let challenge_config = Arc::new(make_server_config("app.example.test")?);
        let challenge_only_config = Arc::new(make_server_config("challenge.example.test")?);

        let configs = TerminationTlsConfigs::new(
            HashMap::from([("app.example.test".to_owned(), default_config.clone())]),
            HashMap::from([
                ("app.example.test".to_owned(), challenge_config.clone()),
                (
                    "challenge.example.test".to_owned(),
                    challenge_only_config.clone(),
                ),
            ]),
        );

        assert!(configs.default_server_config("app.example.test").is_some());
        assert!(
            configs
                .default_server_config("challenge.example.test")
                .is_none()
        );
        assert!(
            configs
                .acme_challenge_server_config("app.example.test")
                .is_some()
        );
        assert!(
            configs
                .acme_challenge_server_config("challenge.example.test")
                .is_some()
        );
        assert!(
            configs
                .default_server_config("missing.example.test")
                .is_none()
        );
        assert!(
            configs
                .acme_challenge_server_config("missing.example.test")
                .is_none()
        );

        Ok(())
    }

    fn make_server_config(hostname: &str) -> io::Result<ServerConfig> {
        let certified_key =
            generate_simple_self_signed(vec![hostname.to_owned()]).map_err(io::Error::other)?;
        let cert_der = CertificateDer::from(certified_key.cert);
        let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], PrivateKeyDer::from(key_der))
            .map_err(io::Error::other)
    }
}
