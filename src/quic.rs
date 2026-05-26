use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use quinn::TransportConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
};

use crate::{ClientIdentity, client_identity_from_certificate_der};

pub const RUNEWARP_ALPN: &[u8] = b"runewarp/1";
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2 * 60);
pub const MAX_SERVER_OPENED_BIDI_STREAMS: u32 = 1024;

#[derive(Debug)]
pub enum QuicConfigError {
    Rustls(rustls::Error),
    NoInitialCipherSuite(quinn::crypto::rustls::NoInitialCipherSuite),
}

impl fmt::Display for QuicConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustls(_) => formatter.write_str("TLS configuration error"),
            Self::NoInitialCipherSuite(_) => formatter.write_str("QUIC TLS configuration error"),
        }
    }
}

impl std::error::Error for QuicConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rustls(error) => Some(error),
            Self::NoInitialCipherSuite(error) => Some(error),
        }
    }
}

impl From<rustls::Error> for QuicConfigError {
    fn from(error: rustls::Error) -> Self {
        Self::Rustls(error)
    }
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for QuicConfigError {
    fn from(error: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(error)
    }
}

pub fn make_server_quic_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
    server_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("newly created QUIC server configs should expose a unique transport config");
    configure_server_transport(transport_config);

    Ok(server_config)
}

pub fn make_server_quic_config_with_client_auth(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    trusted_client_identities: &[ClientIdentity],
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let provider = server_crypto_provider();
    let verifier = PinnedClientCertVerifier::new(
        trusted_client_identities,
        provider.signature_verification_algorithms,
    );
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, private_key)?;
    server_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("newly created QUIC server configs should expose a unique transport config");
    configure_server_transport(transport_config);

    Ok(server_config)
}

pub fn make_server_quic_config_with_client_auth_resolver(
    cert_resolver: Arc<dyn ResolvesServerCert>,
    trusted_client_identities: &[ClientIdentity],
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let provider = server_crypto_provider();
    let verifier = PinnedClientCertVerifier::new(
        trusted_client_identities,
        provider.signature_verification_algorithms,
    );
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(cert_resolver);
    server_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("newly created QUIC server configs should expose a unique transport config");
    configure_server_transport(transport_config);

    Ok(server_config)
}

pub fn make_client_quic_config(
    roots: RootCertStore,
) -> Result<quinn::ClientConfig, QuicConfigError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(client_transport_config()));

    Ok(client_config)
}

pub fn make_client_quic_config_with_client_auth(
    roots: RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig, QuicConfigError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, private_key)?;
    client_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(client_transport_config()));

    Ok(client_config)
}

fn configure_server_transport(transport_config: &mut TransportConfig) {
    transport_config.max_concurrent_bidi_streams(0_u8.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("the fixed idle timeout should fit quinn's idle timeout type"),
    ));
    transport_config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
}

fn client_transport_config() -> TransportConfig {
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(MAX_SERVER_OPENED_BIDI_STREAMS.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("the fixed idle timeout should fit quinn's idle timeout type"),
    ));
    transport_config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
    transport_config
}

fn server_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

#[derive(Debug)]
struct PinnedClientCertVerifier {
    trusted_client_identities: HashSet<ClientIdentity>,
    supported_algorithms: WebPkiSupportedAlgorithms,
    root_hint_subjects: Vec<DistinguishedName>,
}

impl PinnedClientCertVerifier {
    fn new(
        trusted_client_identities: &[ClientIdentity],
        supported_algorithms: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            trusted_client_identities: trusted_client_identities.iter().cloned().collect(),
            supported_algorithms,
            root_hint_subjects: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let client_identity = client_identity_from_certificate_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.trusted_client_identities.contains(&client_identity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::{make_client_quic_config, make_server_quic_config};

    #[test]
    fn server_quic_config_uses_runewarp_transport_defaults() {
        let (certificate, private_key) = make_self_signed_cert("tunnel.example.test");
        let server_config =
            make_server_quic_config(vec![certificate], private_key_from_der(&private_key)).unwrap();
        let debug = format!("{:?}", server_config.transport);

        assert!(debug.contains("max_concurrent_bidi_streams: 0"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(300000)"));
        assert!(debug.contains("keep_alive_interval: Some(120s)"));
    }

    #[test]
    fn client_quic_config_uses_runewarp_transport_defaults() {
        let (certificate, _) = make_self_signed_cert("tunnel.example.test");
        let client_config = make_client_quic_config(root_store_with(&certificate)).unwrap();
        let debug = format!("{client_config:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 1024"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(300000)"));
        assert!(debug.contains("keep_alive_interval: Some(120s)"));
    }

    fn make_self_signed_cert(server_name: &str) -> (CertificateDer<'static>, Vec<u8>) {
        let certified_key = generate_simple_self_signed(vec![server_name.to_owned()]).unwrap();
        (
            CertificateDer::from(certified_key.cert),
            certified_key.signing_key.serialize_der(),
        )
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        roots
    }
}
