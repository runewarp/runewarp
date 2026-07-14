use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

use crate::{ClientIdentity, client_identity_from_certificate_der, runtime_log};

/// Live Client-identity handshake admission consulted by the QUIC verifier.
pub trait ClientIdentityAdmission: Send + Sync + fmt::Debug {
    fn authorizes_client_identity(&self, identity: &ClientIdentity) -> bool;
}

pub const RUNEWARP_ALPN: &[u8] = b"runewarp/1";
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_SERVER_OPENED_BIDI_STREAMS: u32 = 1024;
const ADMISSION_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(10);

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
    make_server_quic_config_with_client_admission(
        cert_chain,
        private_key,
        Arc::new(StaticClientIdentityAdmission::from_identities(
            trusted_client_identities,
        )),
    )
}

pub fn make_server_quic_config_with_client_admission(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let provider = server_crypto_provider();
    let verifier =
        PinnedClientCertVerifier::new(admission, provider.signature_verification_algorithms);
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
    make_server_quic_config_with_client_admission_resolver(
        cert_resolver,
        Arc::new(StaticClientIdentityAdmission::from_identities(
            trusted_client_identities,
        )),
    )
}

pub fn make_server_quic_config_with_client_admission_resolver(
    cert_resolver: Arc<dyn ResolvesServerCert>,
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let provider = server_crypto_provider();
    let verifier =
        PinnedClientCertVerifier::new(admission, provider.signature_verification_algorithms);
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

pub(crate) async fn with_handshake_timeout<F, T, E>(
    future: F,
    timeout: Duration,
    on_timeout: impl FnOnce() -> E,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(on_timeout()),
    }
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
struct StaticClientIdentityAdmission {
    trusted_client_identities: HashSet<ClientIdentity>,
}

impl StaticClientIdentityAdmission {
    fn from_identities(trusted_client_identities: &[ClientIdentity]) -> Self {
        Self {
            trusted_client_identities: trusted_client_identities.iter().cloned().collect(),
        }
    }
}

impl ClientIdentityAdmission for StaticClientIdentityAdmission {
    fn authorizes_client_identity(&self, identity: &ClientIdentity) -> bool {
        self.trusted_client_identities.contains(identity)
    }
}

#[derive(Debug)]
struct PinnedClientCertVerifier {
    admission: Arc<dyn ClientIdentityAdmission>,
    supported_algorithms: WebPkiSupportedAlgorithms,
    root_hint_subjects: Vec<DistinguishedName>,
    last_unauthorized_log: Mutex<Option<Instant>>,
}

impl PinnedClientCertVerifier {
    fn new(
        admission: Arc<dyn ClientIdentityAdmission>,
        supported_algorithms: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            admission,
            supported_algorithms,
            root_hint_subjects: Vec::new(),
            last_unauthorized_log: Mutex::new(None),
        }
    }

    fn should_log_unauthorized(&self) -> bool {
        let now = Instant::now();
        let mut last_logged = self
            .last_unauthorized_log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last_logged.is_some_and(|last| {
            now.saturating_duration_since(last) < ADMISSION_FAILURE_LOG_INTERVAL
        }) {
            return false;
        }
        *last_logged = Some(now);
        true
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
        if self.admission.authorizes_client_identity(&client_identity) {
            Ok(ClientCertVerified::assertion())
        } else {
            if self.should_log_unauthorized() {
                runtime_log::server_tunnel_connection_unauthorized(&client_identity);
            }
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
    use std::future::pending;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::pem::{Error as PemError, PemObject};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::danger::ClientCertVerifier;
    use tracing_subscriber::fmt::writer::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{
        PinnedClientCertVerifier, StaticClientIdentityAdmission, make_client_quic_config,
        make_server_quic_config, with_handshake_timeout,
    };
    use crate::generate_client_identity;

    #[test]
    fn server_quic_config_uses_runewarp_transport_defaults() {
        let (certificate, private_key) = make_self_signed_cert("tunnel.example.test");
        let server_config =
            make_server_quic_config(vec![certificate], private_key_from_der(&private_key)).unwrap();
        let debug = format!("{:?}", server_config.transport);

        assert!(debug.contains("max_concurrent_bidi_streams: 0"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(60000)"));
        assert!(debug.contains("keep_alive_interval: Some(20s)"));
    }

    #[test]
    fn client_quic_config_uses_runewarp_transport_defaults() {
        let (certificate, _) = make_self_signed_cert("tunnel.example.test");
        let client_config = make_client_quic_config(root_store_with(&certificate)).unwrap();
        let debug = format!("{client_config:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 1024"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("max_idle_timeout: Some(60000)"));
        assert!(debug.contains("keep_alive_interval: Some(20s)"));
    }

    #[tokio::test]
    async fn handshake_timeout_wrapper_returns_the_timeout_error_after_the_deadline() {
        let error = with_handshake_timeout(
            pending::<Result<(), io::Error>>(),
            Duration::from_millis(10),
            || io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"),
        )
        .await
        .expect_err("pending handshake should time out");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "handshake timed out");
    }

    #[test]
    fn unauthorized_client_identity_verification_rate_limits_warn_logs() {
        let generated_client_identity = generate_client_identity().unwrap();
        let certificate = client_leaf_certificate(&generated_client_identity).unwrap();
        let client_identity = generated_client_identity.client_identity.clone();
        let provider = rustls::crypto::ring::default_provider();
        let verifier = PinnedClientCertVerifier::new(
            Arc::new(StaticClientIdentityAdmission::from_identities(&[])),
            provider.signature_verification_algorithms,
        );

        let output = capture_logs(|| {
            let result =
                verifier.verify_client_cert(&certificate, &[], rustls::pki_types::UnixTime::now());
            assert!(result.is_err());
            let repeated =
                verifier.verify_client_cert(&certificate, &[], rustls::pki_types::UnixTime::now());
            assert!(repeated.is_err());
        });

        assert!(
            output.contains(
                format!(
                    "WARN server tunnel connection unauthorized: client-identity={client_identity}"
                )
                .as_str()
            )
        );
        assert_eq!(
            output
                .matches("WARN server tunnel connection unauthorized")
                .count(),
            1
        );
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(SharedBuffer);

    impl SharedBuffer {
        fn read(&self) -> String {
            String::from_utf8(self.0.lock().expect("buffer mutex poisoned").clone())
                .expect("runtime log output must be valid UTF-8")
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .0
                .lock()
                .expect("buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(self.clone())
        }
    }

    fn capture_logs(action: impl FnOnce()) -> String {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(buffer.clone())
                .with_ansi(false)
                .without_time()
                .with_target(false),
        );
        tracing::subscriber::with_default(subscriber, action);
        buffer.read()
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

    fn client_leaf_certificate(
        generated_client_identity: &crate::GeneratedClientIdentity,
    ) -> io::Result<CertificateDer<'static>> {
        match CertificateDer::from_pem_slice(generated_client_identity.certificate_pem.as_bytes()) {
            Ok(certificate) => Ok(certificate),
            Err(PemError::NoItemsFound) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing client certificate",
            )),
            Err(source) => Err(io::Error::other(source)),
        }
    }
}
