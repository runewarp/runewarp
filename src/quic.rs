#[cfg(test)]
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::{ClientIdentity, client_identity_from_certificate_der, runtime_log};

/// Live Client-identity handshake admission consulted by the QUIC verifier.
pub trait ClientIdentityAdmission: Send + Sync + fmt::Debug {
    fn authorizes_client_identity(&self, identity: &ClientIdentity) -> bool;
}

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
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

/// Server TLS that requires a Client certificate whose pinned identity `admission` authorizes.
///
/// Callers set ALPN and wrap it in their QUIC transport configuration.
pub(crate) fn pinned_client_auth_server_crypto(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<rustls::ServerConfig, QuicConfigError> {
    Ok(pinned_client_auth_server_builder(admission)?.with_single_cert(cert_chain, private_key)?)
}

pub(crate) fn pinned_client_auth_server_builder(
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<
    rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>,
    QuicConfigError,
> {
    let provider = server_crypto_provider();
    let verifier =
        PinnedClientCertVerifier::new(admission, provider.signature_verification_algorithms);
    Ok(rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(verifier)))
}

/// Pinned Client identity of an authenticated QUIC connection's leaf certificate.
pub(crate) fn peer_client_identity(connection: &quinn::Connection) -> Option<ClientIdentity> {
    let identity = connection.peer_identity()?;
    let certificate_chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let certificate = certificate_chain.first()?;
    client_identity_from_certificate_der(certificate.as_ref()).ok()
}

pub(crate) fn is_tls_access_denied(error: &quinn::ConnectionError) -> bool {
    const TLS_ACCESS_DENIED_ALERT: u8 = 0x31;
    matches!(
        error,
        quinn::ConnectionError::TransportError(error)
            if error.code == quinn::TransportErrorCode::crypto(TLS_ACCESS_DENIED_ALERT)
    ) || matches!(error, quinn::ConnectionError::ConnectionClosed(close)
        if close.error_code == quinn::TransportErrorCode::crypto(TLS_ACCESS_DENIED_ALERT))
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

fn server_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct StaticClientIdentityAdmission {
    trusted_client_identities: HashSet<ClientIdentity>,
}

#[cfg(test)]
impl StaticClientIdentityAdmission {
    pub(crate) fn from_identities(trusted_client_identities: &[ClientIdentity]) -> Self {
        Self {
            trusted_client_identities: trusted_client_identities.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
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

    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::{Error as PemError, PemObject};
    use rustls::server::danger::ClientCertVerifier;
    use tracing_subscriber::fmt::writer::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{PinnedClientCertVerifier, StaticClientIdentityAdmission, with_handshake_timeout};
    use crate::generate_client_identity;

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
