use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A fresh owner-only TLS proof for the exact Server-hostname challenge path.
/// An external routing controller must observe this fingerprint at the consumed
/// destination, not infer it from a desired configuration or a handling log.
#[derive(Clone, Debug)]
pub struct ChallengeRouteRequest {
    pub hostname: crate::ServerHostname,
    pub certificate: CertificateDer<'static>,
    pub fingerprint: String,
}

/// Evidence supplied by the trusted routing observer. The fingerprint must come from
/// a fresh observation of the request's TLS proof. Version identifies consumed routing.
#[derive(Clone, Debug)]
pub struct ConsumedChallengeRoute {
    pub fingerprint: String,
    pub version: String,
}

/// Production integration with an externally consumed challenge route. Implementations
/// must observe the exact Server-hostname TCP/acme-tls/1 path to this runtime. A config
/// write, Visitor/Tunnel promotion or boolean readiness flag is insufficient evidence.
pub trait ChallengeRouteObserver: Send + Sync {
    fn observe(
        &self,
        request: ChallengeRouteRequest,
    ) -> BoxFuture<'_, io::Result<ConsumedChallengeRoute>>;
}

/// Observe consumed routing by making a real TLS connection through an ingress address.
/// The default uses the Server hostname on TCP 443. Routed deployments can supply an
/// observer operating from their external witness and returning its consumed route version.
pub struct TcpChallengeRoute {
    target: Option<SocketAddr>,
    version: String,
}

impl Default for TcpChallengeRoute {
    fn default() -> Self {
        Self {
            target: None,
            version: "direct-tcp-443".to_owned(),
        }
    }
}

impl TcpChallengeRoute {
    /// `target` must be the ingress whose consumed route is being observed.
    pub fn at(target: SocketAddr, version: &str) -> io::Result<Self> {
        validate_version(version)?;
        Ok(Self {
            target: Some(target),
            version: version.to_owned(),
        })
    }
}

impl ChallengeRouteObserver for TcpChallengeRoute {
    fn observe(
        &self,
        request: ChallengeRouteRequest,
    ) -> BoxFuture<'_, io::Result<ConsumedChallengeRoute>> {
        Box::pin(async move {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(request.certificate.clone())
                .map_err(io::Error::other)?;
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![crate::acme::ACME_TLS_ALPN.to_vec()];
            let name = ServerName::try_from(request.hostname.as_str().to_owned())
                .map_err(io::Error::other)?;
            let connect = async {
                let tcp = match self.target {
                    Some(target) => TcpStream::connect(target).await?,
                    None => TcpStream::connect((request.hostname.as_str(), 443)).await?,
                };
                let tls = TlsConnector::from(Arc::new(config))
                    .connect(name, tcp)
                    .await?;
                let (_, connection) = tls.get_ref();
                if connection.alpn_protocol() != Some(crate::acme::ACME_TLS_ALPN)
                    || connection
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        != Some(&request.certificate)
                {
                    return Err(io::Error::other("challenge route proof did not match"));
                }
                Ok(ConsumedChallengeRoute {
                    fingerprint: request.fingerprint,
                    version: self.version.clone(),
                })
            };
            tokio::time::timeout(Duration::from_secs(5), connect)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "challenge route observation timed out",
                    )
                })?
        })
    }
}

pub(super) fn validate_version(version: &str) -> io::Result<()> {
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err(io::Error::other("invalid consumed challenge route version"));
    }
    Ok(())
}
