use std::fmt;
use std::fs;
use std::io::{self, BufReader, Cursor};
use std::net::SocketAddr;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::lookup_host;

use crate::{
    Client, ClientConfig, ClientConnectError, ClientIdentity, ClientSettings, QuicConfigError,
    Server, ServerConfig, ServerSettings, make_client_quic_config_with_client_auth,
    make_server_quic_config,
};

pub struct PreparedServer {
    server: Server,
    trusted_client_identities: Vec<ClientIdentity>,
}

impl PreparedServer {
    pub async fn bind(
        settings: &ServerSettings,
        public_bind_addr: SocketAddr,
        tunnel_bind_addr: SocketAddr,
    ) -> Result<Self, ServerStartupError> {
        let cert_chain = load_certificate_chain(&settings.cert_file)?;
        let private_key = load_private_key(&settings.key_file)?;
        let quic_server_config = make_server_quic_config(cert_chain, private_key)
            .map_err(ServerStartupError::QuicConfig)?;
        let server = Server::bind(ServerConfig {
            public_bind_addr,
            tunnel_bind_addr,
            quic_server_config,
        })
        .await
        .map_err(ServerStartupError::Bind)?;

        Ok(Self {
            server,
            trusted_client_identities: settings
                .tunnels
                .iter()
                .map(|tunnel| tunnel.client_identity.clone())
                .collect(),
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.server.public_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.server.tunnel_addr()
    }

    pub fn trusted_client_identities(&self) -> &[ClientIdentity] {
        &self.trusted_client_identities
    }

    pub async fn run(self) -> io::Result<()> {
        self.server.run().await
    }
}

pub struct PreparedClient {
    client: Client,
}

impl PreparedClient {
    pub async fn connect(
        settings: &ClientSettings,
        local_bind_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let mut server_addrs = lookup_host((settings.server_hostname.as_str(), 443))
            .await
            .map_err(ClientStartupError::Resolve)?;
        let Some(server_addr) = server_addrs.next() else {
            return Err(ClientStartupError::MissingServerAddress {
                server_hostname: settings.server_hostname.clone(),
            });
        };
        Self::connect_to(settings, local_bind_addr, server_addr).await
    }

    pub async fn connect_to(
        settings: &ClientSettings,
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let roots = load_root_store(settings.server_ca_file.as_deref())?;
        let cert_chain =
            load_certificate_chain(&settings.cert_file).map_err(ClientStartupError::TlsMaterial)?;
        let private_key =
            load_private_key(&settings.key_file).map_err(ClientStartupError::TlsMaterial)?;
        let quic_client_config =
            make_client_quic_config_with_client_auth(roots, cert_chain, private_key)
                .map_err(ClientStartupError::QuicConfig)?;
        let client = Client::connect(ClientConfig {
            local_bind_addr,
            server_addr,
            server_name: settings.server_hostname.clone(),
            backend_addr: settings
                .services
                .first()
                .expect("validated client settings always include one service")
                .local_addr
                .clone(),
            quic_client_config,
        })
        .await
        .map_err(ClientStartupError::Connect)?;

        Ok(Self { client })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client.local_addr()
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        self.client.run().await
    }
}

#[derive(Debug)]
pub enum ServerStartupError {
    ReadFile {
        path: std::path::PathBuf,
        source: io::Error,
    },
    MissingCertificate {
        path: std::path::PathBuf,
    },
    MissingPrivateKey {
        path: std::path::PathBuf,
    },
    ParsePem {
        path: std::path::PathBuf,
        source: io::Error,
    },
    QuicConfig(QuicConfigError),
    Bind(io::Error),
}

impl fmt::Display for ServerStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::MissingCertificate { path } => {
                write!(formatter, "no certificates found in {}", path.display())
            }
            Self::MissingPrivateKey { path } => {
                write!(formatter, "no private key found in {}", path.display())
            }
            Self::ParsePem { path, source } => {
                write!(
                    formatter,
                    "failed to parse PEM in {}: {source}",
                    path.display()
                )
            }
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Bind(source) => write!(formatter, "failed to bind server listeners: {source}"),
        }
    }
}

impl std::error::Error for ServerStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParsePem { source, .. } => Some(source),
            Self::QuicConfig(source) => Some(source),
            Self::Bind(source) => Some(source),
            Self::MissingCertificate { .. } | Self::MissingPrivateKey { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum ClientStartupError {
    TlsMaterial(ServerStartupError),
    NativeRoots { errors: usize },
    AddRootCertificate(rustls::Error),
    QuicConfig(QuicConfigError),
    Resolve(io::Error),
    MissingServerAddress { server_hostname: String },
    Connect(ClientConnectError),
}

impl fmt::Display for ClientStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsMaterial(source) => write!(formatter, "{source}"),
            Self::NativeRoots { errors } => write!(
                formatter,
                "failed to load the system trust store: {errors} certificate(s) could not be loaded"
            ),
            Self::AddRootCertificate(source) => write!(
                formatter,
                "failed to add a trusted CA certificate: {source}"
            ),
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Resolve(source) => {
                write!(formatter, "failed to resolve the Server hostname: {source}")
            }
            Self::MissingServerAddress { server_hostname } => {
                write!(
                    formatter,
                    "the Server hostname did not resolve to any addresses: {server_hostname}"
                )
            }
            Self::Connect(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ClientStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TlsMaterial(source) => Some(source),
            Self::AddRootCertificate(source) => Some(source),
            Self::QuicConfig(source) => Some(source),
            Self::Resolve(source) => Some(source),
            Self::Connect(source) => Some(source),
            Self::NativeRoots { .. } | Self::MissingServerAddress { .. } => None,
        }
    }
}

fn load_certificate_chain(
    path: &std::path::Path,
) -> Result<Vec<CertificateDer<'static>>, ServerStartupError> {
    let bytes = fs::read(path).map_err(|source| ServerStartupError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ServerStartupError::ParsePem {
            path: path.to_path_buf(),
            source,
        })?;
    if certs.is_empty() {
        return Err(ServerStartupError::MissingCertificate {
            path: path.to_path_buf(),
        });
    }
    Ok(certs)
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, ServerStartupError> {
    let bytes = fs::read(path).map_err(|source| ServerStartupError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    let private_key = rustls_pemfile::private_key(&mut reader).map_err(|source| {
        ServerStartupError::ParsePem {
            path: path.to_path_buf(),
            source,
        }
    })?;
    private_key.ok_or_else(|| ServerStartupError::MissingPrivateKey {
        path: path.to_path_buf(),
    })
}

fn load_root_store(
    server_ca_file: Option<&std::path::Path>,
) -> Result<RootCertStore, ClientStartupError> {
    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        return Err(ClientStartupError::NativeRoots {
            errors: native_certs.errors.len(),
        });
    }
    for cert in native_certs.certs {
        roots
            .add(cert)
            .map_err(ClientStartupError::AddRootCertificate)?;
    }
    if let Some(server_ca_file) = server_ca_file {
        for cert in
            load_certificate_chain(server_ca_file).map_err(ClientStartupError::TlsMaterial)?
        {
            roots
                .add(cert)
                .map_err(ClientStartupError::AddRootCertificate)?;
        }
    }
    Ok(roots)
}
