use std::io;

use quinn::Connection;
use tokio::io::AsyncRead;

use crate::acme::ACME_TLS_ALPN;
use crate::client_hello::{ClientHelloError, read_client_hello};
use crate::hostname::validate_public_hostname;

use super::tunnel_registry::TunnelRegistry;

#[derive(Clone)]
pub(crate) struct VisitorDecisionModule {
    server_hostname: String,
    tunnel_registry: TunnelRegistry,
}

impl VisitorDecisionModule {
    pub(crate) fn new(
        server_hostname: String,
        tunnel_registry: TunnelRegistry,
    ) -> io::Result<Self> {
        Ok(Self {
            server_hostname: validate_public_hostname(&server_hostname).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("server.hostname is invalid: {error}"),
                )
            })?,
            tunnel_registry,
        })
    }

    pub(crate) async fn decide<R>(&self, visitor: &mut R) -> VisitorDecision
    where
        R: AsyncRead + Unpin,
    {
        let parsed_client_hello = match read_client_hello(visitor).await {
            Ok(parsed_client_hello) => parsed_client_hello,
            Err(error) => return VisitorDecision::Reject(map_client_hello_error(error)),
        };
        let serves_acme_tls_alpn_01 = parsed_client_hello.offers_alpn_protocol(ACME_TLS_ALPN);
        let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();

        if public_hostname == self.server_hostname {
            return if serves_acme_tls_alpn_01 {
                VisitorDecision::ServeAcmeTlsAlpn01(AcmeDecision {
                    server_hostname: public_hostname,
                    buffered_bytes,
                })
            } else {
                VisitorDecision::Reject(VisitorRejection::ServerHostname {
                    server_hostname: public_hostname,
                })
            };
        }

        if !self
            .tunnel_registry
            .contains_public_hostname(&public_hostname)
        {
            return VisitorDecision::Reject(VisitorRejection::UnauthorizedPublicHostname {
                public_hostname,
            });
        }

        let Some(tunnel_connection) = self
            .tunnel_registry
            .current_connection(&public_hostname)
            .await
        else {
            return VisitorDecision::Reject(VisitorRejection::NoActiveTunnelConnection {
                public_hostname,
            });
        };

        VisitorDecision::Forward(ForwardDecision {
            public_hostname,
            buffered_bytes,
            tunnel_connection,
        })
    }
}

#[derive(Debug)]
pub(crate) enum VisitorDecision {
    Reject(VisitorRejection),
    ServeAcmeTlsAlpn01(AcmeDecision),
    Forward(ForwardDecision),
}

#[derive(Debug)]
pub(crate) enum VisitorRejection {
    InvalidTls,
    MissingSni,
    InvalidSni,
    ClientHelloTooLong { limit: usize },
    IncompleteClientHello,
    ReadFailure { kind: io::ErrorKind },
    ServerHostname { server_hostname: String },
    UnauthorizedPublicHostname { public_hostname: String },
    NoActiveTunnelConnection { public_hostname: String },
}

#[derive(Debug)]
pub(crate) struct AcmeDecision {
    pub(crate) server_hostname: String,
    pub(crate) buffered_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ForwardDecision {
    pub(crate) public_hostname: String,
    pub(crate) buffered_bytes: Vec<u8>,
    pub(crate) tunnel_connection: Connection,
}

fn map_client_hello_error(error: ClientHelloError) -> VisitorRejection {
    match error {
        ClientHelloError::Io(error) => VisitorRejection::ReadFailure { kind: error.kind() },
        ClientHelloError::InvalidTls => VisitorRejection::InvalidTls,
        ClientHelloError::InvalidSni => VisitorRejection::InvalidSni,
        ClientHelloError::MissingSni => VisitorRejection::MissingSni,
        ClientHelloError::TooLong { limit } => VisitorRejection::ClientHelloTooLong { limit },
        ClientHelloError::UnexpectedEof => VisitorRejection::IncompleteClientHello,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::ClientConnection;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use crate::acme::ACME_TLS_ALPN;
    use crate::{
        GeneratedClientIdentity, ServerTunnelSettings, generate_client_identity,
        make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    };

    use super::super::tunnel_registry::TunnelRegistry;
    use super::{VisitorDecision, VisitorDecisionModule};

    #[tokio::test]
    async fn authorized_public_hostname_with_active_tunnel_connection_yields_forward_decision() {
        let client_identity = generate_client_identity().expect("generate test client identity");
        let registry = TunnelRegistry::configured(
            "Tunnel.Example.Test.",
            &[ServerTunnelSettings {
                public_hostnames: vec!["App.Example.Test.".to_owned()],
                client_identity: client_identity.client_identity.clone(),
            }],
        )
        .unwrap();
        let fixture = TunnelConnectionFixture::connect(&client_identity).await;
        registry.register(fixture.server_connection.clone()).await;

        let module =
            VisitorDecisionModule::new("Tunnel.Example.Test.".to_owned(), registry).unwrap();
        let client_hello = build_client_hello("app.example.test");
        let mut reader = buffered_reader(client_hello.clone()).await;

        let decision = module.decide(&mut reader).await;

        match decision {
            VisitorDecision::Forward(forward) => {
                assert_eq!(forward.public_hostname, "app.example.test");
                assert_eq!(forward.buffered_bytes, client_hello);
            }
            other => panic!("expected a forward decision, got {other:?}"),
        }

        let _ = fixture;
    }

    #[tokio::test]
    async fn unconfigured_public_hostname_yields_unauthorized_rejection() {
        let registry = TunnelRegistry::single(vec!["app.example.test".to_owned()]).unwrap();
        let module =
            VisitorDecisionModule::new("tunnel.example.test".to_owned(), registry).unwrap();
        let client_hello = build_client_hello("api.example.test");
        let mut reader = buffered_reader(client_hello).await;

        let decision = module.decide(&mut reader).await;

        match decision {
            VisitorDecision::Reject(super::VisitorRejection::UnauthorizedPublicHostname {
                public_hostname,
            }) => assert_eq!(public_hostname, "api.example.test"),
            other => panic!("expected an unauthorized rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_hostname_with_acme_alpn_yields_acme_decision() {
        let registry = TunnelRegistry::single(vec!["app.example.test".to_owned()]).unwrap();
        let module =
            VisitorDecisionModule::new("Tunnel.Example.Test.".to_owned(), registry).unwrap();
        let client_hello =
            build_client_hello_with_alpn("tunnel.example.test", vec![ACME_TLS_ALPN.to_vec()]);
        let mut reader = buffered_reader(client_hello.clone()).await;

        let decision = module.decide(&mut reader).await;

        match decision {
            VisitorDecision::ServeAcmeTlsAlpn01(acme_decision) => {
                assert_eq!(acme_decision.server_hostname, "tunnel.example.test");
                assert_eq!(acme_decision.buffered_bytes, client_hello);
            }
            other => panic!("expected an ACME decision, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorized_public_hostname_without_active_tunnel_connection_yields_rejection() {
        let registry = TunnelRegistry::single(vec!["app.example.test".to_owned()]).unwrap();
        let module =
            VisitorDecisionModule::new("tunnel.example.test".to_owned(), registry).unwrap();
        let client_hello = build_client_hello("app.example.test");
        let mut reader = buffered_reader(client_hello).await;

        let decision = module.decide(&mut reader).await;

        match decision {
            VisitorDecision::Reject(super::VisitorRejection::NoActiveTunnelConnection {
                public_hostname,
            }) => assert_eq!(public_hostname, "app.example.test"),
            other => panic!("expected a no-active-tunnel rejection, got {other:?}"),
        }
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        _client_connection: Connection,
        server_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> Self {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test");
            let server_endpoint = Endpoint::server(
                make_server_quic_config_with_client_auth(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                    std::slice::from_ref(&client_identity.client_identity),
                )
                .unwrap(),
                localhost(0),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            let mut client_endpoint = Endpoint::client(localhost(0)).unwrap();
            client_endpoint.set_default_client_config(
                make_client_quic_config_with_client_auth(
                    root_store_with(&certificate),
                    client_certificate_chain(client_identity),
                    client_private_key(client_identity),
                )
                .unwrap(),
            );

            let accept_connection = async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            };
            let connect_client = async {
                client_endpoint
                    .connect(server_addr, "tunnel.example.test")
                    .unwrap()
                    .await
                    .unwrap()
            };
            let (server_connection, client_connection) =
                tokio::join!(accept_connection, connect_client);

            Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                _client_connection: client_connection,
                server_connection,
            }
        }
    }

    async fn buffered_reader(bytes: Vec<u8>) -> DuplexStream {
        let (mut writer, reader) = tokio::io::duplex(bytes.len() + 1);
        tokio::spawn(async move {
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        reader
    }

    fn build_client_hello(server_name: &str) -> Vec<u8> {
        build_client_hello_with_alpn(server_name, Vec::new())
    }

    fn build_client_hello_with_alpn(server_name: &str, alpn_protocols: Vec<Vec<u8>>) -> Vec<u8> {
        let trusted_cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(server_name.to_owned()).unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
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

    fn client_certificate_chain(
        client_identity: &GeneratedClientIdentity,
    ) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut Cursor::new(client_identity.certificate_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn client_private_key(client_identity: &GeneratedClientIdentity) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut Cursor::new(client_identity.private_key_pem.as_bytes()))
            .unwrap()
            .unwrap()
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        roots
    }
}
