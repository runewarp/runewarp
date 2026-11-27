use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quinn::Endpoint;
use std::sync::Arc;

use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData, generate_simple_self_signed};
use runewarp::{
    Client, ClientConnectConfig, ClientIdentity, make_client_tunnel_h3_config,
    make_server_tunnel_h3_config,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256;

mod common;

use common::{
    GeneratedClientIdentity, assert_generated_client_identity_certificate_profile,
    generate_client_identity, legacy_p256_client_identity_without_eku,
};

#[tokio::test]
async fn in_memory_p256_client_identity_completes_tunnel_handshake() -> io::Result<()> {
    let client_identity = generate_client_identity().map_err(io::Error::other)?;
    let certificate = CertificateDer::from_pem_slice(client_identity.certificate_pem.as_bytes())
        .map_err(io::Error::other)?;
    assert_generated_client_identity_certificate_profile(certificate.as_ref());
    complete_authorized_tunnel_handshake(&client_identity).await
}

#[tokio::test]
async fn legacy_p256_client_identity_without_eku_completes_tunnel_handshake() -> io::Result<()> {
    let client_identity = legacy_p256_client_identity_without_eku();
    assert_legacy_p256_without_eku_profile(&client_identity)?;
    complete_authorized_tunnel_handshake(&client_identity).await
}

#[tokio::test]
async fn ed25519_client_identity_is_rejected_even_when_authorized() -> io::Result<()> {
    let client_identity = self_signed_identity(KeyPair::generate_for(&PKCS_ED25519).unwrap());
    assert_handshake_rejected(&client_identity).await
}

#[tokio::test]
async fn rsa_client_identity_is_rejected_even_when_authorized() -> io::Result<()> {
    let client_identity = self_signed_identity(rsa_key_pair());
    assert_handshake_rejected(&client_identity).await
}

#[tokio::test]
async fn new_client_identity_authenticates_to_an_older_server_verifier() -> io::Result<()> {
    // Older Servers pinned the leaf SPKI and accepted every signature scheme the provider supports.
    let client_identity = generate_client_identity().map_err(io::Error::other)?;
    let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(OlderServerVerifier {
            pinned: *client_identity.client_identity.as_bytes(),
        }))
        .with_single_cert(
            vec![certificate.clone()],
            private_key_from_der(&private_key),
        )
        .map_err(io::Error::other)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(io::Error::other)?,
        )),
        localhost(0),
    )?;
    let server_addr = server_endpoint.local_addr()?;
    let accept = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
        })?;
        incoming.await.map_err(io::Error::other)
    });

    let mut client_endpoint = Endpoint::client(localhost(0))?;
    client_endpoint.set_default_client_config(
        make_client_tunnel_h3_config(
            root_store_with(&certificate)?,
            client_certificate_chain(&client_identity)?,
            client_private_key(&client_identity)?,
        )
        .map_err(io::Error::other)?,
    );
    let client = timeout(
        Duration::from_secs(5),
        client_endpoint
            .connect(server_addr, "tunnel.example.test")
            .map_err(io::Error::other)?,
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
    .map_err(io::Error::other)?;
    let server = timeout(Duration::from_secs(5), accept)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
        .map_err(io::Error::other)??;

    assert!(server.peer_identity().is_some());
    client.close(0_u32.into(), b"done");
    Ok(())
}

#[derive(Debug)]
struct OlderServerVerifier {
    pinned: [u8; 32],
}

impl rustls::server::danger::ClientCertVerifier for OlderServerVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let (_, parsed) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let identity =
            ClientIdentity::from_subject_public_key_info(parsed.tbs_certificate.subject_pki.raw);
        if identity.as_bytes() == &self.pinned {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn self_signed_identity(key: KeyPair) -> GeneratedClientIdentity {
    let certificate = rcgen::CertificateParams::new(vec!["runewarp-client".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    GeneratedClientIdentity {
        private_key_pem: key.serialize_pem(),
        certificate_pem: certificate.pem(),
        client_identity: ClientIdentity::from_subject_public_key_info(
            &key.subject_public_key_info(),
        ),
    }
}

/// ring cannot generate RSA keys, so the RSA fixture comes from openssl.
fn rsa_key_pair() -> KeyPair {
    let output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()
        .expect("openssl must be installed to build the RSA identity fixture");
    assert!(output.status.success(), "openssl genpkey failed");
    KeyPair::from_pem_and_sign_algo(
        std::str::from_utf8(&output.stdout).unwrap(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap()
}

async fn assert_handshake_rejected(client_identity: &GeneratedClientIdentity) -> io::Result<()> {
    let outcome = timeout(
        Duration::from_secs(5),
        complete_authorized_tunnel_handshake(client_identity),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rejection timed out"))?;
    // Setup failures (binding, TLS config, Tunnel establishment) are not rejections: only a QUIC
    // close carrying a TLS (crypto) error code proves the Server refused the handshake.
    let error = outcome.expect_err(
        "the Server must reject non-P-256 identities even when their fingerprint is authorized",
    );
    let detail = format!("{error:?}");
    assert!(
        detail.contains("ConnectionClosed") && detail.contains("Code::crypto("),
        "expected a TLS handshake rejection, got: {detail}"
    );
    Ok(())
}

async fn complete_authorized_tunnel_handshake(
    client_identity: &GeneratedClientIdentity,
) -> io::Result<()> {
    let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
    let server_endpoint = Endpoint::server(
        make_server_tunnel_h3_config(
            vec![certificate.clone()],
            private_key_from_der(&private_key),
            std::sync::Arc::new(
                runewarp::ServerAuthorization::from_static_tunnels(
                    &runewarp::ServerHostname::try_from("tunnel.example.test").unwrap(),
                    &[runewarp::ServerTunnelConfig {
                        id: None,
                        public_hostnames: vec![
                            runewarp::PublicHostname::try_from("app.example.test").unwrap(),
                        ],
                        authorized_client_identities: vec![client_identity.client_identity.clone()],
                    }],
                )
                .unwrap(),
            ),
        )
        .map_err(io::Error::other)?,
        localhost(0),
    )
    .map_err(io::Error::other)?;

    let client_config = ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: server_endpoint.local_addr()?,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: "127.0.0.1:443".to_owned(),
        quic_client_config: make_client_tunnel_h3_config(
            root_store_with(&certificate)?,
            client_certificate_chain(client_identity)?,
            client_private_key(client_identity)?,
        )
        .map_err(io::Error::other)?,
    };

    let accept_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
            })?;
        let connection = timeout(Duration::from_secs(1), incoming)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
            .map_err(io::Error::other)?;
        let tunnel = runewarp::tunnel::ServerTunnel::establish(
            connection,
            runewarp::ServerHostname::try_from("tunnel.example.test").unwrap(),
            runewarp::tunnel::ServerRuntimeGeneration::generate(),
        )
        .await
        .map_err(io::Error::other)?;
        let _ = tunnel.closed().await;
        Ok::<(), io::Error>(())
    });

    let client = Client::connect(client_config)
        .await
        .map_err(io::Error::other)?;
    drop(client);
    accept_task
        .await
        .map_err(|join_error| io::Error::other(format!("accept task failed: {join_error}")))??;
    Ok(())
}

fn assert_legacy_p256_without_eku_profile(
    client_identity: &GeneratedClientIdentity,
) -> io::Result<()> {
    let certificate = CertificateDer::from_pem_slice(client_identity.certificate_pem.as_bytes())
        .map_err(io::Error::other)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| io::Error::other(error.to_string()))?;
    assert_eq!(
        parsed.signature_algorithm.algorithm,
        OID_SIG_ECDSA_WITH_SHA256
    );
    assert!(
        parsed
            .key_usage()
            .map_err(|error| io::Error::other(error.to_string()))?
            .is_none(),
        "legacy fixture must omit key usage"
    );
    assert!(
        parsed
            .extended_key_usage()
            .map_err(|error| io::Error::other(error.to_string()))?
            .is_none(),
        "legacy fixture must omit extended key usage"
    );
    Ok(())
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn make_self_signed_cert(server_name: &str) -> io::Result<(CertificateDer<'static>, Vec<u8>)> {
    let certified_key =
        generate_simple_self_signed(vec![server_name.to_owned()]).map_err(io::Error::other)?;
    Ok((
        CertificateDer::from(certified_key.cert),
        certified_key.signing_key.serialize_der(),
    ))
}

fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(der.to_vec()).into()
}

fn client_certificate_chain(
    client_identity: &GeneratedClientIdentity,
) -> io::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(client_identity.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)
}

fn client_private_key(
    client_identity: &GeneratedClientIdentity,
) -> io::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(client_identity.private_key_pem.as_bytes())
        .map_err(io::Error::other)
}

fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).map_err(io::Error::other)?;
    Ok(roots)
}
