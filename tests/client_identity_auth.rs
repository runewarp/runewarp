use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use runewarp::{
    Client, ClientConnectConfig, GeneratedClientIdentity, generate_client_identity,
    make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256;

mod common;

use common::{
    assert_generated_client_identity_certificate_profile, legacy_p256_client_identity_without_eku,
};

#[tokio::test]
async fn newly_generated_ed25519_client_identity_completes_tunnel_handshake() -> io::Result<()> {
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

async fn complete_authorized_tunnel_handshake(
    client_identity: &GeneratedClientIdentity,
) -> io::Result<()> {
    let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
    let server_endpoint = Endpoint::server(
        make_server_quic_config_with_client_auth(
            vec![certificate.clone()],
            private_key_from_der(&private_key),
            std::slice::from_ref(&client_identity.client_identity),
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
        quic_client_config: make_client_quic_config_with_client_auth(
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
        let _connection = timeout(Duration::from_secs(1), incoming)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
            .map_err(io::Error::other)?;
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
