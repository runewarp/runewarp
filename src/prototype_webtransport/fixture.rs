use super::{Result, SERVER, STEP};
use crate::{
    ClientIdentity, generate_client_identity,
    quic::StaticClientIdentityAdmission,
    tls_material::{certificate_chain_from_pem, private_key_from_pem},
    tunnel_h3::{make_client_tunnel_h3_config, make_server_tunnel_h3_config},
};
use quinn::Endpoint;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::time::timeout;

pub(super) struct Fixture {
    pub server: Endpoint,
    pub client: Endpoint,
    pub identity: ClientIdentity,
    certificate: CertificateDer<'static>,
}

impl Fixture {
    pub fn new(credit: u32, admit: bool) -> Result<Self> {
        let certificate = rcgen::generate_simple_self_signed(vec![SERVER.into()])?;
        let key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into();
        let cert = CertificateDer::from(certificate.cert);
        let generated = generate_client_identity()?;
        let chain = certificate_chain_from_pem(generated.certificate_pem.as_bytes())?;
        let client_key = private_key_from_pem(generated.private_key_pem.as_bytes())?;
        let identities = if admit {
            vec![generated.client_identity.clone()]
        } else {
            vec![]
        };
        let server_config = make_server_tunnel_h3_config(
            vec![cert.clone()],
            key,
            Arc::new(StaticClientIdentityAdmission::from_identities(&identities)),
        )?;
        let server = Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone())?;
        let mut config = make_client_tunnel_h3_config(roots, chain, client_key)?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(credit.into());
        transport.max_concurrent_uni_streams(8u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        config.transport_config(Arc::new(transport));
        let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        client.set_default_client_config(config);
        Ok(Self {
            server,
            client,
            identity: generated.client_identity,
            certificate: cert,
        })
    }

    pub fn remove_client_certificate(&mut self) -> Result<()> {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone())?;
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto.enable_early_data = false;
        let config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));
        self.client.set_default_client_config(config);
        Ok(())
    }

    pub async fn connect(&self) -> Result<(quinn::Connection, quinn::Connection)> {
        let address = self.server.local_addr()?;
        timeout(STEP, async {
            let server = async {
                Ok::<_, super::Error>(self.server.accept().await.ok_or("endpoint closed")?.await?)
            };
            let client =
                async { Ok::<_, super::Error>(self.client.connect(address, SERVER)?.await?) };
            tokio::try_join!(server, client)
        })
        .await?
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"");
        self.server.close(0u32.into(), b"");
    }
}
