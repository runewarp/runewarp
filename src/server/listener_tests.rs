//! Real sockets exercise shared admission across independently bound addresses.
use super::*;
use crate::{Client, ClientConnectConfig, ServerTunnelConfig};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

async fn fixture(
    limits: ServerAdmissionLimits,
) -> Result<(Server, quinn::ClientConfig), Box<dyn std::error::Error>> {
    let hostname = ServerHostname::try_from("tunnel.example.test").expect("literal hostname");
    let identity = crate::generate_client_identity()?;
    let cert = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let authorization = ServerAuthorization::from_static_tunnels(
        &hostname,
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![
                crate::PublicHostname::try_from("app.example.test").expect("literal hostname"),
            ],
            authorized_client_identities: vec![identity.client_identity],
        }],
    )?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    use rustls::pki_types::pem::PemObject;
    let client_config = crate::make_client_tunnel_h3_config(
        roots,
        rustls::pki_types::CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?,
        rustls::pki_types::PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())?,
    )?;
    let server = Server::bind_with_admission_limits_and_proxy(
        ServerBindConfig {
            public_bind_addrs: vec!["127.0.0.1:0".parse()?, "[::1]:0".parse()?],
            tunnel_connection_bind_addrs: vec!["127.0.0.1:0".parse()?, "[::1]:0".parse()?],
            readiness_bind_addr: None,
            server_hostname: hostname,
            authorization: authorization.clone(),
            public_tls_config: None,
            quic_server_config: crate::make_server_tunnel_h3_config(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
                Arc::new(authorization),
            )?,
            admission: ServerAdmission::Static,
        },
        limits,
        None,
        vec![],
        None,
    )
    .await?;
    Ok((server, client_config))
}

async fn connect(
    config: quinn::ClientConfig,
    address: SocketAddr,
    backend: SocketAddr,
) -> Result<Client, crate::ClientConnectError> {
    Client::connect(ClientConnectConfig {
        local_bind_addr: if address.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        }
        .parse()
        .expect("literal"),
        server_addr: address,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend.to_string(),
        quic_client_config: config,
    })
    .await
}

async fn visitor(address: SocketAddr) -> io::Result<TcpStream> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut tls = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("app.example.test").expect("literal hostname"),
    )
    .map_err(io::Error::other)?;
    let mut hello = Vec::new();
    tls.write_tls(&mut hello)?;
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&hello).await?;
    Ok(stream)
}

#[tokio::test]
async fn visitor_capacity_is_shared_across_public_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, config) = fixture(ServerAdmissionLimits {
        max_active_routed_streams: 1,
        ..ServerAdmissionLimits::default()
    })
    .await?;
    let publics = server.public_addrs()?;
    let tunnels = server.tunnel_addrs()?;
    let shutdown = OrderlyShutdown::new(Duration::from_secs(2), Duration::ZERO);
    let trigger = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let client = connect(config, tunnels[1], backend.local_addr()?).await?;
    let client_task = tokio::spawn(client.run());
    let mut first = visitor(publics[0]).await?;
    let (mut forwarded, _) = timeout(Duration::from_secs(2), backend.accept()).await??;
    let mut byte = [0];
    // Observing forwarded bytes proves that the first Visitor holds active capacity.
    timeout(Duration::from_secs(2), forwarded.read_exact(&mut byte)).await??;
    let mut second = visitor(publics[1]).await?;
    assert!(matches!(
        timeout(Duration::from_secs(2), second.read(&mut byte)).await?,
        Ok(0) | Err(_)
    ));
    forwarded.write_all(b"ok").await?;
    let mut reply = [0; 2];
    timeout(Duration::from_secs(2), first.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"ok");
    trigger.begin_graceful();
    drop(first);
    drop(forwarded);
    timeout(Duration::from_secs(2), server_task).await???;
    let _ = timeout(Duration::from_secs(2), client_task).await??;
    Ok(())
}

#[tokio::test]
async fn tunnel_connection_limits_are_shared_across_udp_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    for limit in [
        AdmissionLimit::TunnelConnectionsGlobal,
        AdmissionLimit::TunnelConnectionsPerTunnel,
        AdmissionLimit::TunnelConnectionsPerIdentity,
    ] {
        let mut limits = ServerAdmissionLimits::default();
        match limit {
            AdmissionLimit::TunnelConnectionsGlobal => limits.max_tunnel_connections = 1,
            AdmissionLimit::TunnelConnectionsPerTunnel => {
                limits.max_tunnel_connections_per_tunnel = 1
            }
            AdmissionLimit::TunnelConnectionsPerIdentity => {
                limits.max_tunnel_connections_per_identity = 1
            }
            _ => unreachable!(),
        }
        let (server, config) = fixture(limits).await?;
        let publics = server.public_addrs()?;
        let tunnels = server.tunnel_addrs()?;
        let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
        let trigger = shutdown.clone();
        let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let first = connect(config.clone(), tunnels[0], backend.local_addr()?).await?;
        let first_task = tokio::spawn(first.run());
        let mut visitor = visitor(publics[1]).await?;
        let (mut forwarded, _) = timeout(Duration::from_secs(2), backend.accept()).await??;
        let mut byte = [0];
        timeout(Duration::from_secs(2), forwarded.read_exact(&mut byte)).await??;
        // The first connection is registered and serving before we attempt the sibling.
        if let Ok(second) = timeout(
            Duration::from_secs(2),
            connect(config, tunnels[1], backend.local_addr()?),
        )
        .await?
        {
            assert!(
                timeout(Duration::from_secs(2), second.run())
                    .await?
                    .is_err(),
                "{limit:?} must reject the second connection"
            );
        }
        forwarded.write_all(b"x").await?;
        timeout(Duration::from_secs(2), visitor.read_exact(&mut byte)).await??;
        assert_eq!(byte, *b"x", "{limit:?} must preserve the first connection");
        trigger.begin_fast();
        timeout(Duration::from_secs(2), server_task).await???;
        let _ = timeout(Duration::from_secs(2), first_task).await??;
    }
    Ok(())
}

#[tokio::test]
async fn graceful_shutdown_finishes_visitors_on_every_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, config) = fixture(ServerAdmissionLimits::default()).await?;
    let publics = server.public_addrs()?;
    let tunnels = server.tunnel_addrs()?;
    let shutdown = OrderlyShutdown::new(Duration::from_secs(2), Duration::ZERO);
    let trigger = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let mut clients = Vec::new();
    let mut visitors = Vec::new();
    let mut backends = Vec::new();
    for (public, tunnel) in publics.into_iter().zip(tunnels) {
        let client = connect(config.clone(), tunnel, backend.local_addr()?).await?;
        clients.push(tokio::spawn(client.run()));
        visitors.push(visitor(public).await?);
        let (mut forwarded, _) = timeout(Duration::from_secs(2), backend.accept()).await??;
        timeout(Duration::from_secs(2), forwarded.read_exact(&mut [0])).await??;
        backends.push(forwarded);
    }
    trigger.begin_graceful();
    for (mut visitor, mut backend) in visitors.into_iter().zip(backends) {
        visitor.shutdown().await?;
        timeout(Duration::from_secs(2), backend.read_to_end(&mut Vec::new())).await??;
        backend.write_all(b"final tail").await?;
        backend.shutdown().await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), visitor.read_to_end(&mut response)).await??;
        assert_eq!(response, b"final tail");
    }
    timeout(Duration::from_secs(2), server_task).await???;
    for client in clients {
        let _ = timeout(Duration::from_secs(2), client).await??;
    }
    Ok(())
}
