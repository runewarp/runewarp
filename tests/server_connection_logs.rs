use runewarp::tunnel::ClientTunnel;
use runewarp::{
    OrderlyShutdown, Server, ServerAdmission, ServerAuthorization, ServerBindConfig,
    ServerTunnelConfig,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};
#[path = "common/log_capture.rs"]
mod log_capture;
use log_capture::Logs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn client_config(
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
    identity: &runewarp::GeneratedClientIdentity,
) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    Ok(runewarp::make_client_tunnel_h3_config(
        roots,
        CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()?,
        PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())?,
    )?)
}

async fn connect(
    config: quinn::ClientConfig,
    address: SocketAddr,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let mut endpoint = quinn::Endpoint::client(
        if address.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        }
        .parse()?,
    )?;
    endpoint.set_default_client_config(config);
    let connection = timeout(
        Duration::from_secs(2),
        endpoint.connect(address, "tunnel.example.test")?,
    )
    .await??;
    Ok((endpoint, connection))
}

async fn visitor(address: SocketAddr, hostname: &str) -> Result<TcpStream> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut tls = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(hostname.to_owned())?,
    )?;
    let mut hello = Vec::new();
    tls.write_tls(&mut hello)?;
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&hello).await?;
    Ok(stream)
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing {name}: {line}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_connection_logs_correlate_visitors_and_tunnels_across_listeners() -> Result<()> {
    let logs = Logs::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )?;
    let hostname: runewarp::ServerHostname =
        "tunnel.example.test".try_into().expect("literal hostname");
    let identity = runewarp::generate_client_identity()?;
    let cert = rcgen::generate_simple_self_signed(vec!["tunnel.example.test".to_owned()])?;
    let authorization = ServerAuthorization::from_static_tunnels(
        &hostname,
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec!["app.example.test".try_into().expect("literal hostname")],
            authorized_client_identities: vec![identity.client_identity.clone()],
        }],
    )?;
    let addresses = vec!["127.0.0.1:0".parse()?, "[::1]:0".parse()?];
    let server = Server::bind(ServerBindConfig {
        public_bind_addrs: addresses.clone(),
        tunnel_connection_bind_addrs: addresses,
        readiness_bind_addr: None,
        server_hostname: hostname.clone(),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: runewarp::make_server_tunnel_h3_config(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            Arc::new(authorization),
        )?,
        admission: ServerAdmission::Static,
    })
    .await?;
    let publics = server.public_addrs()?;
    let tunnels = server.tunnel_addrs()?;
    let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
    let trigger = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });
    let config = client_config(&cert, &identity)?;
    let ((endpoint_a, connection_a), (endpoint_b, connection_b)) = tokio::try_join!(
        connect(config.clone(), tunnels[0]),
        connect(config.clone(), tunnels[1])
    )?;
    let (mut client_a, mut client_b) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            ClientTunnel::establish(
                connection_a.clone(),
                &hostname,
                Arc::new(Semaphore::new(256))
            ),
            ClientTunnel::establish(
                connection_b.clone(),
                &hostname,
                Arc::new(Semaphore::new(256))
            ),
        )
    })
    .await??;
    let generation = client_a.server_generation().to_string();
    assert_eq!(generation, client_b.server_generation().to_string());
    let mut visitor_a = visitor(publics[0], "app.example.test").await?;
    let mut stream_a = timeout(Duration::from_secs(2), async {
        tokio::select! { stream = client_a.accept_tunnel_stream() => stream, stream = client_b.accept_tunnel_stream() => stream }
    }).await?.expect("forwarded Visitor");
    // A real response proves the route has emitted before the next connection is accepted.
    stream_a.write_all(b"a").await?;
    let mut byte = [0];
    timeout(Duration::from_secs(2), visitor_a.read_exact(&mut byte)).await??;
    assert_eq!(byte, *b"a");
    let mut visitor_b = visitor(publics[1], "app.example.test").await?;
    let mut stream_b = timeout(Duration::from_secs(2), async {
        tokio::select! { stream = client_a.accept_tunnel_stream() => stream, stream = client_b.accept_tunnel_stream() => stream }
    }).await?.expect("second forwarded Visitor");
    stream_b.write_all(b"b").await?;
    timeout(Duration::from_secs(2), visitor_b.read_exact(&mut byte)).await??;
    assert_eq!(byte, *b"b");
    let mut rejected = visitor(publics[0], "unknown.example.test").await?;
    let _ = timeout(Duration::from_secs(2), rejected.read(&mut byte)).await?;
    // The same endpoint now exercises failed and unauthorized handshakes before HTTP/3.
    let unauthorized = runewarp::generate_client_identity()?;
    let mut bad_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    bad_endpoint.set_default_client_config(client_config(&cert, &unauthorized)?);
    if let Ok(connection) = timeout(
        Duration::from_secs(2),
        bad_endpoint.connect(tunnels[0], "tunnel.example.test")?,
    )
    .await?
    {
        timeout(Duration::from_secs(2), connection.closed()).await?;
    }
    connection_a.close(0u32.into(), b"test done");
    connection_b.close(0u32.into(), b"test done");
    timeout(Duration::from_secs(2), async {
        loop {
            let output = logs.read();
            if output.matches("server tunnel connection closed:").count() == 2
                && output.contains("server tunnel connection failed:")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    trigger.begin_fast();
    timeout(Duration::from_secs(2), server_task).await???;
    drop((endpoint_a, endpoint_b, bad_endpoint));
    let output = logs.read();
    let lines: Vec<_> = output.lines().collect();
    let accepted: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("server tunnel connection accepted:"))
        .collect();
    assert_eq!(accepted.len(), 2, "{output}");
    let mut ids = HashSet::new();
    for line in &accepted {
        assert_eq!(field(line, "server-generation"), generation);
        let id: u64 = field(line, "connection-id").parse()?;
        assert!(ids.insert(id));
        assert_eq!(
            lines
                .iter()
                .filter(|closed| closed.contains("server tunnel connection closed:")
                    && field(closed, "connection-id") == id.to_string())
                .count(),
            1,
            "stable lifecycle ID: {output}"
        );
    }
    let mut previous_id = *ids.iter().max().expect("two accepted Tunnels");
    for line in lines.iter().filter(|line| line.contains("server route ")) {
        let id: u64 = field(line, "connection-id").parse()?;
        assert!(
            id > previous_id,
            "one increasing sequence across TCP and QUIC: {output}"
        );
        previous_id = id;
        assert_eq!(field(line, "server-generation"), generation);
        assert!(
            ids.insert(field(line, "connection-id").parse::<u64>()?),
            "one ID per distinct Visitor: {output}"
        );
    }
    assert_eq!(
        ids.len(),
        5,
        "two Tunnel connections and three Visitors: {output}"
    );
    assert!(output.contains(&format!(
        "server runtime started: server-generation={generation}"
    )));
    let unauthorized_line = lines
        .iter()
        .find(|line| line.contains("server tunnel connection unauthorized:"))
        .expect("unauthorized event");
    let failed_line = lines
        .iter()
        .find(|line| line.contains("server tunnel connection failed:"))
        .expect("handshake failure event");
    for line in [unauthorized_line, failed_line] {
        assert_eq!(field(line, "server-generation"), generation);
    }
    assert_eq!(
        field(unauthorized_line, "connection-id"),
        field(failed_line, "connection-id")
    );
    let failed_id: u64 = field(failed_line, "connection-id").parse()?;
    assert!(failed_id > previous_id);
    assert!(ids.insert(failed_id));
    for line in lines
        .iter()
        .filter(|line| line.contains("server route ") || line.contains("server tunnel connection "))
    {
        assert!(!line.contains("remote-address="));
        assert!(!line.contains("127.0.0.1"));
        assert!(!line.contains("[::1]"));
    }
    Ok(())
}
