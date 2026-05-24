use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    ClientServiceSettings, ClientSettings, PreparedClient, Server, ServerConfig,
    ServerTunnelSettings, generate_client_identity, load_client_settings,
    make_server_quic_config_with_client_auth,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::tempdir;

#[tokio::test]
async fn prepared_client_connects_from_validated_settings() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        configured_tunnels: vec![ServerTunnelSettings {
            public_hostnames: vec!["app.example.test".to_owned()],
            client_identity: client_identity.client_identity.clone(),
        }],
        logs: true,
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_auth(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            std::slice::from_ref(&client_identity.client_identity),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem).unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "client-identity"

[[client.services]]
backend-address = "localhost:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();
    let client = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr)
        .await
        .unwrap();

    assert_ne!(client.local_addr().unwrap().port(), 0);

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn prepared_client_uses_the_configured_server_address_port() {
    let tempdir = tempdir().unwrap();
    let certified_server = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();
    let server = Server::bind(ServerConfig {
        public_bind_addr: SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        tunnel_bind_addr: SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        server_hostname: "localhost".to_owned(),
        configured_tunnels: vec![ServerTunnelSettings {
            public_hostnames: vec!["app.example.test".to_owned()],
            client_identity: client_identity.client_identity.clone(),
        }],
        logs: true,
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_auth(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            std::slice::from_ref(&client_identity.client_identity),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem).unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        format!(
            r#"
[client]
server-address = "localhost:{}"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "client-identity"

[[client.services]]
backend-address = "localhost:443"
"#,
            tunnel_addr.port()
        ),
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();
    let client = PreparedClient::connect(&settings, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        .await
        .unwrap();

    assert_ne!(client.local_addr().unwrap().port(), 0);

    server_task.abort();
    let _ = server_task.await;
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(der.to_vec()).into()
}

#[tokio::test]
async fn prepared_client_rejects_settings_without_services() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        configured_tunnels: vec![ServerTunnelSettings {
            public_hostnames: vec!["app.example.test".to_owned()],
            client_identity: client_identity.client_identity.clone(),
        }],
        logs: true,
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_auth(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            std::slice::from_ref(&client_identity.client_identity),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem).unwrap();
    fs::write(
        tempdir.path().join("client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let settings = ClientSettings {
        server_hostname: "tunnel.example.test".to_owned(),
        server_port: 443,
        logs: true,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().to_path_buf(),
        reconnect_interval: Duration::from_secs(5),
        services: Vec::new(),
    };

    let join = tokio::spawn(async move {
        PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await
    })
    .await;

    let error = match join {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => panic!("expected client startup to reject missing services"),
        Err(error) => panic!("expected a client startup error, got panic: {error}"),
    };
    assert!(
        error
            .to_string()
            .contains("client settings must include at least one Service")
    );

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn prepared_client_rejects_multi_service_catch_all_settings() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    fs::write(
        tempdir.path().join("server-ca.pem"),
        certified_server.cert.pem(),
    )
    .unwrap();
    let client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let settings = ClientSettings {
        server_hostname: "tunnel.example.test".to_owned(),
        server_port: 443,
        logs: true,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        reconnect_interval: Duration::from_secs(5),
        services: vec![
            ClientServiceSettings {
                public_hostnames: None,
                backend_address: "localhost:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "localhost:8443".to_owned(),
            },
        ],
    };

    let error = match PreparedClient::connect_to(&settings, localhost(0), localhost(0)).await {
        Ok(_) => panic!("expected client startup to reject a multi-service catch-all shape"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(
        "client.services[].public-hostnames may be omitted only when there is exactly one service"
    ));
}

#[tokio::test]
async fn prepared_client_rejects_duplicate_service_hostnames_in_direct_settings() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    fs::write(
        tempdir.path().join("server-ca.pem"),
        certified_server.cert.pem(),
    )
    .unwrap();
    let client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let settings = ClientSettings {
        server_hostname: "tunnel.example.test".to_owned(),
        server_port: 443,
        logs: true,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        reconnect_interval: Duration::from_secs(5),
        services: vec![
            ClientServiceSettings {
                public_hostnames: Some(vec!["App.Example.Test.".to_owned()]),
                backend_address: "localhost:443".to_owned(),
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "localhost:8443".to_owned(),
            },
        ],
    };

    let error = match PreparedClient::connect_to(&settings, localhost(0), localhost(0)).await {
        Ok(_) => panic!("expected client startup to reject duplicate service hostnames"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(
        "client.services[].public-hostnames must be unique after normalization: app.example.test"
    ));
}
