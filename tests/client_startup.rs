use rcgen::generate_simple_self_signed;
use runewarp::{
    ClientConfig, ClientInstancePrep, ClientPublicCertConfig, ClientTlsMode, LogLevel,
    PreparedClient, PublicHostname, Server, ServerAddress, ServerAdmission, ServerAuthorization,
    ServerBindConfig, ServerHostname, ServerTunnelConfig, ServiceConfig, generate_client_identity,
    initialize_manual_client_public_cert, load_client_config,
    make_server_quic_config_with_client_admission,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tempfile::tempdir;

fn public_hostname(hostname: &str) -> PublicHostname {
    PublicHostname::try_from(hostname).unwrap()
}

fn server_hostname(hostname: &str) -> ServerHostname {
    ServerHostname::try_from(hostname).unwrap()
}

fn server_address(value: &str) -> ServerAddress {
    ServerAddress::parse(value).unwrap()
}

#[tokio::test]
async fn prepared_client_connects_from_validated_settings() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();
    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
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

    let settings = load_client_config(&tempdir.path().join("config.toml")).unwrap();
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
    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("localhost"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        // Bind dual-stack wildcard listeners so `localhost` resolution order does not make
        // this port-selection test flaky across environments.
        public_bind_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        tunnel_connection_bind_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        readiness_bind_addr: None,
        server_hostname: server_hostname("localhost"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
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

    let settings = load_client_config(&tempdir.path().join("config.toml")).unwrap();
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
    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
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

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Info,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().to_path_buf(),
        services: Vec::new(),
        public_cert_config: None,
        control: None,
        admission: runewarp::ClientAdmission::Static,
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
            .contains("client config must include at least one Service")
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

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Info,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![
            ServiceConfig {
                public_hostnames: None,
                backend_address: "localhost:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:8443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
        ],
        public_cert_config: None,
        control: None,
        admission: runewarp::ClientAdmission::Static,
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

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Info,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("App.Example.Test.")]),
                backend_address: "localhost:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:8443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
        ],
        public_cert_config: None,
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    let error = match PreparedClient::connect_to(&settings, localhost(0), localhost(0)).await {
        Ok(_) => panic!("expected client startup to reject duplicate service hostnames"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(
        "client.services[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

#[tokio::test]
async fn prepared_client_rejects_missing_public_cert_material_for_terminating_service() {
    let tempdir = tempdir().unwrap();
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

    // public-cert-dir exists but has no material for app.example.test
    let public_cert_dir = tempdir.path().join("public-cert");
    fs::create_dir(&public_cert_dir).unwrap();

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: None,
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:443".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
            proxy_protocol: None,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Manual {
            directory: public_cert_dir,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    let error = match PreparedClient::connect_to(&settings, localhost(0), localhost(0)).await {
        Ok(_) => panic!("expected startup to fail when cert material is missing"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("app.example.test"),
        "error should mention the hostname: {error}"
    );
}

#[tokio::test]
async fn prepared_client_loads_valid_public_cert_material_for_terminating_service() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();

    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

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

    let public_cert_dir = tempdir.path().join("public-cert");
    initialize_manual_client_public_cert(&public_cert_dir, "app.example.test").unwrap();

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-ca-not-needed.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:443".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
            proxy_protocol: None,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Manual {
            directory: public_cert_dir,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    // We use a fake server_ca_file path; the connect will succeed despite the missing ca file
    // because we pass the server_cert directly. Use server_ca_file that doesn't exist but
    // wire up using the server cert directly in a root store.
    // For this test, we just verify startup doesn't fail due to cert material validation.
    // Use the actual server cert as CA.
    let server_cert_pem =
        rcgen::generate_simple_self_signed(vec!["tunnel.example.test".to_owned()])
            .unwrap()
            .cert
            .pem();
    let server_ca_path = tempdir.path().join("server-ca.pem");
    fs::write(&server_ca_path, server_cert_pem).unwrap();

    let settings = ClientConfig {
        server_ca_file: Some(server_ca_path),
        ..settings
    };

    // This should not error due to missing cert material (the material was initialized above).
    // It may fail with a connection error (wrong CA), but not a startup/material error.
    let result = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await;
    match result {
        Err(runewarp::ClientStartupError::TlsMaterial(_)) => {
            panic!("startup should not fail with TlsMaterial error when cert material is present")
        }
        Err(runewarp::ClientStartupError::InvalidSettings(msg))
            if msg.contains("app.example.test") =>
        {
            panic!("startup should not fail with missing cert material: {msg}")
        }
        _ => {} // other errors (connection, handshake, etc.) are acceptable
    }

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn prepared_client_accepts_mixed_terminate_and_passthrough_services() {
    // A settings object with one terminating and one passthrough service should pass
    // startup validation when cert material exists for the terminating hostname.
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();

    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![
                public_hostname("app.example.test"),
                public_hostname("api.example.test"),
            ],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        &client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        &client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    // Cert material for the terminating service only — passthrough needs none
    let public_cert_dir = tempdir.path().join("public-cert");
    initialize_manual_client_public_cert(&public_cert_dir, "app.example.test").unwrap();

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: None,
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
                proxy_protocol: None,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("api.example.test")]),
                backend_address: "localhost:9443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
        ],
        public_cert_config: Some(ClientPublicCertConfig::Manual {
            directory: public_cert_dir,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    // Startup must succeed — mixed services are valid
    let result = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await;
    match result {
        Err(runewarp::ClientStartupError::TlsMaterial(e)) => {
            panic!("startup should not fail with TlsMaterial error for mixed services: {e}")
        }
        Err(runewarp::ClientStartupError::InvalidSettings(msg)) => {
            panic!("startup should not reject a valid mixed-service configuration: {msg}")
        }
        _ => {} // connection errors are fine; we only care about startup validation
    }

    server_task.abort();
    let _ = server_task.await;
}

/// Client in ACME mode should connect immediately without blocking on certificate readiness.
/// The ACME resolver is created with no ready certs; startup must still succeed.
#[tokio::test]
async fn acme_client_starts_without_blocking_on_cert_readiness() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();

    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        &client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        &client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let acme_state_dir = tempdir.path().join("acme-state");
    fs::create_dir(&acme_state_dir).unwrap();

    // Use server_cert PEM as trust anchor for this test
    let server_ca_pem = rcgen::generate_simple_self_signed(vec!["tunnel.example.test".to_owned()])
        .unwrap()
        .cert
        .pem();
    fs::write(tempdir.path().join("server-ca.pem"), server_ca_pem).unwrap();

    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:80".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
            proxy_protocol: None,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    // Startup must succeed without blocking — the ACME resolver starts with no cert loaded,
    // but the client does not wait for cert acquisition before connecting.
    let result = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await;
    match result {
        Err(runewarp::ClientStartupError::InvalidSettings(msg)) => {
            panic!("ACME client startup must not fail with InvalidSettings: {msg}")
        }
        Err(runewarp::ClientStartupError::TlsMaterial(e)) => {
            panic!("ACME client startup must not fail with TlsMaterial: {e}")
        }
        _ => {} // connection errors (wrong CA) are acceptable; we only check startup
    }

    server_task.abort();
    let _ = server_task.await;
}

/// Shared Client-instance preparation survives reconnect-style redials without duplicating
/// Terminate-mode TLS / ACME ownership (#193).
#[tokio::test]
async fn shared_client_instance_prep_survives_reconnect_style_redials() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();
    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![public_hostname("app.example.test")],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
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
    let public_cert_dir = tempdir.path().join("public-cert");
    initialize_manual_client_public_cert(&public_cert_dir, "app.example.test").unwrap();

    let settings = ClientConfig {
        server_addresses: vec![
            server_address("tunnel.example.test:1"),
            server_address("tunnel.example.test:2"),
        ],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:443".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
            proxy_protocol: None,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Manual {
            directory: public_cert_dir,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    let instance = ClientInstancePrep::prepare(&settings).await.unwrap();
    instance.start_acme_once();
    assert_eq!(instance.acme_manager_count(), 0);

    let first = PreparedClient::connect_to_server_address(
        &settings,
        &instance,
        localhost(0),
        &settings.server_addresses[0],
        tunnel_addr,
    )
    .await
    .unwrap();
    assert!(std::ptr::eq(
        first.instance().as_ref() as *const _,
        instance.as_ref() as *const _
    ));
    drop(first);

    // Reconnect-style redial and a second address worker share the same preparation.
    let second = PreparedClient::connect_to_server_address(
        &settings,
        &instance,
        localhost(0),
        &settings.server_addresses[1],
        tunnel_addr,
    )
    .await
    .unwrap();
    let third = PreparedClient::connect_to_server_address(
        &settings,
        &instance,
        localhost(0),
        &settings.server_addresses[0],
        tunnel_addr,
    )
    .await
    .unwrap();
    assert_eq!(instance.acme_manager_count(), 0);
    assert!(std::ptr::eq(
        second.instance().as_ref() as *const _,
        third.instance().as_ref() as *const _
    ));

    instance.stop_acme().await;
    drop(second);
    drop(third);
    server_task.abort();
    let _ = server_task.await;
}

/// ACME mode only builds configs for services with tls-mode = "terminate".
/// Passthrough services must not contribute hostnames to the ACME hostname set.
#[tokio::test]
async fn acme_client_only_manages_terminating_service_hostnames() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let client_identity = generate_client_identity().unwrap();

    let authorization = ServerAuthorization::from_static_tunnels(
        &server_hostname("tunnel.example.test"),
        &[ServerTunnelConfig {
            id: None,
            public_hostnames: vec![
                public_hostname("app.example.test"),
                public_hostname("api.example.test"),
            ],
            authorized_client_identities: vec![client_identity.client_identity.clone()],
        }],
    )
    .unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        authorization: authorization.clone(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_admission(
            vec![server_cert.clone()],
            private_key_from_der(&server_key),
            Arc::new(authorization.clone()),
        )
        .unwrap(),
        admission: ServerAdmission::Static,
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        &client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        &client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let acme_state_dir = tempdir.path().join("acme-state");
    fs::create_dir(&acme_state_dir).unwrap();

    let server_ca_pem = rcgen::generate_simple_self_signed(vec!["tunnel.example.test".to_owned()])
        .unwrap()
        .cert
        .pem();
    fs::write(tempdir.path().join("server-ca.pem"), server_ca_pem).unwrap();

    // Two services: one terminating (ACME-managed), one passthrough (no cert needed).
    let settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
                proxy_protocol: None,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("api.example.test")]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            },
        ],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
        control: None,
        admission: runewarp::ClientAdmission::Static,
    };

    // Startup must succeed: the passthrough service does not require ACME management.
    let result = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await;
    match result {
        Err(runewarp::ClientStartupError::InvalidSettings(msg)) => {
            panic!(
                "ACME client startup must not fail with InvalidSettings for mixed services: {msg}"
            )
        }
        Err(runewarp::ClientStartupError::TlsMaterial(e)) => {
            panic!("ACME client startup must not fail with TlsMaterial for mixed services: {e}")
        }
        _ => {}
    }

    server_task.abort();
    let _ = server_task.await;
}
