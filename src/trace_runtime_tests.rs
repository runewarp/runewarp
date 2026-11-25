//! Span export and log correlation through real in-process Server and Client runtimes.
use crate::capacity_benchmark::{address, client_hello, connect_visitor, setup};
use crate::runtime_log::test_support::{JsonLogs, ids};
use crate::trace_export::OUTCOME;
use crate::trace_export::test_support::{CapturedSpans, assert_safe_attributes, attribute};
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

#[tokio::test]
async fn runtimes_export_handshake_connect_and_visitor_spans() -> Result<(), Box<dyn Error>> {
    if !crate::trace_export::test_support::isolated(
        module_path!(),
        "runtimes_export_handshake_connect_and_visitor_spans",
    ) {
        return Ok(());
    }
    // The Server mints its generation before trace export starts, as `runewarp server` does.
    let generation = crate::ServerRuntimeGeneration::generate();
    let captured = CapturedSpans::with_role(1.0, crate::TraceRole::Server(generation));
    let logs = JsonLogs::install(captured.provider());
    let directory = tempfile::tempdir()?;
    setup(directory.path())?;
    let identity = std::fs::read_to_string(
        directory
            .path()
            .join("identity")
            .join(crate::CLIENT_IDENTITY_FILENAME),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = listener.local_addr()?;
    let backend = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let tunnel_bind = tokio::net::lookup_host(("localhost", 0))
        .await?
        .next()
        .ok_or("localhost has no address")?;
    let server_settings = crate::load_server_config(&directory.path().join("server.toml"))?;
    let server =
        crate::ServerRuntime::prepare(&server_settings, address(0), tunnel_bind, generation)
            .await?;
    let public = server.public_addr()?;
    let port = server.tunnel_addr()?.port();
    let shutdown = server.shutdown();
    let server = tokio::spawn(server.run());
    let config_path = directory.path().join("client.toml");
    std::fs::write(
        &config_path,
        format!(
            "[client]\nserver-address = \"localhost:{port}\"\nserver-trust = \"ca-file\"\nserver-ca-file = \"cert/server-ca.crt\"\nidentity-dir = \"identity\"\n[[client.services]]\nbackend-address = \"{backend_address}\"\n"
        ),
    )?;
    let settings = crate::load_client_config(&config_path)?;
    let runtime = crate::ClientRuntime::prepare(&settings, tunnel_bind).await?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let client = runtime.run(async {
        let _ = stopped.await;
        Ok(crate::ShutdownMode::Fast)
    });
    tokio::pin!(client);

    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = async {
        loop {
            if let Ok(Ok((socket, _, _))) = tokio::time::timeout(
                Duration::from_millis(500),
                connect_visitor(public, client_hello()?, 0),
            )
            .await
            {
                return Ok::<_, Box<dyn Error>>(socket);
            }
            if Instant::now() > deadline {
                return Err("runtime readiness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let visitor = tokio::select! {
        visitor = ready => visitor?,
        result = &mut client => return Err(format!("Client exited early: {result:?}").into()),
    };

    // The echoing Visitor is still open, so every span below ended before Visitor close.
    let spans = captured.finished();
    let outcome = |name: &str| {
        spans
            .iter()
            .filter(|span| span.name == name)
            .filter_map(|span| attribute(span, OUTCOME))
            .collect::<Vec<_>>()
    };
    assert!(outcome("tunnel_connection.handshake").contains(&"accepted".to_owned()));
    assert!(outcome("client.tunnel_connect").contains(&"connected".to_owned()));
    assert!(outcome("visitor").contains(&"placed".to_owned()));
    assert!(outcome("client.visitor").contains(&"connected".to_owned()));
    let handshake = spans
        .iter()
        .find(|span| span.name == "tunnel_connection.handshake")
        .ok_or("handshake span")?;
    // The resource tags every exported span with the generation, children included.
    assert_eq!(
        attribute(handshake, "runewarp.server_generation"),
        Some(generation.to_string())
    );
    assert_eq!(
        captured.resource_attribute("service.instance.id"),
        Some(generation.to_string())
    );
    // Lines logged during each span's work carry its IDs.
    for (text, name, outcome) in [
        (
            "server tunnel connection accepted",
            "tunnel_connection.handshake",
            "accepted",
        ),
        (
            "client tunnel connection connecting",
            "client.tunnel_connect",
            "connected",
        ),
        (
            "client tunnel connection connected",
            "client.tunnel_connect",
            "connected",
        ),
        ("server route forwarded", "visitor", "placed"),
    ] {
        let lines = logs.containing(text);
        assert!(!lines.is_empty(), "no {text:?} line in {:?}", logs.lines());
        for line in lines {
            let span = spans
                .iter()
                .find(|span| Some(crate::trace_export::test_support::ids(span)) == ids(&line))
                .ok_or_else(|| format!("{text:?} line has no exported span's IDs: {line}"))?;
            assert_eq!(span.name, name, "{line}");
            assert_eq!(attribute(span, OUTCOME).as_deref(), Some(outcome), "{line}");
        }
    }
    for child in ["intake", "route", "stream_open"] {
        assert!(
            spans.iter().any(|span| span.name == child),
            "missing {child} span"
        );
    }
    assert_safe_attributes(
        &spans,
        &[
            "localhost",
            "127.0.0.1",
            "app.example.test",
            identity.trim(),
            &backend_address.port().to_string(),
            &port.to_string(),
        ],
    );

    drop(visitor);
    let _ = stop.send(());
    shutdown.begin_fast();
    tokio::time::timeout(Duration::from_secs(5), client).await??;
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    backend.abort();
    Ok(())
}
