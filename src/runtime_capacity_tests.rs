//! Real role-runtime Visitor capacity regression, isolated from process-global test counters.
use crate::capacity_benchmark::{GUARD_RESETS, address, client_hello, connect_visitor, setup};
use std::error::Error;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn configured_budget_waits_for_credit_through_real_runtimes() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "RUNEWARP_CAPACITY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "runtime_capacity_tests::configured_budget_waits_for_credit_through_real_runtimes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()?;
        assert!(status.success(), "isolated capacity runtime regression");
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(configured_budget())
}

async fn configured_budget() -> Result<(), Box<dyn Error>> {
    let guards_before = GUARD_RESETS.load(Ordering::Relaxed);
    assert_eq!(guards_before, 0, "child runs only this regression");
    let directory = tempfile::tempdir()?;
    setup(directory.path())?;
    let listener = TcpListener::bind("[::1]:0").await?;
    let backend_address = listener.local_addr()?;
    let backend = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.expect("backend accept");
                    tasks.spawn(async move {
                        let (mut read, mut write) = socket.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let tunnel_bind = tokio::net::lookup_host(("localhost", 0))
        .await?
        .next()
        .ok_or("localhost has no address")?;
    let server_settings = crate::load_server_config(&directory.path().join("server.toml"))?;
    let server = crate::ServerRuntime::prepare(&server_settings, address(0), tunnel_bind).await?;
    let public = server.public_addr()?;
    let port = server.tunnel_addr()?.port();
    let shutdown = server.shutdown();
    let server = tokio::spawn(server.run());
    let config_path = directory.path().join("client.toml");
    std::fs::write(
        &config_path,
        format!(
            "[client]\nserver-address = \"localhost:{port}\"\nmax-visitor-streams = 256\nserver-trust = \"ca-file\"\nserver-ca-file = \"cert/server-ca.crt\"\nidentity-dir = \"identity\"\n[[client.services]]\nbackend-address = \"{backend_address}\"\n"
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
    let work = async {
        let mut sockets = Vec::new();
        // The first successful full echo is readiness, not a guessed sleep or an attempted socket.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(Ok((socket, _, _))) = tokio::time::timeout(
                Duration::from_millis(500),
                connect_visitor(public, client_hello()?, 0),
            )
            .await
            {
                sockets.push(socket);
                break;
            }
            if Instant::now() > deadline {
                return Err::<(), Box<dyn Error>>("runtime readiness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for index in 1..256 {
            sockets.push(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    connect_visitor(public, client_hello()?, index),
                )
                .await??
                .0,
            );
        }
        let pending = connect_visitor(public, client_hello()?, 256);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pending)
                .await
                .is_err(),
            "257th Visitor must wait at configured capacity"
        );
        // Keep all admitted Visitors held through the Server's real five-second open deadline.
        // This checks admission, continued forwarding and the actual guard counter.
        // Single-release saturation recovery is not guaranteed; see runewarp/runewarp#267.
        let elapsed = Instant::now();
        let excess = tokio::time::timeout(Duration::from_secs(6), pending).await?;
        assert!(excess.is_err(), "excess Visitor reaches the open deadline");
        assert!(elapsed.elapsed() >= Duration::from_secs(4));
        assert_eq!(GUARD_RESETS.load(Ordering::Relaxed), guards_before);
        let mut first = sockets.pop().expect("256 byte-validated Visitors");
        first.write_all(b"still working").await?;
        let mut bytes = [0; 13];
        first.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"still working");
        assert_eq!(GUARD_RESETS.load(Ordering::Relaxed), guards_before);
        Ok(())
    };
    tokio::pin!(work);
    let (work, client_finished) = tokio::select! {
        result = &mut work => (result, false),
        result = &mut client => (Err(format!("Client exited early: {result:?}").into()), true),
    };
    let _ = stop.send(());
    shutdown.begin_fast();
    if !client_finished {
        tokio::time::timeout(Duration::from_secs(5), client).await??;
    }
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    backend.abort();
    let _ = backend.await;
    work
}
