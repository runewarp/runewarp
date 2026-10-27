use futures_util::future::BoxFuture;
use runewarp::server_certificate::{
    CertificateSnapshot, CertificateValidation, ChallengeRouteObserver, ChallengeRouteRequest,
    ConsumedChallengeRoute, ServerAcmeOptions, TcpChallengeRoute,
};
use runewarp::{
    PreparedClient, PreparedServer, generate_client_identity, load_client_config,
    load_server_config,
};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
mod certificate_support;

struct Route(Mutex<Option<std::net::SocketAddr>>);
impl ChallengeRouteObserver for Route {
    fn observe<'a>(
        &'a self,
        request: ChallengeRouteRequest,
    ) -> BoxFuture<'a, std::io::Result<ConsumedChallengeRoute>> {
        let target = *self.0.lock().unwrap();
        Box::pin(async move {
            let target = target.ok_or_else(|| std::io::Error::other("route not consumed"))?;
            TcpChallengeRoute::at(target, "ingress-v1")?
                .observe(request)
                .await
        })
    }
}

struct Clock(std::sync::atomic::AtomicU64);
impl runewarp::server_certificate::CertificateClock for Clock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
struct SlowRead {
    started: std::sync::atomic::AtomicBool,
    used: std::sync::atomic::AtomicBool,
}
impl runewarp::server_certificate::CertificateStoreIo for SlowRead {
    fn read_file(&self, path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
        if !self.used.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.started
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(600));
            return Err(std::io::Error::other("controlled slow cache read failure"));
        }
        runewarp::server_certificate::LocalCertificateStoreIo.read_file(path, limit)
    }
    fn sync_file(
        &self,
        file: &std::fs::File,
        _: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        file.sync_all()
    }
    fn rename(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
        _: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        fs::rename(from, to)
    }
    fn sync_directory(
        &self,
        path: &std::path::Path,
        _: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_tunnel_handshakes_survive_failed_activation_without_rebinding() {
    runtime_case(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_clock_safety_deadline_stops_new_admissions_and_cannot_resume() {
    runtime_case(true).await;
}
async fn runtime_case(expire: bool) {
    let clock = Arc::new(Clock(std::sync::atomic::AtomicU64::new(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    let (pem, roots) =
        certificate_support::material("edge.example.test", 1_789_900_000, 1_990_100_000);
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap()
    .with_clock(clock.clone());
    let snapshot = CertificateSnapshot::validate(&pem, &policy, SystemTime::now()).unwrap();
    let text = std::str::from_utf8(&pem).unwrap();
    fs::write(
        path.join("server-ca.pem"),
        &text[text.find("-----BEGIN CERTIFICATE-----").unwrap()..],
    )
    .unwrap();
    let identity = generate_client_identity().unwrap();
    fs::write(path.join("client.crt"), identity.certificate_pem).unwrap();
    fs::write(path.join("client.key"), identity.private_key_pem).unwrap();
    fs::write(
        path.join("client-identity.txt"),
        identity.client_identity.to_string(),
    )
    .unwrap();
    fs::create_dir(path.join("acme")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.join("acme"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        path.join("server.toml"),
        format!(
            r#"
[server]
hostname = "edge.example.test"
readiness-bind-address = "127.0.0.1:0"
[server.acme]
email = "admin@example.test"
state-dir = "acme"
[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
            identity.client_identity
        ),
    )
    .unwrap();
    fs::write(
        path.join("client.toml"),
        r#"
[client]
server-address = "edge.example.test"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "."
[[client.services]]
backend-address = "127.0.0.1:1"
"#,
    )
    .unwrap();
    let route = Arc::new(Route(Mutex::new(None)));
    let ca_tls = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    );
    let mut options = ServerAcmeOptions::new(
        policy,
        "https://localhost:1/directory",
        ca_tls,
        route.clone(),
    )
    .unwrap();
    let slow = Arc::new(SlowRead {
        started: std::sync::atomic::AtomicBool::new(false),
        used: std::sync::atomic::AtomicBool::new(false),
    });
    options.storage_io = slow.clone();
    options.recovery_timeout = Duration::from_secs(2);
    options.retry_interval = Duration::from_millis(20);
    let server = PreparedServer::bind_listeners_with_acme(
        &load_server_config(&path.join("server.toml")).unwrap(),
        vec!["127.0.0.1:0".parse().unwrap()],
        vec!["127.0.0.1:0".parse().unwrap()],
        options,
    )
    .await
    .unwrap();
    let controller = server.certificate_controller().unwrap();
    assert!(
        tokio::net::TcpStream::connect(server.readiness_addr().unwrap())
            .await
            .is_err(),
        "first boot without a certificate cannot be traffic ready"
    );
    controller.install_snapshot(snapshot.clone()).unwrap();
    let public = server.public_addr().unwrap();
    let tunnel = server.tunnel_addr().unwrap();
    let settings = load_client_config(&path.join("client.toml")).unwrap();
    let server = tokio::spawn(server.run());
    for _ in 0..3 {
        let client = timeout(
            Duration::from_secs(2),
            PreparedClient::connect_to(&settings, "127.0.0.1:0".parse().unwrap(), tunnel),
        )
        .await
        .unwrap()
        .unwrap();
        drop(client);
    }
    assert!(
        !path.join("acme/owner.lock").exists(),
        "passive startup performs no owner-store writes"
    );
    assert!(!controller.status().owns_acme);
    assert!(
        controller
            .export_snapshot(Duration::from_secs(7200))
            .is_err()
    );
    assert!(
        controller.status().serving,
        "failed pre-drain export leaves the old serving certificate usable"
    );
    if expire {
        clock
            .0
            .store(1_990_099_970, std::sync::atomic::Ordering::SeqCst);
        assert!(
            timeout(
                Duration::from_secs(2),
                PreparedClient::connect_to(&settings, "127.0.0.1:0".parse().unwrap(), tunnel)
            )
            .await
            .unwrap()
            .is_err()
        );
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.join("acme"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        controller.request_ownership();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !controller.status().owns_acme,
            "an unusable lock cannot grant ownership"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.join("acme"), fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("acme/committed"), b"blocked storage").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            controller.status().serving,
            "storage failure retains the snapshot"
        );
        fs::remove_file(path.join("acme/committed")).unwrap();
        timeout(Duration::from_secs(1), async {
            while !slow.started.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        for _ in 0..8 {
            let client = timeout(
                Duration::from_secs(2),
                PreparedClient::connect_to(&settings, "127.0.0.1:0".parse().unwrap(), tunnel),
            )
            .await
            .unwrap()
            .unwrap();
            drop(client);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            !controller.status().driving_acme,
            "an unconsumed route cannot start ACME"
        );
        *route.0.lock().unwrap() = Some(public);
        let client = timeout(
            Duration::from_secs(2),
            PreparedClient::connect_to(&settings, "127.0.0.1:0".parse().unwrap(), tunnel),
        )
        .await
        .unwrap()
        .unwrap();
        drop(client);
        assert!(controller.status().serving);
    }
    assert!(
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(controller.status().maintenance);
    assert!(
        tokio::net::TcpStream::connect(public).await.is_err(),
        "maintenance stops new ingress"
    );
    assert!(!controller.status().serving);
    controller.request_ownership();
    assert!(controller.install_snapshot(snapshot).is_err());
    assert!(controller.status().maintenance, "maintenance is terminal");
}
