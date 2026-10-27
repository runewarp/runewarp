use runewarp::server_certificate::{
    CertificateOwner, CertificateStore, CertificateValidation, ServerAcmeOptions, TcpChallengeRoute,
};
use runewarp::{
    PreparedClient, ServerRuntime, generate_client_identity, load_client_config, load_server_config,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls_acme::{AccountCache, CertCache};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, timeout};
#[path = "certificate_support/ca.rs"]
mod ca;

fn validation(path: &Path) -> CertificateValidation {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&fs::read(path.join("root.pem")).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap()
}
fn reply(value: Value) {
    println!("CERTIFICATE_TEST {value}");
    std::io::stdout().flush().unwrap();
}

// A disposable process adapter over the supported production ServerRuntime/control handle.
#[test]
fn certificate_process() {
    let Some(path) = std::env::var_os("RUNEWARP_TEST_CERTIFICATE_PROCESS") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let directory = std::env::var("RUNEWARP_TEST_CA_DIRECTORY").unwrap();
        let policy = validation(&path);
        if std::env::var_os("RUNEWARP_TEST_SEED_CERTIFICATE").is_some() {
            let owner = CertificateOwner::try_acquire(&path.join("state")).unwrap().unwrap();
            let cache = CertificateStore::open(owner, policy, "mailto:admin@example.test", &directory).unwrap();
            cache.store_account(&["mailto:admin@example.test".to_owned()], &directory, &rustls_acme::acme::Account::generate_key_pair()).await.unwrap();
            cache.store_cert(&["edge.example.test".to_owned()], &directory, &fs::read(path.join("seed.pem")).unwrap()).await.unwrap();
            reply(json!({"seeded":true})); return;
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&fs::read(path.join("root.pem")).unwrap()) { roots.add(cert.unwrap()).unwrap(); }
        let client = Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
        let route = std::env::var("RUNEWARP_TEST_CHALLENGE_INGRESS").unwrap().parse().unwrap();
        let mut options = ServerAcmeOptions::new(policy, &directory, client, Arc::new(TcpChallengeRoute::at(route, "consumed-local-ingress-v1").unwrap())).unwrap();
        options.recovery_timeout = Duration::from_secs(15); options.retry_interval = Duration::from_millis(20);
        let mut settings = load_server_config(&path.join("server.toml")).unwrap();
        settings.graceful_shutdown_duration = Duration::from_millis(50);
        let server = ServerRuntime::prepare_listeners_with_acme(&settings, vec!["127.0.0.1:0".parse().unwrap()], vec!["127.0.0.1:0".parse().unwrap()], options).await.unwrap();
        let control = server.certificate_controller().unwrap(); let shutdown = server.shutdown();
        let public = server.public_addr().unwrap(); let tunnel = server.tunnel_addr().unwrap();
        let mut server = Some(tokio::spawn(server.run()));
        reply(json!({"public":public.to_string(),"tunnel":tunnel.to_string()}));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || { for line in std::io::stdin().lock().lines() { if tx.send(line.unwrap()).is_err() { break } } });
        while let Some(command) = rx.recv().await {
            match command.as_str() {
                "takeover" => { control.request_ownership(); reply(json!({"requested":true})); }
                "route-lost" => { control.challenge_route_lost(); reply(json!({"revoked":true})); }
                "drain" => { shutdown.begin_graceful(); if let Some(server) = server.take() { server.await.unwrap().unwrap(); } reply(json!({"drained":true})); }
                "status" => { let status = control.status(); reply(json!({"serving":status.serving,"owns":status.owns_acme,"driving":status.driving_acme,"fingerprint":status.fingerprint,"maintenance":status.maintenance,"route":status.route_version})); }
                "export" => { let snapshot = control.export_snapshot(Duration::from_secs(7200)); reply(json!({"fingerprint":snapshot.as_ref().ok().map(|s|s.fingerprint()),"ready":snapshot.is_ok()})); }
                _ => panic!("unexpected fixture command"),
            }
        }
    });
}

struct Process {
    child: Child,
    input: ChildStdin,
    output: std::sync::mpsc::Receiver<Value>,
}
impl Process {
    fn spawn(path: &Path, directory: &str, ingress: std::net::SocketAddr, seed: bool) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "certificate_process", "--nocapture"])
            .env("RUNEWARP_TEST_CERTIFICATE_PROCESS", path)
            .env("RUNEWARP_TEST_CA_DIRECTORY", directory)
            .env("RUNEWARP_TEST_CHALLENGE_INGRESS", ingress.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if seed {
            command.env("RUNEWARP_TEST_SEED_CERTIFICATE", "1");
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(value) = line.strip_prefix("CERTIFICATE_TEST ")
                    && tx.send(serde_json::from_str(value).unwrap()).is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
        }
    }
    fn read(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(10))
            .expect("bounded child process reply")
    }
    fn command(&mut self, command: &str) -> Value {
        writeln!(self.input, "{command}").unwrap();
        self.input.flush().unwrap();
        self.read()
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        self.child.wait().unwrap();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}

fn fixture(path: &Path, authority: &ca::Authority) {
    fs::write(path.join("root.pem"), &authority.pem).unwrap();
    let (certificate, key) = authority.leaf("edge.example.test", true);
    fs::write(
        path.join("seed.pem"),
        format!("{}{certificate}", key.serialize_pem()),
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
    fs::create_dir(path.join("state")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        path.join("server.toml"),
        format!(
            r#"
[server]
hostname = "edge.example.test"
[server.acme]
email = "admin@example.test"
state-dir = "state"
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
server-ca-file = "root.pem"
identity-dir = "."
[[client.services]]
backend-address = "127.0.0.1:1"
"#,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_due_renewal_retries_only_after_owner_exit_and_consumed_route() {
    takeover(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_death_before_first_export_requires_exclusive_issuance_before_serving() {
    takeover(false).await;
}

async fn takeover(seed: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path();
    let authority = ca::Authority::new();
    fixture(path, &authority);
    let ingress = ca::Ingress::new().await;
    let ca = ca::FakeCa::new(authority, ingress.address).await;
    if seed {
        let mut seeder = Process::spawn(path, &ca.directory, ingress.address, true);
        assert_eq!(seeder.read()["seeded"], true);
        assert!(seeder.child.wait().unwrap().success());
    }
    let mut old = Process::spawn(path, &ca.directory, ingress.address, false);
    let old_addresses = old.read();
    *ingress.target.lock().unwrap() =
        Some(old_addresses["public"].as_str().unwrap().parse().unwrap());
    old.command("takeover");
    timeout(Duration::from_secs(5), async {
        while ca.orders() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("old owner starts its due acquisition");
    assert_eq!(ca.orders(), 1);
    let requests = ca.requests();
    let first = old.command("export");
    assert_eq!(first["ready"], seed);
    let store_before = store_metadata(&path.join("state"));
    let mut new = Process::spawn(path, &ca.directory, ingress.address, false);
    let addresses = new.read();
    let tunnel = addresses["tunnel"].as_str().unwrap().parse().unwrap();
    let public = addresses["public"].as_str().unwrap().parse().unwrap();
    let settings = load_client_config(&path.join("client.toml")).unwrap();
    let connect = || {
        timeout(
            Duration::from_secs(2),
            PreparedClient::connect_to(&settings, "127.0.0.1:0".parse().unwrap(), tunnel),
        )
    };
    assert_eq!(connect().await.unwrap().is_ok(), seed);
    assert!(
        ca::observe_acme_challenge(public).await.is_err(),
        "passive snapshot is never a challenge certificate"
    );
    assert!(!new.command("status")["owns"].as_bool().unwrap());
    assert_eq!(
        ca.requests(),
        requests,
        "passive serving makes no CA request"
    );
    assert!(
        store_metadata(&path.join("state")) == store_before,
        "passive serving changes no owner-store file"
    );
    new.command("takeover");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(ca.orders(), 1, "the waiting process cannot contact the CA");
    assert_eq!(ca.requests(), requests);
    assert!(!new.command("status")["owns"].as_bool().unwrap());
    old.command("drain");
    old.command("takeover");
    assert!(
        !old.command("status")["driving"].as_bool().unwrap(),
        "a drained process cannot restart ACME"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        ca.orders(),
        1,
        "drain without process exit cannot release ownership"
    );
    old.kill();
    // Keep the consumed ingress pointing at the dead process. Ownership alone must not drive ACME.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(ca.orders(), 1);
    assert_eq!(
        ca.requests(),
        requests,
        "ownership without consumed routing makes no CA request"
    );
    *ingress.target.lock().unwrap() = Some(public);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut handshakes = 0;
    loop {
        let status = new.command("status");
        if seed {
            assert!(
                connect().await.unwrap().is_ok(),
                "a fresh authenticated Tunnel must survive takeover"
            );
            handshakes += 1;
        }
        if status["serving"] == true && ca.challenges() > 0 {
            let snapshot = new.command("export");
            if snapshot["ready"] == true && snapshot["fingerprint"] != first["fingerprint"] {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "next owner did not complete local issuance: {status}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        ca.orders(),
        2,
        "the abandoned order is retried by the next owner"
    );
    assert_eq!(ca.challenges(), 1);
    assert!(connect().await.unwrap().is_ok());
    if seed {
        assert!(handshakes >= 2);
    }
    assert_eq!(new.command("status")["route"], "consumed-local-ingress-v1");
    *ingress.target.lock().unwrap() = None;
    new.command("route-lost");
    assert!(new.command("status")["serving"].as_bool().unwrap());
    assert!(connect().await.unwrap().is_ok());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!new.command("status")["driving"].as_bool().unwrap());
    *ingress.target.lock().unwrap() = Some(public);
    timeout(Duration::from_secs(2), async {
        while !new.command("status")["driving"].as_bool().unwrap() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        ca.orders(),
        2,
        "routing recovery reuses the durable certificate"
    );
}

fn store_metadata(root: &Path) -> Vec<(std::path::PathBuf, u64, std::time::SystemTime)> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let metadata = entry.metadata().unwrap();
        result.push((entry.path(), metadata.len(), metadata.modified().unwrap()));
        if metadata.is_dir() {
            result.extend(store_metadata(&entry.path()));
        }
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    result
}
