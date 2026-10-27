use runewarp::server_certificate::{CertificateOwner, CertificateStore, CertificateValidation};
use rustls_acme::{AccountCache, CertCache};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
mod certificate_support;

#[tokio::test]
async fn committed_state_preserves_valid_material_when_a_candidate_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("private");
    let owner = CertificateOwner::try_acquire(&state).unwrap().unwrap();
    let (pem, roots) =
        certificate_support::material("edge.example.test", 1_789_900_000, 1_990_100_000);
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap();
    let cache = CertificateStore::open(
        owner,
        policy.clone(),
        "mailto:admin@example.test",
        "https://ca.example.test/directory",
    )
    .unwrap();
    let domains = vec!["edge.example.test".to_owned()];
    let contacts = vec!["mailto:admin@example.test".to_owned()];
    let account = rustls_acme::acme::Account::generate_key_pair();
    cache
        .store_account(&contacts, "https://ca.example.test/directory", &account)
        .await
        .unwrap();
    cache
        .store_cert(&domains, "https://ca.example.test/directory", &pem)
        .await
        .unwrap();
    let first = cache.export_snapshot(Duration::from_secs(7200)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let owner_files: Vec<_> = std::fs::read_dir(state.join("committed/generations"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_none())
            .collect();
        for path in &owner_files {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        assert_eq!(
            CertificateStore::read_snapshot(&state, &policy, SystemTime::now())
                .unwrap()
                .unwrap()
                .fingerprint(),
            first.fingerprint()
        );
        for path in &owner_files {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    assert!(
        cache
            .store_cert(&domains, "https://ca.example.test/directory", b"broken")
            .await
            .is_err()
    );
    assert!(
        cache
            .store_account(&contacts, "https://ca.example.test/directory", b"broken")
            .await
            .is_err()
    );
    assert_eq!(
        cache
            .load_account(&contacts, "https://ca.example.test/directory")
            .await
            .unwrap(),
        Some(account)
    );
    let recovered = CertificateStore::read_snapshot(&state, &policy, SystemTime::now())
        .unwrap()
        .unwrap();
    assert_eq!(first.fingerprint(), recovered.fingerprint());
    assert_eq!(
        cache
            .export_snapshot(Duration::from_secs(7200))
            .unwrap()
            .fingerprint(),
        first.fingerprint()
    );
}

struct FailIo(std::sync::Mutex<Option<runewarp::server_certificate::StoreOperation>>);
impl FailIo {
    fn check(
        &self,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        if self.0.lock().unwrap().as_ref() == Some(&operation) {
            return Err(std::io::Error::other("injected storage failure"));
        }
        Ok(())
    }
}
impl runewarp::server_certificate::CertificateStoreIo for FailIo {
    fn sync_file(
        &self,
        file: &std::fs::File,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.check(operation)?;
        file.sync_all()
    }
    fn rename(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.check(operation)?;
        std::fs::rename(from, to)
    }
    fn sync_directory(
        &self,
        path: &std::path::Path,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.check(operation)?;
        std::fs::File::open(path)?.sync_all()
    }
}

#[tokio::test]
async fn every_failed_publication_recovers_a_complete_old_or_new_pair() {
    use runewarp::server_certificate::StoreOperation::*;
    for operation in [
        GenerationSync,
        GenerationRename,
        GenerationDirectorySync,
        ManifestSync,
        ManifestRename,
        ManifestDirectorySync,
        CleanupDirectorySync,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private");
        let owner = CertificateOwner::try_acquire(&path).unwrap().unwrap();
        let (pem, roots) =
            certificate_support::material("edge.example.test", 1_789_900_000, 1_990_100_000);
        let policy = CertificateValidation::new(
            "edge.example.test".try_into().unwrap(),
            Arc::new(roots),
            Duration::from_secs(3600),
            Duration::from_secs(60),
        )
        .unwrap();
        let faults = Arc::new(FailIo(std::sync::Mutex::new(None)));
        let cache = CertificateStore::open_with_io(
            owner.clone(),
            policy.clone(),
            "mailto:admin@example.test",
            "https://ca.example.test/directory",
            faults.clone(),
        )
        .unwrap();
        let domains = vec!["edge.example.test".to_owned()];
        let contacts = vec!["mailto:admin@example.test".to_owned()];
        let account = rustls_acme::acme::Account::generate_key_pair();
        cache
            .store_account(&contacts, "https://ca.example.test/directory", &account)
            .await
            .unwrap();
        cache
            .store_cert(&domains, "https://ca.example.test/directory", &pem)
            .await
            .unwrap();
        let first = cache.export_snapshot(Duration::from_secs(7200)).unwrap();
        let replacement = rustls_acme::acme::Account::generate_key_pair();
        *faults.0.lock().unwrap() = Some(operation);
        assert!(
            cache
                .store_account(&contacts, "https://ca.example.test/directory", &replacement)
                .await
                .is_err()
        );
        assert!(cache.export_snapshot(Duration::from_secs(7200)).is_err());
        let cache = CertificateStore::open(
            owner,
            policy,
            "mailto:admin@example.test",
            "https://ca.example.test/directory",
        )
        .unwrap();
        let recovered = cache
            .load_account(&contacts, "https://ca.example.test/directory")
            .await
            .unwrap()
            .unwrap();
        assert!(recovered == account || recovered == replacement);
        assert_eq!(
            cache
                .export_snapshot(Duration::from_secs(7200))
                .unwrap()
                .fingerprint(),
            first.fingerprint()
        );
    }
}

// The process fixture exits at the actual filesystem adapter call. No destructor,
// waiter cancellation or in-process reopen can stand in for this crash boundary.
#[test]
fn store_process() {
    let Some(root) = std::env::var_os("RUNEWARP_TEST_STORE_PROCESS") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let mut roots = rustls::RootCertStore::empty();
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(root.join("roots.pem")).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap();
    let owner = CertificateOwner::try_acquire(&root.join("state"))
        .unwrap()
        .unwrap();
    let action = std::env::var("RUNEWARP_TEST_STORE_ACTION").unwrap();
    let operation = std::env::var("RUNEWARP_TEST_STORE_OPERATION").ok();
    let crash = Arc::new(CrashIo {
        operation,
        after: std::env::var_os("RUNEWARP_TEST_STORE_AFTER").is_some(),
        armed: std::sync::atomic::AtomicBool::new(false),
        seen: std::sync::atomic::AtomicUsize::new(0),
        occurrence: std::env::var("RUNEWARP_TEST_STORE_OCCURRENCE")
            .ok()
            .map(|v| v.parse().unwrap())
            .unwrap_or(1),
    });
    let cache = CertificateStore::open_with_io(
        owner,
        policy,
        "mailto:admin@example.test",
        "https://ca.example.test/directory",
        crash.clone(),
    )
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let contacts = vec!["mailto:admin@example.test".to_owned()];
        let domains = vec!["edge.example.test".to_owned()];
        let url = "https://ca.example.test/directory";
        if action == "seed" {
            cache
                .store_account(
                    &contacts,
                    url,
                    &std::fs::read(root.join("old-account")).unwrap(),
                )
                .await
                .unwrap();
            cache
                .store_cert(&domains, url, &std::fs::read(root.join("old.pem")).unwrap())
                .await
                .unwrap();
        } else if action == "verify" {
            let account = cache.load_account(&contacts, url).await.unwrap().unwrap();
            assert!(
                account == std::fs::read(root.join("old-account")).unwrap()
                    || account == std::fs::read(root.join("new-account")).unwrap()
            );
            let certificate = cache.export_snapshot(Duration::from_secs(7200)).unwrap();
            let bytes = cache.load_cert(&domains, url).await.unwrap().unwrap();
            let (_, parsed) = x509_parser::parse_x509_certificate(
                CertificateDer::from_pem_slice(&bytes).unwrap().as_ref(),
            )
            .map(|(_, p)| ((), p.validity().not_after.timestamp()))
            .unwrap();
            assert!([1_990_100_000, 1_990_200_000].contains(&parsed));
            assert_eq!(certificate.fingerprint().len(), 64);
        } else {
            crash.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            if action == "account" {
                cache
                    .store_account(
                        &contacts,
                        url,
                        &std::fs::read(root.join("new-account")).unwrap(),
                    )
                    .await
                    .unwrap();
            } else {
                cache
                    .store_cert(&domains, url, &std::fs::read(root.join("new.pem")).unwrap())
                    .await
                    .unwrap();
            }
            panic!("crash boundary was not reached");
        }
    });
}
struct CrashIo {
    operation: Option<String>,
    after: bool,
    armed: std::sync::atomic::AtomicBool,
    seen: std::sync::atomic::AtomicUsize,
    occurrence: usize,
}
impl CrashIo {
    fn crash(&self, operation: runewarp::server_certificate::StoreOperation, after: bool) {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst)
            && self.after == after
            && self.operation.as_ref() == Some(&format!("{operation:?}"))
            && self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.occurrence
        {
            std::process::exit(75);
        }
    }
}
impl runewarp::server_certificate::CertificateStoreIo for CrashIo {
    fn sync_file(
        &self,
        file: &std::fs::File,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.crash(operation, false);
        file.sync_all()?;
        self.crash(operation, true);
        Ok(())
    }
    fn rename(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.crash(operation, false);
        std::fs::rename(from, to)?;
        self.crash(operation, true);
        Ok(())
    }
    fn sync_directory(
        &self,
        path: &std::path::Path,
        operation: runewarp::server_certificate::StoreOperation,
    ) -> std::io::Result<()> {
        self.crash(operation, false);
        std::fs::File::open(path)?.sync_all()?;
        self.crash(operation, true);
        Ok(())
    }
}

#[test]
fn process_crashes_at_publication_boundaries_recover_complete_state() {
    use runewarp::server_certificate::StoreOperation::*;
    for operation in [
        GenerationSync,
        GenerationRename,
        GenerationDirectorySync,
        ManifestSync,
        ManifestRename,
        ManifestDirectorySync,
        CleanupDirectorySync,
    ] {
        let repeats = if matches!(
            operation,
            GenerationSync | GenerationRename | GenerationDirectorySync
        ) {
            2
        } else {
            1
        };
        for occurrence in 1..=repeats {
            for after in [false, true] {
                for action in ["account", "certificate"] {
                    let directory = tempfile::tempdir().unwrap();
                    let root = directory.path();
                    let (old, _) = certificate_support::material(
                        "edge.example.test",
                        1_789_900_000,
                        1_990_100_000,
                    );
                    let (new, _) = certificate_support::material(
                        "edge.example.test",
                        1_789_900_000,
                        1_990_200_000,
                    );
                    let certs = |bytes: &[u8]| {
                        let text = std::str::from_utf8(bytes).unwrap();
                        text[text.find("-----BEGIN CERTIFICATE-----").unwrap()..].to_owned()
                    };
                    std::fs::write(
                        root.join("roots.pem"),
                        format!("{}{}", certs(&old), certs(&new)),
                    )
                    .unwrap();
                    std::fs::write(root.join("old.pem"), old).unwrap();
                    std::fs::write(root.join("new.pem"), new).unwrap();
                    std::fs::write(
                        root.join("old-account"),
                        rustls_acme::acme::Account::generate_key_pair(),
                    )
                    .unwrap();
                    std::fs::write(
                        root.join("new-account"),
                        rustls_acme::acme::Account::generate_key_pair(),
                    )
                    .unwrap();
                    let child = |mode: &str| {
                        let mut command =
                            std::process::Command::new(std::env::current_exe().unwrap());
                        command
                            .args(["--exact", "store_process", "--nocapture"])
                            .env("RUNEWARP_TEST_STORE_PROCESS", root)
                            .env("RUNEWARP_TEST_STORE_OCCURRENCE", occurrence.to_string())
                            .env("RUNEWARP_TEST_STORE_ACTION", mode)
                            .env("RUNEWARP_TEST_STORE_OPERATION", format!("{operation:?}"))
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::inherit());
                        if after {
                            command.env("RUNEWARP_TEST_STORE_AFTER", "1");
                        }
                        command.status().unwrap()
                    };
                    assert!(child("seed").success());
                    assert_eq!(child(action).code(), Some(75));
                    assert!(
                        child("verify").success(),
                        "recovery failed at {operation:?}, after={after}, action={action}"
                    );
                    let generations = std::fs::read_dir(root.join("state/committed/generations"))
                        .unwrap()
                        .count();
                    assert!(generations <= 4, "recovery removes uncommitted candidates");
                }
            }
        }
    }
}

#[tokio::test]
async fn missing_current_generation_recovers_the_prior_complete_generation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private");
    let owner = CertificateOwner::try_acquire(&path).unwrap().unwrap();
    let (pem, roots) =
        certificate_support::material("edge.example.test", 1_789_900_000, 1_990_100_000);
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap();
    let cache = CertificateStore::open(
        owner.clone(),
        policy.clone(),
        "mailto:admin@example.test",
        "https://ca.example.test/directory",
    )
    .unwrap();
    let contacts = vec!["mailto:admin@example.test".to_owned()];
    let domains = vec!["edge.example.test".to_owned()];
    let url = "https://ca.example.test/directory";
    let old = rustls_acme::acme::Account::generate_key_pair();
    cache.store_account(&contacts, url, &old).await.unwrap();
    cache.store_cert(&domains, url, &pem).await.unwrap();
    let fingerprint = cache
        .export_snapshot(Duration::from_secs(7200))
        .unwrap()
        .fingerprint()
        .to_owned();
    cache
        .store_account(
            &contacts,
            url,
            &rustls_acme::acme::Account::generate_key_pair(),
        )
        .await
        .unwrap();
    // Corruption is injected at the filesystem seam, without reaching into cache internals.
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("committed/current.json")).unwrap())
            .unwrap();
    let current = path
        .join("committed/generations")
        .join(manifest["generations"][0].as_str().unwrap());
    std::fs::remove_file(current).unwrap();
    let recovered =
        CertificateStore::open(owner, policy, "mailto:admin@example.test", url).unwrap();
    assert_eq!(
        recovered.load_account(&contacts, url).await.unwrap(),
        Some(old)
    );
    assert_eq!(
        recovered
            .export_snapshot(Duration::from_secs(7200))
            .unwrap()
            .fingerprint(),
        fingerprint
    );
}

#[tokio::test]
async fn readable_malformed_account_material_blocks_the_owner_without_exposing_it_to_passive_serving()
 {
    use sha2::{Digest, Sha256};
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let owner = CertificateOwner::try_acquire(&path).unwrap().unwrap();
    let (pem, roots) =
        certificate_support::material("edge.example.test", 1_789_900_000, 1_990_100_000);
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap();
    let url = "https://ca.example.test/directory";
    let cache = CertificateStore::open(
        owner.clone(),
        policy.clone(),
        "mailto:admin@example.test",
        url,
    )
    .unwrap();
    cache
        .store_account(
            &["mailto:admin@example.test".to_owned()],
            url,
            &rustls_acme::acme::Account::generate_key_pair(),
        )
        .await
        .unwrap();
    cache
        .store_cert(&["edge.example.test".to_owned()], url, &pem)
        .await
        .unwrap();
    let fingerprint = cache
        .export_snapshot(Duration::from_secs(7200))
        .unwrap()
        .fingerprint()
        .to_owned();
    let manifest_path = path.join("committed/current.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let old = manifest["generations"][0].as_str().unwrap().to_owned();
    let generations = path.join("committed/generations");
    let mut generation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(generations.join(&old)).unwrap()).unwrap();
    generation["account"] = serde_json::json!([0, 1, 2]);
    let bytes = serde_json::to_vec(&generation).unwrap();
    let id: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(generations.join(&id), bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            generations.join(&id),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    std::fs::copy(
        generations.join(format!("{old}.pem")),
        generations.join(format!("{id}.pem")),
    )
    .unwrap();
    manifest["generations"][0] = id.into();
    std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(
        CertificateStore::open(owner, policy.clone(), "mailto:admin@example.test", url).is_err()
    );
    assert_eq!(
        CertificateStore::read_snapshot(&path, &policy, SystemTime::now())
            .unwrap()
            .unwrap()
            .fingerprint(),
        fingerprint
    );
}
