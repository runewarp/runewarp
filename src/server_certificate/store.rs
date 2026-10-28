use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::future::BoxFuture;
use rustls_acme::caches::DirCache;
use rustls_acme::{AccountCache, CertCache};
use serde::{Deserialize, Serialize};

use super::{
    CertificateOwner, CertificateSnapshot, CertificateValidation, hex_digest, private_directory,
    private_regular_file,
};

const MAX_STATE_BYTES: u64 = 1024 * 1024;

/// Real persistence boundaries, also usable for storage fault injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOperation {
    GenerationSync,
    GenerationRename,
    GenerationDirectorySync,
    ManifestSync,
    ManifestRename,
    ManifestDirectorySync,
    CleanupDirectorySync,
}

/// Filesystem durability adapter. Implementations must perform the requested operation
/// before returning success. No write job may outlive the process holding ownership.
pub trait CertificateStoreIo: Send + Sync {
    fn read_file(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        read_private(path, limit)
    }
    fn sync_file(&self, file: &File, operation: StoreOperation) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path, operation: StoreOperation) -> io::Result<()>;
    fn sync_directory(&self, directory: &Path, operation: StoreOperation) -> io::Result<()>;
}

#[derive(Debug)]
pub struct LocalCertificateStoreIo;

impl CertificateStoreIo for LocalCertificateStoreIo {
    fn sync_file(&self, file: &File, _: StoreOperation) -> io::Result<()> {
        file.sync_all()
    }
    fn rename(&self, from: &Path, to: &Path, _: StoreOperation) -> io::Result<()> {
        fs::rename(from, to)
    }
    fn sync_directory(&self, directory: &Path, _: StoreOperation) -> io::Result<()> {
        File::open(directory)?.sync_all()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    hostname: String,
    contact: String,
    directory_url: String,
    account: Option<Vec<u8>>,
    certificate: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Manifest {
    generations: Vec<String>,
}

/// An owner-only cache adapter for rustls-acme. Each immutable generation contains a
/// complete account/certificate pair. One atomic manifest retains the current and prior
/// generation. Serving exports contain only independently validated certificate material.
#[derive(Clone)]
pub struct CertificateStore {
    inner: Arc<Store>,
}

struct Store {
    owner: CertificateOwner,
    policy: CertificateValidation,
    contact: String,
    directory_url: String,
    io: Arc<dyn CertificateStoreIo>,
    writing: Arc<Mutex<()>>,
    failed: AtomicBool,
}

impl CertificateStore {
    pub fn open(
        owner: CertificateOwner,
        policy: CertificateValidation,
        contact: &str,
        directory_url: &str,
    ) -> io::Result<Self> {
        Self::open_with_io(
            owner,
            policy,
            contact,
            directory_url,
            Arc::new(LocalCertificateStoreIo),
        )
    }

    pub fn open_with_io(
        owner: CertificateOwner,
        policy: CertificateValidation,
        contact: &str,
        directory_url: &str,
        io: Arc<dyn CertificateStoreIo>,
    ) -> io::Result<Self> {
        let writing = owner.writing.clone();
        let _guard = writing.lock().expect("certificate store mutex poisoned");
        let directory = owner.directory.join("committed");
        private_directory(&directory)?;
        private_directory(&directory.join("generations"))?;
        let result = Self {
            inner: Arc::new(Store {
                owner,
                policy,
                contact: contact.to_owned(),
                directory_url: directory_url.to_owned(),
                io,
                writing: writing.clone(),
                failed: AtomicBool::new(false),
            }),
        };
        let generation = result.inner.load()?;
        if let Some(account) = &generation.account {
            validate_account(account)?;
        }
        result.inner.recover_manifest()?;
        // A new owner re-establishes durability after an interrupted publication. Failure
        // blocks ACME entirely; an already installed serving snapshot remains independent.
        result.inner.sync_committed()?;
        result.inner.prune()?;
        Ok(result)
    }

    pub(super) async fn import_legacy(&self) -> io::Result<()> {
        let directory = self.inner.directory();
        if !tokio::task::spawn_blocking(move || read_manifest(&directory))
            .await
            .map_err(io::Error::other)??
            .generations
            .is_empty()
        {
            return Ok(());
        }
        let legacy = DirCache::new(self.inner.owner.directory.clone());
        let contacts = vec![self.inner.contact.clone()];
        let domains = vec![self.inner.policy.hostname.as_str().to_owned()];
        if let Some(account) = legacy
            .load_account(&contacts, &self.inner.directory_url)
            .await?
        {
            self.store_account(&contacts, &self.inner.directory_url, &account)
                .await?;
        }
        if let Some(pem) = legacy
            .load_cert(&domains, &self.inner.directory_url)
            .await?
            && CertificateSnapshot::validate(&pem, &self.inner.policy, self.inner.policy.now())
                .is_ok()
        {
            self.store_cert(&domains, &self.inner.directory_url, &pem)
                .await?;
        }
        Ok(())
    }

    /// Read committed immutable material without acquiring ownership or writing any file.
    pub fn read_snapshot(
        directory: &Path,
        policy: &CertificateValidation,
        now: SystemTime,
    ) -> io::Result<Option<CertificateSnapshot>> {
        let path = directory.join("committed");
        // Readers can race a later owner's garbage collection. Re-read the atomic
        // manifest rather than copying a mutable file or accepting a partial generation.
        for _ in 0..3 {
            let manifest = read_manifest(&path)?;
            for id in &manifest.generations {
                // Passive serving reads only the owner-published certificate/key export.
                // Account state remains in its separate immutable owner-only cache blob.
                if let Ok(pem) = read_private(
                    &path.join("generations").join(format!("{id}.pem")),
                    MAX_STATE_BYTES,
                ) && let Ok(snapshot) = CertificateSnapshot::validate(&pem, policy, now)
                {
                    return Ok(Some(snapshot));
                }
            }
            if manifest.generations.is_empty() {
                return Ok(None);
            }
        }
        Err(invalid_state())
    }

    /// Revalidate and sync the committed snapshot immediately before an irreversible drain.
    /// The caller supplies its entire warm/drain/takeover/recovery/clock budget.
    pub fn export_snapshot(&self, required_remaining: Duration) -> io::Result<CertificateSnapshot> {
        let _guard = self
            .inner
            .writing
            .lock()
            .expect("certificate store mutex poisoned");
        if self.inner.failed.load(Ordering::SeqCst) {
            return Err(io::Error::other(
                "certificate persistence requires recovery",
            ));
        }
        self.inner.sync_committed()?;
        let mut policy = self.inner.policy.clone();
        policy.minimum_remaining = policy.minimum_remaining.max(required_remaining);
        Self::read_snapshot(
            self.inner.owner.directory(),
            &policy,
            self.inner.policy.now(),
        )?
        .ok_or_else(invalid_state)
    }
}

impl Store {
    fn directory(&self) -> PathBuf {
        self.owner.directory.join("committed")
    }

    fn recover_manifest(&self) -> io::Result<()> {
        let directory = self.directory();
        let manifest = read_manifest_with_io(&directory, self.io.as_ref())?;
        let retained: Vec<_> = manifest
            .generations
            .iter()
            .filter(|id| read_generation_with_io(&directory, id, self.io.as_ref()).is_ok())
            .cloned()
            .collect();
        for id in &retained {
            let generation = read_generation_with_io(&directory, id, self.io.as_ref())?;
            if let Some(pem) = generation.certificate
                && CertificateSnapshot::validate(&pem, &self.policy, self.policy.now()).is_ok()
            {
                let export = directory.join("generations").join(format!("{id}.pem"));
                if read_private(&export, MAX_STATE_BYTES).ok().as_deref() != Some(pem.as_slice()) {
                    self.publish_blob(&export, &pem)?;
                }
            }
        }
        if retained == manifest.generations {
            return Ok(());
        }
        if retained.is_empty() {
            return Err(invalid_state());
        }
        for id in &retained {
            self.io.sync_file(
                &File::open(directory.join("generations").join(id))?,
                StoreOperation::GenerationSync,
            )?;
        }
        self.io.sync_directory(
            &directory.join("generations"),
            StoreOperation::GenerationDirectorySync,
        )?;
        self.publish_manifest(&Manifest {
            generations: retained,
        })
    }

    fn publish_manifest(&self, manifest: &Manifest) -> io::Result<()> {
        let directory = self.directory();
        let manifest = serde_json::to_vec(manifest).map_err(|_| invalid_state())?;
        let candidate = directory.join("candidate.json");
        let file = write_private(&candidate, &manifest)?;
        self.io.sync_file(&file, StoreOperation::ManifestSync)?;
        self.io.rename(
            &candidate,
            &directory.join("current.json"),
            StoreOperation::ManifestRename,
        )?;
        self.io
            .sync_directory(&directory, StoreOperation::ManifestDirectorySync)
    }

    fn load(&self) -> io::Result<Generation> {
        let directory = self.directory();
        let manifest = read_manifest_with_io(&directory, self.io.as_ref())?;
        if manifest.generations.is_empty() {
            return Ok(Generation {
                hostname: self.policy.hostname.as_str().to_owned(),
                contact: self.contact.clone(),
                directory_url: self.directory_url.clone(),
                ..Generation::default()
            });
        }
        for id in manifest.generations {
            if let Ok(generation) = read_generation_with_io(&directory, &id, self.io.as_ref()) {
                if generation.hostname != self.policy.hostname.as_str()
                    || generation.contact != self.contact
                    || generation.directory_url != self.directory_url
                {
                    return Err(invalid_state());
                }
                if let Some(account) = &generation.account {
                    validate_account(account)?;
                }
                return Ok(generation);
            }
        }
        Err(invalid_state())
    }

    fn sync_committed(&self) -> io::Result<()> {
        let directory = self.directory();
        let manifest = read_manifest_with_io(&directory, self.io.as_ref())?;
        for id in manifest.generations {
            let file = File::open(directory.join("generations").join(&id))?;
            self.io.sync_file(&file, StoreOperation::GenerationSync)?;
            let export = directory.join("generations").join(format!("{id}.pem"));
            if export.try_exists()? {
                self.io
                    .sync_file(&File::open(export)?, StoreOperation::GenerationSync)?;
            }
        }
        self.io.sync_directory(
            &directory.join("generations"),
            StoreOperation::GenerationDirectorySync,
        )?;
        if directory.join("current.json").try_exists()? {
            self.io.sync_file(
                &File::open(directory.join("current.json"))?,
                StoreOperation::ManifestSync,
            )?;
        }
        self.io
            .sync_directory(&directory, StoreOperation::ManifestDirectorySync)
    }

    fn publish(&self, generation: Generation) -> io::Result<()> {
        let directory = self.directory();
        let bytes = serde_json::to_vec(&generation).map_err(|_| invalid_state())?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(invalid_state());
        }
        let id = hex_digest(&bytes);
        // Clean up only unreferenced prior candidates before starting another bounded write.
        self.prune()?;
        self.publish_blob(&directory.join("generations").join(&id), &bytes)?;
        if let Some(pem) = &generation.certificate {
            self.publish_blob(
                &directory.join("generations").join(format!("{id}.pem")),
                pem,
            )?;
        }
        let previous = read_manifest_with_io(&directory, self.io.as_ref())?
            .generations
            .into_iter()
            .find(|old| {
                *old != id && read_generation_with_io(&directory, old, self.io.as_ref()).is_ok()
            });
        let mut generations = vec![id];
        generations.extend(previous);
        self.publish_manifest(&Manifest { generations })?;
        self.prune()
    }

    fn prune(&self) -> io::Result<()> {
        let directory = self.directory();
        let manifest = read_manifest_with_io(&directory, self.io.as_ref())?;
        let mut removed = false;
        for entry in fs::read_dir(directory.join("generations"))? {
            let entry = entry?;
            if !manifest.generations.iter().any(|id| {
                entry.file_name() == id.as_str()
                    || entry.file_name() == format!("{id}.pem").as_str()
            }) {
                fs::remove_file(entry.path())?;
                removed = true;
            }
        }
        if removed {
            self.io.sync_directory(
                &directory.join("generations"),
                StoreOperation::CleanupDirectorySync,
            )?;
        }
        Ok(())
    }

    fn publish_blob(&self, destination: &Path, bytes: &[u8]) -> io::Result<()> {
        let directory = self.directory().join("generations");
        let candidate = directory.join("candidate");
        let file = write_private(&candidate, bytes)?;
        self.io.sync_file(&file, StoreOperation::GenerationSync)?;
        self.io
            .rename(&candidate, destination, StoreOperation::GenerationRename)?;
        self.io
            .sync_directory(&directory, StoreOperation::GenerationDirectorySync)
    }

    fn check(&self, names: &[String], expected: &str, url: &str) -> io::Result<()> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(io::Error::other(
                "certificate persistence requires recovery",
            ));
        }
        if names != [expected] || url != self.directory_url {
            return Err(invalid_state());
        }
        Ok(())
    }
}

// Explicit boxed signatures match the dependency's public async-trait interface without
// adding a macro dependency. Blocking I/O owns the process-held lock and never unlocks it.
impl CertCache for CertificateStore {
    type EC = io::Error;
    fn load_cert<'a, 'b, 'c, 'f>(
        &'a self,
        domains: &'b [String],
        url: &'c str,
    ) -> BoxFuture<'f, io::Result<Option<Vec<u8>>>>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            self.inner
                .check(domains, self.inner.policy.hostname.as_str(), url)?;
            let this = self.clone();
            tokio::task::spawn_blocking(move || {
                let generation = this.inner.load()?;
                // An expired or otherwise invalid prior certificate cannot become ordinary
                // serving material. Keep its account and permit a fresh acquisition.
                Ok(generation.certificate.and_then(|pem| {
                    CertificateSnapshot::validate(&pem, &this.inner.policy, this.inner.policy.now())
                        .ok()
                        .map(|snapshot| snapshot.to_pem())
                }))
            })
            .await
            .map_err(io::Error::other)?
        })
    }
    fn store_cert<'a, 'b, 'c, 'd, 'f>(
        &'a self,
        domains: &'b [String],
        url: &'c str,
        cert: &'d [u8],
    ) -> BoxFuture<'f, io::Result<()>>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        'd: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            self.inner
                .check(domains, self.inner.policy.hostname.as_str(), url)?;
            let snapshot =
                CertificateSnapshot::validate(cert, &self.inner.policy, self.inner.policy.now())?;
            let this = self.clone();
            tokio::task::spawn_blocking(move || {
                let _guard = this
                    .inner
                    .writing
                    .lock()
                    .expect("certificate store mutex poisoned");
                let mut generation = this.inner.load()?;
                generation.certificate = Some(snapshot.to_pem());
                let result = this.inner.publish(generation);
                if result.is_err() {
                    this.inner.failed.store(true, Ordering::SeqCst);
                }
                result
            })
            .await
            .map_err(io::Error::other)?
        })
    }
}

impl AccountCache for CertificateStore {
    type EA = io::Error;
    fn load_account<'a, 'b, 'c, 'f>(
        &'a self,
        contacts: &'b [String],
        url: &'c str,
    ) -> BoxFuture<'f, io::Result<Option<Vec<u8>>>>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            self.inner.check(contacts, &self.inner.contact, url)?;
            let this = self.clone();
            tokio::task::spawn_blocking(move || Ok(this.inner.load()?.account))
                .await
                .map_err(io::Error::other)?
        })
    }
    fn store_account<'a, 'b, 'c, 'd, 'f>(
        &'a self,
        contacts: &'b [String],
        url: &'c str,
        account: &'d [u8],
    ) -> BoxFuture<'f, io::Result<()>>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        'd: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            self.inner.check(contacts, &self.inner.contact, url)?;
            validate_account(account)?;
            let account = account.to_vec();
            let this = self.clone();
            tokio::task::spawn_blocking(move || {
                let _guard = this
                    .inner
                    .writing
                    .lock()
                    .expect("certificate store mutex poisoned");
                let mut generation = this.inner.load()?;
                generation.account = Some(account);
                let result = this.inner.publish(generation);
                if result.is_err() {
                    this.inner.failed.store(true, Ordering::SeqCst);
                }
                result
            })
            .await
            .map_err(io::Error::other)?
        })
    }
}

fn validate_account(bytes: &[u8]) -> io::Result<()> {
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(bytes);
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|_| invalid_state())?;
    if pair.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
        return Err(invalid_state());
    }
    Ok(())
}

fn read_manifest(directory: &Path) -> io::Result<Manifest> {
    read_manifest_with_io(directory, &LocalCertificateStoreIo)
}

fn read_manifest_with_io(directory: &Path, io: &dyn CertificateStoreIo) -> io::Result<Manifest> {
    let path = directory.join("current.json");
    let bytes = match io.read_file(&path, 512) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Manifest::default()),
        Err(error) => return Err(error),
    };
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| invalid_state())?;
    if manifest.generations.is_empty()
        || manifest.generations.len() > 2
        || manifest.generations.iter().any(|id| {
            id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(invalid_state());
    }
    Ok(manifest)
}

fn read_generation_with_io(
    directory: &Path,
    id: &str,
    io: &dyn CertificateStoreIo,
) -> io::Result<Generation> {
    let bytes = io.read_file(&directory.join("generations").join(id), MAX_STATE_BYTES)?;
    if hex_digest(&bytes) != id {
        return Err(invalid_state());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid_state())
}

fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    private_regular_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid_state());
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<File> {
    // Candidate names are owner-only and bounded; discard an interrupted candidate.
    if path.try_exists()? {
        private_regular_file(path)?;
        fs::remove_file(path)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    Ok(file)
}

fn invalid_state() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid committed Server certificate state",
    )
}
