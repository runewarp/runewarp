//! Server certificate serving and process-held ACME ownership.

mod controller;
mod route;
mod store;
pub use controller::{ServerAcmeOptions, ServerCertificateController, ServerCertificateStatus};
pub use route::{
    ChallengeRouteObserver, ChallengeRouteRequest, ConsumedChallengeRoute, TcpChallengeRoute,
};
pub use store::{CertificateStore, CertificateStoreIo, LocalCertificateStoreIo, StoreOperation};

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rustls::client::{WebPkiServerVerifier, danger::ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

/// Trust and lifetime requirements for every serving certificate, including cached ones.
#[derive(Clone)]
pub struct CertificateValidation {
    hostname: crate::ServerHostname,
    roots: Arc<rustls::RootCertStore>,
    minimum_remaining: Duration,
    safety_margin: Duration,
    clock: Arc<dyn CertificateClock>,
}

/// Wall time used for certificate admission. ACME's own renewal timer remains owned by
/// rustls-acme; this clock controls Core's independent validation and safety deadline.
pub trait CertificateClock: Send + Sync {
    fn now(&self) -> SystemTime;
}
struct SystemCertificateClock;
impl CertificateClock for SystemCertificateClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
impl std::fmt::Debug for CertificateValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateValidation")
            .field("hostname", &self.hostname)
            .field("minimum_remaining", &self.minimum_remaining)
            .field("safety_margin", &self.safety_margin)
            .finish()
    }
}

impl CertificateValidation {
    pub fn new(
        hostname: crate::ServerHostname,
        roots: Arc<rustls::RootCertStore>,
        minimum_remaining: Duration,
        safety_margin: Duration,
    ) -> io::Result<Self> {
        if safety_margin.is_zero() || minimum_remaining <= safety_margin {
            return Err(io::Error::other(
                "certificate lifetime budget must exceed a positive safety margin",
            ));
        }
        Ok(Self {
            hostname,
            roots,
            minimum_remaining,
            safety_margin,
            clock: Arc::new(SystemCertificateClock),
        })
    }
    pub fn hostname(&self) -> &crate::ServerHostname {
        &self.hostname
    }

    pub fn with_clock(mut self, clock: Arc<dyn CertificateClock>) -> Self {
        self.clock = clock;
        self
    }
    pub(super) fn now(&self) -> SystemTime {
        self.clock.now()
    }
}

/// Immutable private certificate and key material. Contains no account or authorization state.
#[derive(Clone)]
pub struct CertificateSnapshot {
    pem: Arc<[u8]>,
    key: Arc<CertifiedKey>,
    valid_from: SystemTime,
    expires_at: SystemTime,
    fingerprint: String,
}

impl std::fmt::Debug for CertificateSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateSnapshot")
            .field("fingerprint", &self.fingerprint)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CertificateSnapshot {
    /// Validate owned immutable material before using it for ordinary TLS or handoff.
    pub fn validate(
        pem: &[u8],
        policy: &CertificateValidation,
        now: SystemTime,
    ) -> io::Result<Self> {
        if pem.len() > 128 * 1024 {
            return Err(invalid_certificate());
        }
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid_certificate())?;
        let leaf = chain.first().ok_or_else(invalid_certificate)?;
        let private_key = PrivateKeyDer::from_pem_slice(pem).map_err(|_| invalid_certificate())?;
        let key = CertifiedKey::from_der(
            chain.clone(),
            private_key,
            &rustls::crypto::ring::default_provider(),
        )
        .map_err(|_| invalid_certificate())?;
        key.keys_match().map_err(|_| invalid_certificate())?;
        let verifier = WebPkiServerVerifier::builder(policy.roots.clone())
            .build()
            .map_err(|_| invalid_certificate())?;
        let name = ServerName::try_from(policy.hostname.as_str().to_owned())
            .map_err(|_| invalid_certificate())?;
        verifier
            .verify_server_cert(
                leaf,
                &chain[1..],
                &name,
                &[],
                UnixTime::since_unix_epoch(
                    now.duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(|_| invalid_certificate())?,
                ),
            )
            .map_err(|_| invalid_certificate())?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|_| invalid_certificate())?;
        let expires_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(
                u64::try_from(parsed.validity().not_after.timestamp())
                    .map_err(|_| invalid_certificate())?,
            ))
            .ok_or_else(invalid_certificate)?;
        let valid_from = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(
                u64::try_from(parsed.validity().not_before.timestamp())
                    .map_err(|_| invalid_certificate())?,
            ))
            .ok_or_else(invalid_certificate)?;
        if expires_at
            .duration_since(now)
            .map_err(|_| invalid_certificate())?
            < policy.minimum_remaining
        {
            return Err(invalid_certificate());
        }
        // Canonicalize the blob. No extra PEM blocks, account data or arbitrary comments
        // supplied by a caller can ride along in the serving export.
        let private_key = PrivateKeyDer::from_pem_slice(pem).map_err(|_| invalid_certificate())?;
        let pair = rcgen::KeyPair::try_from(&private_key).map_err(|_| invalid_certificate())?;
        let mut canonical = pair.serialize_pem();
        let text = std::str::from_utf8(pem).map_err(|_| invalid_certificate())?;
        for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
            let (body, _) = block
                .split_once("-----END CERTIFICATE-----")
                .ok_or_else(invalid_certificate)?;
            canonical.push_str("-----BEGIN CERTIFICATE-----");
            canonical.push_str(body);
            canonical.push_str("-----END CERTIFICATE-----\n");
        }
        Ok(Self {
            pem: canonical.into_bytes().into(),
            key: Arc::new(key),
            valid_from,
            expires_at,
            fingerprint: hex_digest(leaf.as_ref()),
        })
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Private transport bytes for an authenticated, local handoff. Never log these bytes.
    pub fn to_pem(&self) -> Vec<u8> {
        self.pem.to_vec()
    }
}

fn invalid_certificate() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Server certificate failed identity, key, trust or lifetime validation",
    )
}

// Retain the descriptor even when an embedder drops its runtime. No voluntary unlock can
// race a forgotten future or inherited resolver. std opens descriptors close-on-exec.
static PROCESS_OWNERS: Mutex<Vec<Arc<File>>> = Mutex::new(Vec::new());

/// Exclusive local ACME ownership, retained until this process exits.
///
/// Every participating process must use the same private directory on a local filesystem.
/// Never unlink, replace, clone, pass or inherit the lock descriptor. Forking an owner is
/// unsupported. Upgrades from binaries without this lock must be sequential.
#[derive(Clone, Debug)]
pub struct CertificateOwner {
    directory: PathBuf,
    _file: Arc<File>,
    writing: Arc<Mutex<()>>,
}

impl CertificateOwner {
    /// Attempt ownership without waiting or disturbing the current owner.
    pub fn try_acquire(directory: &Path) -> io::Result<Option<Self>> {
        private_directory(directory)?;
        let path = directory.join("owner.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match fs::symlink_metadata(&path) {
            Ok(_) => private_regular_file(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = options.open(&path)?;
        private_regular_file(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        let file = Arc::new(file);
        PROCESS_OWNERS
            .lock()
            .expect("process ownership mutex poisoned")
            .push(file.clone());
        Ok(Some(Self {
            directory: directory.to_owned(),
            _file: file,
            writing: Arc::new(Mutex::new(())),
        }))
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

pub(crate) fn private_directory(path: &Path) -> io::Result<()> {
    if !path.try_exists()? {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.try_exists()? {
            private_directory(parent)?;
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => File::open(parent)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::other("certificate directory is not a directory"));
    }
    check_permissions(&metadata)
}

fn private_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::other("certificate state is not a regular file"));
    }
    check_permissions(&metadata)
}

fn check_permissions(metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "certificate state must be private to its owner",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(io::Error::other(
            "private certificate storage requires Unix permissions",
        ))
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
