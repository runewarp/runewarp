use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::hostname::normalize_public_hostname;
use crate::tls_material::{SERVER_CERT_FILENAME, SERVER_KEY_FILENAME};

pub const CLIENT_PUBLIC_CA_FILENAME: &str = "public-ca.crt";
pub const CLIENT_PUBLIC_CA_LIFETIME_DAYS: u64 = 3650;
pub const CLIENT_PUBLIC_CERT_LIFETIME_DAYS: u64 = 90;

const CLIENT_PUBLIC_STATE_DIR: &str = "state";
const CLIENT_PUBLIC_CA_KEY_FILENAME: &str = "public-ca.key";

#[derive(Debug)]
pub enum ClientPublicCertError {
    CreateDirectory { path: PathBuf, source: io::Error },
    ReadFile { path: PathBuf, source: io::Error },
    WriteFile { path: PathBuf, source: io::Error },
    Generate(rcgen::Error),
}

impl fmt::Display for ClientPublicCertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDirectory { path, source } => {
                write!(formatter, "failed to create {}: {source}", path.display())
            }
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::WriteFile { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            Self::Generate(source) => write!(
                formatter,
                "failed to generate client public certificates: {source}"
            ),
        }
    }
}

impl std::error::Error for ClientPublicCertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDirectory { source, .. }
            | Self::ReadFile { source, .. }
            | Self::WriteFile { source, .. } => Some(source),
            Self::Generate(source) => Some(source),
        }
    }
}

impl From<rcgen::Error> for ClientPublicCertError {
    fn from(source: rcgen::Error) -> Self {
        Self::Generate(source)
    }
}

/// Bootstraps a shared client public CA and a leaf certificate for `hostname`.
///
/// If the CA already exists in `directory` (detected by the presence of
/// `state/public-ca.key`), the existing CA is reused and only the leaf
/// material for `hostname` is generated. This allows adding leaf certificates
/// for additional hostnames without rotating the Visitor-facing trust anchor.
///
/// Refuses to overwrite existing leaf material for the same hostname.
///
/// Layout under `directory`:
/// ```text
/// public-ca.crt                   # Visitor trust anchor (distribute this)
/// {hostname}/server.crt           # leaf cert for the terminating hostname
/// {hostname}/server.key           # leaf key for the terminating hostname
/// state/public-ca.key             # CA private key (keep private)
/// ```
pub fn initialize_manual_client_public_cert(
    directory: &Path,
    hostname: &str,
) -> Result<(), ClientPublicCertError> {
    let hostname = normalize_public_hostname(hostname);
    let state_dir = directory.join(CLIENT_PUBLIC_STATE_DIR);
    let leaf_dir = directory.join(&hostname);
    let ca_cert_path = directory.join(CLIENT_PUBLIC_CA_FILENAME);
    let ca_key_path = state_dir.join(CLIENT_PUBLIC_CA_KEY_FILENAME);

    create_directory(directory, 0o755)?;
    create_directory(&state_dir, 0o700)?;
    create_directory(&leaf_dir, 0o755)?;

    let leaf_cert_path = leaf_dir.join(SERVER_CERT_FILENAME);
    let leaf_key_path = leaf_dir.join(SERVER_KEY_FILENAME);

    if ca_key_path.exists() {
        // CA already initialized: reuse it and issue a new leaf only.
        let (leaf_cert_pem, leaf_key_pem) =
            generate_leaf_from_existing_ca(&ca_cert_path, &ca_key_path, &hostname)?;
        write_new_file_with_mode(&leaf_cert_path, leaf_cert_pem.as_bytes(), 0o644)?;
        write_new_file_with_mode(&leaf_key_path, leaf_key_pem.as_bytes(), 0o600)?;
    } else {
        // Fresh init: generate CA and first leaf together.
        let generated = generate_client_public_cert_material(&hostname)?;
        write_new_file_with_mode(&ca_cert_path, generated.ca_pem.as_bytes(), 0o644)?;
        write_new_file_with_mode(&ca_key_path, generated.ca_key_pem.as_bytes(), 0o600)?;
        write_new_file_with_mode(&leaf_cert_path, generated.leaf_cert_pem.as_bytes(), 0o644)?;
        write_new_file_with_mode(&leaf_key_path, generated.leaf_key_pem.as_bytes(), 0o600)?;
    }

    Ok(())
}

/// Returns the subdirectory that holds the leaf cert and key for `hostname`.
pub fn client_public_cert_leaf_dir(directory: &Path, hostname: &str) -> PathBuf {
    directory.join(normalize_public_hostname(hostname))
}

/// Renews the leaf certificate for `hostname` under `directory`, reusing the
/// existing shared Client public CA. The CA itself is not changed.
///
/// Replaces `{hostname}/server.crt` and `{hostname}/server.key` atomically.
pub fn renew_manual_client_public_cert(
    directory: &Path,
    hostname: &str,
) -> Result<(), ClientPublicCertError> {
    let hostname = normalize_public_hostname(hostname);
    let ca_cert_path = directory.join(CLIENT_PUBLIC_CA_FILENAME);
    let ca_key_path = directory
        .join(CLIENT_PUBLIC_STATE_DIR)
        .join(CLIENT_PUBLIC_CA_KEY_FILENAME);

    let leaf_dir = directory.join(&hostname);
    let (leaf_cert_pem, leaf_key_pem) =
        generate_leaf_from_existing_ca(&ca_cert_path, &ca_key_path, &hostname)?;

    replace_file_atomically_with_mode(
        &leaf_dir.join(SERVER_CERT_FILENAME),
        leaf_cert_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &leaf_dir.join(SERVER_KEY_FILENAME),
        leaf_key_pem.as_bytes(),
        0o600,
    )?;

    Ok(())
}

/// Rotates the shared Client public CA and reissues every leaf certificate for
/// the given `hostnames`. Both the CA cert and CA private key are replaced;
/// every managed leaf cert and key are replaced under their hostname
/// subdirectories.
pub fn rotate_manual_client_public_cert_authority(
    directory: &Path,
    hostnames: &[String],
) -> Result<(), ClientPublicCertError> {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    let ca_params = ca_cert_params(not_before)?;
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let state_dir = directory.join(CLIENT_PUBLIC_STATE_DIR);

    // Generate all leaf material before writing anything, so failures before
    // the first write leave the directory unchanged.
    let leaves: Vec<(String, String, String)> = hostnames
        .iter()
        .map(|h| {
            let h = normalize_public_hostname(h);
            let leaf_params = leaf_cert_params(&h, not_before)?;
            let leaf_key = KeyPair::generate()?;
            let leaf_key_pem = leaf_key.serialize_pem();
            let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;
            Ok((h, leaf_cert.pem(), leaf_key_pem))
        })
        .collect::<Result<_, rcgen::Error>>()?;

    // Write CA material atomically.
    replace_file_atomically_with_mode(
        &directory.join(CLIENT_PUBLIC_CA_FILENAME),
        ca_cert_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &state_dir.join(CLIENT_PUBLIC_CA_KEY_FILENAME),
        ca_key_pem.as_bytes(),
        0o600,
    )?;

    // Write leaf material for every managed hostname.
    for (hostname, leaf_cert_pem, leaf_key_pem) in leaves {
        let leaf_dir = directory.join(&hostname);
        replace_file_atomically_with_mode(
            &leaf_dir.join(SERVER_CERT_FILENAME),
            leaf_cert_pem.as_bytes(),
            0o644,
        )?;
        replace_file_atomically_with_mode(
            &leaf_dir.join(SERVER_KEY_FILENAME),
            leaf_key_pem.as_bytes(),
            0o600,
        )?;
    }

    Ok(())
}

struct GeneratedClientPublicCertMaterial {
    ca_pem: String,
    ca_key_pem: String,
    leaf_cert_pem: String,
    leaf_key_pem: String,
}

fn generate_client_public_cert_material(
    hostname: &str,
) -> Result<GeneratedClientPublicCertMaterial, rcgen::Error> {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);

    let ca_params = ca_cert_params(not_before)?;
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate()?;
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_params = leaf_cert_params(hostname, not_before)?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    Ok(GeneratedClientPublicCertMaterial {
        ca_pem: ca_cert.pem(),
        ca_key_pem,
        leaf_cert_pem: leaf_cert.pem(),
        leaf_key_pem,
    })
}

/// Loads an existing CA from `ca_cert_path` and `ca_key_path` and issues a new
/// leaf certificate for `hostname`. Returns `(leaf_cert_pem, leaf_key_pem)`.
fn generate_leaf_from_existing_ca(
    ca_cert_path: &Path,
    ca_key_path: &Path,
    hostname: &str,
) -> Result<(String, String), ClientPublicCertError> {
    use std::fs;

    let ca_cert_pem =
        fs::read_to_string(ca_cert_path).map_err(|source| ClientPublicCertError::ReadFile {
            path: ca_cert_path.to_path_buf(),
            source,
        })?;
    let ca_key_pem =
        fs::read_to_string(ca_key_path).map_err(|source| ClientPublicCertError::ReadFile {
            path: ca_key_path.to_path_buf(),
            source,
        })?;

    let ca_key = KeyPair::from_pem(&ca_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)?;

    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    let leaf_key = KeyPair::generate()?;
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_params = leaf_cert_params(hostname, not_before)?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    Ok((leaf_cert.pem(), leaf_key_pem))
}

fn ca_cert_params(not_before: OffsetDateTime) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::new())?;
    params.not_before = not_before;
    params.not_after = not_before + Duration::days(CLIENT_PUBLIC_CA_LIFETIME_DAYS as i64);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Runewarp Client Public CA");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    Ok(params)
}

fn leaf_cert_params(
    hostname: &str,
    not_before: OffsetDateTime,
) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
    params.not_before = not_before;
    params.not_after = not_before + Duration::days(CLIENT_PUBLIC_CERT_LIFETIME_DAYS as i64);
    params
        .distinguished_name
        .push(DnType::CommonName, hostname.to_owned());
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    Ok(params)
}

fn create_directory(path: &Path, mode: u32) -> Result<(), ClientPublicCertError> {
    use std::fs::DirBuilder;
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(mode);
    builder
        .create(path)
        .map_err(|source| ClientPublicCertError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        })
}

fn write_new_file_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ClientPublicCertError> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options
        .open(path)
        .map_err(|source| ClientPublicCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(contents)
        .map_err(|source| ClientPublicCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })
}

fn open_new_file_with_mode(path: &Path, mode: u32) -> Result<std::fs::File, ClientPublicCertError> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    options
        .open(path)
        .map_err(|source| ClientPublicCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })
}

fn replace_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ClientPublicCertError> {
    use std::io::ErrorKind;

    let Some(parent) = path.parent() else {
        return Err(ClientPublicCertError::WriteFile {
            path: path.to_path_buf(),
            source: io::Error::new(ErrorKind::InvalidInput, "missing parent directory"),
        });
    };

    let Some(filename) = path.file_name() else {
        return Err(ClientPublicCertError::WriteFile {
            path: path.to_path_buf(),
            source: io::Error::new(ErrorKind::InvalidInput, "missing filename"),
        });
    };

    for attempt in 0..16 {
        let temporary_path = parent.join(format!(
            ".{}.runewarp-tmp-{}-{attempt}",
            filename.to_string_lossy(),
            std::process::id()
        ));
        let mut file = match open_new_file_with_mode(&temporary_path, mode) {
            Ok(file) => file,
            Err(ClientPublicCertError::WriteFile { source, .. })
                if source.kind() == ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Err(source) = file.write_all(contents) {
            let _ = fs::remove_file(&temporary_path);
            return Err(ClientPublicCertError::WriteFile {
                path: path.to_path_buf(),
                source,
            });
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary_path, path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(ClientPublicCertError::WriteFile {
                path: path.to_path_buf(),
                source,
            });
        }
        return Ok(());
    }

    Err(ClientPublicCertError::WriteFile {
        path: path.to_path_buf(),
        source: io::Error::other("failed to find a unique temporary path after 16 attempts"),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::tls_material::{
        SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, load_certificate_chain, load_private_key,
    };

    #[test]
    fn init_writes_all_expected_artifacts() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();

        assert!(dir.path().join("public-ca.crt").is_file());
        assert!(dir.path().join("state/public-ca.key").is_file());
        assert!(dir.path().join("app.example.test/server.crt").is_file());
        assert!(dir.path().join("app.example.test/server.key").is_file());
    }

    #[test]
    fn init_normalizes_hostname_in_subdirectory() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "App.Example.Test.").unwrap();

        assert!(dir.path().join("app.example.test/server.crt").is_file());
        assert!(dir.path().join("app.example.test/server.key").is_file());
    }

    #[test]
    fn init_writes_pem_artifacts() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();

        let ca_pem = fs::read_to_string(dir.path().join("public-ca.crt")).unwrap();
        let ca_key_pem = fs::read_to_string(dir.path().join("state/public-ca.key")).unwrap();
        let leaf_cert_pem =
            fs::read_to_string(dir.path().join("app.example.test/server.crt")).unwrap();
        let leaf_key_pem =
            fs::read_to_string(dir.path().join("app.example.test/server.key")).unwrap();

        assert!(ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(leaf_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(leaf_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn init_refuses_to_overwrite_existing_artifacts() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();
        let result = initialize_manual_client_public_cert(dir.path(), "app.example.test");

        assert!(result.is_err());
    }

    #[test]
    fn second_init_with_different_hostname_succeeds() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();
        let result = initialize_manual_client_public_cert(dir.path(), "api.example.test");

        assert!(
            result.is_ok(),
            "second init with a new hostname should succeed: {result:?}"
        );
        assert!(dir.path().join("api.example.test/server.crt").is_file());
        assert!(dir.path().join("api.example.test/server.key").is_file());
    }

    #[test]
    fn second_init_keeps_ca_cert_byte_stable() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();
        let ca_pem_before = fs::read(dir.path().join("public-ca.crt")).unwrap();

        initialize_manual_client_public_cert(dir.path(), "api.example.test").unwrap();
        let ca_pem_after = fs::read(dir.path().join("public-ca.crt")).unwrap();

        assert_eq!(
            ca_pem_before, ca_pem_after,
            "public-ca.crt must be byte-for-byte stable across a second init"
        );
    }

    #[test]
    fn second_init_issues_distinct_leaf_for_new_hostname() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();
        initialize_manual_client_public_cert(dir.path(), "api.example.test").unwrap();

        let app_certs =
            load_certificate_chain(&dir.path().join("app.example.test/server.crt")).unwrap();
        let api_certs =
            load_certificate_chain(&dir.path().join("api.example.test/server.crt")).unwrap();

        assert!(!app_certs.is_empty());
        assert!(!api_certs.is_empty());
        assert_ne!(
            app_certs[0].as_ref(),
            api_certs[0].as_ref(),
            "leaf certs for different hostnames must differ"
        );
    }

    #[test]
    fn init_generates_loadable_cert_and_key_for_hostname() {
        let dir = tempdir().unwrap();

        initialize_manual_client_public_cert(dir.path(), "app.example.test").unwrap();

        let leaf_dir = dir.path().join("app.example.test");
        let certs = load_certificate_chain(&leaf_dir.join(SERVER_CERT_FILENAME)).unwrap();
        let _key = load_private_key(&leaf_dir.join(SERVER_KEY_FILENAME)).unwrap();

        assert!(!certs.is_empty());
    }

    #[test]
    fn leaf_dir_helper_normalizes_hostname() {
        let base = std::path::PathBuf::from("/var/lib/runewarp/public-cert");
        let dir = client_public_cert_leaf_dir(&base, "App.Example.Test.");
        assert_eq!(dir, base.join("app.example.test"));
    }
}
