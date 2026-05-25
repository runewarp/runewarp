use std::fmt;
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

    create_directory(directory, 0o755)?;
    create_directory(&state_dir, 0o700)?;
    create_directory(&leaf_dir, 0o755)?;

    let generated = generate_client_public_cert_material(&hostname)?;

    write_new_file_with_mode(
        &directory.join(CLIENT_PUBLIC_CA_FILENAME),
        generated.ca_pem.as_bytes(),
        0o644,
    )?;
    write_new_file_with_mode(
        &state_dir.join(CLIENT_PUBLIC_CA_KEY_FILENAME),
        generated.ca_key_pem.as_bytes(),
        0o600,
    )?;
    write_new_file_with_mode(
        &leaf_dir.join(SERVER_CERT_FILENAME),
        generated.leaf_cert_pem.as_bytes(),
        0o644,
    )?;
    write_new_file_with_mode(
        &leaf_dir.join(SERVER_KEY_FILENAME),
        generated.leaf_key_pem.as_bytes(),
        0o600,
    )?;

    Ok(())
}

/// Returns the subdirectory that holds the leaf cert and key for `hostname`.
pub fn client_public_cert_leaf_dir(directory: &Path, hostname: &str) -> PathBuf {
    directory.join(normalize_public_hostname(hostname))
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::tls_material::{SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, load_certificate_chain, load_private_key};

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
