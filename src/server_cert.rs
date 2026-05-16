use std::fmt;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::hostname::normalize_public_hostname;
use crate::tls_material::{SERVER_CERT_FILENAME, SERVER_KEY_FILENAME};

pub const SERVER_CA_FILENAME: &str = "server-ca.crt";
pub const SERVER_CA_LIFETIME_DAYS: u64 = 3650;
pub const SERVER_CERT_LIFETIME_DAYS: u64 = 90;

const SERVER_STATE_DIR: &str = "state";
const SERVER_MANUAL_STATE_DIR: &str = "manual";
const SERVER_CA_KEY_FILENAME: &str = "server-ca.key";
const SERVER_HOSTNAME_FILENAME: &str = "server-hostname.txt";

#[derive(Debug)]
pub enum ServerCertError {
    CreateDirectory { path: PathBuf, source: io::Error },
    WriteFile { path: PathBuf, source: io::Error },
    Generate(rcgen::Error),
}

impl fmt::Display for ServerCertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDirectory { path, source } => {
                write!(formatter, "failed to create {}: {source}", path.display())
            }
            Self::WriteFile { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            Self::Generate(source) => write!(formatter, "failed to generate server certificates: {source}"),
        }
    }
}

impl std::error::Error for ServerCertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDirectory { source, .. } | Self::WriteFile { source, .. } => Some(source),
            Self::Generate(source) => Some(source),
        }
    }
}

impl From<rcgen::Error> for ServerCertError {
    fn from(source: rcgen::Error) -> Self {
        Self::Generate(source)
    }
}

pub fn initialize_manual_server_certificate(
    directory: &Path,
    hostname: &str,
) -> Result<(), ServerCertError> {
    let hostname = normalize_public_hostname(hostname);
    let manual_state_directory = manual_state_directory(directory);
    create_directory(directory, 0o755)?;
    create_directory(&directory.join(SERVER_STATE_DIR), 0o700)?;
    create_directory(&manual_state_directory, 0o700)?;

    let generated = generate_manual_server_cert_material(&hostname)?;
    write_new_file_with_mode(
        &directory.join(SERVER_CERT_FILENAME),
        generated.server_cert_pem.as_bytes(),
        0o644,
    )?;
    write_new_file_with_mode(
        &directory.join(SERVER_KEY_FILENAME),
        generated.server_key_pem.as_bytes(),
        0o600,
    )?;
    write_new_file_with_mode(
        &directory.join(SERVER_CA_FILENAME),
        generated.server_ca_pem.as_bytes(),
        0o644,
    )?;
    write_new_file_with_mode(
        &manual_state_directory.join(SERVER_CA_KEY_FILENAME),
        generated.server_ca_key_pem.as_bytes(),
        0o600,
    )?;
    write_new_file_with_mode(
        &manual_state_directory.join(SERVER_HOSTNAME_FILENAME),
        hostname.as_bytes(),
        0o644,
    )?;

    Ok(())
}

struct GeneratedServerCertMaterial {
    server_cert_pem: String,
    server_key_pem: String,
    server_ca_pem: String,
    server_ca_key_pem: String,
}

fn generate_manual_server_cert_material(
    hostname: &str,
) -> Result<GeneratedServerCertMaterial, rcgen::Error> {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);

    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.not_before = not_before;
    ca_params.not_after = not_before + Duration::days(SERVER_CA_LIFETIME_DAYS as i64);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Runewarp Server CA");
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_before + Duration::days(SERVER_CERT_LIFETIME_DAYS as i64);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname.to_owned());
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    leaf_params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_key = KeyPair::generate()?;
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    Ok(GeneratedServerCertMaterial {
        server_cert_pem: leaf_cert.pem(),
        server_key_pem: leaf_key_pem,
        server_ca_pem: ca_cert.pem(),
        server_ca_key_pem: ca_key_pem,
    })
}

fn manual_state_directory(directory: &Path) -> PathBuf {
    directory.join(SERVER_STATE_DIR).join(SERVER_MANUAL_STATE_DIR)
}

fn create_directory(path: &Path, mode: u32) -> Result<(), ServerCertError> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(mode);
    builder
        .create(path)
        .map_err(|source| ServerCertError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        })
}

fn write_new_file_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<(), ServerCertError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options.open(path).map_err(|source| ServerCertError::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(contents)
        .map_err(|source| ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}
