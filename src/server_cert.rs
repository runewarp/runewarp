use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::cert_file_ops;
use crate::hostname::normalize_public_hostname;
use crate::tls_material::{SERVER_CERT_FILENAME, SERVER_KEY_FILENAME};

pub const SERVER_CA_FILENAME: &str = "server-ca.crt";
pub const SERVER_CA_LIFETIME_DAYS: u64 = 3650;
pub const SERVER_CERT_LIFETIME_DAYS: u64 = 90;

const SERVER_STATE_DIR: &str = "state";
const SERVER_CA_KEY_FILENAME: &str = "server-ca.key";
const SERVER_HOSTNAME_FILENAME: &str = "server-hostname.txt";

pub struct ManualServerCertificateState {
    pub hostname: String,
}

#[derive(Debug)]
pub enum ServerCertError {
    CreateDirectory { path: PathBuf, source: io::Error },
    ReadFile { path: PathBuf, source: io::Error },
    WriteFile { path: PathBuf, source: io::Error },
    Generate(rcgen::Error),
    ParseState(rcgen::Error),
}

impl fmt::Display for ServerCertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDirectory { path, .. } => {
                write!(formatter, "failed to create {}", path.display())
            }
            Self::ReadFile { path, .. } => {
                write!(formatter, "failed to read {}", path.display())
            }
            Self::WriteFile { path, .. } => {
                write!(formatter, "failed to write {}", path.display())
            }
            Self::Generate(_) => formatter.write_str("failed to generate server certificates"),
            Self::ParseState(_) => {
                formatter.write_str("failed to parse stored server certificate state")
            }
        }
    }
}

impl std::error::Error for ServerCertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDirectory { source, .. }
            | Self::ReadFile { source, .. }
            | Self::WriteFile { source, .. } => Some(source),
            Self::Generate(source) | Self::ParseState(source) => Some(source),
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

pub fn inspect_manual_server_certificate(
    directory: &Path,
) -> Result<ManualServerCertificateState, ServerCertError> {
    let cert_path = directory.join(SERVER_CERT_FILENAME);
    let key_path = directory.join(SERVER_KEY_FILENAME);
    let ca_path = directory.join(SERVER_CA_FILENAME);
    let ca_key_path = manual_state_directory(directory).join(SERVER_CA_KEY_FILENAME);

    let _ = fs::read_to_string(&cert_path).map_err(|source| ServerCertError::ReadFile {
        path: cert_path,
        source,
    })?;
    let _ = fs::read_to_string(&key_path).map_err(|source| ServerCertError::ReadFile {
        path: key_path,
        source,
    })?;
    let _ = fs::read_to_string(&ca_path).map_err(|source| ServerCertError::ReadFile {
        path: ca_path,
        source,
    })?;
    let _ = fs::read_to_string(&ca_key_path).map_err(|source| ServerCertError::ReadFile {
        path: ca_key_path,
        source,
    })?;
    let _ = load_manual_server_ca_issuer(directory)?;

    Ok(ManualServerCertificateState {
        hostname: load_stored_hostname(directory)?,
    })
}

pub fn renew_manual_server_certificate(directory: &Path) -> Result<(), ServerCertError> {
    let hostname = load_stored_hostname(directory)?;
    let issuer = load_manual_server_ca_issuer(directory)?;
    let generated = generate_server_leaf_cert_material(&hostname, &issuer)?;

    replace_file_atomically_with_mode(
        &directory.join(SERVER_CERT_FILENAME),
        generated.server_cert_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &directory.join(SERVER_KEY_FILENAME),
        generated.server_key_pem.as_bytes(),
        0o600,
    )?;

    Ok(())
}

pub fn rotate_manual_server_certificate_authority(
    directory: &Path,
    hostname: &str,
) -> Result<(), ServerCertError> {
    let hostname = normalize_public_hostname(hostname);
    let manual_state_directory = manual_state_directory(directory);
    let generated = generate_manual_server_cert_material(&hostname)?;

    replace_file_atomically_with_mode(
        &directory.join(SERVER_CERT_FILENAME),
        generated.server_cert_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &directory.join(SERVER_KEY_FILENAME),
        generated.server_key_pem.as_bytes(),
        0o600,
    )?;
    replace_file_atomically_with_mode(
        &directory.join(SERVER_CA_FILENAME),
        generated.server_ca_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &manual_state_directory.join(SERVER_CA_KEY_FILENAME),
        generated.server_ca_key_pem.as_bytes(),
        0o600,
    )?;
    replace_file_atomically_with_mode(
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

    let ca_params = server_ca_params(not_before)?;
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_material = generate_server_leaf_cert_material(hostname, &issuer)?;

    Ok(GeneratedServerCertMaterial {
        server_cert_pem: leaf_material.server_cert_pem,
        server_key_pem: leaf_material.server_key_pem,
        server_ca_pem: ca_cert.pem(),
        server_ca_key_pem: ca_key_pem,
    })
}

struct GeneratedServerLeafCertMaterial {
    server_cert_pem: String,
    server_key_pem: String,
}

fn generate_server_leaf_cert_material(
    hostname: &str,
    issuer: &Issuer<'_, KeyPair>,
) -> Result<GeneratedServerLeafCertMaterial, rcgen::Error> {
    let leaf_params =
        server_leaf_params(hostname, OffsetDateTime::now_utc() - Duration::minutes(1))?;
    let leaf_key = KeyPair::generate()?;
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_cert = leaf_params.signed_by(&leaf_key, issuer)?;

    Ok(GeneratedServerLeafCertMaterial {
        server_cert_pem: leaf_cert.pem(),
        server_key_pem: leaf_key_pem,
    })
}

fn server_ca_params(not_before: OffsetDateTime) -> Result<CertificateParams, rcgen::Error> {
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
    Ok(ca_params)
}

fn server_leaf_params(
    hostname: &str,
    not_before: OffsetDateTime,
) -> Result<CertificateParams, rcgen::Error> {
    let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_before + Duration::days(SERVER_CERT_LIFETIME_DAYS as i64);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname.to_owned());
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::KeyEncipherment);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    Ok(leaf_params)
}

fn manual_state_directory(directory: &Path) -> PathBuf {
    directory.join(SERVER_STATE_DIR)
}

fn load_stored_hostname(directory: &Path) -> Result<String, ServerCertError> {
    let path = manual_state_directory(directory).join(SERVER_HOSTNAME_FILENAME);
    let hostname = fs::read_to_string(&path).map_err(|source| ServerCertError::ReadFile {
        path: path.clone(),
        source,
    })?;
    Ok(normalize_public_hostname(hostname.trim()))
}

fn load_manual_server_ca_issuer(
    directory: &Path,
) -> Result<Issuer<'static, KeyPair>, ServerCertError> {
    let path = manual_state_directory(directory).join(SERVER_CA_KEY_FILENAME);
    let server_ca_key_pem =
        fs::read_to_string(&path).map_err(|source| ServerCertError::ReadFile {
            path: path.clone(),
            source,
        })?;
    let ca_key = KeyPair::from_pem(&server_ca_key_pem).map_err(ServerCertError::ParseState)?;
    Ok(Issuer::new(
        server_ca_params(OffsetDateTime::now_utc() - Duration::minutes(1))
            .map_err(ServerCertError::ParseState)?,
        ca_key,
    ))
}

fn write_new_file_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ServerCertError> {
    cert_file_ops::write_new_file_with_mode(path, contents, mode).map_err(|source| {
        ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn replace_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ServerCertError> {
    cert_file_ops::replace_file_atomically_with_mode(path, contents, mode).map_err(|source| {
        ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn create_directory(path: &Path, mode: u32) -> Result<(), ServerCertError> {
    cert_file_ops::create_directory(path, mode).map_err(|source| ServerCertError::CreateDirectory {
        path: path.to_path_buf(),
        source,
    })
}
