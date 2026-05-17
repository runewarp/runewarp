use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, ErrorKind, Write};
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
const SERVER_CA_KEY_FILENAME: &str = "server-ca.key";
const SERVER_HOSTNAME_FILENAME: &str = "server-hostname.txt";

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
                "failed to generate server certificates: {source}"
            ),
            Self::ParseState(source) => write!(
                formatter,
                "failed to parse stored server certificate state: {source}"
            ),
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

fn write_new_file_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ServerCertError> {
    let mut file = open_new_file_with_mode(path, mode)?;
    file.write_all(contents)
        .map_err(|source| ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

fn replace_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ServerCertError> {
    let Some(parent) = path.parent() else {
        return Err(ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source: io::Error::new(ErrorKind::InvalidInput, "missing parent directory"),
        });
    };

    let Some(filename) = path.file_name() else {
        return Err(ServerCertError::WriteFile {
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
            Err(ServerCertError::WriteFile { source, .. })
                if source.kind() == ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Err(source) = file.write_all(contents) {
            let _ = fs::remove_file(&temporary_path);
            return Err(ServerCertError::WriteFile {
                path: path.to_path_buf(),
                source,
            });
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary_path, path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(ServerCertError::WriteFile {
                path: path.to_path_buf(),
                source,
            });
        }
        return Ok(());
    }

    Err(ServerCertError::WriteFile {
        path: path.to_path_buf(),
        source: io::Error::new(
            ErrorKind::AlreadyExists,
            "failed to allocate a temporary file for atomic replacement",
        ),
    })
}

fn open_new_file_with_mode(path: &Path, mode: u32) -> Result<std::fs::File, ServerCertError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    options
        .open(path)
        .map_err(|source| ServerCertError::WriteFile {
            path: path.to_path_buf(),
            source,
        })
}
