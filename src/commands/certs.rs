use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use runewarp::{ConfigFileError, XdgPathError, default_config_path};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;

pub(super) const MANUAL_CERT_RENEW_AFTER_DAYS: i64 = 60;

pub(super) fn resolve_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
    configured_dir: impl Fn(&Path) -> Result<Option<PathBuf>, ConfigFileError>,
    default_dir: impl Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(directory) = directory {
        return Ok(directory);
    }

    if let Some(config_path) = candidate_config_path(config)
        && let Some(configured_dir) =
            configured_dir(&config_path).map_err(|error| -> Box<dyn Error> { Box::new(error) })?
    {
        return Ok(configured_dir);
    }

    default_dir().map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

pub(super) fn candidate_config_path(config: Option<PathBuf>) -> Option<PathBuf> {
    match config {
        Some(config) => Some(config),
        None => default_config_path()
            .ok()
            .filter(|default_config_path| default_config_path.is_file()),
    }
}

pub(super) struct CertificateWindow {
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

pub(super) fn read_certificate_window(path: &Path) -> Result<CertificateWindow, Box<dyn Error>> {
    let certificate_pem = fs::read(path)?;
    let certificate_der = match CertificateDer::from_pem_slice(&certificate_pem) {
        Ok(certificate_der) => certificate_der,
        Err(PemError::NoItemsFound) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "missing certificate").into());
        }
        Err(source) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, source).into());
        }
    };
    let (_, certificate) = parse_x509_certificate(certificate_der.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid X.509 certificate"))?;

    Ok(CertificateWindow {
        issued_at: certificate.validity().not_before.to_datetime(),
        expires_at: certificate.validity().not_after.to_datetime(),
    })
}

pub(super) fn format_utc(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting should succeed")
}
