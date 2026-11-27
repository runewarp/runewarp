//! Participant identity keys for Clients and Servers.
//!
//! An identity is one ECDSA P-256 private key stored as unencrypted PKCS#8 PEM. The identity
//! fingerprint is SHA-256 over the key's DER SubjectPublicKeyInfo (SPKI), always encoded with the
//! uncompressed point. Certificates are built in memory from the key whenever a TLS peer needs one;
//! they are containers for the public key and carry no other meaning.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PKCS_ED25519, PublicKeyData,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::parse_x509_certificate;

use crate::cert_file_ops;

/// Default identity key filename inside each role's XDG data directory.
pub const IDENTITY_KEY_FILENAME: &str = "identity.key";

const IDENTITY_KEY_MODE: u32 = 0o600;
const PKCS8_PEM_LABEL: &str = "PRIVATE KEY";
/// RFC 5280 GeneralizedTime value for a certificate with no well-defined expiration.
const NO_EXPIRY_YEAR: i32 = 9999;
const UNCOMPRESSED_P256_POINT_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// SHA-256 fingerprint of a participant's DER SubjectPublicKeyInfo.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientIdentity([u8; 32]);

impl ClientIdentity {
    pub fn from_subject_public_key_info(subject_public_key_info: &[u8]) -> Self {
        Self(spki_fingerprint(subject_public_key_info))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lowercase_hex(formatter, &self.0)
    }
}

impl FromStr for ClientIdentity {
    type Err = ParseClientIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_lowercase_hex_fingerprint(value)
            .map(Self)
            .map_err(|error| match error {
                HexFingerprintError::WrongLength => ParseClientIdentityError::WrongLength,
                HexFingerprintError::InvalidHex => ParseClientIdentityError::InvalidHex,
            })
    }
}

#[derive(Debug)]
pub enum ParseClientIdentityError {
    WrongLength,
    InvalidHex,
}

impl fmt::Display for ParseClientIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => write!(
                formatter,
                "client identity must be 64 lowercase hex characters"
            ),
            Self::InvalidHex => write!(
                formatter,
                "client identity must use lowercase hex without separators"
            ),
        }
    }
}

impl std::error::Error for ParseClientIdentityError {}

/// Role whose in-memory certificate is built from an identity key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRole {
    Client,
    Server,
}

impl IdentityRole {
    fn subject_alt_name(self) -> &'static str {
        match self {
            Self::Client => "runewarp-client",
            Self::Server => "runewarp-server",
        }
    }
}

/// A loaded or generated ECDSA P-256 identity key.
pub struct IdentityKey {
    key_pair: KeyPair,
    subject_public_key_info: Vec<u8>,
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityKey")
            .field("fingerprint", &self.client_identity().to_string())
            .finish_non_exhaustive()
    }
}

/// TLS certificate chain and private key derived from one identity key.
pub struct IdentityTlsCredentials {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl IdentityKey {
    /// Generate a new P-256 identity key.
    pub fn generate() -> Result<Self, IdentityKeyError> {
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(IdentityKeyError::Generate)?;
        Ok(Self::from_key_pair(key_pair))
    }

    /// Parse an identity key from its PEM file contents.
    pub fn from_pem(pem: &str) -> Result<Self, IdentityKeyError> {
        let labels = pem_begin_labels(pem);
        let label = match labels.as_slice() {
            [] => return Err(IdentityKeyError::NotPem),
            [label] => *label,
            _ => return Err(IdentityKeyError::MultiplePemBlocks),
        };
        match label {
            PKCS8_PEM_LABEL => {}
            "EC PRIVATE KEY" => return Err(IdentityKeyError::Sec1),
            "ENCRYPTED PRIVATE KEY" => return Err(IdentityKeyError::Encrypted),
            other => return Err(IdentityKeyError::UnsupportedPemLabel(other.to_owned())),
        }
        let pkcs8 = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| IdentityKeyError::InvalidPkcs8)?;
        // Classify by the PKCS#8 algorithm identifier first, so keys the signer backend cannot
        // load (such as P-521) still get the algorithm error rather than a format error.
        check_pkcs8_algorithm(pkcs8.secret_pkcs8_der())?;
        let key_pair = KeyPair::try_from(&PrivateKeyDer::Pkcs8(pkcs8))
            .map_err(|_| IdentityKeyError::InvalidPkcs8)?;
        if key_pair.algorithm() == &PKCS_ECDSA_P256_SHA256 {
            Ok(Self::from_key_pair(key_pair))
        } else if key_pair.algorithm() == &PKCS_ED25519 {
            Err(IdentityKeyError::Ed25519)
        } else {
            Err(IdentityKeyError::UnsupportedAlgorithm)
        }
    }

    /// Read and validate the identity key at `path`.
    pub fn read(path: &Path) -> Result<Self, IdentityKeyFileError> {
        let pem = fs::read_to_string(path).map_err(|source| IdentityKeyFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_pem(&pem).map_err(|source| IdentityKeyFileError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// PKCS#8 PEM encoding of the private key.
    pub fn to_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Canonical DER SubjectPublicKeyInfo with the uncompressed point.
    pub fn subject_public_key_info(&self) -> &[u8] {
        &self.subject_public_key_info
    }

    pub fn client_identity(&self) -> ClientIdentity {
        ClientIdentity::from_subject_public_key_info(&self.subject_public_key_info)
    }

    pub fn server_identity(&self) -> crate::ServerIdentity {
        crate::ServerIdentity::from_subject_public_key_info(&self.subject_public_key_info)
    }

    /// Build an in-memory self-signed certificate for `role` and pair it with the private key.
    ///
    /// The certificate's serial is unspecified and its signature and bytes change on every build.
    /// Only its SPKI is meaningful.
    pub fn tls_credentials(
        &self,
        role: IdentityRole,
    ) -> Result<IdentityTlsCredentials, IdentityKeyError> {
        let certificate = self.certificate(role)?;
        Ok(IdentityTlsCredentials {
            cert_chain: vec![certificate],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                self.key_pair.serialize_der(),
            )),
        })
    }

    fn certificate(&self, role: IdentityRole) -> Result<CertificateDer<'static>, IdentityKeyError> {
        Ok(self.rcgen_certificate(role)?.der().clone())
    }

    fn rcgen_certificate(
        &self,
        role: IdentityRole,
    ) -> Result<rcgen::Certificate, IdentityKeyError> {
        let mut params = CertificateParams::new(vec![role.subject_alt_name().to_owned()])
            .map_err(IdentityKeyError::Certificate)?;
        params.not_before = OffsetDateTime::UNIX_EPOCH;
        params.not_after = no_expiry_time();
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params
            .self_signed(&self.key_pair)
            .map_err(IdentityKeyError::Certificate)
    }

    fn from_key_pair(key_pair: KeyPair) -> Self {
        let subject_public_key_info = key_pair.subject_public_key_info();
        Self {
            key_pair,
            subject_public_key_info,
        }
    }
}

/// Accept only an `id-ecPublicKey` PKCS#8 key on the P-256 curve.
fn check_pkcs8_algorithm(der: &[u8]) -> Result<(), IdentityKeyError> {
    use x509_parser::asn1_rs::{FromDer, Sequence};
    use x509_parser::oid_registry::OID_SIG_ED25519;
    use x509_parser::x509::AlgorithmIdentifier;

    let (_, private_key_info) =
        Sequence::from_der(der).map_err(|_| IdentityKeyError::InvalidPkcs8)?;
    let (rest, _version) = u32::from_der(private_key_info.content.as_ref())
        .map_err(|_| IdentityKeyError::InvalidPkcs8)?;
    let (_, algorithm) =
        AlgorithmIdentifier::from_der(rest).map_err(|_| IdentityKeyError::InvalidPkcs8)?;
    if algorithm.algorithm == OID_SIG_ED25519 {
        return Err(IdentityKeyError::Ed25519);
    }
    let is_p256 = algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256);
    if is_p256 {
        Ok(())
    } else {
        Err(IdentityKeyError::UnsupportedAlgorithm)
    }
}

fn no_expiry_time() -> OffsetDateTime {
    time::Date::from_calendar_date(NO_EXPIRY_YEAR, time::Month::December, 31)
        .and_then(|date| date.with_hms(23, 59, 59))
        .map(|date_time| date_time.assume_utc())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Why an identity key is rejected.
#[derive(Debug)]
pub enum IdentityKeyError {
    NotPem,
    MultiplePemBlocks,
    Sec1,
    Encrypted,
    UnsupportedPemLabel(String),
    InvalidPkcs8,
    Ed25519,
    UnsupportedAlgorithm,
    Generate(rcgen::Error),
    Certificate(rcgen::Error),
}

impl fmt::Display for IdentityKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPem => formatter.write_str(
                "identity key must be an unencrypted PKCS#8 PEM file with one `PRIVATE KEY` block",
            ),
            Self::MultiplePemBlocks => formatter
                .write_str("identity key file must contain exactly one PEM block (`PRIVATE KEY`)"),
            Self::Sec1 => formatter.write_str(
                "identity key is SEC1 (`EC PRIVATE KEY`); convert it to PKCS#8 without changing \
                 the key with `openssl pkcs8 -topk8 -nocrypt -in <old> -out <new>`",
            ),
            Self::Encrypted => {
                formatter.write_str("identity key is encrypted; passphrases are not supported")
            }
            Self::UnsupportedPemLabel(label) => write!(
                formatter,
                "identity key has unsupported PEM block `{label}`; expected unencrypted PKCS#8 \
                 `PRIVATE KEY`"
            ),
            Self::InvalidPkcs8 => formatter.write_str("identity key is not a valid PKCS#8 key"),
            Self::Ed25519 => formatter.write_str(
                "identity key is Ed25519, which is no longer supported; replace it with an ECDSA \
                 P-256 key (for a Client, run `runewarp client identity rotate --key <path>`)",
            ),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("identity key must be ECDSA P-256 (prime256v1)")
            }
            Self::Generate(_) => formatter.write_str("failed to generate an identity key"),
            Self::Certificate(_) => {
                formatter.write_str("failed to build an identity certificate from the key")
            }
        }
    }
}

impl std::error::Error for IdentityKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Generate(source) | Self::Certificate(source) => Some(source),
            _ => None,
        }
    }
}

/// Failure reading, writing or validating an identity key file.
#[derive(Debug)]
pub enum IdentityKeyFileError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Write {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: IdentityKeyError,
    },
    /// `init` found a file it will not overwrite.
    InvalidExisting {
        path: PathBuf,
        source: Box<IdentityKeyFileError>,
    },
    /// `rotate` found no key to replace.
    Missing {
        path: PathBuf,
    },
    Generate(IdentityKeyError),
}

impl fmt::Display for IdentityKeyFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::Write { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            Self::Parse { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::InvalidExisting { path, source } => write!(
                formatter,
                "refusing to overwrite existing identity key {}: {source}. Repair or remove it, \
                 or run `runewarp client identity rotate` to replace it",
                path.display()
            ),
            Self::Missing { path } => write!(
                formatter,
                "no identity key at {}; run `runewarp client identity init` first",
                path.display()
            ),
            Self::Generate(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for IdentityKeyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::InvalidExisting { source, .. } => Some(source.as_ref()),
            Self::Generate(source) => Some(source),
            Self::Missing { .. } => None,
        }
    }
}

/// Outcome of [`init_identity_key`].
#[derive(Debug)]
pub enum IdentityKeyInit {
    Created(ClientIdentity),
    Existing(ClientIdentity),
}

/// Create a new identity key at `path` with mode 0600, or keep an existing valid key.
///
/// An existing file that is unreadable or not a valid identity key is never overwritten.
pub fn init_identity_key(path: &Path) -> Result<IdentityKeyInit, IdentityKeyFileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return IdentityKey::read(path)
                .map(|key| IdentityKeyInit::Existing(key.client_identity()))
                .map_err(|source| IdentityKeyFileError::InvalidExisting {
                    path: path.to_path_buf(),
                    source: Box::new(source),
                });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(IdentityKeyFileError::InvalidExisting {
                path: path.to_path_buf(),
                source: Box::new(IdentityKeyFileError::Read {
                    path: path.to_path_buf(),
                    source,
                }),
            });
        }
    }

    let key = IdentityKey::generate().map_err(IdentityKeyFileError::Generate)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        cert_file_ops::create_directory(parent, 0o700).map_err(|source| {
            IdentityKeyFileError::Write {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    }
    cert_file_ops::write_new_file_with_mode(path, key.to_pem().as_bytes(), IDENTITY_KEY_MODE)
        .map_err(|source| IdentityKeyFileError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(IdentityKeyInit::Created(key.client_identity()))
}

/// Atomically replace the identity key at `path` with a new P-256 key.
///
/// The existing file must exist but need not be a valid key, so unsupported keys can be replaced.
pub fn rotate_identity_key(path: &Path) -> Result<ClientIdentity, IdentityKeyFileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(IdentityKeyFileError::Missing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(IdentityKeyFileError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let key = IdentityKey::generate().map_err(IdentityKeyFileError::Generate)?;
    cert_file_ops::replace_file_atomically_with_mode(
        path,
        key.to_pem().as_bytes(),
        IDENTITY_KEY_MODE,
    )
    .map_err(|source| IdentityKeyFileError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(key.client_identity())
}

/// Whether the key file grants read access to its group or others.
#[cfg(unix)]
pub fn identity_key_is_group_or_world_readable(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    Ok(fs::metadata(path)?.permissions().mode() & 0o044 != 0)
}

/// Whether the key file grants read access to its group or others.
#[cfg(not(unix))]
pub fn identity_key_is_group_or_world_readable(_path: &Path) -> io::Result<bool> {
    Ok(false)
}

/// Test fixture: a generated key with its in-memory Client certificate, both as PEM.
#[cfg(test)]
pub(crate) struct GeneratedClientIdentity {
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub client_identity: ClientIdentity,
}

#[cfg(test)]
pub(crate) fn generate_client_identity() -> Result<GeneratedClientIdentity, IdentityKeyError> {
    let key = IdentityKey::generate()?;
    Ok(GeneratedClientIdentity {
        private_key_pem: key.to_pem(),
        certificate_pem: key.rcgen_certificate(IdentityRole::Client)?.pem(),
        client_identity: key.client_identity(),
    })
}

/// Log one warning when the key at `path` is readable by its group or others.
///
/// Weak permissions never stop startup: Kubernetes Secret mounts default to 0644.
pub(crate) fn warn_if_identity_key_is_shared(role: &str, path: &Path) {
    if identity_key_is_group_or_world_readable(path).unwrap_or(false) {
        crate::runtime_log::warning(
            role,
            &format!(
                "identity key {} is readable by group or others; restrict it with `chmod 600`",
                path.display()
            ),
        );
    }
}

/// Why a peer certificate is not an acceptable identity container.
#[derive(Debug, Eq, PartialEq)]
pub enum PeerIdentityError {
    ParseCertificate,
    UnsupportedAlgorithm,
    NonCanonicalPoint,
}

impl fmt::Display for PeerIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseCertificate => formatter.write_str("certificate is not valid X.509 DER"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("identity public key must be ECDSA P-256")
            }
            Self::NonCanonicalPoint => formatter
                .write_str("identity public key must use the uncompressed P-256 point encoding"),
        }
    }
}

impl std::error::Error for PeerIdentityError {}

/// Pinned identity of a peer certificate, enforcing the P-256 uncompressed-SPKI policy.
///
/// Only the SPKI is read. Issuer, validity, extensions and signature carry no meaning.
pub fn client_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<ClientIdentity, PeerIdentityError> {
    let (remainder, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| PeerIdentityError::ParseCertificate)?;
    if !remainder.is_empty() {
        return Err(PeerIdentityError::ParseCertificate);
    }
    let spki = &certificate.tbs_certificate.subject_pki;
    let is_p256 = spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256);
    if !is_p256 {
        return Err(PeerIdentityError::UnsupportedAlgorithm);
    }
    let point = spki.subject_public_key.data.as_ref();
    if point.len() != UNCOMPRESSED_P256_POINT_LEN || point[0] != UNCOMPRESSED_POINT_TAG {
        return Err(PeerIdentityError::NonCanonicalPoint);
    }
    Ok(ClientIdentity::from_subject_public_key_info(spki.raw))
}

pub(crate) fn spki_fingerprint(subject_public_key_info: &[u8]) -> [u8; 32] {
    let fingerprint = Sha256::digest(subject_public_key_info);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&fingerprint);
    bytes
}

pub(crate) fn write_lowercase_hex(
    formatter: &mut fmt::Formatter<'_>,
    bytes: &[u8; 32],
) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

pub(crate) enum HexFingerprintError {
    WrongLength,
    InvalidHex,
}

pub(crate) fn parse_lowercase_hex_fingerprint(
    value: &str,
) -> Result<[u8; 32], HexFingerprintError> {
    if value.len() != 64 {
        return Err(HexFingerprintError::WrongLength);
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| HexFingerprintError::InvalidHex)?;
        if pair
            .chars()
            .any(|character| !character.is_ascii_hexdigit() || character.is_ascii_uppercase())
        {
            return Err(HexFingerprintError::InvalidHex);
        }
        bytes[index] = u8::from_str_radix(pair, 16).map_err(|_| HexFingerprintError::InvalidHex)?;
    }
    Ok(bytes)
}

/// Labels of every `-----BEGIN <label>-----` line in `pem`.
fn pem_begin_labels(pem: &str) -> Vec<&str> {
    pem.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("-----BEGIN ")
                .and_then(|rest| rest.strip_suffix("-----"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};

    use super::{
        ClientIdentity, IdentityKey, IdentityKeyError, IdentityRole, PeerIdentityError,
        client_identity_from_certificate_der,
    };

    #[test]
    fn parses_lowercase_hex_client_identities() {
        let identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse::<ClientIdentity>()
            .unwrap();

        assert_eq!(
            identity.to_string(),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn rejects_non_lowercase_hex_client_identities() {
        assert!(
            "00112233445566778899AAbbccddeeff00112233445566778899aabbccddeeff"
                .parse::<ClientIdentity>()
                .is_err()
        );
        assert!(
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff0011223344556677"
                .parse::<ClientIdentity>()
                .is_err()
        );
    }

    #[test]
    fn generated_keys_round_trip_through_pem_with_the_same_identity() {
        let key = IdentityKey::generate().unwrap();
        let reloaded = IdentityKey::from_pem(&key.to_pem()).unwrap();

        assert_eq!(reloaded.client_identity(), key.client_identity());
        assert_eq!(key.subject_public_key_info()[..].len(), 91);
    }

    #[test]
    fn non_p256_pkcs8_keys_are_rejected_with_specific_errors() {
        let ed25519 = KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .serialize_pem();
        let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .unwrap()
            .serialize_pem();

        assert!(matches!(
            IdentityKey::from_pem(&ed25519),
            Err(IdentityKeyError::Ed25519)
        ));
        assert!(matches!(
            IdentityKey::from_pem(&p384),
            Err(IdentityKeyError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn in_memory_certificates_carry_the_key_identity() {
        let key = IdentityKey::generate().unwrap();
        for role in [IdentityRole::Client, IdentityRole::Server] {
            let credentials = key.tls_credentials(role).unwrap();
            let identity =
                client_identity_from_certificate_der(credentials.cert_chain[0].as_ref()).unwrap();
            assert_eq!(identity, key.client_identity());
        }
    }

    #[test]
    fn peer_certificates_with_other_algorithms_are_rejected() {
        for algorithm in [&PKCS_ED25519, &PKCS_ECDSA_P384_SHA384] {
            let key = KeyPair::generate_for(algorithm).unwrap();
            let certificate = rcgen::CertificateParams::new(vec!["peer".to_owned()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            assert_eq!(
                client_identity_from_certificate_der(certificate.der()),
                Err(PeerIdentityError::UnsupportedAlgorithm)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_keys_are_detected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.key");
        let super::IdentityKeyInit::Created(_) = super::init_identity_key(&path).unwrap() else {
            panic!("a new key must be created");
        };
        assert!(!super::identity_key_is_group_or_world_readable(&path).unwrap());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::identity_key_is_group_or_world_readable(&path).unwrap());
        IdentityKey::read(&path).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn client_identities_round_trip_through_lowercase_hex(
            bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let encoded = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();

            let parsed = encoded.parse::<ClientIdentity>().unwrap();

            prop_assert_eq!(parsed.to_string(), encoded);
        }
    }
}
