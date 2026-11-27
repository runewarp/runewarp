use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use runewarp::{
    ClientIdentity, ClientManagedInput, IdentityKey, IdentityRole, ManagedSessionLimits,
    RoleAdapter, ServerIdentity, ServerManagedInput,
};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use x509_parser::oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256};

/// Wire-contract ALPN for Control fixtures (HTTP/2 only).
#[allow(dead_code)]
pub const CONTROL_ALPN_H2: &[u8] = b"h2";

/// Exact Client SSE downlink path from the Managed-session wire contract.
#[allow(dead_code)]
pub const CLIENT_EVENTS_PATH: &str = "/v1/client/events";

/// Exact Server SSE downlink path from the Managed-session wire contract.
#[allow(dead_code)]
pub const SERVER_EVENTS_PATH: &str = "/v1/server/events";

/// Exact Client applied-state path from the Managed-session wire contract.
#[allow(dead_code)]
pub const CLIENT_STATE_PATH: &str = "/v1/client/state";

/// Exact Server applied-state path from the Managed-session wire contract.
#[allow(dead_code)]
pub const SERVER_STATE_PATH: &str = "/v1/server/state";

/// Documented Managed-session silence window (bytes inactivity).
#[allow(dead_code)]
pub const MANAGED_SESSION_SILENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Accepting Client role adapter for Managed-session protocol tests.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct AcceptingClientAdapter;

impl RoleAdapter for AcceptingClientAdapter {
    type Input = ClientManagedInput;

    fn parse_input(
        input: Value,
        limits: &ManagedSessionLimits,
    ) -> Result<Self::Input, runewarp::InputError> {
        runewarp::parse_client_input(input, limits)
    }

    async fn apply(&mut self, _input: Self::Input) -> Result<(), runewarp::ApplyError> {
        Ok(())
    }
}

/// Accepting Server role adapter for Managed-session protocol tests.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct AcceptingServerAdapter;

impl RoleAdapter for AcceptingServerAdapter {
    type Input = ServerManagedInput;

    fn parse_input(
        input: Value,
        limits: &ManagedSessionLimits,
    ) -> Result<Self::Input, runewarp::InputError> {
        runewarp::parse_server_input(input, limits)
    }

    async fn apply(&mut self, _input: Self::Input) -> Result<(), runewarp::ApplyError> {
        Ok(())
    }
}

/// PEM material for a private Control CA, Control server leaf, and one participant identity key.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ControlMtlsMaterial {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    /// P-256 PKCS#8 identity key Control admits by pinned SPKI fingerprint.
    pub client_key_pem: String,
}

/// Paths for Control mTLS material written under `directory`.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ControlMtlsPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_key: PathBuf,
}

/// Generate a Control CA, a `localhost` server leaf, and a participant identity key.
#[allow(dead_code)]
pub fn generate_control_mtls_material(_client_common_name: &str) -> ControlMtlsMaterial {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);

    let ca_key = KeyPair::generate().unwrap();
    let ca_key_pem = ca_key.serialize_pem();
    let ca_params = control_ca_params(not_before);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_params = control_server_leaf_params("localhost", not_before);
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    ControlMtlsMaterial {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_key_pem: IdentityKey::generate().unwrap().to_pem(),
    }
}

/// Generate a fresh participant identity key PEM.
#[allow(dead_code)]
pub fn generate_control_client_identity() -> String {
    IdentityKey::generate().unwrap().to_pem()
}

/// SHA-256 SPKI fingerprint of an identity key PEM, as Control pins it.
#[allow(dead_code)]
pub fn identity_key_fingerprint(key_pem: &str) -> [u8; 32] {
    *IdentityKey::from_pem(key_pem)
        .unwrap()
        .client_identity()
        .as_bytes()
}

/// Control-style admission: a peer is admitted only when its leaf SPKI fingerprint is pinned.
///
/// Like real Control, no CA chain, validity or extension is checked.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct PinnedSpkiAdmission {
    pinned: Arc<Mutex<HashSet<[u8; 32]>>>,
}

#[allow(dead_code)]
impl PinnedSpkiAdmission {
    pub fn for_keys(key_pems: &[&str]) -> Self {
        let admission = Self::default();
        for key_pem in key_pems {
            admission.pin_key(key_pem);
        }
        admission
    }

    pub fn pin_key(&self, key_pem: &str) {
        self.pinned
            .lock()
            .unwrap()
            .insert(identity_key_fingerprint(key_pem));
    }

    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::new(PinnedSpkiVerifier {
            admission: self.clone(),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct PinnedSpkiVerifier {
    admission: PinnedSpkiAdmission,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedSpkiVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let identity = runewarp::client_identity_from_certificate_der(end_entity.as_ref())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if self
            .admission
            .pinned
            .lock()
            .unwrap()
            .contains(identity.as_bytes())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

#[allow(dead_code)]
fn control_ca_params(not_before: OffsetDateTime) -> CertificateParams {
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.not_before = not_before;
    ca_params.not_after = not_before + Duration::days(3650);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Runewarp Control Test CA");
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    ca_params
}

/// Write Control CA, server, and client PEM files under `directory`.
#[allow(dead_code)]
pub fn write_control_ca_and_certs(
    directory: &Path,
    material: &ControlMtlsMaterial,
) -> ControlMtlsPaths {
    fs::create_dir_all(directory).unwrap();
    let paths = ControlMtlsPaths {
        ca_cert: directory.join("ca.crt"),
        server_cert: directory.join("server.crt"),
        server_key: directory.join("server.key"),
        client_key: directory.join("client.key"),
    };
    fs::write(&paths.ca_cert, &material.ca_cert_pem).unwrap();
    fs::write(&paths.server_cert, &material.server_cert_pem).unwrap();
    fs::write(&paths.server_key, &material.server_key_pem).unwrap();
    fs::write(&paths.client_key, &material.client_key_pem).unwrap();
    paths
}

#[allow(dead_code)]
fn control_server_leaf_params(hostname: &str, not_before: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::new(vec![hostname.to_owned()]).unwrap();
    params.not_before = not_before;
    params.not_after = not_before + Duration::days(365);
    params
        .distinguished_name
        .push(DnType::CommonName, hostname.to_owned());
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
}

/// Test fixture: a generated identity key with its in-memory Client certificate as PEM.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct GeneratedClientIdentity {
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub client_identity: ClientIdentity,
}

/// Generate an identity key and the in-memory certificate Core builds from it.
#[allow(dead_code)]
pub fn generate_client_identity() -> Result<GeneratedClientIdentity, runewarp::IdentityKeyError> {
    let key = IdentityKey::generate()?;
    let certificate = key
        .tls_credentials(IdentityRole::Client)?
        .cert_chain
        .remove(0);
    Ok(GeneratedClientIdentity {
        private_key_pem: key.to_pem(),
        certificate_pem: certificate_pem(certificate.as_ref()),
        client_identity: key.client_identity(),
    })
}

/// PEM-encode one DER certificate.
#[allow(dead_code)]
pub fn certificate_pem(der: &[u8]) -> String {
    pem_encode("CERTIFICATE", der)
}

#[allow(dead_code)]
fn pem_encode(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in der.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let value = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                encoded.push(ALPHABET[(value >> shift & 0x3f) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Asserts the in-memory certificate profile Core builds from an identity key.
///
/// Covers ECDSA P-256 with SHA-256, self-signed subject/issuer, digitalSignature, clientAuth and
/// the fixed 1970-01-01 to 9999-12-31 validity. Callers that also need key/fingerprint agreement
/// assert that separately.
#[allow(dead_code)]
pub fn assert_generated_client_identity_certificate_profile(certificate_der: &[u8]) {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate_der)
        .expect("parse generated Client identity certificate");

    assert_eq!(
        parsed.signature_algorithm.algorithm, OID_SIG_ECDSA_WITH_SHA256,
        "identity certificates must be signed with ECDSA SHA-256"
    );
    assert_eq!(
        parsed.tbs_certificate.subject_pki.algorithm.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY,
        "identity public keys must be EC"
    );
    assert_eq!(
        parsed.tbs_certificate.subject, parsed.tbs_certificate.issuer,
        "identity certificates must remain self-signed"
    );

    let key_usage = parsed
        .key_usage()
        .expect("parse key usage")
        .expect("identity certificates declare key usage");
    assert!(
        key_usage.value.digital_signature(),
        "identity certificates declare digitalSignature"
    );

    let extended_key_usage = parsed
        .extended_key_usage()
        .expect("parse extended key usage")
        .expect("identity certificates declare extended key usage");
    assert!(
        extended_key_usage.value.client_auth,
        "identity certificates declare clientAuth"
    );

    assert_eq!(parsed.validity().not_before.timestamp(), 0);
    assert_eq!(
        parsed.validity().not_after.to_datetime().year(),
        9999,
        "identity certificates use the RFC 5280 no-expiry notAfter"
    );
    assert_eq!(
        parsed.validity().not_after.to_datetime().unix_timestamp(),
        253_402_300_799,
        "identity certificates expire at 9999-12-31T23:59:59Z"
    );
}

/// Builds a deliberately expired self-signed Client identity certificate for the same key.
///
/// Validity is backdated so `not_after` is already in the past. Callers that claim to exercise
/// expired material should assert that before relying on the fixture.
#[allow(dead_code)]
pub fn expired_client_identity_material() -> (ClientIdentity, String, String) {
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let not_before = OffsetDateTime::now_utc() - Duration::days(120);
    let mut certificate_params =
        CertificateParams::new(vec!["runewarp-client".to_owned()]).unwrap();
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_before + Duration::days(90);
    let certificate = certificate_params.self_signed(&signing_key).unwrap();
    let client_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    (
        client_identity,
        certificate.pem(),
        signing_key.serialize_pem(),
    )
}

/// Builds a legacy ECDSA P-256 self-signed Client identity certificate without key usage or EKU.
///
/// This locks pin-only Tunnel authentication: purpose metadata is emitted for new identities but
/// is not required for exact-SPKI authorization of existing material.
#[allow(dead_code)]
pub fn legacy_p256_client_identity_without_eku() -> GeneratedClientIdentity {
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    let mut certificate_params =
        CertificateParams::new(vec!["runewarp-client".to_owned()]).unwrap();
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_before + Duration::days(36_500);
    let certificate = certificate_params.self_signed(&signing_key).unwrap();
    let client_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    GeneratedClientIdentity {
        private_key_pem: signing_key.serialize_pem(),
        certificate_pem: certificate.pem(),
        client_identity,
    }
}

/// Write a freshly generated Server identity key to `path` and return its identity.
#[allow(dead_code)]
pub fn write_server_identity_key(path: &Path) -> ServerIdentity {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let key = IdentityKey::generate().unwrap();
    fs::write(path, key.to_pem()).unwrap();
    key.server_identity()
}

/// Write the Control fixture's participant key as a Server identity key at `path`.
#[allow(dead_code)]
pub fn write_control_client_as_server_identity(
    path: &Path,
    material: &ControlMtlsMaterial,
) -> ServerIdentity {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, &material.client_key_pem).unwrap();
    IdentityKey::from_pem(&material.client_key_pem)
        .unwrap()
        .server_identity()
}
