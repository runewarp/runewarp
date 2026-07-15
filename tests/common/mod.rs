use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use runewarp::{
    CLIENT_CERT_LIFETIME_DAYS, ClientIdentity, ClientManagedInput, GeneratedClientIdentity,
    ManagedSessionLimits, RoleAdapter, SERVER_IDENTITY_CERT_FILENAME, SERVER_IDENTITY_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, ServerIdentity, ServerManagedInput,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use x509_parser::oid_registry::OID_SIG_ED25519;

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

/// PEM material for a private Control CA, server leaf, and client identity leaf.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ControlMtlsMaterial {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Paths for Control mTLS material written under `directory`.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ControlMtlsPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

/// Generate a Control CA, a `localhost` server leaf, and a client identity leaf.
#[allow(dead_code)]
pub fn generate_control_mtls_material(client_common_name: &str) -> ControlMtlsMaterial {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);

    let ca_key = KeyPair::generate().unwrap();
    let ca_key_pem = ca_key.serialize_pem();
    let ca_params = control_ca_params(not_before);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_params = control_server_leaf_params("localhost", not_before);
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let client_params = control_client_leaf_params(client_common_name, not_before);
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    ControlMtlsMaterial {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

/// Issue a new client identity leaf signed by an existing Control CA.
#[allow(dead_code)]
pub fn generate_control_client_identity(
    ca_material: &ControlMtlsMaterial,
    client_common_name: &str,
) -> (String, String) {
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    let ca_key = KeyPair::from_pem(&ca_material.ca_key_pem).unwrap();
    let ca_params = control_ca_params(not_before);
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let client_key = KeyPair::generate().unwrap();
    let client_params = control_client_leaf_params(client_common_name, not_before);
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    (client_cert.pem(), client_key.serialize_pem())
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
        client_cert: directory.join("client.crt"),
        client_key: directory.join("client.key"),
    };
    fs::write(&paths.ca_cert, &material.ca_cert_pem).unwrap();
    fs::write(&paths.server_cert, &material.server_cert_pem).unwrap();
    fs::write(&paths.server_key, &material.server_key_pem).unwrap();
    fs::write(&paths.client_cert, &material.client_cert_pem).unwrap();
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

#[allow(dead_code)]
fn control_client_leaf_params(common_name: &str, not_before: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::new(vec![common_name.to_owned()]).unwrap();
    params.not_before = not_before;
    params.not_after = not_before + Duration::days(365);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_owned());
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
}

/// Asserts the certificate profile used for newly generated Client identities.
///
/// Covers Ed25519, self-signed subject/issuer, digitalSignature, clientAuth, and the 100-year
/// validity window. Callers that also need key/fingerprint agreement assert that separately.
#[allow(dead_code)]
pub fn assert_generated_client_identity_certificate_profile(certificate_der: &[u8]) {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate_der)
        .expect("parse generated Client identity certificate");

    assert_eq!(
        parsed.signature_algorithm.algorithm, OID_SIG_ED25519,
        "generated Client identity certificates must be Ed25519"
    );
    assert_eq!(
        parsed.tbs_certificate.subject_pki.algorithm.algorithm, OID_SIG_ED25519,
        "generated Client identity public keys must be Ed25519"
    );
    assert_eq!(
        parsed.tbs_certificate.subject, parsed.tbs_certificate.issuer,
        "generated Client identity certificates must remain self-signed"
    );

    let key_usage = parsed
        .key_usage()
        .expect("parse key usage")
        .expect("generated Client identity certificates declare key usage");
    assert!(
        key_usage.value.digital_signature(),
        "generated Client identity certificates declare digitalSignature"
    );

    let extended_key_usage = parsed
        .extended_key_usage()
        .expect("parse extended key usage")
        .expect("generated Client identity certificates declare extended key usage");
    assert!(
        extended_key_usage.value.client_auth,
        "generated Client identity certificates declare clientAuth"
    );

    let lifetime =
        parsed.validity().not_after.to_datetime() - parsed.validity().not_before.to_datetime();
    assert_eq!(lifetime.whole_days(), CLIENT_CERT_LIFETIME_DAYS as i64);
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
    certificate_params.not_after = not_before + Duration::days(CLIENT_CERT_LIFETIME_DAYS as i64);
    let certificate = certificate_params.self_signed(&signing_key).unwrap();
    let client_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    GeneratedClientIdentity {
        private_key_pem: signing_key.serialize_pem(),
        certificate_pem: certificate.pem(),
        client_identity,
    }
}

/// Write freshly generated Server identity material for tests.
#[allow(dead_code)]
pub fn write_server_identity_material(directory: &Path) -> ServerIdentity {
    fs::create_dir_all(directory).unwrap();
    let signing_key = KeyPair::generate().unwrap();
    let identity =
        ServerIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());
    let certificate = CertificateParams::new(vec!["runewarp-server-identity".to_owned()])
        .unwrap()
        .self_signed(&signing_key)
        .unwrap();
    fs::write(
        directory.join(SERVER_IDENTITY_KEY_FILENAME),
        signing_key.serialize_pem(),
    )
    .unwrap();
    fs::write(
        directory.join(SERVER_IDENTITY_CERT_FILENAME),
        certificate.pem(),
    )
    .unwrap();
    fs::write(
        directory.join(SERVER_IDENTITY_FILENAME),
        identity.to_string(),
    )
    .unwrap();
    identity
}

/// Write Control client leaf PEM as Server identity material under `directory`.
///
/// The Control fixture verifies peer certificates against the same CA, so managed
/// Server session tests reuse that leaf as `server.crt` / `server.key`.
#[allow(dead_code)]
pub fn write_control_client_as_server_identity(
    directory: &Path,
    material: &ControlMtlsMaterial,
) -> ServerIdentity {
    fs::create_dir_all(directory).unwrap();
    let key = KeyPair::from_pem(&material.client_key_pem).unwrap();
    let identity = ServerIdentity::from_subject_public_key_info(&key.subject_public_key_info());
    fs::write(
        directory.join(SERVER_IDENTITY_KEY_FILENAME),
        &material.client_key_pem,
    )
    .unwrap();
    fs::write(
        directory.join(SERVER_IDENTITY_CERT_FILENAME),
        &material.client_cert_pem,
    )
    .unwrap();
    fs::write(
        directory.join(SERVER_IDENTITY_FILENAME),
        identity.to_string(),
    )
    .unwrap();
    identity
}
