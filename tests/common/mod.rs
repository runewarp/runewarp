use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use runewarp::{
    ClientIdentity, SERVER_IDENTITY_CERT_FILENAME, SERVER_IDENTITY_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, ServerIdentity,
};
use time::{Duration, OffsetDateTime};

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

/// Builds a deliberately expired self-signed Client identity certificate for the same key.
///
/// Validity is backdated so `not_after` is already in the past. Callers that claim to exercise
/// expired material should assert that before relying on the fixture.
#[allow(dead_code)]
pub fn expired_client_identity_material() -> (ClientIdentity, String, String) {
    let signing_key = KeyPair::generate().unwrap();
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
