use std::fs;
use std::path::Path;

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use runewarp::{
    ClientIdentity, SERVER_IDENTITY_CERT_FILENAME, SERVER_IDENTITY_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, ServerIdentity,
};
use time::{Duration, OffsetDateTime};

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
