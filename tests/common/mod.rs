use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use runewarp::ClientIdentity;
use time::{Duration, OffsetDateTime};

/// Builds a deliberately expired self-signed Client identity certificate for the same key.
///
/// Validity is backdated so `not_after` is already in the past. Callers that claim to exercise
/// expired material should assert that before relying on the fixture.
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
