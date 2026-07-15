use rcgen::{KeyPair, PublicKeyData};
use runewarp::{CLIENT_CERT_LIFETIME_DAYS, ClientIdentity, generate_client_identity};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

mod common;

use common::assert_generated_client_identity_certificate_profile;

#[test]
fn generated_client_certificate_uses_a_hundred_year_lifetime() {
    let generated = generate_client_identity().unwrap();
    let certificate_der =
        CertificateDer::from_pem_slice(generated.certificate_pem.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der.as_ref()).unwrap();
    let lifetime = certificate.validity().not_after.to_datetime()
        - certificate.validity().not_before.to_datetime();

    assert_eq!(CLIENT_CERT_LIFETIME_DAYS, 36_500);
    assert_eq!(lifetime.whole_days(), CLIENT_CERT_LIFETIME_DAYS as i64);
}

#[test]
fn generated_client_identity_uses_ed25519_with_client_auth_purpose() {
    let generated = generate_client_identity().unwrap();
    let signing_key = KeyPair::from_pem(&generated.private_key_pem).unwrap();
    let key_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());
    let certificate_der =
        CertificateDer::from_pem_slice(generated.certificate_pem.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der.as_ref()).unwrap();

    assert_generated_client_identity_certificate_profile(certificate_der.as_ref());
    assert_eq!(generated.client_identity, key_identity);
    assert_eq!(
        generated.client_identity,
        ClientIdentity::from_subject_public_key_info(certificate.tbs_certificate.subject_pki.raw)
    );
}
