use runewarp::{CLIENT_CERT_LIFETIME_DAYS, generate_client_identity};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

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
