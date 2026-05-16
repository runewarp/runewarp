use std::io::Cursor;

use runewarp::{CLIENT_CERT_LIFETIME_DAYS, generate_client_identity};

#[test]
fn generated_client_certificate_uses_the_phase_two_default_lifetime() {
    let generated = generate_client_identity().unwrap();
    let certificate_der = rustls_pemfile::certs(&mut Cursor::new(generated.certificate_pem))
        .next()
        .unwrap()
        .unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der.as_ref()).unwrap();
    let lifetime = certificate.validity().not_after.to_datetime()
        - certificate.validity().not_before.to_datetime();

    assert_eq!(lifetime.whole_days(), CLIENT_CERT_LIFETIME_DAYS as i64);
}
