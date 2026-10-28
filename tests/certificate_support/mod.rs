use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::RootCertStore;
pub fn material(hostname: &str, start: i64, end: i64) -> (Vec<u8>, RootCertStore) {
    let key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = ca.self_signed(&key).unwrap();
    let issuer = Issuer::new(ca, key);
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec![hostname.to_owned()]).unwrap();
    leaf.not_before = time::OffsetDateTime::from_unix_timestamp(start).unwrap();
    leaf.not_after = time::OffsetDateTime::from_unix_timestamp(end).unwrap();
    let leaf = leaf.signed_by(&key, &issuer).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    (
        format!("{}{}{}", key.serialize_pem(), leaf.pem(), cert.pem()).into_bytes(),
        roots,
    )
}
