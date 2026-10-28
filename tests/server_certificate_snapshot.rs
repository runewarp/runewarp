use rcgen::KeyPair;
use runewarp::server_certificate::{CertificateSnapshot, CertificateValidation};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
mod certificate_support;
use certificate_support::material;

#[test]
fn immutable_snapshot_validates_identity_trust_time_and_lifetime() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
    let (good, roots) = material("edge.example.test", 1_789_900_000, 1_790_100_000);
    let policy = CertificateValidation::new(
        "edge.example.test".try_into().unwrap(),
        Arc::new(roots),
        Duration::from_secs(3600),
        Duration::from_secs(60),
    )
    .unwrap();
    let snapshot = CertificateSnapshot::validate(&good, &policy, now).unwrap();
    assert_eq!(
        snapshot.expires_at(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_100_000)
    );
    assert_eq!(snapshot.fingerprint().len(), 64);
    assert!(!format!("{snapshot:?}").contains("PRIVATE KEY"));
    for (hostname, start, end) in [
        ("wrong.example.test", 1_789_900_000, 1_790_100_000),
        ("edge.example.test", 1_790_000_001, 1_790_100_000),
        ("edge.example.test", 1_789_900_000, 1_789_999_999),
        ("edge.example.test", 1_789_900_000, 1_790_000_100),
    ] {
        let (pem, roots) = material(hostname, start, end);
        let policy = CertificateValidation::new(
            "edge.example.test".try_into().unwrap(),
            Arc::new(roots),
            Duration::from_secs(3600),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(CertificateSnapshot::validate(&pem, &policy, now).is_err());
    }
    assert!(CertificateSnapshot::validate(b"malformed", &policy, now).is_err());
    let (untrusted, _) = material("edge.example.test", 1_789_900_000, 1_790_100_000);
    assert!(CertificateSnapshot::validate(&untrusted, &policy, now).is_err());
    let key = KeyPair::generate().unwrap();
    let certificates = std::str::from_utf8(&good)
        .unwrap()
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .unwrap();
    let mismatch = format!(
        "{}-----BEGIN CERTIFICATE-----{}",
        key.serialize_pem(),
        certificates
    );
    assert!(CertificateSnapshot::validate(mismatch.as_bytes(), &policy, now).is_err());
}
