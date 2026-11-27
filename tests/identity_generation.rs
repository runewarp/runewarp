//! Identity key contract: accepted key files, rejected key files and the in-memory certificate.

use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PublicKeyData};
use runewarp::{ClientIdentity, IdentityKey, IdentityRole, client_identity_from_certificate_der};
use sha2::{Digest, Sha256};

mod common;

use common::assert_generated_client_identity_certificate_profile;

fn fingerprint_of(key: &KeyPair) -> String {
    Sha256::digest(key.subject_public_key_info())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn error_message(pem: &str) -> String {
    IdentityKey::from_pem(pem)
        .expect_err("key must be rejected")
        .to_string()
}

#[test]
fn released_pkcs8_p256_keys_load_and_keep_their_fingerprint() {
    // Released Core (v0.1.0, v0.2.0) wrote rcgen's default P-256 PKCS#8 key.
    let released = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

    let loaded = IdentityKey::from_pem(&released.serialize_pem()).unwrap();

    assert_eq!(
        loaded.client_identity().to_string(),
        fingerprint_of(&released)
    );
    assert_eq!(
        loaded.server_identity().to_string(),
        fingerprint_of(&released)
    );
}

#[test]
fn generated_keys_are_p256_pkcs8_with_one_pem_block() {
    let pem = IdentityKey::generate().unwrap().to_pem();

    assert_eq!(pem.matches("-----BEGIN ").count(), 1);
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let reparsed = KeyPair::from_pem(&pem).unwrap();
    assert_eq!(reparsed.algorithm(), &PKCS_ECDSA_P256_SHA256);
}

#[test]
fn sec1_keys_are_rejected_with_a_same_key_conversion_command() {
    let message = error_message(
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA==\n-----END EC PRIVATE KEY-----\n",
    );

    assert!(message.contains("SEC1"), "{message}");
    assert!(
        message.contains("openssl pkcs8 -topk8 -nocrypt"),
        "{message}"
    );
}

#[test]
fn ed25519_keys_are_rejected_with_a_rotate_instruction() {
    let message = error_message(
        &KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .serialize_pem(),
    );

    assert!(message.contains("Ed25519"), "{message}");
    assert!(
        message.contains("runewarp client identity rotate"),
        "{message}"
    );
}

#[test]
fn other_algorithms_encrypted_and_multi_block_files_are_rejected() {
    let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .unwrap()
        .serialize_pem();
    assert!(error_message(&p384).contains("ECDSA P-256"));

    let encrypted =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
    assert!(error_message(encrypted).contains("encrypted"));

    let key = IdentityKey::generate().unwrap();
    let generated = common::generate_client_identity().unwrap();
    let multi_block = format!("{}{}", key.to_pem(), generated.certificate_pem);
    assert!(error_message(&multi_block).contains("exactly one PEM block"));

    assert!(error_message("not a key").contains("PKCS#8 PEM"));
}

#[test]
fn in_memory_certificates_pin_the_key_spki_for_both_roles() {
    let key = IdentityKey::generate().unwrap();

    for role in [IdentityRole::Client, IdentityRole::Server] {
        let credentials = key.tls_credentials(role).unwrap();
        let certificate = credentials.cert_chain[0].as_ref();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate).unwrap();

        assert_generated_client_identity_certificate_profile(certificate);
        assert_eq!(
            ClientIdentity::from_subject_public_key_info(parsed.tbs_certificate.subject_pki.raw),
            key.client_identity()
        );
        assert_eq!(
            client_identity_from_certificate_der(certificate).unwrap(),
            key.client_identity()
        );
    }
}
