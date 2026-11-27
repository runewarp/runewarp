# Identity is a pinned public key

A Client identity and a Server identity are each one ECDSA P-256 private key, stored as unencrypted PKCS#8 PEM and referenced by `identity-key`. The identity is the SHA-256 of the key's DER SubjectPublicKeyInfo (SPKI) with the uncompressed point, the same data as a DANE TLSA `3 1 1` record. The Server's Tunnel verifier and Control admit a participant by that exact fingerprint. Core builds a self-signed X.509 certificate in memory from the key whenever a TLS peer needs one; the certificate is a container for the public key and carries no other meaning. There is no CA, no certificate issuance and no renewal, so operators manage one file and nothing derived can drift.

This is a hard break. Older identity directories, `identity-dir`, stored certificates and fingerprint files, SEC1 key files and the Ed25519 identities that unreleased builds generated are not read. P-256 PKCS#8 keys from released Core keep their fingerprint.

## Considered options

- **Keep the key, certificate and fingerprint as three files.** Rejected: only the key is a source of truth, nothing validates the certificate, and a crash mid-rotation or a mismatch left an identity that would not load.
- **Run a Client or Server CA.** Rejected for participant identities: it adds issuance, renewal and revocation to a system that already authorizes exact keys. Customer-supplied CA trust is revisited only for Visitor mTLS, such as browser or enterprise devices.
- **Raw public keys (RFC 7250).** Deferred: common TLS terminators in front of Control don't support them today. Revisit when a peer-to-peer link between Runewarp components needs them.
- **Allow several algorithms.** Rejected: an undefined allowlist let RSA, P-384 and Ed25519 through. P-256 alone keeps the accepted identity types defined and narrow. The verifier advertises and accepts only `ecdsa_secp256r1_sha256` and rejects compressed-point SPKIs, so one key never has two fingerprints.

## Consequences

- The certificate's serial, validity and extensions are not trust inputs. Its serial is unspecified and its bytes change on every build; only SPKI continuity is a compatibility contract.
- Participant identities stay distinct from Visitor credentials, so Visitor authentication can choose its own trust model.
- User logins may manage identity bindings, but machine keys keep their own identity and keep working without user sessions. Any future binding expiry needs its own decision on enforcement and offline behaviour.
- Hardware-backed keys or new algorithms extend `identity-key` and the algorithm allowlist. The fingerprint scheme stays the same.
- Control should enforce the same P-256 and uncompressed-SPKI rules when it admits identities.
