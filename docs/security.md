# Security

Runewarp keeps customer TLS termination on the operator's own backend, not on the public edge. The server still sees routing metadata, so the security model is "private tunneling for TLS passthrough," not zero knowledge.

## Status

These docs describe the full intended design. Future items are called out where needed.

## What the server can and cannot see

| Visible to the server | Not visible to the server |
| --- | --- |
| SNI hostname | HTTP headers and bodies |
| Visitor source IP and port | Application plaintext |
| Connection timing and byte counts | Backend TLS private keys |
| Client public-key fingerprint | Decrypted customer traffic |

## Public traffic invariants

- Customer TLS is never terminated on public hostnames.
- The server reads only enough of the ClientHello to route.
- Public traffic must be TLS.
- Non-TLS traffic and TLS without SNI are dropped.

## Tunnel authentication

Runewarp authenticates client tunnels with mutual TLS:

1. the server presents a certificate for `server.hostname`
2. the client validates that certificate
3. the client presents its own certificate
4. the server verifies the client's pinned public-key fingerprint

The pinned value is the client's public key, not the certificate lifetime or serial number.

## Client certificate lifecycle

`runewarp keygen` creates a client keypair and an initial self-signed certificate.

Recommended behavior:

- certificates are valid for **90 days**
- the client renews them at **60 days**
- renewal happens on startup and periodically while the client is running
- renewal reuses the same key by default, so the server fingerprint does not change

That means normal certificate renewal should not require a server config change.

Explicit key rotation is different: changing the key changes the fingerprint. Later phases may allow multiple fingerprints per tunnel entry to make rotation and mixed pools easier.

## Server certificate lifecycle

The server certificate protects the tunnel endpoint itself:

- it covers `server.hostname`
- it is used for QUIC on `443/udp`
- it is also used for ACME TLS-ALPN-01 on `443/tcp`

Server certificate renewal does **not** cause an immediate hard cutover. Existing QUIC connections continue with the certificate from their original handshake until they reconnect.

## ACME scope

Runewarp uses `instant-acme` in **TLS-ALPN-01 only** mode.

- ACME is only for the server hostname.
- ACME never provisions certificates for customer hostnames routed through the tunnel.
- ACME cache data must be writable by the server and protected like any other secret-bearing material.

## Operational risks

- The server cannot prove that every replica in a tunnel pool serves the same hostname set.
- A misconfigured replica can accept load-balanced traffic and then fail it locally.
- There is no backend health check in early phases.

Those are known limitations, not hidden guarantees.

## Future security work

- ECH for public and client connections
- multiple fingerprints per tunnel entry
- health-aware routing decisions
- richer abuse controls and metrics
