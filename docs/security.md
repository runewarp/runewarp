# Security

Runewarp keeps customer TLS termination on the operator's own Local backend, not on the public edge. The Server still sees routing metadata, so the security model is private tunneling for TLS passthrough, not zero knowledge.

## Current status

The current repository ships the phase-1 data path plus config-driven Catch-all startup and `runewarp keygen`. It authenticates the Server side of the Tunnel connection but does **not** yet authenticate Clients. Do not expose the current build to the public internet until Client authentication lands.

## What the Server can and cannot see

| Visible to the Server | Not visible to the Server |
| --- | --- |
| Public hostname from SNI | HTTP headers and bodies |
| Visitor source IP and port | Application plaintext |
| Connection timing and byte counts | Local backend TLS private keys |
| Authenticated Client identity in the committed baseline | Decrypted customer traffic |

## Public traffic invariants

- customer TLS is never terminated on public hostnames
- the Server reads only enough of the ClientHello to route
- public traffic must be TLS
- non-TLS traffic and TLS without SNI are dropped
- Local backends must terminate TLS

## Tunnel authentication

The committed baseline for Tunnel connections is:

1. the Server presents a certificate for `server.hostname`
2. the Client validates that certificate
3. the Client presents its own certificate
4. the Server verifies the pinned Client identity from the Client public key

The pinned value is the Client public key, not the certificate lifetime or serial number.

Current code status: only steps 1 and 2 are implemented.

## Client identity and certificate lifecycle

`runewarp keygen` creates a Client keypair and an initial self-signed certificate.

Recommended behavior:

- certificates are valid for **90 days**
- the Client renews them at **60 days**
- renewal happens on startup and periodically while the Client is running
- renewal reuses the same key by default, so the Client identity does not change

That means ordinary certificate renewal should not require a Server config change. Explicit key rotation is different: changing the key changes the Client identity.

## Server certificate lifecycle

The Server certificate protects the tunnel endpoint itself:

- it covers `server.hostname`
- it is used for QUIC on `443/udp`
- it is also used for ACME TLS-ALPN-01 on `443/tcp`

Server certificate renewal does **not** cause an immediate hard cutover. Existing QUIC connections continue with the certificate from their original handshake until they reconnect.

## ACME scope

Runewarp uses `instant-acme` in **TLS-ALPN-01 only** mode.

- ACME is only for the Server hostname
- ACME never provisions certificates for customer Public hostnames
- ACME cache data must be writable by the Server and protected like any other secret-bearing material

## Operational risks

- Hostname mirroring can drift between Server Tunnels and Client Services
- the runtime does not validate cross-side hostname coverage
- there is no Local backend health check in the committed baseline

Those are known limitations, not hidden guarantees.

## Future security work

- multiple Client instances per Tunnel, with shared or separate Client identities
- ECH for public and Client connections
- health-aware routing decisions
- richer abuse controls and metrics
