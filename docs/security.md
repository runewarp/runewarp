# Security

Runewarp keeps customer TLS termination on the operator's own Local backend, not on the public edge. The Server still sees routing metadata, so the security model is private tunneling for TLS passthrough, not zero knowledge. The shipped phase-3 routing model treats explicit Server-side `public-hostnames` as a security boundary.

## Current status

The current repository now ships the corrected phase-2 surface (`runewarp server cert ...`, `runewarp client identity ...`, directory-based material, exclusive `server-ca-file`, Client authentication, ACME, and same-key Client certificate renewal before initial connect and reconnect attempts) together with explicit Server-authorized exact-match public-hostname routing and per-Tunnel connection isolation.

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
- the Server routes only Public hostnames explicitly authorized on the matched Tunnel
- public traffic must be TLS
- non-TLS traffic and TLS without SNI are dropped
- Local backends must terminate TLS

## Server-side routing authorization

Runewarp keeps hostname authorization on the Server:

- every Server Tunnel lists its explicit `public-hostnames`
- Server Catch-all is not part of the committed model
- if no Tunnel owns the inbound Public hostname, the Server drops the connection
- if the selected Tunnel has no active Client connection, the Server still drops the connection rather than rerouting elsewhere

This prevents random public traffic from being sent down a Tunnel merely because some Client happens to be connected.

## Client-side routing shape

Once the Server has authorized traffic into a Tunnel, the Client has two valid shapes:

- exact-match Services, where the Client also matches the forwarded Public hostname
- one Catch-all Service, where one Local backend handles every hostname the Server already admitted to that Tunnel

Client Catch-all is acceptable because it does **not** widen ingress authority. The Server has already constrained which Public hostnames can reach that Tunnel. If a Client is using exact-match Services and none matches the forwarded Public hostname, the Client should reject the stream.

## Tunnel authentication

The committed baseline for Tunnel connections is:

1. the Server presents a certificate for `server.hostname`
2. the Client validates that certificate either through system trust (ACME/public-CA path) or through the exclusive configured Server CA file (manual/private-CA path)
3. the Client presents its own certificate
4. the Server verifies the pinned `client-identity` from the Client public key

The pinned value is the Client public key, not the certificate lifetime or serial number.

One shared `client-identity` per Tunnel remains the default phase-2 trust model.

Current code status: steps 1-4 are implemented, and `server-ca-file` is exclusive when configured.

## Client identity and certificate lifecycle

`runewarp client identity init` is the intended operator entry point for the Client side. It creates a Client keypair, an initial self-signed certificate, and `client-identity.txt`.

Recommended behavior:

- certificates are valid for **90 days**
- the Client renews them at **60 days**
- renewal happens before the initial connect and before reconnect attempts
- renewal reuses the same key by default, so the Client identity does not change

That means ordinary certificate renewal should not require a Server config change. Explicit key rotation is different: changing the key changes the Client identity.

`runewarp client identity rotate` is therefore a distinct coordinated cutover, not a variant of ordinary renewal.

## Server certificate lifecycle

Runewarp supports two Server-certificate paths:

- ACME for the Server hostname
- a manual/private-CA path through `runewarp server cert init`, `renew`, and `rotate-ca`

The Server certificate protects the tunnel endpoint itself:

- it covers `server.hostname`
- it is used for QUIC on `443/udp`
- ACME TLS-ALPN-01 on `443/tcp` is scoped to `server.hostname` and uses challenge certificates rather than customer Public hostname certificates

Server certificate renewal does **not** cause an immediate hard cutover. Existing QUIC connections continue with the certificate from their original handshake until they reconnect.

In the manual/private-CA path:

- `runewarp server cert init` creates a private Server CA and the initial issued Server leaf
- `runewarp server cert renew` reissues the Server leaf from the same Server CA, so Clients do not need a new trust anchor
- `runewarp server cert rotate-ca` changes the trust anchor itself, so Clients must trust a new CA

To keep the simple manual path easy to operate, the private Server CA key may live in `server.cert.directory/state/` on the public Server. That is a deliberate trade-off: compromise of the public Server can also compromise the private Server CA. ACME remains the expected default for most operators.

## Client trust material

When `client.server-ca-file` is configured:

- trust only the certificates in that file for the Server hostname
- do **not** also trust system roots for that Tunnel connection
- the file may contain a PEM bundle of one or more Server CA certificates during `rotate-ca` transitions

When `client.server-ca-file` is omitted, the Client uses the system trust store for the ACME or public-CA path.

## ACME scope

Runewarp uses `rustls-acme` in **TLS-ALPN-01 only** mode.

- ACME is only for the Server hostname
- ACME never provisions certificates for customer Public hostnames
- ACME state data in `server.acme.state-directory` must be writable by the Server, must exist before boot, and should be protected like any other secret-bearing material

## Operational risks

- Hostname mirroring can drift between Server Tunnels and Client Services in both-sides-explicit configs
- the runtime does not validate cross-side hostname coverage
- there is no Local backend health check in the committed baseline
- the simple manual/private-CA Server path may keep private CA material on the public Server
- same-Tunnel load-balanced pools and zero-downtime replacement remain future work

Those are known limitations, not hidden guarantees.

## Future security work

- zero-downtime Client-identity rotation
- zero-downtime Server CA rotation
- multiple Client instances per Tunnel, with shared or separate Client identities
- ECH for public and Client connections
- health-aware routing decisions
- richer abuse controls and metrics
