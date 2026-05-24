# Security

Runewarp is a private tunneling system for TLS passthrough, not an edge TLS terminator and not a zero-knowledge transport. The **Server** still sees routing metadata so it can authorize **Public hostnames** and forward traffic, but customer TLS is terminated only on the operator's **Local backend**.

## What the Server can and cannot see

| Visible to the Server | Not visible to the Server |
| --- | --- |
| **Public hostname** from SNI | HTTP headers and bodies |
| Visitor source IP and port | Application plaintext |
| Connection timing and byte counts | Local backend TLS private keys |
| Authenticated **Client identity** | Decrypted customer traffic |

## Security boundaries

| Boundary | What it protects |
| --- | --- |
| Server-side **Public hostname** authorization | Prevents random public traffic from entering a Tunnel just because some Client is connected |
| Server certificate validation | Confirms the Client is connected to the intended **Server hostname** |
| Exclusive `ca-file` trust | Limits trust for the Tunnel connection to the configured CA bundle |
| Pinned **Client identity** | Confirms the Client public key authorized for the selected Tunnel |
| Backend TLS termination | Keeps customer TLS termination off the public edge |

## Public traffic invariants

- customer TLS is never terminated on public hostnames
- the Server reads only enough of the ClientHello to route
- the Server routes only **Public hostnames** explicitly authorized on the matched **Tunnel**
- public traffic must be TLS
- non-TLS traffic and TLS without SNI are dropped
- **Local backends** must terminate TLS

## Tunnel authentication

The tunnel-connection trust model is:

1. the Server presents a certificate for `server.hostname`
2. the Client validates that certificate through system trust or through `client.server-trust = "ca-file"` with an exclusive CA bundle
3. the Client presents its own certificate
4. the Server verifies the pinned `client-identity` from the Client public key

The pinned value is the Client public key, not the certificate lifetime or serial number.

## Certificate and identity lifecycle

### Client identity

`runewarp client identity init` creates a Client keypair, an initial self-signed certificate, and `client-identity.txt`.

Ordinary certificate renewal is expected to keep the same key:

- certificates are valid for **90 days**
- the Client renews them at **60 days**
- renewal happens before the initial connect and before reconnect attempts
- same-key renewal preserves the `client-identity`

`runewarp client identity rotate` changes the key and therefore changes the identity.

### Server certificate

Runewarp supports two Server-certificate paths:

- ACME for the **Server hostname**
- a manual/private-CA path through `runewarp server cert init`, `renew`, and `rotate-ca`

In the manual/private-CA path:

- `runewarp server cert init` creates a private **Server CA** and an initial issued leaf
- `runewarp server cert renew` reissues the Server leaf from the same CA
- `runewarp server cert rotate-ca` changes the trust anchor itself, so Clients must trust a new CA

Existing QUIC connections continue with the certificate from their original handshake until they reconnect.

## ACME scope

Runewarp uses `rustls-acme` in **TLS-ALPN-01 only** mode.

- the current ACME config surface is fixed to Let's Encrypt
- ACME is only for the **Server hostname**
- ACME never provisions certificates for customer **Public hostnames**
- when omitted, `server.acme.state-dir` defaults to the XDG state path and is created at startup
- any explicit `server.acme.state-dir` should be protected like secret-bearing material

## Operational limits and trade-offs

| Concern | Behavior |
| --- | --- |
| Cross-side hostname drift | The runtime does not validate cross-side hostname coverage under **Hostname mirroring** |
| Local backend health | There is no pre-flight Local backend health check |
| Manual/private-CA convenience | The simple manual path may keep private Server CA material on the public Server |
| Same-Tunnel availability | The runtime keeps one active connection per Tunnel rather than a load-balanced pool |

These are deliberate boundaries and current limits, not hidden guarantees.
