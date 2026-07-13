# Security

In the default passthrough mode, Runewarp does not terminate customer TLS on the public server. The server sees only the metadata it needs to authorize hostnames and forward traffic. When a service opts into terminate mode, the client terminates TLS and the local backend receives plaintext.

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
| **Exclusive CA trust** | Limits trust for the Tunnel connection to the configured CA bundle |
| Pinned **Client identity** | Confirms the Client public key authorized for the selected Tunnel |
| Backend TLS termination (passthrough) | Keeps customer TLS termination off the public edge in the default mode |
| **Public hostname CA** (terminate) | Operator-managed trust anchor for Visitors when the Client terminates TLS |

## Diagnostics visibility

Runtime diagnostics follow the same boundary.

**May be logged**

- normalized **Public hostname**
- routing outcome, connection timing, and transport errors
- effective Client `server-address` values plus resolved socket addresses on connection-attempt lines
- rejected or authenticated **Client identity** values on tunnel-auth warnings
- Client `backend-address` values in routing diagnostics
- graceful-shutdown lifecycle lines
- `server acme challenge handled` with `server-hostname=...` for `acme-tls/1` traffic on the **Server hostname**
- distinct Client ACME challenge-handling lines for terminating **Public hostnames**

**Must not be logged**

- buffered ClientHello bytes
- HTTP headers or bodies
- decrypted application plaintext
- remote socket addresses for Server tunnel lifecycle or forwarded-route events

## Public traffic invariants

- customer TLS is never terminated on the **Server**
- the Server reads only enough of the ClientHello to route
- the Server routes only **Public hostnames** explicitly authorized on the matched **Tunnel**
- public traffic must be TLS
- non-TLS traffic and TLS without SNI are dropped
- **Local backends** must terminate TLS when `tls-mode = "passthrough"` (default)
- the **Client** terminates TLS when `tls-mode = "terminate"`; the Local backend receives plaintext

## Tunnel authentication

The tunnel-connection trust model is:

1. the Server presents a certificate for `server.hostname`
2. the Client validates that certificate through system trust or through `client.server-trust = "ca-file"` with an exclusive CA bundle
3. the Client presents its own certificate
4. the Server verifies one of the Tunnel's pinned `client-identity` values from the Client public key

The pinned value is the client public key, not the certificate lifetime or serial number. Handshake admission and Public-hostname routing consult one shared **Authorization snapshot**, so identity additions and removals can replace admission without rebinding the tunnel listener. Live Tunnel connections retain their authenticated Client identity, and admitted Visitor streams retain their Public hostname and serving connection, so the runtime can dispatch targeted connection closes and stream resets without disturbing unrelated work.

Static fanout does not change these trust boundaries. When a Client dials multiple **Server addresses**, each **Tunnel connection** still uses the same shared Client identity, Server-certificate validation mode, and local Service-routing config.

## Certificate and identity lifecycle

### Client identity

`runewarp client identity init` creates a Client keypair, an initial self-signed certificate, and `client-identity.txt`.

Self-hosted Client identity certificates are operationally non-expiring key carriers:

- newly initialized and rotated certificates use a **100-year** validity window
- the Server authorizes the pinned Client identity from the subject public key and does not validate certificate issuer, chain, SAN, validity window, or revocation state
- existing shorter-lived certificates remain accepted after their encoded expiry; Core does not rewrite them
- there is no automatic or manual self-signed Client identity certificate renewal

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

### Public hostname certificates (TLS termination)

When one or more Services use `tls-mode = "terminate"`, the Client needs public TLS certificates for those hostnames. Two mutually exclusive paths are supported:

**Manual path** (`client.public-cert-dir`) — operator creates and manages a private **Public hostname CA** and per-hostname leaf certificates:

- `runewarp client public-cert init` creates a private **Public hostname CA** and one or more initial **Public hostname certificates**, using `--hostname` or the config-derived terminating hostname set
- running it again with a different hostname reuses the existing CA and adds a new leaf without replacing the trust anchor
- the CA private key lives in `{public-cert-dir}/state/public-ca.key` and must be kept private

Visitors must trust `public-ca.crt`; it stays stable across additional `init` calls and leaf renewals, but `runewarp client public-cert rotate-ca` replaces it. Per-host certificate material lives at `{public-cert-dir}/{hostname}/public.crt` and `{public-cert-dir}/{hostname}/public.key`. **Public hostname certificates** are **90 days** by default; the **Public hostname CA** is **3650 days**.

**ACME path** (`[client.acme]`) — the Client automatically provisions and renews certificates from Let's Encrypt for the **Public hostnames** of all terminating Services. No pre-generated material is needed; configure `[client.acme]` in the Client config instead of `client.public-cert-dir`. The Client starts with a live ACME manager at startup without blocking on certificate readiness. Terminating hostnames without a ready certificate fail closed at the TLS handshake; there is no fallback to passthrough.

## ACME scope

Runewarp uses `rustls-acme` in **TLS-ALPN-01 only** mode. The current ACME config surface is fixed to Let's Encrypt.

### Server ACME

`[server.acme]` provisions the certificate for `server.hostname` only. When a Visitor connects to the Server hostname with ALPN `acme-tls/1`, the Server handles the challenge itself. All other application traffic addressed to the Server hostname is dropped.

- when omitted, `server.acme.state-dir` defaults to the XDG state path and is created at startup
- Runewarp warns when `server.public-bind-address` is not on TCP 443, but that warning stays advisory because the externally reachable public port may still be 443 through container or NAT mapping
- any explicit `server.acme.state-dir` should be protected like secret-bearing material

### Client ACME

`[client.acme]` provisions certificates for the **Public hostnames** of terminating Services. The managed hostname set is derived from every Service that has both `tls-mode = "terminate"` and explicit `public-hostnames`.

For Client ACME, `acme-tls/1` challenge connections for **Public hostnames** reach the Client through the Server's normal Visitor routing path — the Server does not inspect ALPN for Public hostname traffic and forwards the raw bytes to the Client through the Tunnel. The Client's ACME resolver handles both `acme-tls/1` challenge connections and regular TLS connections for those hostnames.

The Client starts with a live ACME manager at startup and does not block on certificate readiness. Terminating hostnames without a ready ACME certificate fail closed at the TLS handshake; there is no fallback to passthrough.

- `client.acme.state-dir` defaults to the XDG client ACME state path and is created at startup when omitted
- Client ACME depends on the same public TCP 443 reachability at the Server edge because TLS-ALPN-01 challenge traffic still enters through the Server's public listener before it reaches the Client
- any explicit `client.acme.state-dir` should be protected like secret-bearing material

## Operational limits and trade-offs

| Concern | Behavior |
| --- | --- |
| Cross-side hostname drift | The runtime does not validate cross-side hostname coverage under **Hostname mirroring** |
| Local backend health | There is no pre-flight Local backend health check |
| Manual/private-CA convenience | The simple manual path may keep private Server CA material on the public Server |
| Public hostname CA location | The manual path keeps the Public hostname CA private key on the Client machine alongside the running service |
| Same-Tunnel member policing | The runtime keeps a connected pool member in service even if that member rejects some placed streams; there is no automatic ejection or quarantine |

These are current limits, not hidden guarantees.
