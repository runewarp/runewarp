# Configuration

This document describes the agreed Runewarp configuration model. The current binary still ships the earlier phase-2 Catch-all surface (`runewarp keygen`, flat `cert-file` / `key-file`, additive `server-ca-file`, `local-addr`, and `retry-interval`). The changes below are the corrected operator surface to implement next, and they are intended as a clean break from that earlier shape.

## Principles

- Server config owns public routing
- Client config owns local Service selection
- Hostname mirroring is intentional: operators repeat Public hostnames on both sides
- TLS passthrough is the product boundary, so Local backends must terminate TLS
- config keys should name the concept, not the current encoding detail
- keep the surface structural and singular: avoid mode flags and duplicate ways to express the same thing

## CLI shape

```text
runewarp server --config config.toml
runewarp server cert init --directory ./server-cert --hostname tunnel.example.com
runewarp server cert renew --directory ./server-cert
runewarp server cert rotate-ca --directory ./server-cert --hostname tunnel.example.com

runewarp client --config config.toml
runewarp client identity init --directory ./client-identity
runewarp client identity renew --directory ./client-identity
runewarp client identity rotate --directory ./client-identity
```

`runewarp keygen` is removed from the intended operator surface. The renamed commands are a clean break; no compatibility aliases are planned.

## Current implementation status

Today the binary supports:

- one Catch-all Tunnel on the Server
- one Catch-all Service on the Client
- flat manual TLS keys: `cert-file` and `key-file`
- additive `server-ca-file` behavior on the Client
- generated Client key, certificate, and fingerprint material through `runewarp keygen`

The current binary still does **not** implement:

- `runewarp server cert ...`
- `runewarp client identity ...`
- directory-based certificate or identity material
- exclusive Client trust when `server-ca-file` is configured
- Client authentication enforcement
- Client certificate renewal
- ACME

## Catch-all mode

### Server with manual/private-CA certificates

```toml
[server]
hostname = "tunnel.example.com"

[server.cert]
directory = "/etc/runewarp/server"

[[server.tunnels]]
client-identity = "4f7b6f7a9b0f0d2b..."
```

### Server with ACME

```toml
[server]
hostname = "tunnel.example.com"

[server.acme]
email = "admin@example.com"
state-directory = "/var/lib/runewarp/acme"

[[server.tunnels]]
client-identity = "4f7b6f7a9b0f0d2b..."
```

### Client

```toml
[client]
server-hostname = "tunnel.example.com"
identity-directory = "/etc/runewarp/client"
server-ca-file = "/etc/runewarp/server-ca.crt"
reconnect-interval = 5

[[client.services]]
backend-address = "127.0.0.1:443"
```

In catch-all mode:

- the sole Tunnel matches every routed Public hostname except the Server hostname
- the sole Service receives every proxied Public hostname
- `public-hostnames` may be omitted only because there is exactly one entry on each side

## Exact-match mode

### Server

```toml
[server]
hostname = "tunnel.example.com"

[server.acme]
email = "admin@example.com"
state-directory = "/var/lib/runewarp/acme"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."

[[server.tunnels]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
client-identity = "2a6cc0f0a14b4b21..."
```

### Client

```toml
[client]
server-hostname = "tunnel.example.com"
identity-directory = "/etc/runewarp/client"
server-ca-file = "/etc/runewarp/server-ca.crt"
reconnect-interval = 5

[[client.services]]
public-hostnames = ["app.example.com", "api.example.com"]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
backend-address = "caddy.local:8443"
```

Exact-match mode keeps routing authority on the Server while the Client uses mirrored `public-hostnames` only for local Service selection. The current binary still implements Catch-all mode only.

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | Server hostname for the Runewarp edge itself. Used for TLS validation and ACME. |
| `server.cert.directory` | with manual/private-CA Server certificates | Directory containing the deployed Server leaf material. In the simple manual path, this directory also contains `server-ca.crt` and an internal `state/` subdirectory for renewal state. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-directory` | with ACME | Writable path for durable ACME account and certificate state. |
| `server.tunnels[].public-hostnames` | when more than one Tunnel exists | Exact Public hostnames routed through this Tunnel. Omit only in Catch-all mode. |
| `server.tunnels[].client-identity` | yes | Lowercase hex SHA-256 fingerprint of the Client public key's SubjectPublicKeyInfo. This names the trust concept rather than the old `client-public-key-fingerprint` encoding detail. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | Server hostname the Client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.identity-directory` | yes | Directory containing the Client keypair, certificate, and `client-identity.txt`. |
| `client.server-ca-file` | no | Exclusive trust bundle for the Server hostname. When present, trust only the PEM certificates in this file; do not also use system roots. This file may contain more than one CA certificate during a planned CA rotation. |
| `client.reconnect-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].public-hostnames` | when more than one Service exists | Exact Public hostnames this Service accepts locally. Omit only in Catch-all mode. |
| `client.services[].backend-address` | yes | TCP endpoint for the forwarded traffic. This backend must terminate TLS. Hostnames are allowed; the value is an address because it includes a port. |

## Hostname mirroring

Runewarp intentionally repeats Public hostnames in Server Tunnels and Client Services:

- the Server uses them to select a Tunnel
- the Client uses them to select a Service after re-reading the forwarded ClientHello
- the runtime does not negotiate or register those hostnames between the two sides

This is a deliberate trade-off to preserve transparent TLS passthrough without adding a routing header to public traffic.

## Trust model

Runewarp supports two Server-certificate paths:

1. **ACME** for the Server hostname, using the system trust store on Clients.
2. **Manual/private-CA** Server certificates, where `runewarp server cert init` creates a private Server CA and an issued Server leaf for `server.hostname`.

In the manual/private-CA path:

- Clients distribute and trust `server-ca.crt`
- `client.server-ca-file` is exclusive when present; it replaces system trust for the Tunnel connection
- the trust file may contain a CA bundle during `runewarp server cert rotate-ca` transitions

## Directory layout

### `server.cert.directory`

The intended directory layout is:

- `server.crt`
- `server.key`
- `server-ca.crt`
- `state/` for sensitive renewal material, including the private Server CA key in the simple on-box manual path

`runewarp server cert renew` reissues `server.crt` from the existing Server CA. `runewarp server cert rotate-ca` changes the trust anchor itself and therefore requires Clients to trust a new CA.

### `client.identity-directory`

The intended directory layout is:

- `client.crt`
- `client.key`
- `client-identity.txt`

`runewarp client identity renew` reissues `client.crt` with the same key, so the `client-identity` stays stable. `runewarp client identity rotate` changes the key and therefore changes the `client-identity`.

## Validation rules

### General boot-time validation

Runewarp should reject config that violates any of these rules:

- the selected mode must have a matching `[server]` or `[client]` section
- `server.hostname` must be present
- exactly one of `[server.acme]` or `[server.cert]` must be present for Server mode
- `client.server-hostname` must be present
- `client.identity-directory` must be present
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- all `client-identity` values must be lowercase hex without colons
- `reconnect-interval` must be at least `1`
- required directories and files must exist and be readable
- `backend-address` must parse as a TCP address or host:port pair

### Intra-side hostname uniqueness

Runewarp enforces these rules independently on each side:

- `public-hostnames` may be omitted only in Catch-all mode
- any exact hostname overlap across Tunnel entries is an error
- any exact hostname overlap across Service entries is an error
- `server.hostname` itself must not be reused as a routed Public hostname
- exact subdomains such as `api.tunnel.example.com` are allowed
- wildcards covering the Server hostname space, such as `*.tunnel.example.com`, should be rejected

### Cross-side hostname coverage

Runewarp does **not** validate that Server Tunnel `public-hostnames` match Client Service `public-hostnames` at runtime. Under Hostname mirroring, that coverage is an operator responsibility. A future lint or doctor workflow may help detect drift, but the runtime does not turn it into handshake-time registration.

## Automation and rotation

- Client certificate renewal is automatic by default and should also happen on startup
- manual `runewarp client identity renew` exists for repair and explicit operator action
- manual/private-CA Server renewal stays explicit through `runewarp server cert renew`
- ordinary Server leaf renewal keeps the same Server CA
- Client identity rotation is an explicit coordinated cutover, not a multi-identity steady-state config
- one shared `client-identity` per Tunnel remains the default model, even when multi-instance tunnels arrive later

## DNS example

Point your Public hostname at the tunnel server:

```dns
app.example.com. 300 IN CNAME tunnel.example.com.
```

The exact record type is up to the operator. The important part is that Public hostnames resolve to the Server so the Server receives the connection and can route it.

## Migration note

The agreed operator surface is a clean break from the currently implemented flat-key and `keygen` design. Planned follow-on work should update the runtime to the names and structures in this document rather than adding compatibility aliases for the older keys.

## Backend behavior

Runewarp opens `backend-address` only when traffic arrives.

- there is no local backend health check
- Local backends must terminate TLS
- plain HTTP backends are out of scope

## Deployment notes

Binding to `443` requires elevated privileges on Linux. Common options are:

- `CAP_NET_BIND_SERVICE`
- `setcap cap_net_bind_service=+ep /path/to/runewarp`
- a local firewall redirect during development

The committed baseline keeps the public TCP port and Client UDP port at `443`. More flexible port layouts are future work.

## Future work

- wildcard Public hostnames
- multiple Client instances per Tunnel, with one shared `client-identity` by default and separate identities as a later advanced case
- remote configuration
- lint and doctor tooling for Hostname mirroring
- IPv6-first deployment support
- metrics configuration
