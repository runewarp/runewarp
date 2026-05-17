# Configuration

This document describes the agreed Runewarp configuration model. The current binary now ships the corrected phase-2 operator surface (`runewarp server cert ...`, `runewarp client identity ...`, directory-based material, exclusive `server-ca-file`, Client authentication, ACME, and same-key Client certificate renewal before initial connect and reconnect attempts). The committed phase-3 model still removes Server Catch-all: every Server Tunnel must list explicit `public-hostnames`, while the Client either lists explicit `public-hostnames` too or uses one Catch-all Service.

## Principles

- Server config owns public routing
- Client config owns local Service selection
- the Server routes only explicitly authorized Public hostnames into a Tunnel
- Hostname mirroring and One-sided Catch-all are the two intended routing topologies
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
- `runewarp server cert init|renew|rotate-ca`
- `runewarp client identity init|renew|rotate`
- directory-based Server certificate and Client identity material
- exclusive `client.server-ca-file` trust when configured
- pinned `client-identity` enforcement on Tunnel connections
- automatic same-key Client certificate renewal before initial connect and reconnect attempts
- ACME TLS-ALPN-01 for `server.hostname`
- one active Client instance at a time
- one active Tunnel connection at a time

The current binary still does **not** implement:

- required explicit `server.tunnels[].public-hostnames`
- multiple Server Tunnels and one active Tunnel connection per Tunnel
- multiple Client instances, with one Client instance per Tunnel
- multiple Client Services with exact-match selection
- per-role `logs` booleans

## Server exact-match mode

### Server with manual/private-CA certificates

```toml
[server]
hostname = "tunnel.example.com"

[server.cert]
directory = "/etc/runewarp/server"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
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
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."
```

Every Server Tunnel must list explicit `public-hostnames`. Server Catch-all is not part of the committed model.

## Client exact-match mode

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
backend-address = "nginx.local:443"
```

Client exact-match mode is used when the Client also needs per-host local routing decisions.

## Client Catch-all mode

```toml
[client]
server-hostname = "tunnel.example.com"
identity-directory = "/etc/runewarp/client"
server-ca-file = "/etc/runewarp/server-ca.crt"
reconnect-interval = 5

[[client.services]]
backend-address = "127.0.0.1:443"
```

Client Catch-all is valid only when there is exactly one Service. It receives any traffic the Server has already authorized to the connected Tunnel.

## Server with multiple Tunnels

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

Each `client-identity` names exactly one Tunnel. If an operator needs different trust or lifecycle boundaries, they create different Tunnels and run different Client instances.

## Client with multiple Services

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

The grouping of hostnames into Tunnels and Services may differ. One Tunnel can serve multiple Services, and one Service can own multiple Public hostnames when they share one Local backend.

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | Server hostname for the Runewarp edge itself. Used for TLS validation and ACME. |
| `server.logs` | no | Boolean controlling human-readable Server runtime logs. Defaults to `true` when omitted. |
| `server.cert.directory` | with manual/private-CA Server certificates | Directory containing the deployed Server leaf material. In the simple manual path, this directory also contains `server-ca.crt` and an internal `state/` subdirectory for renewal state. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-directory` | with ACME | Writable path for durable ACME account and certificate state. The directory must already exist before boot. |
| `server.tunnels[].public-hostnames` | yes | One or more exact Public hostnames routed through this Tunnel. This field is required on every Server Tunnel and must contain DNS hostnames only. |
| `server.tunnels[].client-identity` | yes | Lowercase hex SHA-256 fingerprint of the Client public key's SubjectPublicKeyInfo. This names the trust concept rather than the old `client-public-key-fingerprint` encoding detail. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | Server hostname the Client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.logs` | no | Boolean controlling human-readable Client runtime logs. Defaults to `true` when omitted. |
| `client.identity-directory` | yes | Directory containing the Client keypair, certificate, and `client-identity.txt`. |
| `client.server-ca-file` | no | Exclusive trust bundle for the Server hostname. When present, trust only the PEM certificates in this file; do not also use system roots. This file may contain more than one CA certificate during a planned CA rotation. |
| `client.reconnect-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].public-hostnames` | when exact-match local routing is desired | Exact Public hostnames this Service accepts locally. Omit only on the sole Catch-all Service. |
| `client.services[].backend-address` | yes | TCP endpoint for the forwarded traffic. This backend must terminate TLS. Hostnames are allowed; the value is an address because it includes a port. |

## Hostname mirroring

Runewarp intentionally supports a both-sides-explicit topology:

- the Server uses them to select a Tunnel
- the Client uses them to select a Service after re-reading the forwarded ClientHello
- the same explicit hostname set is repeated on both sides, even if the grouping into Tunnels and Services differs
- the runtime does not negotiate or register those hostnames between the two sides

This is a deliberate trade-off to preserve transparent TLS passthrough without adding a routing header to public traffic.

## One-sided Catch-all

Runewarp also supports Server exact-match with one Client Catch-all Service:

- the Server still lists the explicit Public hostnames authorized for each Tunnel
- the Client omits `public-hostnames` only on its sole Service
- a single Local backend, such as Caddy, can then make the final per-host decision locally

Client Catch-all does not widen ingress authority because the Server has already limited the hostname set that can enter the Tunnel.

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
- `server.logs`, when present, must be a boolean
- exactly one of `[server.acme]` or `[server.cert]` must be present for Server mode
- `client.server-hostname` must be present
- `client.logs`, when present, must be a boolean
- `client.identity-directory` must be present
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- every `server.tunnels[].public-hostnames` field must be present and contain at least one hostname
- all `client-identity` values must be lowercase hex without colons
- all `client-identity` values must be unique across Server Tunnels
- `reconnect-interval` must be at least `1`
- required directories and files must exist and be readable
- `backend-address` must parse as a TCP address or host:port pair

### Intra-side hostname uniqueness

Runewarp enforces these rules independently on each side:

- `server.tunnels[].public-hostnames` is always required
- `client.services[].public-hostnames` may be omitted only when there is exactly one Service
- `public-hostnames = []` is an error on either side
- hostnames are normalized to lowercase and a trailing dot is stripped before comparison
- `public-hostnames` must be DNS hostnames, including punycode A-labels; raw Unicode, IP literals, and wildcards are rejected
- any exact hostname overlap across Tunnel entries after normalization is an error
- any exact hostname overlap across Service entries after normalization is an error
- `server.hostname` itself must not be reused as a routed Public hostname
- `client.server-hostname` overlap on the Client side is permitted; the Client stays agnostic about Server-side routability
- exact subdomains such as `api.tunnel.example.com` are allowed
- single-entry exact-match is valid: one Tunnel or one Service may still use explicit `public-hostnames`

### Cross-side hostname coverage

Runewarp does **not** validate cross-side hostname coverage at runtime:

- under Hostname mirroring, repeating the explicit hostname set on both sides is an operator responsibility
- under One-sided Catch-all, the Server carries the explicit hostname set while the Client intentionally does not

A future lint or doctor workflow may help detect drift, but the runtime does not turn hostname coverage into handshake-time registration.

## Automation and rotation

- Client certificate renewal is automatic by default before the initial connect and before reconnect attempts
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

The corrected operator surface is now the shipped baseline. Follow-on work should extend the names and structures in this document rather than reintroducing flat-key or `keygen` compatibility aliases.

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
