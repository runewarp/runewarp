# Configuration

This document defines the Runewarp configuration model. Use [`docs/usage.md`](usage.md) for the operator workflow and this document for exact keys, validation rules, and example config shapes.

## Configuration ownership

| Config area | Owns |
| --- | --- |
| `[server]` | Public routing, Server identity, and the Server certificate path |
| `[[server.tunnels]]` | Explicit **Public hostname** authorization and the pinned **Client identity** for one **Tunnel** |
| `[client]` | Tunnel dialing, Server trust, Client identity material, and reconnect behavior |
| `[[client.services]]` | Local routing from one or more **Public hostnames** to one **Local backend** |

## Configuration principles

- Server config owns public routing
- Client config owns local **Service** selection
- the Server routes only explicitly authorized **Public hostnames** into a **Tunnel**
- **Hostname mirroring** and **One-sided Catch-all** are the two supported routing topologies
- TLS passthrough is the product boundary, so **Local backends** must terminate TLS
- config keys should name the product concept rather than an encoding detail

## Supported routing shapes

| Shape | Server | Client |
| --- | --- | --- |
| Exact-match on both sides | Every Tunnel lists explicit `public-hostnames` | Every Service lists explicit `public-hostnames` |
| One-sided Catch-all | Every Tunnel lists explicit `public-hostnames` | The sole Service omits `public-hostnames` |

Server Catch-all is not part of the committed model.

## CLI entry points

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

## Example: Server with manual/private-CA certificates

```toml
[server]
hostname = "tunnel.example.com"

[server.cert]
directory = "/etc/runewarp/server"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."
```

## Example: Server with ACME

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

## Example: Client exact-match routing

```toml
[client]
server-hostname = "tunnel.example.com"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-directory = "/etc/runewarp/client"
reconnect-interval = 5

[[client.services]]
public-hostnames = ["app.example.com", "api.example.com"]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
backend-address = "nginx.local:443"
```

## Example: Client Catch-all routing

```toml
[client]
server-hostname = "tunnel.example.com"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-directory = "/etc/runewarp/client"
reconnect-interval = 5

[[client.services]]
backend-address = "127.0.0.1:443"
```

The Client Catch-all shape is valid only when there is exactly one Service.

## Example: Multiple Tunnels on the Server

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

## Example: Multiple Services on the Client

```toml
[client]
server-hostname = "tunnel.example.com"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-directory = "/etc/runewarp/client"
reconnect-interval = 5

[[client.services]]
public-hostnames = ["app.example.com", "api.example.com"]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
backend-address = "caddy.local:8443"
```

The grouping of hostnames into **Tunnels** and **Services** may differ. One Tunnel can serve multiple Services, and one Service can own multiple **Public hostnames** when they share one **Local backend**.

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | **Server hostname** for the Runewarp edge itself. Used for TLS validation and ACME. |
| `server.logs` | no | Boolean controlling human-readable Server runtime logs. Defaults to `true`. |
| `server.cert.directory` | with the manual/private-CA path | Directory containing the deployed Server leaf material. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-directory` | with ACME | Writable path for durable ACME account and certificate state. The directory must already exist before boot. |
| `server.tunnels[].public-hostnames` | yes | One or more exact **Public hostnames** routed through this Tunnel. |
| `server.tunnels[].client-identity` | yes | Lowercase hex SHA-256 fingerprint of the Client public key's SubjectPublicKeyInfo. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | **Server hostname** the Client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.server-ca-file` | no | Exclusive trust bundle for the Server hostname. Replaces system trust when present. |
| `client.identity-directory` | yes | Directory containing the Client keypair, certificate, and `client-identity.txt`. |
| `client.logs` | no | Boolean controlling human-readable Client runtime logs. Defaults to `true`. |
| `client.reconnect-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].public-hostnames` | when exact-match local routing is desired | Exact **Public hostnames** this Service accepts locally. Omit only on the sole Catch-all Service. |
| `client.services[].backend-address` | yes | TCP endpoint for the forwarded traffic. This backend must terminate TLS. |

## Trust and material directories

### `server.cert.directory`

The manual/private-CA directory layout is:

- `server.crt`
- `server.key`
- `server-ca.crt`
- `state/` for renewal state, including the private Server CA key in the simple on-box manual path

`runewarp server cert renew` reissues `server.crt` from the existing **Server CA**. `runewarp server cert rotate-ca` changes the trust anchor itself and requires Clients to trust a new CA.

### `client.identity-directory`

The Client identity directory layout is:

- `client.crt`
- `client.key`
- `client-identity.txt`

`runewarp client identity renew` reissues `client.crt` with the same key, so the `client-identity` stays stable. `runewarp client identity rotate` changes the key and therefore changes the `client-identity`.

## Validation rules

### General boot-time validation

Runewarp rejects config that violates any of these rules:

- the selected role must have a matching `[server]` or `[client]` section
- `server.hostname` must be present
- exactly one of `[server.acme]` or `[server.cert]` must be present for Server mode
- `client.server-hostname` must be present
- `client.identity-directory` must be present
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- all `client-identity` values must be lowercase hex without colons
- all `client-identity` values must be unique across Server Tunnels
- `reconnect-interval` must be at least `1`
- required directories and files must exist and be readable
- `backend-address` must parse as a TCP address or host:port pair

### Hostname rules

Runewarp enforces these rules independently on each side:

- `server.tunnels[].public-hostnames` is always required
- `client.services[].public-hostnames` may be omitted only when there is exactly one Service
- `public-hostnames = []` is an error on either side
- hostnames are normalized to lowercase and a trailing dot is stripped before comparison
- `public-hostnames` must be DNS hostnames, including punycode A-labels; raw Unicode, IP literals, and wildcards are rejected
- any exact hostname overlap across Tunnel entries after normalization is an error
- any exact hostname overlap across Service entries after normalization is an error
- `server.hostname` itself must not be reused as a routed **Public hostname**
- `client.server-hostname` overlap on the Client side is permitted; the Client stays agnostic about Server-side routability

### Cross-side hostname coverage

Runewarp does not validate cross-side hostname coverage at runtime:

- under **Hostname mirroring**, repeating the explicit hostname set on both sides is an operator responsibility
- under **One-sided Catch-all**, the Server carries the explicit hostname set while the Client intentionally does not

## Operational notes

- `backend-address` is opened only when traffic arrives
- **Local backends** must terminate TLS
- `server-ca-file` is exclusive when configured; the Client does not also use system roots for that Tunnel connection
- binding to `443` on Linux typically requires either elevated privileges or `CAP_NET_BIND_SERVICE`
