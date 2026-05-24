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

Server Catch-all is intentionally not supported.

## CLI entry points

```text
runewarp server --config config.toml
runewarp server cert init --dir ./server-cert --hostname tunnel.example.com
runewarp server cert renew --dir ./server-cert
runewarp server cert rotate-ca --dir ./server-cert --hostname tunnel.example.com

runewarp client --config config.toml
runewarp client identity init --dir ./client-identity
runewarp client identity renew --dir ./client-identity
runewarp client identity rotate --dir ./client-identity
```

Material-management commands also accept `--config` and resolve their working directory with this precedence:

1. explicit `--dir`
2. the configured material directory from the selected config file
3. the XDG default for that command

## Runtime config discovery

When `runewarp server` or `runewarp client` omit `--config`, Runewarp loads:

- `$XDG_CONFIG_HOME/runewarp/config.toml`, or
- `~/.config/runewarp/config.toml` when `XDG_CONFIG_HOME` is unset

## Default locations

When the matching config key is omitted, Runewarp uses:

| Purpose | Default location |
| --- | --- |
| Runtime config | `$XDG_CONFIG_HOME/runewarp/config.toml` or `~/.config/runewarp/config.toml` |
| Manual/private-CA Server material | `$XDG_DATA_HOME/runewarp/server/cert/` or `~/.local/share/runewarp/server/cert/` |
| Client identity material | `$XDG_DATA_HOME/runewarp/client/identity/` or `~/.local/share/runewarp/client/identity/` |
| Client CA bundle for `server-trust = "ca-file"` | `$XDG_DATA_HOME/runewarp/client/server-ca.crt` or `~/.local/share/runewarp/client/server-ca.crt` |
| ACME state | `$XDG_STATE_HOME/runewarp/server/acme/` or `~/.local/state/runewarp/server/acme/` |

## Example: Server with manual/private-CA certificates

```toml
[server]
hostname = "tunnel.example.com"

[server.cert]
material-dir = "/etc/runewarp/server"

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
state-dir = "/var/lib/runewarp/acme"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."
```

## Example: Client exact-match routing

```toml
[client]
server-hostname = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-material-dir = "/etc/runewarp/client"
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
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-material-dir = "/etc/runewarp/client"
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
state-dir = "/var/lib/runewarp/acme"

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
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-material-dir = "/etc/runewarp/client"
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
| `server.cert.material-dir` | no | Directory containing the deployed Server leaf material. Defaults to the XDG data path for manual/private-CA Server material. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-dir` | no | Writable path for durable ACME account and certificate state. When omitted, Runewarp uses and creates the XDG default state directory at startup. |
| `server.tunnels[].public-hostnames` | yes | One or more exact **Public hostnames** routed through this Tunnel. |
| `server.tunnels[].client-identity` | yes | Lowercase hex SHA-256 fingerprint of the Client public key's SubjectPublicKeyInfo. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | **Server hostname** the Client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.server-trust` | no | `system` or `ca-file`. Defaults to `system`. |
| `client.server-ca-file` | no | Exclusive CA bundle for the Server hostname. Valid only when `client.server-trust = "ca-file"`; otherwise system trust is used. When omitted in `ca-file` mode, Runewarp uses the XDG default CA bundle path. |
| `client.identity-material-dir` | no | Directory containing the Client keypair, certificate, and `client-identity.txt`. Defaults to the XDG data path for Client identity material. |
| `client.logs` | no | Boolean controlling human-readable Client runtime logs. Defaults to `true`. |
| `client.reconnect-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].public-hostnames` | when exact-match local routing is desired | Exact **Public hostnames** this Service accepts locally. Omit only on the sole Catch-all Service. |
| `client.services[].backend-address` | yes | TCP endpoint for the forwarded traffic. This backend must terminate TLS. |

## Trust and material directories

### `server.cert.material-dir`

The manual/private-CA directory layout is:

- `server.crt`
- `server.key`
- `server-ca.crt`
- `state/` for renewal state, including the private Server CA key in the simple on-box manual path

`runewarp server cert renew` reissues `server.crt` from the existing **Server CA**. `runewarp server cert rotate-ca` changes the trust anchor itself and requires Clients to trust a new CA.

When omitted, `server.cert.material-dir` defaults to the XDG data location for Server certificate material.

### `client.identity-material-dir`

The Client identity directory layout is:

- `client.crt`
- `client.key`
- `client-identity.txt`

`runewarp client identity renew` reissues `client.crt` with the same key, so the `client-identity` stays stable. `runewarp client identity rotate` changes the key and therefore changes the `client-identity`.

When omitted, `client.identity-material-dir` defaults to the XDG data location for Client identity material.

### `client.server-trust`

Runewarp supports two Client trust modes:

- `system` uses the system trust store
- `ca-file` uses only the configured CA bundle and does not combine it with system roots

When `client.server-trust = "ca-file"` and `client.server-ca-file` is omitted, Runewarp uses the default XDG CA bundle path.

## Validation rules

### General boot-time validation

Runewarp rejects config that violates any of these rules:

- the selected role must have a matching `[server]` or `[client]` section
- `server.hostname` must be present
- exactly one of `[server.acme]` or `[server.cert]` must be present for Server mode
- `client.server-hostname` must be present
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- `client.server-trust` must be either `system` or `ca-file`
- `client.server-ca-file` may be set only when `client.server-trust = "ca-file"`
- all `client-identity` values must be lowercase hex without colons
- all `client-identity` values must be unique across Server Tunnels
- `reconnect-interval` must be at least `1`
- the selected or defaulted material directories and files must exist and be readable, except that the default ACME state directory is created automatically when omitted
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
- `client.server-trust = "ca-file"` is exclusive; the Client does not also use system roots for that Tunnel connection
- binding to `443` on Linux typically requires either elevated privileges or `CAP_NET_BIND_SERVICE`
