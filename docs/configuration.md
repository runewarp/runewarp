# Configuration

This document defines the Runewarp configuration model. Use [`docs/usage.md`](usage.md) for the operator workflow and this document for exact keys, validation rules, and example config shapes.

## Configuration ownership

| Config area | Owns |
| --- | --- |
| `[server]` | Public routing, Server identity, and the Server certificate path |
| `[[server.tunnels]]` | Explicit **Public hostname** authorization and the pinned **Client identity** for one **Tunnel** |
| `[client]` | Tunnel dialing, Server trust, Client identity material, and optional TLS termination certificate config |
| `[[client.services]]` | Local routing from one or more **Public hostnames** to one **Local backend**, with per-Service TLS mode |

## Configuration principles

- Server config owns public routing
- Client config owns local **Service** selection
- the Server routes only explicitly authorized **Public hostnames** into a **Tunnel**
- **Hostname mirroring** and **One-sided Catch-all** are the two supported routing topologies
- TLS passthrough is the default; Local backends terminate TLS in that mode
- Client TLS termination is opt-in per Service via `tls-mode = "terminate"`; the termination certificate is managed at client level via `client.public-cert-dir` (manual) or `[client.acme]`
- config keys should name the product concept rather than an encoding detail

## Supported routing shapes

| Shape | Server | Client |
| --- | --- | --- |
| Exact-match on both sides | Every Tunnel lists explicit `public-hostnames` | Every Service lists explicit `public-hostnames` |
| One-sided Catch-all | Every Tunnel lists explicit `public-hostnames` | The sole Service omits `public-hostnames` |

Server Catch-all is intentionally not supported. Catch-all Services must use `tls-mode = "passthrough"` (the default); they cannot opt into TLS termination.

## CLI entry points

```text
runewarp server --config config.toml
runewarp server cert init --dir ./server-cert --hostname tunnel.example.com
runewarp server cert renew --dir ./server-cert
runewarp server cert rotate-ca --dir ./server-cert --hostname tunnel.example.com

runewarp client --config config.toml
runewarp client --server-address tunnel.example.com --backend-address 127.0.0.1:443
runewarp client identity init --dir ./client-identity
runewarp client identity renew --dir ./client-identity
runewarp client identity rotate --dir ./client-identity
runewarp client public-cert init --dir ./public-cert --hostname app.example.com
runewarp client --config config.toml public-cert init
runewarp client public-cert renew --dir ./public-cert --hostname app.example.com
runewarp client --config config.toml public-cert renew
runewarp client --config config.toml public-cert rotate-ca
```

`--server-address` and `--backend-address` are runtime-only flags on `runewarp client`. They are not accepted by `runewarp client identity ...`.

Material-management commands also accept `--config` and resolve their working directory with this precedence:

1. explicit `--dir`
2. the configured material directory from the selected config file
3. the XDG default for that command

## Runtime config discovery

When `runewarp server` or `runewarp client` omit `--config`, Runewarp loads:

- `$XDG_CONFIG_HOME/runewarp/config.toml`, or
- `~/.config/runewarp/config.toml` when `XDG_CONFIG_HOME` is unset

For `runewarp client`, config/runtime precedence is:

1. an explicit `--config` path selects that file and a missing explicit path remains an error
2. otherwise, a discovered default config file is selected when it exists
3. otherwise, there is no selected Client config and `runewarp client` may start in the CLI-only shape when both `--server-address` and `--backend-address` are present

When a selected config file is involved:

- `--server-address` may replace `client.server-address` before validation
- `--backend-address` may supply the sole Catch-all Service only when the selected config contributes no `[[client.services]]` blocks
- any configured Service blocks `--backend-address`, even when that Service block is malformed
- a selected file with no `[client]` section may still start the Client when both runtime flags are present

Pure CLI-only Client startup keeps using the normal omitted-key defaults for `client.server-trust`, `client.identity-dir`, `client.logs`, and the runtime reconnect cadence.

## Default locations

When the matching config key is omitted, Runewarp uses:

| Purpose | Default location |
| --- | --- |
| Runtime config | `$XDG_CONFIG_HOME/runewarp/config.toml` or `~/.config/runewarp/config.toml` |
| Manual/private-CA Server material | `$XDG_DATA_HOME/runewarp/server/cert/` or `~/.local/share/runewarp/server/cert/` |
| Client identity material | `$XDG_DATA_HOME/runewarp/client/identity/` or `~/.local/share/runewarp/client/identity/` |
| Client CA bundle for `server-trust = "ca-file"` | `$XDG_DATA_HOME/runewarp/client/server-ca.crt` or `~/.local/share/runewarp/client/server-ca.crt` |
| Server ACME state | `$XDG_STATE_HOME/runewarp/server/acme/` or `~/.local/state/runewarp/server/acme/` |
| Client ACME state | `$XDG_STATE_HOME/runewarp/client/acme/` or `~/.local/state/runewarp/client/acme/` |

## Example: Server with manual/private-CA certificates

```toml
[server]
hostname = "tunnel.example.com"
cert-dir = "/etc/runewarp/server"

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
server-address = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

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
server-address = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

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
server-address = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

[[client.services]]
public-hostnames = ["app.example.com", "api.example.com"]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
backend-address = "caddy.local:8443"
```

The grouping of hostnames into **Tunnels** and **Services** may differ. One Tunnel can serve multiple Services, and one Service can own multiple **Public hostnames** when they share one **Local backend**.

## Example: Client TLS termination with manual certificate

```toml
[client]
server-address = "tunnel.example.com"
identity-dir = "/etc/runewarp/client"
public-cert-dir = "/etc/runewarp/client/public-cert"

[[client.services]]
public-hostnames = ["app.example.com"]
backend-address = "127.0.0.1:8080"
tls-mode = "terminate"
```

## Example: Client TLS termination with ACME

```toml
[client]
server-address = "tunnel.example.com"
identity-dir = "/etc/runewarp/client"

[client.acme]
email = "admin@example.com"
state-dir = "/var/lib/runewarp/client/acme"

[[client.services]]
public-hostnames = ["app.example.com"]
backend-address = "127.0.0.1:8080"
tls-mode = "terminate"
```

`tls-mode = "terminate"` requires explicit `public-hostnames` (Catch-all Services cannot terminate). `client.public-cert-dir` and `[client.acme]` are mutually exclusive and both require at least one Service using `tls-mode = "terminate"`.

## Example: Mixed terminate and passthrough services

A single Client can host one Service that terminates TLS and another that passes TLS through unchanged to the local backend:

```toml
[client]
server-address = "tunnel.example.com"
identity-dir = "/etc/runewarp/client"
public-cert-dir = "/etc/runewarp/client/public-cert"

# Service A: Client terminates TLS; backend receives plaintext
[[client.services]]
public-hostnames = ["app.example.com"]
backend-address = "127.0.0.1:8080"
tls-mode = "terminate"

# Service B: Client passes raw TLS bytes through; backend terminates TLS
[[client.services]]
public-hostnames = ["api.example.com"]
backend-address = "127.0.0.1:9443"
tls-mode = "passthrough"
```

Certificate material in `public-cert-dir` is only required for the terminating hostnames (`app.example.com` above).  The passthrough service (`api.example.com`) requires no certificate material on the Client side — the local backend is responsible for its own TLS certificate.

Runtime logs distinguish the two paths:

```
client route app.example.com -> terminated and forwarded
client route api.example.com -> passthrough
```

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | **Server hostname** for the Runewarp edge itself. Used for TLS validation and ACME. |
| `server.logs` | no | Boolean controlling human-readable Server runtime logs. Defaults to `true`. |
| `server.cert-dir` | no | Directory containing the deployed Server leaf material for the manual/private-CA path. Defaults to the XDG data path for manual/private-CA Server material when `[server.acme]` is absent. Mutually exclusive with `[server.acme]`. |
| `server.public-bind-address` | no | Literal TCP socket address for **Visitor** TLS traffic. Defaults to `0.0.0.0:443`. |
| `server.tunnel-bind-address` | no | Literal UDP socket address for **Client** tunnel connections. Defaults to `0.0.0.0:443`. |
| `server.acme.email` | with ACME | Let's Encrypt ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-dir` | no | Writable path for durable ACME account and certificate state. When omitted, Runewarp uses and creates the XDG default state directory at startup. |
| `server.tunnels[].public-hostnames` | yes | One or more exact **Public hostnames** routed through this Tunnel. |
| `server.tunnels[].client-identity` | yes | Lowercase hex SHA-256 fingerprint of the Client public key's SubjectPublicKeyInfo. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-address` | runtime or config | **Server address** the Client dials for its tunnel connection, written as `hostname[:port]`. The host part must be a hostname, not a raw IP literal. When the port is omitted, Runewarp uses UDP port `443`. On `runewarp client`, `--server-address` may supply or replace this value before validation. |
| `client.server-trust` | no | `system` or `ca-file`. Defaults to `system`. |
| `client.server-ca-file` | no | Exclusive CA bundle for the Server hostname. Valid only when `client.server-trust = "ca-file"`; otherwise system trust is used. When omitted in `ca-file` mode, Runewarp uses the XDG default CA bundle path. |
| `client.identity-dir` | no | Directory containing the Client keypair, certificate, and `client-identity.txt`. Defaults to the XDG data path for Client identity material. |
| `client.logs` | no | Boolean controlling human-readable Client runtime logs. Defaults to `true`. |
| `client.public-cert-dir` | when using manual TLS termination | Directory containing the public certificate material for Client-side TLS termination. Mutually exclusive with `[client.acme]`. Required when any Service uses `tls-mode = "terminate"` and no `[client.acme]` is present; runtime validation does not implicitly enable manual mode from the XDG default path. |
| `client.acme.email` | with Client ACME | ACME contact address for the Client public certificate. Required when `[client.acme]` is present. |
| `client.acme.state-dir` | no | Writable path for durable ACME account and certificate state for the Client. When omitted, Runewarp uses and creates the XDG default client ACME state directory at startup. |
| `client.services[].public-hostnames` | when exact-match local routing is desired | Exact **Public hostnames** this Service accepts locally. Omit only on the sole Catch-all Service. Required when `tls-mode = "terminate"`. |
| `client.services[].backend-address` | yes, per Service block | TCP endpoint for the forwarded traffic. When `tls-mode = "passthrough"` (default), this backend must terminate TLS. When `tls-mode = "terminate"`, the Client terminates TLS and connects to the backend in plaintext. `runewarp client --backend-address` may synthesize the sole Catch-all Service only when the selected config contributes no `[[client.services]]` blocks at all. |
| `client.services[].tls-mode` | no | `passthrough` or `terminate`. Defaults to `passthrough`. Catch-all Services must use `passthrough`. |

## Trust and material directories

### `server.cert-dir`

The manual/private-CA directory layout is:

- `server.crt`
- `server.key`
- `server-ca.crt`
- `state/` for renewal state, including the private Server CA key in the simple on-box manual path

`runewarp server cert renew` reissues `server.crt` from the existing **Server CA**. `runewarp server cert rotate-ca` changes the trust anchor itself and requires Clients to trust a new CA.

When omitted and `[server.acme]` is absent, `server.cert-dir` defaults to the XDG data location for Server certificate material.

### `client.identity-dir`

The Client identity directory layout is:

- `client.crt`
- `client.key`
- `client-identity.txt`

`runewarp client identity renew` reissues `client.crt` with the same key, so the `client-identity` stays stable. `runewarp client identity rotate` changes the key and therefore changes the `client-identity`.

When omitted, `client.identity-dir` defaults to the XDG data location for Client identity material.

### `client.public-cert-dir`

When one or more Services use `tls-mode = "terminate"`, the Client needs a public certificate authority and per-hostname leaf certificates. Bootstrap these with:

```
runewarp client public-cert init --hostname app.example.com

# or derive all terminating hostnames from config:
runewarp client --config client.toml public-cert init
```

The directory layout is:

- `public-ca.crt` — CA certificate (share this with Visitors as their trust anchor)
- `state/public-ca.key` — CA private key (keep private)
- `{hostname}/public.crt` — Leaf certificate for the named hostname
- `{hostname}/public.key` — Leaf key for the named hostname

To add a certificate for another hostname in the same directory:

```
runewarp client public-cert init --dir ./public-cert --hostname api.example.com
```

`runewarp client public-cert init` refuses to overwrite an existing CA, so running it a second time with a new hostname reuses the original CA and only writes new leaf material. The Visitor-facing `public-ca.crt` therefore stays stable across additions and leaf renewals; only `rotate-ca` changes that trust anchor.

**Renewing a leaf certificate:**

```bash
# Explicit hostname:
runewarp client public-cert renew --hostname app.example.com

# All terminating hostnames from config (--hostname omitted):
runewarp client --config client.toml public-cert renew
```

When `--hostname` is omitted the target set is derived from `public-hostnames` on `tls-mode = "terminate"` services in the config. Omitting both `--hostname` and `--config` is an error; Runewarp never infers targets from on-disk directories.

**Rotating the Client public CA:**

```bash
runewarp client --config client.toml public-cert rotate-ca
```

`rotate-ca` replaces the shared CA and reissues every managed leaf certificate. `--config` is required. After rotation, distribute the new `public-ca.crt` to Visitors so they trust the new trust anchor.

The `client public-cert` commands resolve their working directory from `--dir`, then `client.public-cert-dir`, then the XDG default data location when neither is set. Runtime validation is stricter: manual TLS termination is enabled only when `client.public-cert-dir` is set explicitly in config; Runewarp does not infer manual mode from the XDG default path.

### `client.server-trust`

Runewarp supports two Client trust modes:

- `system` uses the system trust store
- `ca-file` uses only the configured CA bundle and does not combine it with system roots

When `client.server-trust = "ca-file"` and `client.server-ca-file` is omitted, Runewarp uses the default XDG CA bundle path.

## Validation rules

### General boot-time validation

Runewarp rejects config and startup inputs that violate any of these rules:

- `runewarp server` requires a `[server]` section
- `runewarp client` requires either a selected `[client]` section or both runtime routing flags when no selected Client config exists or the selected file has no `[client]` section
- `server.hostname` must be present
- `[server.acme]` and `server.cert-dir` are mutually exclusive; when `[server.acme]` is absent, Runewarp uses the manual/private-CA path with `server.cert-dir` or its default XDG location
- `runewarp client` must end up with a **Server address** after any allowed `--server-address` overlay
- there must be at least one `[[server.tunnels]]` entry
- `runewarp client` must end up with at least one **Service**, either from config or from the runtime `--backend-address` Catch-all overlay
- `client.server-trust` must be either `system` or `ca-file`
- `client.server-ca-file` may be set only when `client.server-trust = "ca-file"`
- `--backend-address` may be used only when the selected config contributes no `[[client.services]]` blocks
- all `client-identity` values must be lowercase hex without colons
- all `client-identity` values must be unique across Server Tunnels
- `server.public-bind-address` and `server.tunnel-bind-address` must be literal socket addresses
- the selected or defaulted material directories and files must exist and be readable, except that default ACME state directories are created automatically when omitted
- `backend-address` must parse as a TCP address or host:port pair

### Client TLS termination validation

- `client.services[].tls-mode` must be `"passthrough"` or `"terminate"`; defaults to `"passthrough"`
- `client.services[].tls-mode = "terminate"` requires explicit `public-hostnames` on that Service; Catch-all Services cannot opt into termination
- when any Service uses `tls-mode = "terminate"`, either `client.public-cert-dir` or `[client.acme]` must be present
- `client.public-cert-dir` and `[client.acme]` require at least one Service with `tls-mode = "terminate"`; the config is rejected when no terminating Service is present
- `client.public-cert-dir` and `[client.acme]` are mutually exclusive
- `client.public-cert-dir` must be an existing directory
- `client.acme.email` is required when `[client.acme]` is present
- `client.acme.state-dir` must be an existing directory when specified; when omitted, the XDG default is used and created automatically

### Hostname rules

Runewarp enforces these rules independently on each side:

- `server.tunnels[].public-hostnames` is always required
- `client.services[].public-hostnames` may be omitted only when there is exactly one Service
- `public-hostnames = []` is an error on either side
- hostnames are normalized to lowercase and a trailing dot is stripped before comparison
- `public-hostnames` must be DNS hostnames, including punycode A-labels; raw Unicode, IP literals, and wildcards are rejected
- the host portion of `client.server-address` must be a DNS hostname; raw IP literals are rejected
- any exact hostname overlap across Tunnel entries after normalization is an error
- any exact hostname overlap across Service entries after normalization is an error
- `server.hostname` itself must not be reused as a routed **Public hostname**

### Cross-side hostname coverage

Runewarp does not validate cross-side hostname coverage at runtime:

- under **Hostname mirroring**, repeating the explicit hostname set on both sides is an operator responsibility
- under **One-sided Catch-all**, the Server carries the explicit hostname set while the Client intentionally does not

## Operational notes

- `backend-address` is opened only when traffic arrives
- **Local backends** must terminate TLS when `tls-mode = "passthrough"` (default)
- `client.server-trust = "ca-file"` is exclusive; the Client does not also use system roots for that Tunnel connection
- binding to `443` on Linux typically requires either elevated privileges or `CAP_NET_BIND_SERVICE`
