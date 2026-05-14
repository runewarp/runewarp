# Configuration

Runewarp keeps configuration intentionally small. Server config owns public routing. Client config owns local backend selection. Config is always validated on boot for both server and client.

## Status

These docs describe the intended config shape. Early phases support only:

- one catch-all `[[server.tunnels]]` entry
- one catch-all `[[client.services]]` entry

Later phases add multiple tunnel entries, multiple service entries, explicit hostname lists, wildcard hostnames, and more advanced pooling.

## CLI conventions

```text
runewarp --help
runewarp server --config config.toml
runewarp client --config config.toml
runewarp keygen --out-dir ./certs
```

Rules:

- `runewarp` by itself is the same as `runewarp --help`
- `runewarp server` reads the `[server]` section
- `runewarp client` reads the `[client]` section
- if your config file is not named `config.toml`, pass `--config`

## Early-phase minimal config

### Server

```toml
[server]
hostname = "tunnel.example.com"
cert-file = "/etc/runewarp/server.crt"
key-file = "/etc/runewarp/server.key"

[[server.tunnels]]
client-public-key-fingerprint = "4f7b6f7a9b0f0d2b..."
```

### Client

```toml
[client]
server-hostname = "tunnel.example.com"
server-ca-file = "/etc/runewarp/server-ca.pem"
cert-file = "/etc/runewarp/client.crt"
key-file = "/etc/runewarp/client.key"
retry-interval = 5

[[client.services]]
local-addr = "127.0.0.1:443"
```

In this mode:

- the single server tunnel catches every valid SNI
- the single client service receives every forwarded connection

## Later-phase expanded shape

### Server

```toml
[server]
hostname = "tunnel.example.com"

[server.acme]
email = "admin@example.com"
cache-dir = "/var/lib/runewarp/acme"

[[server.tunnels]]
hostnames = ["app.example.com", "api.example.com"]
client-public-key-fingerprint = "4f7b6f7a9b0f0d2b..."

[[server.tunnels]]
hostnames = ["plex.example.com", "pihole.example.com"]
client-public-key-fingerprint = "2a6cc0f0a14b4b21..."
```

### Client

```toml
[client]
server-hostname = "tunnel.example.com"
server-ca-file = "/etc/runewarp/server-ca.pem"
cert-file = "/etc/runewarp/client.crt"
key-file = "/etc/runewarp/client.key"
retry-interval = 5

[[client.services]]
hostnames = ["app.example.com", "api.example.com"]
local-addr = "caddy.local:443"

[[client.services]]
hostnames = ["plex.example.com", "pihole.example.com"]
local-addr = "caddy.local:8443"
```

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | Hostname for the tunnel endpoint itself. Used for TLS validation and ACME. |
| `server.cert-file` | with manual TLS | Manual certificate path for `server.hostname`. Mutually exclusive with `[server.acme]`. |
| `server.key-file` | with manual TLS | Manual private-key path for `server.hostname`. Mutually exclusive with `[server.acme]`. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.cache-dir` | no | Writable path for ACME state and certificates. |
| `server.tunnels[].hostnames` | later phases | Required once more than one tunnel exists. Omit only for the single-tunnel catch-all form. |
| `server.tunnels[].client-public-key-fingerprint` | yes | Lowercase hex SHA-256 fingerprint of the client's DER-encoded public key, with no colons. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | Hostname the client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.server-ca-file` | no | Additional trust anchors loaded alongside the system trust store. This augments system trust; it does not replace it. A self-signed server cert or private CA can live here without being installed system-wide. |
| `client.cert-file` | yes | Client certificate for mTLS. |
| `client.key-file` | yes | Client private key for mTLS. |
| `client.retry-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].hostnames` | later phases | Required once more than one service exists. Omit only for the single-service catch-all form. |
| `client.services[].local-addr` | yes | Local TCP address for the forwarded stream. This backend must terminate TLS. |

## Validation rules

At boot, Runewarp should reject config that violates any of these rules:

- selected mode must have a matching `[server]` or `[client]` section
- `server.hostname` must be present
- `server.cert-file` and `server.key-file` must appear together when manual TLS is used
- `[server.acme]` is mutually exclusive with manual cert/key configuration
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- `hostnames` may be omitted only when there is exactly one tunnel or exactly one service
- any exact hostname overlap across tunnel entries is an error
- any exact hostname overlap across service entries is an error
- `server.hostname` itself must not be reused as a routed hostname
- subdomains such as `api.tunnel.example.com` are allowed
- wildcards covering the server hostname space, such as `*.tunnel.example.com`, should be rejected
- all fingerprints must be lowercase hex without colons
- `retry-interval` must be at least `1`
- cert, key, and CA files must exist and be readable
- `local-addr` must parse as a TCP address or host:port pair

Runewarp does **not** validate that server-side routed hostnames match client-side service hostnames. A mismatch is discovered only when traffic reaches the client.

## DNS example

Point your public hostname at the tunnel server:

```dns
app.example.com. 300 IN CNAME tunnel.example.com.
```

The exact record type is up to the operator. The important part is that public hostnames resolve to the server so the server receives the connection and can route it.

## `runewarp keygen`

`runewarp keygen --out-dir ./certs` should write:

- a client private key
- an initial self-signed client certificate
- the client public-key fingerprint in lowercase hex, without colons, using SHA-256 over the DER-encoded public key

Recommended defaults:

- initial certificate lifetime: `90` days
- renewal target: `60` days
- same key reused during ordinary certificate renewal

## Backend behavior

Runewarp opens `local-addr` only when traffic arrives.

- there is no local backend health check
- local backends must terminate TLS
- plain HTTP backends are out of scope for this design

## Deployment notes

Binding to `443` requires elevated privileges on Linux. Common options are:

- `CAP_NET_BIND_SERVICE`
- `setcap cap_net_bind_service=+ep /path/to/runewarp`
- a local firewall redirect during development

Early phases keep the listen port fixed at `443`. Later phases should allow configurable public and tunnel ports, and eventually per-hostname public ports.

## Logging

Early phases should default to human-readable logs. Structured JSON logging is a later feature.

## Future config work

- multiple fingerprints per tunnel entry
- wildcard hostnames
- remote server configuration
- IPv6-first deployment support
- metrics configuration
