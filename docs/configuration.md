# Configuration

This document describes the committed Runewarp configuration model. The current binary now implements the phase-2 Catch-all operator surface with manual TLS material and `runewarp keygen`. Exact-match routing, ACME, and pinned Client-identity enforcement are still future work.

## Principles

- Server config owns public routing
- Client config owns local Service selection
- Hostname mirroring is intentional: operators repeat Public hostnames on both sides
- TLS passthrough is the product boundary, so Local backends must terminate TLS

## CLI shape

```text
runewarp --help
runewarp server --config config.toml
runewarp client --config config.toml
runewarp keygen --out-dir ./certs
```

Current defaults:

- `runewarp server` reads `./config.toml` when `--config` is omitted
- `runewarp client` reads `./config.toml` when `--config` is omitted
- `runewarp keygen` writes into `./certs` when `--out-dir` is omitted

## Current implementation status

Today the binary supports:

- one Catch-all Tunnel on the Server
- one Catch-all Service on the Client
- manual Server certificate and key loading
- optional extra Client CA material layered on top of the system trust store
- generated Client key, certificate, and fingerprint material through `runewarp keygen`

The current binary still rejects:

- multiple Tunnel entries
- multiple Service entries
- `hostnames` on Tunnel or Service entries
- `[server.acme]`

## Catch-all mode

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

In catch-all mode:

- the sole Tunnel matches every routed Public hostname except the Server hostname
- the sole Service receives every proxied Public hostname
- `hostnames` may be omitted only because there is exactly one entry on each side

## Future exact-match mode

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

Exact-match mode keeps routing authority on the Server while the Client uses the mirrored hostnames only for local Service selection. This is the committed design for a later phase; the current binary still implements Catch-all mode only.

## Server reference

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | Server hostname for the Runewarp edge itself. Used for TLS validation and ACME. |
| `server.cert-file` | with manual TLS | Manual certificate path for `server.hostname`. Mutually exclusive with `[server.acme]`. |
| `server.key-file` | with manual TLS | Manual private-key path for `server.hostname`. Mutually exclusive with `[server.acme]`. |
| `server.acme.email` | with ACME | ACME contact address. TLS-ALPN-01 only. |
| `server.acme.cache-dir` | no | Writable path for ACME state and certificates. |
| `server.tunnels[].hostnames` | when more than one Tunnel exists | Exact Public hostnames routed through this Tunnel. Omit only in Catch-all mode. |
| `server.tunnels[].client-public-key-fingerprint` | yes | Lowercase hex SHA-256 fingerprint of the Client's DER-encoded public key, with no colons. |

## Client reference

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-hostname` | yes | Server hostname the Client dials on UDP port `443`. Re-resolved on every reconnect attempt. |
| `client.server-ca-file` | no | Additional trust anchors loaded alongside the system trust store. This augments system trust; it does not replace it. |
| `client.cert-file` | yes | Client certificate for mTLS. |
| `client.key-file` | yes | Client private key for mTLS. |
| `client.retry-interval` | no | Fixed reconnect delay after the first immediate retry. Minimum `1` second. |
| `client.services[].hostnames` | when more than one Service exists | Exact Public hostnames this Service accepts locally. Omit only in Catch-all mode. |
| `client.services[].local-addr` | yes | Local TCP address for the forwarded traffic. This backend must terminate TLS. |

## Hostname mirroring

Runewarp intentionally repeats Public hostnames in Server Tunnels and Client Services:

- the Server uses them to select a Tunnel
- the Client uses them to select a Service after re-reading the forwarded ClientHello
- the runtime does not negotiate or register those hostnames between the two sides

This is a deliberate trade-off to preserve transparent TLS passthrough without adding a routing header to public traffic.

## Validation rules

### General boot-time validation

Runewarp should reject config that violates any of these rules:

- the selected mode must have a matching `[server]` or `[client]` section
- `server.hostname` must be present
- `server.cert-file` and `server.key-file` must appear together when manual TLS is used
- `[server.acme]` is mutually exclusive with manual cert/key configuration
- there must be at least one `[[server.tunnels]]` entry
- there must be at least one `[[client.services]]` entry
- all fingerprints must be lowercase hex without colons
- `retry-interval` must be at least `1`
- certificate, key, and CA files must exist and be readable
- manual `server.cert-file` / `server.key-file` material must parse and form a usable TLS pair
- `local-addr` must parse as a TCP address or host:port pair

### Intra-side hostname uniqueness

Runewarp enforces these rules independently on each side:

- `hostnames` may be omitted only in Catch-all mode
- any exact hostname overlap across Tunnel entries is an error
- any exact hostname overlap across Service entries is an error
- `server.hostname` itself must not be reused as a routed Public hostname
- exact subdomains such as `api.tunnel.example.com` are allowed
- wildcards covering the Server hostname space, such as `*.tunnel.example.com`, should be rejected

### Cross-side hostname coverage

Runewarp does **not** validate that Server Tunnel hostnames match Client Service hostnames at runtime. Under Hostname mirroring, that coverage is an operator responsibility. A future lint or doctor workflow may help detect drift, but the runtime does not turn it into handshake-time registration.

## DNS example

Point your Public hostname at the tunnel server:

```dns
app.example.com. 300 IN CNAME tunnel.example.com.
```

The exact record type is up to the operator. The important part is that Public hostnames resolve to the Server so the Server receives the connection and can route it.

## `runewarp keygen`

`runewarp keygen --out-dir ./certs` should write:

- `client.key`
- `client.crt`
- `client-fingerprint.txt`, containing the Client public-key fingerprint in lowercase hex, without colons, using SHA-256 over the DER-encoded public key

Recommended defaults:

- initial certificate lifetime: `90` days
- renewal target: `60` days
- the same key is reused during ordinary certificate renewal
- rerunning `keygen` into an existing output directory fails instead of overwriting the current Client identity

## Backend behavior

Runewarp opens `local-addr` only when traffic arrives.

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
- multiple Client instances per Tunnel, with shared or separate Client identities
- remote configuration
- lint and doctor tooling for Hostname mirroring
- IPv6-first deployment support
- metrics configuration
