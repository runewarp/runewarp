# Configuration

Use this document as the configuration reference: keys, defaults, validation rules, and example shapes. Use [`docs/usage.md`](usage.md) for the step-by-step operator workflow. Use [`docs/managed.md`](managed.md) for the Managed-session Control protocol and interoperability contract.

Runewarp `0.1.x` is a public pre-1.0 release line. Minor releases may include breaking CLI or configuration changes, so use the config reference that matches the version you deploy.

## Who configures what

| Config area | Owns |
| --- | --- |
| `[control]` | Managed-mode Control endpoint address and Control trust |
| `[server]` | Public routing, Server identity, and the Server certificate path |
| `[[server.tunnels]]` | Explicit **Public hostname** authorization and one or more pinned **Client identities** for one **Tunnel** |
| `[client]` | Tunnel dialing, Server trust, Client identity material, and optional terminate-mode certificate management |
| `[[client.services]]` | Local routing from one or more **Public hostnames** to one **Local backend**, with per-Service TLS mode |

Runewarp keeps routing split cleanly:

- Server config owns **Public hostname authorization**
- Client config owns local **Service** selection
- the supported routing shapes are **Hostname mirroring** and a **Client with a Catch-all Service**
- Server Catch-all is not supported
- Catch-all Services must use `tls-mode = "passthrough"`

## Routing shapes

| Shape | Server | Client | When to use it |
| --- | --- | --- | --- |
| **Hostname mirroring** | Every Tunnel lists explicit `public-hostnames` | Every Service lists explicit `public-hostnames` | You want explicit local routing per hostname set |
| **Client with a Catch-all Service** | Every Tunnel lists explicit `public-hostnames` | The sole Service omits `public-hostnames` | One Client backend should receive every admitted hostname |

One Tunnel can still cover multiple Services, and one Service can still cover multiple **Public hostnames**. The grouping does not need to line up one-to-one across both sides.

## Runtime config discovery

When `runewarp server` or `runewarp client` omit `--config`, Runewarp loads:

- `$XDG_CONFIG_HOME/runewarp/config.toml`, or
- `~/.config/runewarp/config.toml` when `XDG_CONFIG_HOME` is unset

For `runewarp server`, config/runtime precedence is:

1. an explicit `--config` path selects that file and a missing explicit path remains an error
2. otherwise, the discovered default config file is selected
3. `runewarp server --hostname <HOSTNAME>` replaces `server.hostname` from the selected config before validation
4. when `--hostname` is omitted, `RUNEWARP_SERVER_HOSTNAME` replaces `server.hostname` from the selected config before validation
5. `runewarp server --control-address <HOSTNAME[:PORT]>` replaces `control.address` from the selected config before validation and enables managed mode when an effective Control address is present

The Server runtime stays config-file-first: only `server.hostname` and the effective Control address are overridable at runtime. `--hostname` and `--control-address` belong only to the runtime `runewarp server` command, not `runewarp server cert ...`.

For `runewarp client`, config/runtime precedence is:

1. an explicit `--config` path selects that file and a missing explicit path remains an error
2. otherwise, a discovered default config file is selected when it exists
3. otherwise, there is no selected Client config and `runewarp client` may start in the CLI-only shape when `--control-address` and `--backend-address` are present, or in the static shape when at least one `--server-address` and `--backend-address` are present

When a selected config file is involved:

- repeated `--server-address` flags replace either `client.server-address` or `client.server-addresses` before validation
- `--control-address` replaces `control.address` before validation and enables managed mode when an effective Control address is present
- `--backend-address` may supply the sole Catch-all Service only when the selected config contributes no `[[client.services]]` blocks
- any configured Service blocks `--backend-address`, even when that Service block is malformed
- a selected file with no `[client]` section may still start the Client when both runtime flags are present

## Default locations

When the matching config key is omitted, Runewarp uses:

| Purpose | Default location |
| --- | --- |
| Runtime config | `$XDG_CONFIG_HOME/runewarp/config.toml` or `~/.config/runewarp/config.toml` |
| Manual/private-CA Server material | `$XDG_DATA_HOME/runewarp/server/cert/` or `~/.local/share/runewarp/server/cert/` |
| Client identity material | `$XDG_DATA_HOME/runewarp/client/identity/` or `~/.local/share/runewarp/client/identity/` |
| Manual Public hostname certificates | `$XDG_DATA_HOME/runewarp/client/public-cert/` or `~/.local/share/runewarp/client/public-cert/` |
| Client CA bundle for `server-trust = "ca-file"` | `$XDG_DATA_HOME/runewarp/client/server-ca.crt` or `~/.local/share/runewarp/client/server-ca.crt` |
| Control CA bundle for `control.trust = "ca-file"` | `$XDG_DATA_HOME/runewarp/control/ca.crt` or `~/.local/share/runewarp/control/ca.crt` |
| Server identity material (managed mode) | `$XDG_DATA_HOME/runewarp/server/identity/` or `~/.local/share/runewarp/server/identity/` |
| Server ACME state | `$XDG_STATE_HOME/runewarp/server/acme/` or `~/.local/state/runewarp/server/acme/` |
| Client ACME state | `$XDG_STATE_HOME/runewarp/client/acme/` or `~/.local/state/runewarp/client/acme/` |

## Examples

### Minimal Server

```toml
[server]
hostname = "tunnel.example.com"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identities = [
  "4f7b6f7a9b0f0d2b...",
  "91e92c8a5df6a44e...",
]
```

Add `[server.acme]` for the ACME path, or `server.cert-dir` for the manual/private-CA path.

### Managed Server

```toml
[control]
address = "control.example.com"
trust = "system"

[server]
hostname = "tunnel.example.com"
cert-dir = "/etc/runewarp/server-cert"
identity-dir = "/etc/runewarp/server-identity"
```

Managed mode requires an effective Control address, allows empty `[[server.tunnels]]`, and requires `server.identity-dir` material distinct from `server.cert-dir`. Authorization comes only from Control-published Server snapshots after process start; the Server stays Unready and admits no Tunnel or Visitor work until the first successful apply. See [`managed.md`](managed.md) for the session wire contract.

### Managed Client

```toml
[control]
address = "control.example.com"
trust = "system"

[client]
identity-dir = "/etc/runewarp/client"

[[client.services]]
backend-address = "127.0.0.1:443"
```

Managed Client mode omits static Server addresses. Assignment comes only from Control-published Client snapshots after process start; the Client maintains no Tunnel connections until the first successful apply. Services and TLS mode remain local.

### Client with exact-match routing

```toml
[client]
server-address = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

[[client.services]]
public-hostnames = ["app.example.com", "api.example.com"]
backend-address = "localhost:8443"

[[client.services]]
public-hostnames = ["plex.example.com", "pihole.example.com"]
backend-address = "caddy.local:8443"
```

### Client with a Catch-all Service

```toml
[client]
server-address = "tunnel.example.com"
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

[[client.services]]
backend-address = "127.0.0.1:443"
```

This shape is valid only when there is exactly one Service.

### Client with static fanout

```toml
[client]
server-addresses = ["tunnel-a.example.com", "tunnel-b.example.com"]
server-trust = "ca-file"
server-ca-file = "/etc/runewarp/server-ca.crt"
identity-dir = "/etc/runewarp/client"

[[client.services]]
backend-address = "127.0.0.1:443"
```

Use `client.server-address` for the common one-target case. Use `client.server-addresses` when one Client instance should reconcile multiple Server addresses concurrently.

### Client terminate mode

```toml
[client]
server-address = "tunnel.example.com"
identity-dir = "/etc/runewarp/client"

[[client.services]]
public-hostnames = ["app.example.com"]
backend-address = "127.0.0.1:8080"
tls-mode = "terminate"
```

Add `[client.acme]` for ACME-managed certificates, or `client.public-cert-dir` for the manual **Public hostname certificate** path. Catch-all Services cannot terminate TLS.

## Key reference

### Top-level

| Key | Required | Notes |
| --- | --- | --- |
| `log-level` | no | Top-level runtime stderr log level for the selected role. Supported values: `off`, `error`, `warn`, `info`, `debug`, `trace`. Defaults to `info`. `trace` is accepted, but no trace-only runtime events are emitted today, so it currently behaves the same as `debug`. |

At `info`, Runewarp emits readiness, tunnel connection lifecycle events, warnings, and errors. `debug` adds routing diagnostics and ACME challenge-handling detail. Output is stderr-only and each line uses a UTC RFC3339 timestamp, level, and message.

### Control

| Key | Required | Notes |
| --- | --- | --- |
| `control.address` | when `[control]` is present | DNS hostname with optional port for the Control endpoint. HTTPS is mandatory and inferred. Schemes, paths, and IP literals are rejected. On `runewarp server` and `runewarp client`, `--control-address` may replace this value before validation. |
| `control.trust` | no | `system` or `ca-file`. Defaults to `system`. |
| `control.ca-file` | no | Exclusive CA bundle for the Control endpoint. Valid only when `control.trust = "ca-file"`. When omitted in `ca-file` mode, Runewarp uses the XDG default Control CA path. |

### Server

| Key | Required | Notes |
| --- | --- | --- |
| `server.hostname` | yes | **Server hostname** for the Runewarp edge itself. Used for TLS validation and ACME. On the runtime `runewarp server` command only, `--hostname` or `RUNEWARP_SERVER_HOSTNAME` may replace this value before validation, with `--hostname` taking precedence. |
| `server.cert-dir` | no | Directory containing manual/private-CA Server material. Defaults to the XDG Server material path when `[server.acme]` is absent. Mutually exclusive with `[server.acme]`. |
| `server.identity-dir` | managed only | Directory containing Server identity material for Control authentication. Valid only in managed mode. Defaults to the XDG Server identity path. Must resolve to a different directory than `server.cert-dir`. |
| `server.public-bind-address` | no | Literal TCP socket address for **Visitor** TLS traffic. Defaults to `0.0.0.0:443`. |
| `server.tunnel-bind-address` | no | Literal UDP socket address for **Client** **Tunnel connections**. Defaults to `0.0.0.0:443`. |
| `server.readiness-bind-address` | no | Optional literal TCP socket address for a probe-only **Server readiness** listener. When configured, TCP accept success means the Server is ready for new ingress admission. There is no default listener. In managed mode the listener address is validated at startup, but the probe stays Unready until the first successful Server input apply. |
| `server.graceful-shutdown-duration` | no | Operator-facing graceful drain window for the Server role. Defaults to `"60s"`. Supports non-negative integer durations with `ms`, `s`, `m`, or `h` suffixes. `"0s"` disables the longer drain window and makes graceful Server shutdown converge to fast Server behavior. |
| `server.acme.email` | with ACME | Let's Encrypt ACME contact address. TLS-ALPN-01 only. |
| `server.acme.state-dir` | no | Writable path for durable ACME account and certificate state. When omitted, Runewarp uses the XDG default state path and creates it during startup after validation succeeds. |
| `server.tunnels[].public-hostnames` | yes | One or more exact **Public hostnames** routed through this Tunnel. |
| `server.tunnels[].client-identity` | with singular authorization | Lowercase hex SHA-256 fingerprint of one authorized Client public key's SubjectPublicKeyInfo. Mutually exclusive with `server.tunnels[].client-identities`. |
| `server.tunnels[].client-identities` | with plural authorization | One or more lowercase hex SHA-256 fingerprints of authorized Client public keys' SubjectPublicKeyInfo values. Mutually exclusive with `server.tunnels[].client-identity`. |

### Client

| Key | Required | Notes |
| --- | --- | --- |
| `client.server-address` | runtime or config | Ergonomic single-target **Server address** shortcut, written as `hostname[:port]`. Mutually exclusive with `client.server-addresses`. When the port is omitted, Runewarp uses UDP port `443`. On `runewarp client`, one `--server-address` may supply or replace this value before validation. |
| `client.server-addresses` | no | One or more explicit **Server addresses** for static fanout. Mutually exclusive with `client.server-address`. Each entry uses the same `hostname[:port]` rules as the singular field. Repeated `--server-address` flags replace this list before validation. |
| `client.server-trust` | no | `system` or `ca-file`. Defaults to `system`. |
| `client.server-ca-file` | no | Exclusive CA bundle for the Server hostname. Valid only when `client.server-trust = "ca-file"`. When omitted in `ca-file` mode, Runewarp uses the XDG default CA bundle path. |
| `client.identity-dir` | no | Directory containing the Client keypair, certificate, and `client-identity.txt`. Defaults to the XDG Client identity path. |
| `client.public-cert-dir` | no | Directory containing manual **Public hostname certificate** material for terminate mode. Mutually exclusive with `[client.acme]`. When any Service uses `tls-mode = "terminate"` and `[client.acme]` is absent, Runewarp uses this directory or, when omitted, the XDG default public-cert path. |
| `client.acme.email` | with Client ACME | ACME contact address for **Public hostname certificates**. Required when `[client.acme]` is present. |
| `client.acme.state-dir` | no | Writable path for durable Client ACME state. When omitted, Runewarp uses the XDG default state path and creates it during startup after validation succeeds. |
| `client.services[].public-hostnames` | when exact-match local routing is desired | Exact **Public hostnames** this Service accepts locally. Omit only on the sole Catch-all Service. Required when `tls-mode = "terminate"`. |
| `client.services[].backend-address` | yes, per Service block | TCP endpoint for the forwarded traffic. Under `passthrough` the **Local backend** terminates TLS. Under `terminate` the Client terminates TLS and connects to the backend in plaintext. `runewarp client --backend-address` may synthesize the sole Catch-all Service only when the selected config contributes no `[[client.services]]` blocks at all. |
| `client.services[].tls-mode` | no | `passthrough` or `terminate`. Defaults to `passthrough`. Catch-all Services must use `passthrough`. |

Client reconnect behavior is runtime-owned. There is no `client.reconnect-interval` setting or CLI flag; both config-driven and CLI-only startup use the same built-in jittered backoff described in `docs/protocol.md`.

## Certificates and trust

### Server certificate material

`server.cert-dir` holds:

- `server.crt`
- `server.key`
- `server-ca.crt`
- `state/` for renewal state, including the private Server CA key in the simple on-box manual path

`runewarp server cert renew` reissues `server.crt` from the existing **Server CA**. `runewarp server cert rotate-ca` changes the trust anchor itself and requires Clients to trust a new CA.

When `[server.acme]` is enabled, Runewarp warns at startup if `server.public-bind-address` is not on TCP 443. That warning is advisory rather than fatal because container and NAT deployments may still publish port 443 externally even when the internal bind port differs.

### Client identity material

`client.identity-dir` holds:

- `client.crt`
- `client.key`
- `client-identity.txt`

`runewarp client identity rotate` changes the key and therefore changes the `client-identity`. Self-signed Client identity certificates are operationally non-expiring key carriers; Core does not renew them automatically or through a CLI subcommand.

### Terminate-mode certificate material

When one or more Services use `tls-mode = "terminate"`, the Client needs either manual **Public hostname certificate** material or `[client.acme]`.

`client.public-cert-dir` holds:

- `public-ca.crt`
- `state/public-ca.key`
- `{hostname}/public.crt`
- `{hostname}/public.key`

`runewarp client public-cert init` keeps the shared **Public hostname CA** stable. `renew` reissues leaves under the same CA. `rotate-ca` replaces the CA and requires Visitors to trust the new `public-ca.crt`.

`[client.acme]` still depends on public TCP 443 reachability at the Server edge because `acme-tls/1` traffic for terminating **Public hostnames** follows the same public ingress and Tunnel path as ordinary Visitor TLS.

### Control trust

When managed mode is enabled, Runewarp supports the same exclusive trust modes for the Control endpoint as for tunnel Server addresses:

- `system` uses the system trust store
- `ca-file` uses only the configured CA bundle and does not combine it with system roots

### Server identity material (managed mode)

`server.identity-dir` holds:

- `server.crt`
- `server.key`
- `server-identity.txt`

This material authenticates the Server to Control. It is distinct from the **Server certificate** presented on the tunnel endpoint.

### Client-to-server trust

Runewarp supports two Client trust modes:

- `system` uses the system trust store
- `ca-file` uses only the configured CA bundle and does not combine it with system roots

## Validation rules

### General boot-time validation

- `runewarp server` requires a `[server]` section
- `runewarp client` requires either a selected `[client]` section or the appropriate runtime routing flags when no selected Client config exists or the selected file has no `[client]` section: static mode needs `--server-address` and `--backend-address`; managed CLI-only mode needs `--control-address` and `--backend-address`
- present `[control]` requires an effective `control.address` after any `--control-address` override
- managed mode is enabled when an effective Control address is present after config and CLI preparation
- in managed mode, `[[server.tunnels]]` must be empty, `server.identity-dir` is required (or defaults to the XDG Server identity path), and `client.server-address`, `client.server-addresses`, and `--server-address` are rejected
- in static mode, `server.identity-dir` is rejected and at least one `[[server.tunnels]]` entry is required
- `server.identity-dir` must resolve to a different directory than `server.cert-dir`
- `server.hostname` must be present unless the runtime `runewarp server --hostname` flag or `RUNEWARP_SERVER_HOSTNAME` supplies it
- `[server.acme]` and `server.cert-dir` are mutually exclusive; when `[server.acme]` is absent, Runewarp uses the manual/private-CA path with `server.cert-dir` or its default XDG location
- `runewarp client` must end up with at least one effective **Server address** after any allowed `--server-address` overlay in static mode
- `client.server-address` and `client.server-addresses` are mutually exclusive
- `client.server-addresses` must contain at least one entry when present
- there must be at least one `[[server.tunnels]]` entry in static mode
- `runewarp client` must end up with at least one **Service**, either from config or from the runtime `--backend-address` Catch-all overlay
- `client.server-trust` must be either `system` or `ca-file`
- `client.server-ca-file` may be set only when `client.server-trust = "ca-file"`
- `control.trust` must be either `system` or `ca-file`
- `control.ca-file` may be set only when `control.trust = "ca-file"`
- `--backend-address` may be used only when the selected config contributes no `[[client.services]]` blocks
- every `client-identity` value and every entry in `client-identities` must be lowercase hex without colons
- `server.tunnels[].client-identity` and `server.tunnels[].client-identities` are mutually exclusive
- every authorized Client identity must be unique across all Server Tunnels
- `server.public-bind-address`, `server.tunnel-bind-address`, and `server.readiness-bind-address` when present must be literal socket addresses
- `server.graceful-shutdown-duration` must be a non-negative duration string such as `"0s"`, `"60s"`, `"5m"`, or `"250ms"`
- the selected or defaulted material directories and files must exist and be readable, except that omitted ACME state directories are resolved during config preparation and created only during startup after validation succeeds
- `backend-address` must parse as a TCP address or host:port pair

### Client TLS termination validation

- `client.services[].tls-mode` must be `"passthrough"` or `"terminate"`; defaults to `"passthrough"`
- `client.services[].tls-mode = "terminate"` requires explicit `public-hostnames` on that Service; Catch-all Services cannot opt into termination
- when any Service uses `tls-mode = "terminate"` and `[client.acme]` is absent, Runewarp selects the manual Public hostname certificate path from `client.public-cert-dir` or from the default XDG public-cert directory
- `client.public-cert-dir` and `[client.acme]` require at least one Service with `tls-mode = "terminate"`; the config is rejected when no terminating Service is present
- `client.public-cert-dir` and `[client.acme]` are mutually exclusive
- the selected manual Public hostname certificate directory must be an existing directory
- `client.acme.email` is required when `[client.acme]` is present
- `client.acme.state-dir` must be an existing directory when specified; when omitted, the XDG default path is used and created automatically during startup after validation succeeds

### Hostname rules

- Runewarp validates and canonicalizes hostname-bearing config once at the config seam, then keeps the resulting typed **Server hostname** and **Public hostname** values through startup and routing
- `server.tunnels[].public-hostnames` is always required
- `client.services[].public-hostnames` may be omitted only when there is exactly one Service
- `public-hostnames = []` is an error on either side
- hostnames are normalized to lowercase and a trailing dot is stripped before comparison
- `public-hostnames` must be DNS hostnames, including punycode A-labels; raw Unicode, IP literals, and wildcards are rejected
- the host portion of `client.server-address` and of each `client.server-addresses[]` entry must be a DNS hostname; raw IP literals are rejected
- effective Client **Server addresses** must be unique after normalization
- any exact hostname overlap across Tunnel entries after normalization is an error
- any exact hostname overlap across Service entries after normalization is an error
- `server.hostname` itself must not be reused as a routed **Public hostname**

## Cross-side hostname coverage

Runewarp does not validate cross-side hostname coverage at runtime:

- under **Hostname mirroring**, repeating the explicit hostname set on both sides is an operator responsibility
- when the Client uses a **Catch-all Service**, the Server carries the explicit hostname set while the Client intentionally does not
