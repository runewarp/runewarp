# Usage

This guide is the operator-facing path for installing Runewarp, preparing trust material, starting the runtime, and verifying traffic. Use [`docs/configuration.md`](configuration.md) when you need the full key reference or additional config shapes.

## Choose a path

| Path | Best for | Next step |
| --- | --- | --- |
| Released binary | Running Runewarp directly on your own hosts or service manager | Follow [Operate from the released binary](#operate-from-the-released-binary) |
| Docker example | Evaluating the shipped topology end to end before adapting it | Follow [Evaluate with the Docker example](#evaluate-with-the-docker-example) |

## Before you start

Runewarp assumes:

- a public **Server** reachable on its configured `server.public-bind-address` for **Visitor** TLS traffic and `server.tunnel-bind-address` for **Client** **Tunnel connections**; both default to `0.0.0.0:443`
- one or more operator-owned **Public hostnames** that resolve to the Server
- a **Local backend** behind the Client — TLS-terminating under **TLS passthrough**, or plaintext in **Terminate mode**
- a decision about the Server certificate path: ACME for the **Server hostname** or the manual/private-CA path

If the product language in this guide feels unfamiliar, read [`CONTEXT.md`](../CONTEXT.md) first.

## Evaluate with the Docker example

The repository ships one concrete example under [`examples/docker/`](../examples/docker/) that demonstrates:

- one **Server**
- one **Client**
- one **Tunnel**
- a **Catch-all Service** that forwards both `app.example.test` and `api.example.test` to Caddy

Use it when you want to prove the end-to-end path before writing your own config.

```bash
git clone https://github.com/runewarp/runewarp.git
cd runewarp/examples/docker
./prepare.sh
docker compose up -d
./smoke.sh
```

Use [`examples/docker/README.md`](../examples/docker/README.md) for the full walkthrough, topology, and reset flow.

## Operate from the released binary

### 1. Install Runewarp

```bash
cargo install runewarp
```

Runewarp is one binary with role-specific subcommands:

```bash
runewarp server --help
runewarp client --help
```

### 2. Prepare the Server certificate path

Choose one of the two supported Server-certificate paths:

| Path | When to use it | What to do |
| --- | --- | --- |
| ACME (Let's Encrypt) | Publicly routable Server hostname and standard public trust | Configure `[server.acme]`; Runewarp keeps the ACME provider fixed to Let's Encrypt here, and omitting `state-dir` uses the default XDG state location |
| Manual/private-CA | Private deployments or operator-managed trust | Create the material with `runewarp server cert init` and distribute `server-ca.crt` to Clients |

Manual/private-CA initialization:

```bash
runewarp server cert init --hostname tunnel.example.com
```

When `server.hostname` is already set in config, `runewarp server cert init` and `runewarp server cert rotate-ca` can omit `--hostname`.

### 3. Prepare the Client identity

Create the Client keypair, certificate, and durable `client-identity`:

```bash
runewarp client identity init
```

Read the generated `client-identity.txt` value from the default Client identity directory and place it into the matching Server `[[server.tunnels]]` entry as `client-identity`.

If you omit `--dir`, Runewarp uses the default XDG data locations:

- Client identity material: `$XDG_DATA_HOME/runewarp/client/identity/` or `~/.local/share/runewarp/client/identity/`
- Manual/private-CA Server material: `$XDG_DATA_HOME/runewarp/server/cert/` or `~/.local/share/runewarp/server/cert/`

If you prefer custom directories, pass `--dir` during setup and point the matching config keys at those paths: `server.cert-dir`, `client.identity-dir`, and, when needed, `client.server-ca-file`.

For the manual/private-CA path, either copy the generated `server-ca.crt` to `$XDG_DATA_HOME/runewarp/client/server-ca.crt` (or `~/.local/share/runewarp/client/server-ca.crt`) on each Client or set `client.server-ca-file` to the deployed CA bundle path.

### 3a. Prepare Public hostname certificate material (TLS termination only)

If any Client Service uses `tls-mode = "terminate"`, choose one of the two supported certificate paths:

| Path | When to use it | What to do |
| --- | --- | --- |
| Manual (`client.public-cert-dir`) | Private deployments or operator-managed trust; Visitors need a shared **Public hostname CA** | Create material with `runewarp client public-cert init`, set `client.public-cert-dir`, and distribute `public-ca.crt` to Visitors |
| ACME (`[client.acme]`) | Publicly routable Public hostnames and standard public trust | Configure `[client.acme]` in Client config; no pre-generated material needed |

**Manual path:**

```bash
runewarp client public-cert init --hostname app.example.com

# or derive every terminating hostname from config:
runewarp client --config client.toml public-cert init
```

Run once per terminating hostname, or omit `--hostname` and supply `--config` to derive the full terminating-hostname set from `client.services[].public-hostnames` where `tls-mode = "terminate"`. A second run with a new hostname reuses the existing **Public hostname CA** and adds only the new **Public hostname certificate**. Share `public-ca.crt` with each Visitor as their trust anchor. When the CA already exists, `runewarp client public-cert init` refuses to replace it, keeping that trust anchor stable until you explicitly run `rotate-ca`.

Set `client.public-cert-dir` in the Client config to the directory where the material was written. The `client public-cert` commands resolve their working directory from `--dir`, then `client.public-cert-dir`, then the XDG default when neither is set, but runtime validation does **not** make manual mode implicit from that default path: terminating Services still require explicit `client.public-cert-dir` in config unless you use `[client.acme]`.

**Renewing Public hostname certificates (manual path):**

To renew a leaf certificate for a single hostname:

```bash
runewarp client public-cert renew --hostname app.example.com
```

To renew all terminating hostnames derived from config (requires `--config`):

```bash
runewarp client --config client.toml public-cert renew
```

For `init` and `renew`, the `--hostname` set comes from `public-hostnames` on `tls-mode = "terminate"` services in the config when `--hostname` is omitted. Omitting `--hostname` without a config file is an error.

**Rotating the Public hostname CA (manual path):**

`rotate-ca` replaces the trust anchor and reissues every managed leaf certificate. Visitors must trust the new `public-ca.crt` after rotation. Requires `--config` so Runewarp can determine which hostnames are managed:

```bash
runewarp client --config client.toml public-cert rotate-ca
```

The managed hostname set comes from `public-hostnames` on `tls-mode = "terminate"` services in the config. Scanning on-disk leaf directories is not used.

**ACME path:**

Add `[client.acme]` to the Client config instead of `client.public-cert-dir`. The Client automatically provisions and renews certificates from Let's Encrypt for every **Public hostname** on a terminating Service. No pre-generated material is needed. The Client starts with a live ACME manager at startup without blocking on certificate readiness; a terminating hostname without a ready certificate fails closed at the TLS handshake until the certificate is issued. `acme-tls/1` challenge traffic for **Public hostnames** is routed through the Server to the Client using the same path as ordinary Visitor TLS.

### 4. Write config

The smallest practical setup is a Server with explicit **Public hostnames** and one Client **Catch-all Service**:

```toml
# /etc/runewarp/server.toml
[server]
hostname = "tunnel.example.com"

[server.acme]
email = "admin@example.com"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."
```

```toml
# /etc/runewarp/client.toml
[client]
server-address = "tunnel.example.com"

[[client.services]]
backend-address = "caddy.local:443"
```

That Client has a **Catch-all Service**: the Server stays explicit about **Public hostname authorization**, while the sole Client **Service** forwards every admitted hostname to one TLS-terminating **Local backend**.

If the Client must dial a non-default tunnel port, append it to `server-address` as `hostname:port`.

If the Server must listen on non-default sockets, set `server.public-bind-address` for **Visitor** TLS traffic and `server.tunnel-bind-address` for **Client** **Tunnel connections**.

If you are using the manual/private-CA Server path, add:

```toml
server-trust = "ca-file"
# optionally override the default CA bundle path:
# server-ca-file = "/etc/runewarp/server-ca.crt"
```

See [`docs/configuration.md`](configuration.md) for exact-match Client routing, multi-Tunnel Server configs, multi-Service Client configs, and the complete key reference.

### 5. Start the runtime

```bash
runewarp server --config /etc/runewarp/server.toml
runewarp client --config /etc/runewarp/client.toml
```

Runewarp loads `--config` from `$XDG_CONFIG_HOME/runewarp/config.toml` when omitted, falling back to `~/.config/runewarp/config.toml` when `XDG_CONFIG_HOME` is unset. Explicit paths are still easier to operate and review.

For the smallest Client startup, `runewarp client` can also run without a selected Client config when you provide both runtime routing flags:

```bash
runewarp client --server-address tunnel.example.com --backend-address caddy.local:443
```

That CLI-only shape creates one Client-side **Catch-all Service**, defaults `client.server-trust` to `system`, and still uses the usual omitted-key defaults for the Client identity directory, logs, and reconnect behavior.

Precedence rules for `runewarp client` are:

- an explicit `--config` path is authoritative and a missing explicit path is still an error
- when `--config` is omitted, a discovered default config file remains authoritative when it exists
- if the selected file has no `[client]` section, `runewarp client` can still start when both `--server-address` and `--backend-address` are provided
- when a selected config file exists, `--server-address` may replace `client.server-address` before validation
- when a selected config file exists, `--backend-address` may supply the sole Catch-all Service only when that file contributes no `[[client.services]]` blocks at all
- any configured Service blocks `--backend-address`, even when the Service block is malformed

The routing flags belong only to the runtime `runewarp client` form. `runewarp client identity ...` continues to accept only identity-material options.

### 6. Verify traffic

1. Point each **Public hostname** at the Server.
2. Make a TLS request to the Public hostname.
3. Confirm the request succeeds and the expected application answers. Under **TLS passthrough** the backend's own certificate should appear; in **Terminate mode** the Client-presented **Public hostname certificate** should appear and the backend should receive plaintext.

When logs are enabled, the Server and Client emit human-readable routing diagnostics that help confirm:

- which **Public hostname** was selected
- which **Tunnel** was chosen
- which **Service** accepted the stream on the Client

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| No traffic reaches the backend | No active **Tunnel connection** | Confirm the Client is running and can reach the Server on the configured `server.tunnel-bind-address` |
| Client cannot connect to the Server | Wrong Server trust path | Check `client.server-trust = "ca-file"` and the selected `client.server-ca-file` path for the manual/private-CA path, or confirm the ACME/public-CA chain is trusted |
| Server drops a Public hostname | No Server `[[tunnels]]` entry grants **Public hostname authorization** for it | Check `server.tunnels[].public-hostnames` |
| Client rejects the stream | No matching **Service** on the Client | Check Client `public-hostnames`, or confirm the sole Service is intentionally Catch-all |
| Passthrough backend handshake fails | Backend is not terminating TLS | Confirm `backend-address` points at a TLS-speaking endpoint for `tls-mode = "passthrough"` |
| Terminate-mode backend fails immediately | Backend still expects TLS after the Client terminated it | Confirm the matching Service uses `tls-mode = "terminate"` and the backend speaks plaintext TCP |
