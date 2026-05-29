# Usage

Use this guide for the operator workflow: install Runewarp, prepare trust material, start the runtime, and verify traffic. Use [`docs/configuration.md`](configuration.md) for the full key reference, validation rules, and alternate config shapes.

## Choose a path

| Path | Best for | Next step |
| --- | --- | --- |
| CLI | Running Runewarp directly on your own hosts or service manager | Follow [Operate the CLI](#operate-the-cli) |
| Docker example | Proving the shipped topology end to end before adapting it | Follow [Evaluate with the Docker example](#evaluate-with-the-docker-example) |

## Before you start

Runewarp assumes:

- a public **Server** reachable on its configured `server.public-bind-address` for **Visitor** TLS traffic and `server.tunnel-bind-address` for **Client** **Tunnel connections**
- one or more operator-owned **Public hostnames** that resolve to the Server
- a **Local backend** behind the Client
- a decision about the Server certificate path and, if any Service uses `tls-mode = "terminate"`, the Client certificate path for those **Public hostnames**

If the product language here feels unfamiliar, read [`CONTEXT.md`](../CONTEXT.md) first.

## Evaluate with the Docker example

The repository ships one concrete example under [`examples/docker/`](../examples/docker/). Use it when you want to prove the end-to-end path before writing your own config.

```bash
git clone https://github.com/runewarp/runewarp.git
cd runewarp/examples/docker
./prepare.sh
docker compose up -d
./smoke.sh
```

Use [`examples/docker/README.md`](../examples/docker/README.md) for the full walkthrough and reset flow.

## Operate the CLI

### 1. Install Runewarp

```bash
cargo install runewarp
```

Runewarp is one binary with role-specific subcommands:

```bash
runewarp --help
runewarp server --help
runewarp client --help
```

### 2. Choose the Server certificate path

Choose one of the supported Server-certificate paths:

| Path | When to use it | What to do |
| --- | --- | --- |
| ACME (Let's Encrypt) | Publicly routable **Server hostname** and standard public trust | Configure `[server.acme]` |
| Manual/private-CA | Private deployments or operator-managed trust | Create the material with `runewarp server cert init` and distribute `server-ca.crt` to Clients |

Manual/private-CA initialization:

```bash
runewarp server cert init --hostname tunnel.example.com
```

When `server.hostname` is already set in config, `runewarp server cert init` and `runewarp server cert rotate-ca` can omit `--hostname`.

### 3. Create the Client identity

Create the Client keypair, certificate, and durable `client-identity`:

```bash
runewarp client identity init
```

Read the generated `client-identity.txt` value and place it into the matching Server `[[server.tunnels]]` entry as `client-identity`.

To print only the fingerprint for scripts:

```bash
runewarp client identity show
```

### 4. If needed, choose the Client certificate path for terminate mode

Skip this step when every Service uses the default `tls-mode = "passthrough"`.

If any Service uses `tls-mode = "terminate"`, choose one of these paths:

| Path | When to use it | What to do |
| --- | --- | --- |
| Manual **Public hostname certificates** | Private deployments or operator-managed trust | Run `runewarp client public-cert init` and distribute `public-ca.crt` to Visitors |
| ACME (`[client.acme]`) | Publicly routable **Public hostnames** and standard public trust | Configure `[client.acme]` |

Manual initialization:

```bash
runewarp client public-cert init --hostname app.example.com
```

Or derive the terminating hostnames from the selected Client config:

```bash
runewarp client public-cert init
```

### 5. Write the smallest practical config

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
backend-address = "localhost:8443"
```

That Client uses a **Catch-all Service**: the Server still owns explicit **Public hostname authorization**, while the sole Client Service forwards every admitted hostname to one **Local backend**.

If you are using the manual/private-CA Server path, add:

```toml
server-trust = "ca-file"
# optionally override the default CA bundle path:
# server-ca-file = "/etc/runewarp/server-ca.crt"
```

For exact-match Client routing, multiple Services or Tunnels, terminate-mode config, defaults, and full key definitions, use [`docs/configuration.md`](configuration.md).

### 6. Start the runtime

```bash
runewarp server -c /etc/runewarp/server.toml
runewarp client -c /etc/runewarp/client.toml
```

If you omit `--config`, Runewarp looks for `$XDG_CONFIG_HOME/runewarp/config.toml`, then `~/.config/runewarp/config.toml` when `XDG_CONFIG_HOME` is unset. Use [`docs/configuration.md`](configuration.md) for the full config discovery and runtime override rules.

### 7. Verify traffic

1. Point each **Public hostname** at the Server.
2. Make a TLS request to the Public hostname.
3. Confirm the expected application answers.

Under **TLS passthrough**, the backend's own certificate should appear. In **Terminate mode**, the Client-presented **Public hostname certificate** should appear and the backend should receive plaintext.

At the default `log-level = "info"`, Runewarp logs readiness, tunnel connection lifecycle, warnings, and errors to stderr. Set `log-level = "debug"` when you need per-connection routing detail. Use [`docs/configuration.md`](configuration.md) for the exact logging semantics.

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| No traffic reaches the backend | No active **Tunnel connection** | Confirm the Client is running and can reach the Server on `server.tunnel-bind-address` |
| Client cannot connect to the Server | Wrong Server trust path | Check `client.server-trust` and `client.server-ca-file`, or confirm the ACME/public-CA chain is trusted |
| Server drops a Public hostname | No Server `[[server.tunnels]]` entry grants **Public hostname authorization** for it | Check `server.tunnels[].public-hostnames` |
| Client rejects the stream | No matching **Service** on the Client | Check Client `public-hostnames`, or confirm the sole Service is intentionally Catch-all |
| Passthrough backend handshake fails | Backend is not terminating TLS | Confirm the backend behind a passthrough Service speaks TLS |
| Terminate-mode backend fails immediately | Backend still expects TLS after the Client terminated it | Confirm the matching Service uses `tls-mode = "terminate"` and the backend speaks plaintext TCP |
