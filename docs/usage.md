# Usage

This guide is the operator-facing path for installing Runewarp, preparing trust material, starting the runtime, and verifying traffic. Use [`docs/configuration.md`](configuration.md) when you need the full key reference or additional config shapes.

## Choose a path

| Path | Best for | Next step |
| --- | --- | --- |
| Released binary | Running Runewarp directly on your own hosts or service manager | Follow [Operate from the released binary](#operate-from-the-released-binary) |
| Docker example | Evaluating the shipped topology end to end before adapting it | Follow [Evaluate with the Docker example](#evaluate-with-the-docker-example) |

## Before you start

Runewarp assumes:

- a public **Server** reachable on `443/tcp` for **Visitor** TLS traffic and `443/udp` for **Client** tunnel connections
- one or more operator-owned **Public hostnames** that resolve to the Server
- a TLS-terminating **Local backend** behind the Client
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
| ACME | Publicly routable Server hostname and standard public trust | Configure `[server.acme]`; omit `state-dir` to use the default XDG state location |
| Manual/private-CA | Private deployments or operator-managed trust | Create the material with `runewarp server cert init` and distribute `server-ca.crt` to Clients |

Manual/private-CA initialization:

```bash
runewarp server cert init --hostname tunnel.example.com
```

When `server.hostname` is already set in config, `runewarp server cert init --config /path/to/server.toml` and `runewarp server cert rotate-ca --config /path/to/server.toml` can omit `--hostname`.

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

That Client has a **Catch-all Service**: the Server stays explicit about the authorized **Public hostnames**, while the sole Client **Service** forwards every admitted hostname to one TLS-terminating backend.

If the Client must dial a non-default tunnel port, append it to `server-address` as `hostname:port`.

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

### 6. Verify traffic

1. Point each **Public hostname** at the Server.
2. Make a TLS request to the Public hostname.
3. Confirm the backend answers with its own certificate and application response.

When logs are enabled, the Server and Client emit human-readable routing diagnostics that help confirm:

- which **Public hostname** was selected
- which **Tunnel** was chosen
- which **Service** accepted the stream on the Client

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| No traffic reaches the backend | No active **Tunnel connection** | Confirm the Client is running and can reach the Server on `443/udp` |
| Client cannot connect to the Server | Wrong Server trust path | Check `client.server-trust = "ca-file"` and the selected `client.server-ca-file` path for the manual/private-CA path, or confirm the ACME/public-CA chain is trusted |
| Server drops a Public hostname | Hostname is not authorized on any Server `[[tunnels]]` entry | Check `server.tunnels[].public-hostnames` |
| Client rejects the stream | No matching **Service** on the Client | Check Client `public-hostnames`, or confirm the sole Service is intentionally Catch-all |
| Backend handshake fails | Backend is not terminating TLS | Confirm `backend-address` points at a TLS-speaking endpoint |
