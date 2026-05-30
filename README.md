<div align="center">
  <h1>
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/runewarp-horizontal-on-dark.svg">
      <img src="assets/runewarp-horizontal-on-light.svg" alt="Runewarp" width="320">
    </picture>
  </h1>
  <p>
    <strong>
      Public ingress. Private by design.
    </strong>
  </p>
</div>

Runewarp is an ingress tunneling tool for exposing local services without moving TLS termination to the edge. Clients connect out over QUIC, so you can publish services without putting your backend directly on the Internet or leaking your public IP.

## Install

Available from [crates.io](https://crates.io/crates/runewarp):
```bash
cargo install runewarp
```

Container image from [Docker Hub](https://hub.docker.com/r/runewarp/runewarp):
```bash
docker pull runewarp/runewarp
```

## Get started

1. Install Ruby locally, then run the Docker example in [`examples/docker/README.md`](examples/docker/README.md) to verify the end-to-end path.
2. Use [`docs/usage.md`](docs/usage.md) for the operator workflow.
3. Use [`docs/configuration.md`](docs/configuration.md) for config keys, defaults, and examples.

## Goals

- **TLS passthrough ingress tunneling** — Server routes traffic by SNI without terminating or inspecting TLS
- **Privacy-respecting by design** — Server never sees HTTP headers or application plaintext
- **Traverse NAT and firewalls** — Client uses outbound QUIC, so no port forwarding or public IP is required
- **Self-hostable and operator-controlled** — single Rust binary for both Client and Server
- **Remain operationally simple** — TOML config, a handful of CLI commands, no runtime dependencies

## Non-goals

- **Server TLS termination** — Server never decrypts or re-encrypts Visitor traffic
- **HTTP-layer routing** — no path-based routing, header inspection, or Layer 7 awareness of any kind

## Compatibility

Runewarp `0.1.x` is a public pre-1.0 release line. Patch releases aim to stay low-risk, but minor releases may include breaking CLI or configuration changes.

## Architecture

```mermaid
flowchart TD
    V[Visitor]
    C["Client instance"]
    B["Local backend<br/>terminates TLS"]

    subgraph S["Server"]
        direction TB
        P["Public listener<br/>TCP 443 / Visitor TLS"]
        R["SNI router<br/>select Tunnel by Public hostname"]
        U["Tunnel listener<br/>UDP 443 / QUIC/TLS"]

        P -->|"read ClientHello + SNI"| R
        R -->|"open stream on active Tunnel"| U
    end

    V -->|"Visitor TLS for a Public hostname"| P
    C -->|"dials QUIC/TLS Tunnel connection"| U
    U -->|"deliver encrypted stream"| C
    C -->|"select Service and proxy"| B
```

Visitors connect to the public server over TLS, and each client instance keeps one long-lived QUIC tunnel connection back to it. The server routes by SNI and forwards the encrypted stream to the selected client, which then proxies it to the local backend. A service can opt into terminate mode when the client, not the backend, should terminate TLS. See [`docs/architecture.md`](docs/architecture.md) for the detailed transport view.

## Comparison

How Runewarp compares to other tunnel tools:

### vs [ngrok](https://ngrok.com/)

A managed cloud gateway focused on developer workflows, edge routing, and traffic policy.

- **Runewarp Server only operates on TLS:** no edge traffic policy, header inspection, or request transformation on the public **Server**.
- **ngrok edge-side workflows:** managed policy, routing, and developer ergonomics are part of the platform.

### vs [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)

A managed connector into Cloudflare's edge, with routing and platform features built around that edge.

- **Runewarp is fully operator-run:** open source on both the **Client** and **Server**, self-hosted public ingress.
- **Cloudflare fits managed-edge workflows:** CDN, WAF, Access, DDoS protection, and other platform features come with the service.

### vs [Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel)

A tailnet-based way to publish a local service publicly without exposing the device IP.

- **Runewarp works with custom domains:** explicit Server-side hostname ownership and no dependency on a tailnet, the Tailscale daemon, or `*.ts.net` names.
- **Funnel for existing Tailscale users:** the relay stays out of plaintext and the workflow is convenient when you already use that ecosystem.

### vs [rathole](https://github.com/rathole-org/rathole)

A simple, open-source client/server tunneling tool whose config model and simple client/server architecture helped inspire Runewarp.

- **Runewarp keeps routing explicit:** one QUIC/TLS **Tunnel connection** per **Client instance**, **Server-authoritative routing** by **Public hostname**, and no separate control channel.
- **rathole supports more protocols today:** service tokens, UDP forwarding, and more transport options.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Install, configure, start, verify, and troubleshoot Runewarp |
| [`docs/configuration.md`](docs/configuration.md) | Config reference, defaults, validation rules, and examples |
| [`docs/architecture.md`](docs/architecture.md) | System shape, routing model, trust model, and topology diagrams |
| [`docs/security.md`](docs/security.md) | Visibility limits, authentication, certificate handling, and trade-offs |
| [`docs/protocol.md`](docs/protocol.md) | Wire behavior and runtime invariants |
| [`docs/release-automation.md`](docs/release-automation.md) | Release CI and publication automation |
| [`docs/release-guide.md`](docs/release-guide.md) | Maintainer release procedure and recovery steps |
| [`docs/roadmap.md`](docs/roadmap.md) | Forward-looking roadmap and planned features |
| [`examples/docker/README.md`](examples/docker/README.md) | Walkthrough of the Docker example |

## License

Licensed under Apache License, Version 2.0 ([`LICENSE`](LICENSE)).
