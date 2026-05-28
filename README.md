<div align="center">
  <h1>
    Runewarp
  </h1>
  <p>
    <strong>
      Public ingress. Private by design.
    </strong>
  </p>
</div>

Runewarp is an ingress tunneling tool for exposing local services without moving TLS termination to the edge. Clients connect out over QUIC, so you can publish services without putting your backend directly on the Internet or leaking your public IP.

## Goals

- **TLS passthrough ingress tunneling** — Server routes traffic by SNI without terminating or inspecting TLS
- **Privacy-respecting by design** — Server never sees HTTP headers or application plaintext
- **Traverse NAT and firewalls** — Client uses outbound QUIC, so no port forwarding or public IP is required
- **Self-hostable and operator-controlled** — single Rust binary for both Client and Server
- **Remain operationally simple** — TOML config, a handful of CLI commands, no runtime dependencies

## Non-goals

- **Server TLS termination** — Server never decrypts or re-encrypts Visitor traffic
- **HTTP-layer routing** — no path-based routing, header inspection, or Layer 7 awareness of any kind

## Install

Available from [crates.io](https://crates.io/crates/runewarp):
```bash
cargo install runewarp
```

Container image from [Docker Hub](https://hub.docker.com/r/runewarp/runewarp):
```bash
docker pull runewarp/runewarp
```

## Getting started

1. Read and run the Docker example [`examples/docker/README.md`](examples/docker/README.md).
2. Read [`docs/usage.md`](docs/usage.md) for the operator workflow.
3. Read [`docs/configuration.md`](docs/configuration.md) for config keys and examples.

## Comparison

Runewarp is inspired by [rathole](https://github.com/rathole-org/rathole), but it makes a narrower set of trade-offs around trust boundaries and public ingress. The notes below compare current shipped behavior, not roadmap items.

### vs [rathole](https://github.com/rathole-org/rathole)

[rathole](https://github.com/rathole-org/rathole) is a general reverse proxy for NAT traversal with service-wise tokens and broader protocol and transport options today, including UDP forwarding and multiple TCP-based transport choices. Runewarp is narrower: one long-lived QUIC/TLS **Tunnel connection** per **Client instance**, mTLS plus pinned **Client identity** on that tunnel, **Server-authoritative routing** by explicit **Public hostnames**, and no separate control channel. If you want a compact, flexible port-forwarding tool, rathole is broader today; if you specifically want SNI-routed TLS ingress with the public **Server** kept out of customer plaintext by default, Runewarp is the stricter fit.

### vs [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)

[Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/) uses the open-source `cloudflared` connector to keep multiple outbound connections into Cloudflare's managed edge, where CDN, WAF, Access, DDoS protection, and other edge features can be applied. Runewarp keeps the public edge self-hosted and intentionally narrower: the **Server** routes TLS by SNI and never terminates customer TLS, while optional termination can happen only on the **Client** near the **Local backend**. Cloudflare is stronger when you want a managed edge with platform features already built in; Runewarp is for operators who want to keep the ingress boundary and routing authority on infrastructure they run themselves.

### vs [Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel)

[Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel) also keeps its relay out of plaintext: traffic reaches a Funnel relay and then a TCP proxy into your device, while TLS terminates on the Tailscale node that serves the local app. The main difference is deployment model. Funnel is part of a tailnet product, depends on the Tailscale daemon and `*.ts.net` names, and is easiest when you already live inside that ecosystem. Runewarp instead gives you a self-hosted public **Server**, explicit Server-side hostname ownership, and the option to keep customer TLS termination on the **Local backend** by default. Funnel is simpler inside a Tailscale setup; Runewarp is better when you want an operator-run public ingress layer without adopting a tailnet model.

### vs [ngrok](https://ngrok.com/)

[ngrok](https://ngrok.com/) is a managed cloud gateway with strong developer ergonomics, traffic policy, and broader edge features. Its HTTP-focused product is designed around the ngrok edge handling routing, policy, and authentication, while secure tunnels connect back to local services. Runewarp is much narrower: self-hosted public ingress, TLS-only public traffic, SNI-based routing, and no HTTP-layer inspection on the **Server**. ngrok is stronger when you want polished managed workflows or edge-side traffic handling; Runewarp is for operators who want a simpler, self-hosted TLS passthrough boundary, with **Terminate mode** available on the **Client** when a plaintext backend is needed.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Guide for installation, setup, startup, verification, and troubleshooting |
| [`docs/configuration.md`](docs/configuration.md) | Configuration reference, defaults, and example configs |
| [`docs/architecture.md`](docs/architecture.md) | High-level design, routing model, trust boundaries, and topology diagrams |
| [`docs/security.md`](docs/security.md) | Visibility model, trust model, and security limits |
| [`docs/protocol.md`](docs/protocol.md) | Wire behavior and runtime invariants |
| [`docs/roadmap.md`](docs/roadmap.md) | Forward-looking roadmap and planned features |
| [`examples/docker/README.md`](examples/docker/README.md) | Walkthrough of the Docker example |

## License

Licensed under Apache License, Version 2.0 ([`LICENSE`](LICENSE)).
