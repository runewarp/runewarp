# Roadmap

The reference docs describe the committed Runewarp design. This document owns forward-looking sequencing and the mini-projects that may expand the product over time.

## Shipped baseline

Runewarp already ships the following baseline:

| Area | Shipped baseline |
| --- | --- |
| Core data path | Public TLS passthrough from the **Server** to a **Client**-side **Local backend** |
| Operator surface and trust | `runewarp server`, `runewarp client`, `runewarp server cert ...`, `runewarp client identity ...`, ACME, manual/private-CA certificates, and pinned Client authentication |
| Explicit routing | Required Server `public-hostnames`, multiple Server **Tunnels**, multiple Client **Services** |
| Preview packaging | Shared Docker image, non-root container execution, CI automation, and preview image export workflows |

## Public release

This track turns the shipped baseline into a clean first public release.

### Release notes and changelog discipline

**Outcome**

- the first public release has a supportable release story rather than ad hoc notes

**Planned work**

- introduce a root changelog
- define the release-note voice for operator-facing changes, boundaries, and limitations
- call out changes that affect configuration, trust material, or rollout expectations

### Public distribution channels

**Outcome**

- operators can install Runewarp through the release channels described by the public docs

**Planned work**

- publish the crate to crates.io
- publish the shared container image to Docker Hub
- keep binary versioning, image naming, and release tags aligned

### Install and packaging validation

**Outcome**

- the documented install paths are tested as release surfaces rather than assumed

**Planned work**

- validate `cargo install runewarp`
- validate public container pulls and basic startup
- make sure the docs and release artifacts describe the same operator surface

## Availability

This track hardens routed hostname sets against avoidable downtime across **Client** and **Server** deployment shapes.

### Same-Tunnel Client pools

**Outcome**

- one **Tunnel** can be served by multiple concurrent Client instances so capacity and availability no longer hinge on one active connection

**Planned work**

- replace the single-active-connection rule with a **Tunnel pool**
- keep pool membership scoped per Tunnel so unrelated hostname sets stay isolated
- define how incoming streams pick a serving Client instance without changing the public TLS passthrough boundary

### Pool selection policy

**Outcome**

- stream placement is predictable under load and understandable during incidents

**Planned work**

- least-active balancing across the live connections in one Tunnel pool
- round-robin tie-breaking when load is equal
- explicit behavior when pool members disappear while traffic is in flight

### Replica identity model

**Outcome**

- multi-instance deployments have a clear trust and misconfiguration story

**Planned work**

- keep one shared `client-identity` per Tunnel as the default pool model
- define what happens when a replica presents the wrong identity or mismatched config
- make replica failure modes easier for operators to diagnose

### Multi-node Server deployments

**Outcome**

- more than one public **Server** node can participate in the same logical Runewarp deployment for failover and higher edge availability

**Planned work**

- define how multiple public **Server** nodes route traffic to the correct **Tunnel** without centralizing the data path
- decide how configuration and connection state are shared or replicated across nodes
- preserve the current routing authority model while adding public-edge redundancy

### Zero-downtime Server rollouts

**Outcome**

- operators can replace or restart public **Server** nodes without avoidable downtime during planned changes

**Planned work**

- drain new Visitor traffic and client-side proxied streams during orderly shutdown while letting replacement capacity come online
- give in-flight Visitor connections and proxied streams a bounded grace period to finish before forced close
- hand new Tunnel and Visitor traffic to replacement **Server** nodes without promising in-flight connection migration in the first milestone

## Protocol expansion

This track grows the data plane without changing the product boundary.

### Public QUIC passthrough

**Outcome**

- Runewarp can route QUIC-based application traffic on the public edge as well as TLS over TCP, including HTTP/3-capable **Local backends** and visitors that already speak QUIC natively

**Planned work**

- decide how public QUIC passthrough coexists with Client Tunnel connections on `443/udp`
- support HTTP/3 on top of the public QUIC data path without requiring `runewarp proxy` for QUIC-capable visitors
- explicitly evaluate whether early Client-side QUIC termination belongs in this track or a later extension
- preserve explicit Server-side authorization for the routed hostname set
- keep customer traffic opaque to the public edge
- keep DTLS and other UDP protocols exploratory until the routing and trust model is clear without a visitor-side proxy

### Wildcard Public hostnames

**Outcome**

- one Tunnel or Service can intentionally own a bounded wildcard hostname set

**Planned work**

- define the wildcard syntax accepted in config
- decide how wildcard precedence interacts with exact-match hostnames
- preserve clear operator reasoning about authorization and overlap

### PROXY protocol delivery

**Outcome**

- Local backends can opt into receiving original Visitor source metadata without changing the default data path

**Planned work**

- add per-Service opt-in delivery for TCP backends in both `tls-mode = "passthrough"` and `tls-mode = "terminate"`
- define how PROXY protocol framing reaches Local backends without widening the default trust boundary
- keep source-metadata delivery explicit so backends only opt in when they are prepared to consume it

## Operations

This track improves day-2 operation, observability, and safer runtime change management.

### Live config reload

**Outcome**

- operators can apply approved config changes without restarting the whole runtime

**Planned work**

- reload Server and Client config without widening routing authority
- add file-watching triggers for both Server and Client on top of the same validated reload path
- decide how in-flight connections behave when routing entries change
- keep validation fail-closed when new config is invalid

### CLI and config ergonomics

**Outcome**

- operators can discover, inspect, initialize, and edit the selected config path without guessing where Runewarp keeps state

**Planned work**

- add `runewarp config show` for the effective selected-role config, including the selected config path
- add `runewarp config init` for minimal non-destructive config scaffolding at the default or explicit path
- add `runewarp config edit` as a `$EDITOR` wrapper for the selected config path, with a clear `config init` hint when no config exists

### Background runtime ergonomics

**Outcome**

- operators can run long-lived Server and Client processes cleanly under service managers and, when needed, from the CLI in the background without a fork-and-forget trap

**Planned work**

- document systemd units and operator workflows as the first-class service-manager path
- keep foreground operation and service-manager execution as the simplest production story
- define a small background-runtime lifecycle surface around `-d`, including status/stop semantics and explicit log-destination behavior

### Health-aware routing

**Outcome**

- routing decisions can account for backend or Client health instead of only connection presence

**Planned work**

- introduce health signals for **Local backends** and later for pooled Client instances
- decide whether health is passive, active, or both
- preserve the current fail-closed stance when no healthy target exists

### Metrics and logging

**Outcome**

- larger deployments can observe routing behavior without scraping human-readable logs alone

**Planned work**

- Prometheus and StatsD metrics
- structured JSON logging alongside the current human-readable mode
- clearer counters for routed hostnames, rejected streams, reconnects, and pool health

### Routing lint and doctor tooling

**Outcome**

- operators can detect configuration drift before it becomes a production incident

**Planned work**

- lint and doctor tooling for **Hostname mirroring** drift
- pre-flight checks for common trust-material mistakes
- clearer diagnostics for overlap, missing coverage, and unsupported shapes

### Port flexibility and deployment ergonomics

**Outcome**

- operators can fit Runewarp into a wider range of network and platform constraints

**Planned work**

- configurable public and tunnel ports
- later per-hostname public port support
- IPv6 support where it changes deployment assumptions or listener behavior

### Backend connection reuse benchmarks

**Outcome**

- backend connection reuse is introduced only if measurement shows it improves latency without breaking the protocol boundary

**Planned work**

- benchmark the current one-stream-to-one-backend-connection model before adding pooling complexity
- identify which backend protocol shapes, if any, could safely benefit from reuse
- keep "no pooling" as an acceptable result if the measured gains are weak or correctness costs are high

### Runtime timeout review

**Outcome**

- connection, handshake, idle, and retry timers follow explicit Runewarp-specific guidance instead of ad hoc defaults

**Planned work**

- review tunnel, backend, and shutdown-related timeouts against Runewarp's transport model
- compare the resulting guidance with common reverse-proxy defaults such as Caddy without treating those defaults as the target
- tighten or relax current timers only where the operational trade-offs are understood and documented

## Advanced networking

This track handles harder privacy and trust-distribution problems.

### Encrypted ClientHello

**Outcome**

- public and tunnel traffic can hide more routing metadata where the surrounding ecosystem supports it

**Planned work**

- evaluate ECH for public traffic
- evaluate ECH for Client tunnel connections
- decide how ECH interacts with the product's SNI-based routing model

### Zero-downtime trust rotation

**Outcome**

- operators can rotate trust anchors and identities without coordinated outages

**Planned work**

- zero-downtime `client-identity` rotation
- zero-downtime **Server CA** rotation
- safer overlap and cutover mechanics than the current reconnect-based model

## Managed service and control plane

This track explores the trust and management surfaces needed for a future managed Runewarp offering without redefining the current self-hosted baseline too early.

### Managed Client authentication

**Outcome**

- a managed control plane can authorize Client instances with control-plane-issued trust material while the underlying durable Client identity model stays coherent

**Planned work**

- explore short-lived Client certificates issued by a control-plane CA that attest the existing durable `client-identity` key
- define how a managed-service Server would trust that control-plane CA without changing the self-hosted baseline by accident
- keep the roadmap exploratory on how that trust path coexists with static self-hosted trust configuration
- scope the first design around managed-service deployments rather than making control-plane trust the default self-hosted path

### Server configuration API

**Outcome**

- a future managed control plane can manage Server-side routing and trust state through an explicit management surface rather than by smuggling config through the data path

**Planned work**

- design a separate authenticated management API for Server configuration
- keep Server-authoritative routing intact even when configuration is managed remotely
- decide later how managed configuration relates to static config files during rollout, recovery, and mixed deployments

## Visitor proxy

This later track adds a visitor-side proxy mode (`runewarp proxy`) for applications that still need a visitor-side wrapper after the native public data paths have expanded, starting with TCP access to existing terminating Services through Runewarp.

### TCP visitor proxy

**Outcome**

- **Visitors** can run a Runewarp in proxy mode with minimal setup to reach TCP services through ordinary Runewarp ingress

**Planned work**

- add `runewarp proxy` mode to existing binary
- start with TCP rather than bundling UDP into the first milestone
- reuse ordinary Visitor TLS to normal **Terminate mode** Services instead of adding a proxy-specific routing mode
- keep visitor setup minimal without locking the roadmap to a strict zero-config distribution story

### UDP extension

**Outcome**

- Visitor proxy can later cover UDP workloads once the underlying public QUIC data path exists

**Planned work**

- build the UDP story on top of public QUIC passthrough rather than inventing a separate path first
- keep `runewarp proxy` focused on protocols that still need a visitor-side wrapper after native public QUIC support exists
- revisit the visitor UX once the protocol prerequisites are in place

## Deliberate non-goals

- edge TLS termination for customer traffic
- plain HTTP backend support
