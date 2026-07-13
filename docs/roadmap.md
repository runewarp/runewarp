# Roadmap

The reference docs describe the current Runewarp design. This document tracks the larger pieces of work that may expand the product over time.

## Current baseline

Runewarp already ships:

| Area | Shipped baseline |
| --- | --- |
| Core data path | Public TLS passthrough from the **Server** to a **Client**-side **Local backend** |
| Operator surface and trust | `runewarp server`, `runewarp client`, `runewarp server cert ...`, `runewarp client identity ...`, ACME, manual/private-CA certificates, and pinned Client authentication |
| Explicit routing | Required Server `public-hostnames`, multiple Server **Tunnels**, multiple Client **Services** |
| Packaging | Shared Docker image, non-root container execution, CI automation, and preview image export workflows |

## Availability

This track reduces avoidable downtime across client and server deployment shapes.

### Tunnel-pool resilience

**Goal**

- stream placement is predictable under load and understandable during incidents

**Planned work**

- add drain-aware withdrawal so planned shutdown can remove one pool member without dropping its active streams immediately
- decide whether pre-establishment placement failures should retry on another live pool member
- improve runtime visibility into which pool member served each stream during incidents

### Replica identity model

**Goal**

- multi-instance deployments have a clear trust and misconfiguration story

**Planned work**

- keep one shared `client-identity` per Tunnel as the default pool model
- decide whether mismatched pool members should ever be auto-ejected instead of failing only the streams they receive
- make replica failure modes easier for operators to diagnose

### Multi-node Server deployments

**Goal**

- more than one public **Server** node can participate in the same logical Runewarp deployment for failover and higher edge availability

**Planned work**

- define how multiple public **Server** nodes route traffic to the correct **Tunnel** without centralizing the data path
- decide how configuration and connection state are shared or replicated across nodes
- preserve the current routing authority model while adding public-edge redundancy

### Zero-downtime Server rollouts

**Goal**

- operators can replace or restart public **Server** nodes without avoidable downtime during planned changes

**Planned work**

- drain new Visitor traffic and client-side proxied streams during orderly shutdown while letting replacement capacity come online
- give in-flight Visitor connections and proxied streams a bounded grace period to finish before forced close
- hand new Tunnel and Visitor traffic to replacement **Server** nodes without promising in-flight connection migration in the first milestone

## Protocol expansion

This track expands the data plane without changing the product boundary.

### Tunnel protocol evolution

**Goal**

- the Client and Server use a versioned, capability-negotiated protocol with typed bidirectional exchange for ingress lifecycle and metadata

**Planned work**

- support extensible Client-to-Server and Server-to-Client messages without turning the Tunnel connection into a managed configuration channel
- make Client-triggered drain the first required lifecycle signal: a draining Client instance stops receiving new Visitor work while existing work gets its bounded opportunity to finish
- evaluate HTTP/3, Reverse HTTP CONNECT, Extended CONNECT, and the Capsule Protocol against the current `runewarp/1` transport through research and a measured prototype
- adopt HTTP/3 only if that evidence justifies replacing the simpler custom QUIC-stream protocol; otherwise preserve the required lifecycle and extension behavior on a narrower substrate
- keep generic CONNECT-UDP, CONNECT-IP, private-access, mesh, NAT-traversal, and relay product modes outside this committed Core track

### Public QUIC passthrough

**Goal**

- Runewarp can route QUIC-based application traffic on the public edge as well as TLS over TCP, including ordinary browser HTTP/3 traffic and other QUIC-native **Visitors** reaching QUIC-capable **Local backends**

**Planned work**

- decide how public QUIC passthrough coexists with Client Tunnel connections on `443/udp`
- support ordinary Visitor HTTP/3 directly, without requiring a Runewarp-aware visitor proxy
- relay Public QUIC through the existing authenticated Client–Server transport without requiring a second transport; the exact stream/datagram substrate follows the tunnel-protocol evidence
- allow HTTP Datagram, QUIC DATAGRAM, or Capsule Protocol primitives internally without exposing generic CONNECT-UDP as a Core product mode
- explicitly evaluate whether early Client-side QUIC termination belongs in this track or a later extension
- preserve explicit Server-side authorization for the routed hostname set
- keep customer traffic opaque to the public edge
- keep DTLS and other UDP protocols exploratory until the routing and trust model is clear without a visitor-side proxy

### Wildcard Public hostnames

**Goal**

- one Tunnel or Service can intentionally own a bounded wildcard hostname set

**Planned work**

- define the wildcard syntax accepted in config
- decide how wildcard precedence interacts with exact-match hostnames
- preserve clear operator reasoning about authorization and overlap

### PROXY protocol delivery

**Goal**

- Local backends can opt into receiving original Visitor source metadata without changing the default data path

**Planned work**

- add per-Service opt-in delivery for TCP backends in both `tls-mode = "passthrough"` and `tls-mode = "terminate"`
- define how PROXY protocol framing reaches Local backends without widening the default trust boundary
- keep source-metadata delivery explicit so backends only opt in when they are prepared to consume it

## Operations

This track improves day-2 operations, observability, and safer runtime changes.

### Live config reload

**Goal**

- operators can apply approved config changes without restarting the whole runtime

**Planned work**

- reload Server and Client config without widening routing authority
- add file-watching triggers for both Server and Client on top of the same validated reload path
- decide how in-flight connections behave when routing entries change
- keep validation fail-closed when new config is invalid

### CLI and config ergonomics

**Goal**

- operators can discover, inspect, initialize, and edit the selected config path without guessing where Runewarp keeps state

**Planned work**

- add `runewarp config show` for the effective selected-role config, including the selected config path
- add `runewarp config init` for minimal non-destructive config scaffolding at the default or explicit path
- add `runewarp config edit` as a `$EDITOR` wrapper for the selected config path, with a clear `config init` hint when no config exists

### Background runtime ergonomics

**Goal**

- operators can run long-lived Server and Client processes cleanly under service managers and, when needed, from the CLI in the background without a fork-and-forget trap

**Planned work**

- document systemd units and operator workflows as the first-class service-manager path
- keep foreground operation and service-manager execution as the simplest production story
- define a small background-runtime lifecycle surface around `-d`, including status/stop semantics and explicit log-destination behavior

### Health-aware routing

**Goal**

- routing decisions can account for backend or Client health instead of only connection presence

**Planned work**

- introduce health signals for **Local backends** and later for pooled Client instances
- decide whether health is passive, active, or both
- preserve the current fail-closed stance when no healthy target exists

### Metrics and logging

**Goal**

- larger deployments can observe routing behavior without scraping human-readable logs alone

**Planned work**

- Prometheus and StatsD metrics
- structured JSON logging alongside the current human-readable mode
- clearer counters for routed hostnames, rejected streams, reconnects, and pool health

### Routing lint and doctor tooling

**Goal**

- operators can detect configuration drift before it becomes a production incident

**Planned work**

- lint and doctor tooling for **Hostname mirroring** drift
- pre-flight checks for common trust-material mistakes
- clearer diagnostics for overlap, missing coverage, and unsupported shapes

### Port flexibility and deployment ergonomics

**Goal**

- operators can fit Runewarp into a wider range of network and platform constraints

**Planned work**

- configurable public and tunnel ports
- later per-hostname public port support
- IPv6 support where it changes deployment assumptions or listener behavior

### Backend connection reuse benchmarks

**Goal**

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

This track covers harder privacy and trust-distribution problems.

### Encrypted ClientHello

**Goal**

- public and tunnel traffic can hide more routing metadata where the surrounding ecosystem supports it

**Planned work**

- evaluate ECH for public traffic
- evaluate ECH for Client tunnel connections
- decide how ECH interacts with the product's SNI-based routing model

### Zero-downtime trust rotation

**Goal**

- operators can rotate trust anchors and identities without coordinated outages

**Planned work**

- zero-downtime `client-identity` rotation
- zero-downtime **Server CA** rotation
- safer overlap and cutover mechanics than the current reconnect-based model

## Managed service and control plane

This track explores what a future managed Runewarp offering would need without redefining the current self-hosted baseline too early.

### Managed Client authentication

**Goal**

- a managed control plane can authorize Client instances with control-plane-issued trust material while the underlying durable Client identity model stays coherent

**Planned work**

- explore short-lived Client certificates issued by a control-plane CA that attest the existing durable `client-identity` key
- define how a managed-service Server would trust that control-plane CA without changing the self-hosted baseline by accident
- keep the roadmap exploratory on how that trust path coexists with static self-hosted trust configuration
- scope the first design around managed-service deployments rather than making control-plane trust the default self-hosted path

### Server configuration API

**Goal**

- a future managed control plane can manage Server-side routing and trust state through an explicit management surface rather than by smuggling config through the data path

**Planned work**

- design a separate authenticated management API for Server configuration
- keep Server-authoritative routing intact even when configuration is managed remotely
- decide later how managed configuration relates to static config files during rollout, recovery, and mixed deployments

## Deliberate non-goals

- edge TLS termination for customer traffic
- plain HTTP backend support
