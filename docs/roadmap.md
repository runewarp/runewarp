# Roadmap

The reference docs describe current Runewarp behavior. This page summarizes future Core themes; live GitHub issues own detailed investigation and implementation state.

Status terms are intentionally broad:

- **Active:** tracked by a current issue map
- **Exploring:** useful direction without a committed design

## Current baseline

Runewarp ships TLS-over-TCP ingress through a public Server and outbound QUIC Tunnel connections to Clients. It supports static and Managed-session configuration, explicit Public-hostname authorization, Client-side passthrough or Terminate mode, pooled Client instances, static fanout, readiness, bounded graceful shutdown, ACME and manual trust paths, and multi-architecture container publication.

See [architecture](architecture.md), [protocol](protocol.md), and [configuration](configuration.md) for implemented behavior.

## Protocol evolution — Active

The [HTTP/3 reverse-tunnel issue map](https://github.com/runewarp/runewarp/issues/167) investigates a versioned, extensible Client–Server protocol and graceful Client drain. The work must preserve a simple data path, keep managed configuration on the separate Managed session, and justify any move from the current `runewarp/1` QUIC-stream protocol with research and a measured prototype.

Generic private access, mesh, NAT traversal, CONNECT-UDP, and CONNECT-IP remain outside this committed Core track.

## Public QUIC passthrough — Active

The [Public QUIC issue map](https://github.com/runewarp/runewarp/issues/114) investigates routing ordinary QUIC-native Visitors, including browser HTTP/3, to QUIC-capable Local backends while keeping customer traffic opaque to the public Server.

The open questions are shared UDP listener classification, routing and trust, relay substrate, lifecycle guarantees, and operator configuration. DTLS and generic UDP forwarding remain exploratory until their routing and authorization model is equally clear.

## Availability — Exploring

- drain-aware Tunnel-pool withdrawal without promising live stream migration
- predictable handling of pre-establishment placement failure
- clearer pool-member diagnostics and replica identity failures
- multi-node Server routing and failover without centralizing the data path
- zero-downtime Server rollout mechanics around readiness and bounded drain

## Routing and metadata — Exploring

- bounded wildcard Public-hostname authorization with explicit precedence and overlap rules
- per-Service PROXY protocol delivery for backends that deliberately accept original Visitor metadata
- health-aware routing that fails closed when no healthy target exists
- routing lint and doctor tooling for Hostname-mirroring drift and trust-material errors

## Operator experience — Exploring

- validated live config reload with explicit in-flight behavior
- `config show`, `config init`, and `config edit` workflows
- documented service-manager operation before any background-process CLI surface
- structured logs and metrics for routing, rejection, reconnect, and pool health
- clearer external/NAT port mapping, later per-hostname public ports, and IPv6 deployment support; Server listener ports are already configurable through `server.public-bind-address` and `server.tunnel-bind-address`

## Performance and timeouts — Exploring

- benchmark backend connection reuse before adding pooling complexity; keeping one backend connection per stream is an acceptable outcome
- review handshake, connection, retry, idle, and shutdown timers against Runewarp's transport model before changing defaults

## Trust and privacy — Exploring

- Encrypted ClientHello where ecosystem support can coexist with SNI-based authorization
- overlapping Client-identity and Server-CA trust rotation without coordinated outages

## Managed extensions — Exploring

The implemented Core Managed-session contract is normative in [`managed.md`](managed.md). Potential extensions include Control-issued attestations for existing durable Client identities and explicit Server-management APIs. Persistence, product lifecycle state, certificate issuance, and hosted deployment topology remain outside the current Core contract.

## Deliberate non-goals

- customer TLS termination on the public Server edge
- plaintext HTTP ingress on the public edge
- HTTP-layer routing, including paths, headers, or request transformation
- generic private-network, mesh, or VPN behavior

Plain HTTP Local backends are supported only behind a Service using `tls-mode = "terminate"`, where the Client terminates Visitor TLS before forwarding plaintext TCP.
