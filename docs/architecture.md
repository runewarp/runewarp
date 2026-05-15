# Architecture

This document describes the committed Runewarp design. The current repository is still narrower: phase 1 ships only the library data path, one active Client instance with one Tunnel connection, and no config-driven CLI, ACME, or Client authentication yet.

## Roles

| Component | Responsibility |
| --- | --- |
| Visitor | Connect to a Public hostname over TLS |
| Server | Accept Visitor traffic, select a Tunnel, and forward the original encrypted stream |
| Client instance | Maintain one Tunnel connection, choose a Service locally, and forward traffic to a Local backend |
| Local backend | Terminate TLS and serve the application |

## Core routing model

Runewarp keeps routing authority on the Server:

- the Server decides which Public hostnames belong to which Tunnel
- the Client does not register hostnames with the Server
- Public hostnames are the routing identity; there is no separate Tunnel or Service name field
- exact hostname overlap is rejected within Server Tunnels and within Client Services

Runewarp deliberately uses **Hostname mirroring**:

- operators repeat Public hostnames on both sides
- the Server uses them to select a Tunnel
- the Client uses the forwarded ClientHello to select a Service
- the public data path stays transparent because no extra routing header is added

## Catch-all mode

When each side has exactly one entry, `hostnames` may be omitted:

- the sole `[[server.tunnels]]` entry becomes a Catch-all Tunnel
- the sole `[[client.services]]` entry becomes a Catch-all Service

Catch-all mode matches every routed Public hostname except the Server hostname.

## Data path

1. A Visitor connects to `443/tcp` on the Server.
2. The Server buffers enough of the ClientHello to extract SNI.
3. The Server rejects non-TLS traffic, missing-SNI traffic, and application traffic addressed to the Server hostname.
4. The Server selects a Tunnel by Public hostname.
5. The Server forwards the original encrypted bytes over an existing Tunnel connection.
6. The receiving Client instance re-reads the forwarded ClientHello, selects a Service, and connects to the Local backend.
7. The Local backend terminates TLS and serves the application.

Runewarp adds no framing header to public traffic. The forwarded byte stream begins with the Visitor's original ClientHello.

## Trust and validation

- the Server hostname identifies the public edge itself
- each Tunnel trusts one Client identity in the base design
- a Client identity is the pinned public key, not a certificate serial or lifetime
- intra-side hostname uniqueness is enforced at boot
- cross-side hostname coverage is **not** validated at runtime; drift under Hostname mirroring is an operator responsibility

The current code authenticates only the Server side of the Tunnel connection. Client authentication is part of the committed operator design, but it has not landed in the phase-1 runtime yet.

## Product boundaries

- TLS passthrough is the product boundary
- customer TLS is terminated only on the Local backend
- plain HTTP backends are out of scope
- edge TLS termination for customer traffic is out of scope

## Current implementation note

Each Client instance establishes one Tunnel connection. The current code keeps only one active Client instance at a time, and supporting multiple Client instances per Tunnel is future work, so load-balanced Tunnel pools are intentionally left out of the committed baseline docs.

## Future work

- load-balanced Tunnel pools across multiple Client instances
- wildcard Public hostnames
- public QUIC and HTTP/3 passthrough
- ECH
- clustered routing and live config distribution
