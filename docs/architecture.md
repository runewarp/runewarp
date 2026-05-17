# Architecture

This document describes the committed Runewarp design. The current repository now ships the corrected phase-2 operator/runtime/authentication surface around `runewarp server cert ...`, `runewarp client identity ...`, directory-based material, exclusive manual-CA trust, Client authentication, same-key Client certificate renewal before the initial connect and reconnect attempts, and ACME for `server.hostname`. The committed phase-3 model still removes Server Catch-all and adds exact-match Server routing with one active Tunnel connection per Tunnel; those routing changes are not implemented yet.

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
- the Server only routes Public hostnames explicitly authorized on a Tunnel
- the Client does not register hostnames with the Server
- Public hostnames are the routing identity; there is no separate Tunnel or Service name field
- exact hostname overlap is rejected within Server Tunnels and within Client Services

Runewarp deliberately supports **Hostname mirroring**:

- operators repeat Public hostnames on both sides
- the Server uses them to select a Tunnel
- the Client uses the forwarded ClientHello to select a Service
- the grouping into Tunnels and Services may differ
- the public data path stays transparent because no extra routing header is added

Runewarp also supports **One-sided Catch-all**:

- the Server still uses explicit Public hostnames on every Tunnel
- the Client may omit `public-hostnames` only on its sole Service
- one Local backend can then handle every hostname the Server has already authorized for that Tunnel

## Client routing shape

Server Tunnels always declare explicit Public hostnames.

Client Services can be configured in two ways:

- exact-match Services, where the Client also lists explicit Public hostnames
- one Catch-all Service, used when one Local backend should receive every proxied hostname for that Tunnel

## Data path

1. A Visitor connects to `443/tcp` on the Server.
2. The Server buffers enough of the ClientHello to extract SNI.
3. The Server rejects non-TLS traffic, missing-SNI traffic, and application traffic addressed to the Server hostname.
4. The Server selects a Tunnel by exact Public hostname.
5. If that Tunnel has no active connection, the Server drops the connection.
6. Otherwise, the Server forwards the original encrypted bytes over that Tunnel connection.
7. The receiving Client instance re-reads the forwarded ClientHello, selects a Service, and connects to the Local backend.
8. If no Client Service matches, the Client rejects the stream.
9. The Local backend terminates TLS and serves the application.

Runewarp adds no framing header to public traffic. The forwarded byte stream begins with the Visitor's original ClientHello.

## Trust and validation

- the Server hostname identifies the public edge itself
- each Tunnel trusts one shared Client identity in the base design
- a Client identity is the pinned public key, not a certificate serial or lifetime
- manual Server certificates use a private Server CA that issues the Server leaf for `server.hostname`
- when the Client is configured with a Server CA file, that file replaces system trust for the Tunnel connection and may contain a CA bundle during `rotate-ca` transitions
- each Server Tunnel owns one explicit set of Public hostnames, and each `client-identity` names exactly one Tunnel
- intra-side hostname uniqueness is enforced at boot
- cross-side hostname coverage is **not** validated at runtime; drift under Hostname mirroring is an operator responsibility

The current code authenticates both sides of the Tunnel connection, uses exclusive configured `server-ca-file` trust on the Client, exposes the corrected operator surface, and renews same-key Client certificates before the initial connect and reconnect attempts. Phase-3 exact-match Server authorization and per-Tunnel connection isolation have not landed yet.

## Product boundaries

- TLS passthrough is the product boundary
- customer TLS is terminated only on the Local backend
- plain HTTP backends are out of scope
- edge TLS termination for customer traffic is out of scope

## Current implementation note

Each Client instance establishes one Tunnel connection. The committed phase-3 model keeps one active connection per Tunnel and one Client instance per Tunnel. The current code still keeps only one active Client instance at a time and still uses the phase-2 Server Catch-all shape, so those phase-3 changes are intentionally documented ahead of implementation.

## Future work

- load-balanced Tunnel pools across multiple Client instances of the same Tunnel
- wildcard Public hostnames
- public QUIC and HTTP/3 passthrough
- ECH
- clustered routing and live config distribution
