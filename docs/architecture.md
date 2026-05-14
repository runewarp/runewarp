# Architecture

Runewarp is a self-hostable tunnel for private TLS services. The public edge inspects only enough of the ClientHello to route by SNI, then forwards the original encrypted byte stream to a client running beside the real TLS endpoint.

## Status

These docs describe the full intended design. Features that land later are marked as future work. Early phases start with one catch-all tunnel on the server and one catch-all service on the client.

## System roles

| Component | Responsibility |
| --- | --- |
| Server | Accept public traffic, authenticate client tunnels, choose a tunnel pool, forward bytes, handle ACME for its own hostname |
| Client | Maintain the outbound QUIC tunnel, choose the local backend, forward bytes to the service |
| Local backend | Terminate TLS and serve the application |

## Core routing model

Runewarp keeps routing authority on the server:

- The server decides which public hostnames belong to which tunnel entry.
- The client does not register hostnames with the server.
- Hostnames are the routing identity. There is no separate tunnel or service name field.
- Exact hostname overlap is a boot-time validation error on both server and client.

Early phases use a single catch-all tunnel and a single catch-all service:

- one `[[server.tunnels]]` entry, with `hostnames` omitted
- one `[[client.services]]` entry, with `hostnames` omitted

Later phases expand that model to multiple tunnel entries and multiple service entries, while keeping server-owned routing.

## Listener model

### Early phases

| Endpoint | Purpose |
| --- | --- |
| `443/tcp` | Public TLS passthrough and ACME TLS-ALPN-01 for the server hostname |
| `443/udp` | Client QUIC tunnels only |

### Future phases

Later phases may also accept public QUIC and HTTP/3 on `443/udp`. At that point the server will need to distinguish public QUIC from client tunnel QUIC using SNI and ALPN during handshake handling.

## Tunnel pools

A tunnel pool is the set of live client connections accepted for the same configured client public-key fingerprint.

- New public streams are assigned with least-active balancing.
- Ties are broken round-robin.
- Existing streams stay on the connection that accepted them.
- The server cannot verify that every replica in a pool serves the same hostnames.

That last point is an operational risk: if one replica is missing a hostname, the server can still send traffic there, and the failure only shows up on the client side.

## Routing expansion

The long-term routing model is broader than the early-phase catch-all form:

- exact-match hostname routing after the single-entry phase
- wildcard hostname support in a later phase
- multiple client fingerprints per tunnel entry in a later phase
- remote server configuration in a later phase

Subdomain routing under the server hostname is allowed. For example, `api.tunnel.example.com` may be routed as an application hostname. Wildcards covering the server hostname space, such as `*.tunnel.example.com`, should be rejected.

## No framing on public streams

Runewarp does not add a custom framing header to public traffic. The forwarded stream already begins with the visitor's TLS ClientHello, so:

1. the server can extract SNI to choose a tunnel pool
2. the client can read the same ClientHello to choose `local-addr`
3. the public data path stays transparent

If client/server coordination is needed later, prefer HTTP/3 on the existing QUIC connection over inventing a custom protocol.

## Future architecture work

- public QUIC and HTTP/3 passthrough on `443/udp`
- ECH support for both public and client connections
- clustered multi-node routing
- live config updates without dropping active connections
- IPv6 support
- configurable public and tunnel ports
