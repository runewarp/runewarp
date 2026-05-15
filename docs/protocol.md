# Protocol

This document describes the committed Runewarp wire behavior. The current code implements only the phase-1 catch-all TCP-to-QUIC-to-TCP data path with one active Client instance and Server-authenticated Tunnel connections.

## Listener model

| Listener | Traffic | Baseline handling |
| --- | --- | --- |
| `443/tcp` | Visitor TLS | Read ClientHello, extract SNI, route raw bytes without terminating customer TLS |
| `443/tcp` | ACME for the Server hostname | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `443/udp` | Client Tunnel connections | QUIC/TLS with ALPN `runewarp/1` |

Current code status: the Visitor TLS path and the Server-authenticated QUIC connection are implemented. ACME and Client authentication land in later phases.

## Public TCP routing

For each inbound TCP connection on port `443`:

1. Buffer bytes until the TLS ClientHello can be parsed, up to a hard cap of **16 KB**.
2. If the cap is hit before SNI is extracted, drop the connection.
3. If the bytes are not valid TLS, drop the connection.
4. If TLS is valid but SNI is missing, drop the connection.
5. If SNI equals `server.hostname` and ALPN is `acme-tls/1`, handle the ACME challenge.
6. If SNI equals `server.hostname` and ALPN is anything else, drop the connection.
7. Otherwise, select a Tunnel by Public hostname:
   - in Catch-all mode, the single Tunnel matches every routed Public hostname except the Server hostname
   - with multiple Tunnels, use exact hostname matching
8. Open a bidirectional stream on the selected Tunnel connection, forward the buffered ClientHello bytes, then continue streaming in both directions.

The buffered ClientHello must never be logged or echoed back in diagnostics.

## Tunnel connection handshake

Each Client instance establishes one long-lived QUIC connection to `server-hostname:443` over UDP:

1. Resolve `client.server-hostname`.
2. Dial UDP port `443`.
3. Negotiate QUIC with ALPN `runewarp/1`.
4. Validate the Server certificate for the Server hostname.
5. In the committed baseline, present the Client certificate and authenticate the pinned Client identity from its public key.

Current code status: step 5 is not implemented yet.

Rules:

- QUIC **0-RTT is disabled**
- reconnect attempts re-resolve `server-hostname` every time, including the first immediate retry
- idle timeout should stay in the **5-10 minute** range
- keepalive pings should be sent every **2-3 minutes** to survive common NATs and mobile carriers

## Client-side Service selection

When the Client receives a new QUIC stream:

1. If it has exactly one configured Service and that Service omits `hostnames`, send the stream directly to that `local-addr`.
2. Otherwise, buffer the forwarded ClientHello and parse it using the same **16 KB** cap.
3. Extract and normalize the SNI hostname.
4. Match the hostname to `client.services[*].hostnames`.
5. Open a TCP connection to the selected `local-addr`.
6. Forward bytes in both directions.

Hostname mirroring is why both sides may list the same Public hostname: the Server uses it to choose a Tunnel and the Client uses it to choose a Service.

Notes:

- the ClientHello may span multiple reads on both TCP and QUIC streams
- the parser must accumulate bytes until the TLS record is complete before attempting to extract SNI
- `local-addr` must point at a TLS-terminating backend

## Closure semantics

Runewarp uses symmetric close behavior:

- a TCP FIN maps to QUIC `STREAM_FIN` in the same direction
- a QUIC `STREAM_FIN` maps to TCP half-close in the same direction
- resets or connection loss terminate the stream immediately

## Retry behavior

Client reconnect behavior is:

1. retry immediately once after disconnect
2. if that fails, wait `retry-interval`
3. keep retrying every `retry-interval` seconds

`retry-interval` must be at least **1 second**.

When a QUIC connection drops, all streams on that connection are lost. They are not migrated elsewhere.

## Operational limits

- each Client instance has exactly one Tunnel connection
- the runtime does not validate cross-side hostname coverage under Hostname mirroring
- there is no pre-flight Local backend health check
- the current implementation keeps only one active Client instance at a time

## Future protocol work

- load-balanced Tunnel pools across multiple Client instances
- public QUIC and HTTP/3 passthrough on `443/udp`
- wildcard hostname routing
- ECH for public and Client connections
- HTTP/3-based remote configuration on the existing QUIC connection instead of a custom control protocol
