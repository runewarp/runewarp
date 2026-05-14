# Protocol

This document describes the intended wire behavior for Runewarp. Early phases begin with a smaller subset: one catch-all tunnel, one catch-all service, public TLS over TCP, and client tunnels over QUIC on UDP.

## Port 443 handling

### Early phases

| Listener | Traffic | Handling |
| --- | --- | --- |
| `443/tcp` | Public TLS | Read ClientHello, extract SNI, route raw bytes without TLS termination |
| `443/tcp` | ACME for the server hostname | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `443/udp` | Client tunnels | QUIC/TLS with ALPN `runewarp/1` and mTLS |

### Future phases

Public QUIC and HTTP/3 may also arrive on `443/udp` in a later phase. When that happens, the server will need to separate public QUIC from client tunnel QUIC during handshake processing, using SNI and ALPN.

## TCP public decision tree

For each inbound TCP connection on port 443:

1. Buffer bytes until the TLS ClientHello can be parsed, up to a hard cap of **16 KB**.
2. If the cap is hit before SNI is extracted, drop the connection.
3. If the bytes are not valid TLS, drop the connection.
4. If TLS is valid but SNI is missing, drop the connection.
5. If SNI equals `server.hostname` and ALPN is `acme-tls/1`, handle the ACME challenge.
6. If SNI equals `server.hostname` and ALPN is anything else, drop the connection and log the event.
7. Otherwise, route by hostname:
   - in early phases, the single server tunnel catches all valid SNI values
   - later, the server routes by its configured hostname table
8. Open a QUIC stream to the selected client connection and forward the buffered bytes, then continue streaming in both directions.

The buffered ClientHello must never be logged or echoed back in diagnostics.

## Tunnel handshake

The client establishes one long-lived QUIC connection to `server-hostname:443` over UDP:

1. Resolve `client.server-hostname`.
2. Dial UDP port `443`.
3. Negotiate QUIC with ALPN `runewarp/1`.
4. Validate the server certificate.
5. Present the client certificate for mTLS.
6. Verify the pinned client public-key fingerprint on the server.

Rules:

- QUIC **0-RTT is disabled**.
- Reconnect attempts re-resolve `server-hostname` every time, including the first immediate retry.
- Idle timeout should stay in the **5-10 minute** range.
- Keepalive pings should be sent every **2-3 minutes** to survive common NATs and mobile carriers.

## Client-side backend selection

When the client receives a new QUIC stream:

1. If it has exactly one configured service and that service omits `hostnames`, send the stream directly to that `local-addr`.
2. Otherwise, buffer the forwarded ClientHello and parse it using the same **16 KB** cap.
3. Extract and normalize the SNI hostname.
4. Match the hostname to `client.services[*].hostnames`.
5. Open a TCP connection to the selected `local-addr`.
6. Forward bytes in both directions.

Notes:

- The ClientHello may span multiple reads on both TCP and QUIC streams.
- The parser must accumulate bytes until the TLS record is complete before attempting to extract SNI.
- `local-addr` must point at a TLS-terminating backend.

## Closure semantics

Runewarp uses symmetric close behavior:

- a TCP FIN maps to QUIC `STREAM_FIN` in the same direction
- a QUIC `STREAM_FIN` maps to TCP half-close in the same direction
- resets or connection loss terminate the stream immediately

An active stream remains counted as active until both directions are closed or the stream has been reset.

## Retry behavior

Client reconnect behavior is:

1. retry immediately once after disconnect
2. if that fails, wait `retry-interval`
3. keep retrying every `retry-interval` seconds

`retry-interval` must be at least **1 second**.

When a QUIC connection drops, all streams on that connection are lost. They are not migrated to another client connection.

## Local backend behavior

Runewarp connects to `local-addr` on demand when a public stream arrives.

- there is **no** pre-flight backend health check
- a dead backend is discovered only when connection attempts fail
- a misconfigured or dead replica may still look eligible to the server until streams begin failing

That limitation is acceptable early on, but health-aware routing is a planned future improvement.

## Load balancing

When multiple client connections are available in the same tunnel pool:

- choose the connection with the fewest active streams
- break ties round-robin
- decrement the active count only when the stream is fully closed or reset

Later phases may allow a single tunnel entry to trust multiple fingerprints as one load-balanced pool.

## Known limits

- The server does not validate that client-side hostname coverage matches server-side hostname routing.
- A client with a dead local backend can repeatedly be chosen by least-active balancing once its failed streams have drained.
- Early phases handle public TLS on TCP only. Public QUIC and HTTP/3 are future work.

## Future protocol work

- public QUIC and HTTP/3 passthrough on `443/udp`
- wildcard hostname routing
- ECH for public and client connections, which will require key material for routed domains
- HTTP/3-based remote configuration on the existing QUIC connection instead of a custom control protocol
