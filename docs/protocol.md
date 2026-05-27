# Protocol

This document describes the committed Runewarp wire behavior and runtime invariants.

## Listener model

| Listener | Traffic | Behavior |
| --- | --- | --- |
| `server.public-bind-address` (default `0.0.0.0:443/tcp`) | Visitor TLS | Read ClientHello, extract SNI, and route raw bytes without terminating customer TLS |
| `server.public-bind-address` (same TCP listener) | ACME for the **Server hostname** | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `server.tunnel-bind-address` (default `0.0.0.0:443/udp`) | Client **Tunnel connections** | QUIC/TLS with ALPN `runewarp/1` |

## Public TLS routing

For each inbound TCP connection on the configured `server.public-bind-address`:

1. Buffer bytes until the TLS ClientHello can be parsed, up to a hard cap of **16 KB**.
2. If the cap is hit before SNI is extracted, drop the connection.
3. If the bytes are not valid TLS, drop the connection.
4. If TLS is valid but SNI is missing, drop the connection.
5. If SNI equals `server.hostname` and ALPN is `acme-tls/1`, handle the ACME challenge.
6. If SNI equals `server.hostname` and ALPN is anything else, drop the connection.
7. Otherwise, select a **Tunnel** by exact normalized **Public hostname** from `server.tunnels[].public-hostnames`.
8. If no Tunnel owns that hostname, drop the connection.
9. If the selected Tunnel has no active **Tunnel connection**, drop the connection.
10. Open a bidirectional stream on the selected Tunnel connection, forward the buffered ClientHello bytes, then continue streaming in both directions.

The buffered ClientHello must never be logged or echoed back in diagnostics. With top-level `log-level = "debug"`, stderr diagnostics may log the normalized **Public hostname** using stable event plus key=value fields such as `public-hostname`, `backend-address`, and `reason`. `acme-tls/1` traffic for the **Server hostname** is logged as `server acme challenge handled` with `server-hostname=...`, while Client-side `acme-tls/1` traffic for terminating **Public hostnames** is logged as distinct ACME challenge handling rather than ordinary terminate routing. Runtime tunnel failure causes keep separate full-detail lines whose operator-facing `warn` lines are shortened.

## Drop conditions

| Condition | Result |
| --- | --- |
| Non-TLS traffic on the public TCP listener | Drop immediately |
| TLS without SNI | Drop immediately |
| Application traffic addressed to the **Server hostname** | Drop unless it is ACME TLS-ALPN-01 |
| **Public hostname** not authorized by the selected **Tunnel** | Drop immediately |
| No active **Tunnel connection** for the selected **Tunnel** | Drop immediately |
| No matching Client **Service** | Reject the stream on the Client |
| Terminating hostname with no ready ACME certificate | TLS handshake failure at the Client (fail closed) |

## Tunnel connection handshake

Each **Client instance** establishes one long-lived QUIC connection to `client.server-address` over UDP:

1. Resolve the hostname portion of `client.server-address`.
2. Dial the UDP port from `client.server-address`, defaulting to `443` when the port is omitted.
3. Negotiate QUIC with ALPN `runewarp/1`.
4. Validate the Server certificate for the **Server hostname**, using either system trust or `client.server-trust = "ca-file"` with an exclusive CA bundle.
5. Present the Client certificate and authenticate the pinned `client-identity` from its public key.

Rules:

- QUIC **0-RTT is disabled**
- reconnect attempts re-resolve the hostname portion of `client.server-address` every time, including the first immediate retry
- tunnel handshakes time out after **10 seconds** on both the Client and Server sides
- idle timeout is **60 seconds**
- keepalive pings are sent every **20 seconds**

## Client-side Service selection

When the Client receives a new QUIC stream:

1. Buffer the forwarded ClientHello and parse it using the same **16 KB** cap.
2. Extract and normalize the SNI hostname.
3. If there is exactly one configured **Service** and it omits `public-hostnames`, select that **Catch-all Service**.
4. Otherwise, match the hostname to `client.services[*].public-hostnames`.
5. If no Service matches, reject the stream immediately.
6. If the matched Service has `tls-mode = "passthrough"` (default):
   a. Open a TCP connection to the selected `backend-address`.
   b. Forward the buffered ClientHello bytes, then continue streaming in both directions.
7. If the matched Service has `tls-mode = "terminate"`:
   a. Complete the TLS handshake with the Visitor using the per-hostname certificate — from `client.public-cert-dir` (manual path) or from `[client.acme]` (ACME path). If `[client.acme]` is in use and the certificate for that hostname is not yet ready, the TLS handshake fails immediately (fail closed); there is no fallback to passthrough.
   b. Open a TCP connection to the selected `backend-address`.
   c. Proxy decrypted data between the TLS stream and the plaintext backend connection.

Notes:

- the ClientHello may span multiple reads on both TCP and QUIC streams
- the parser must accumulate bytes until the TLS record is complete before attempting to extract SNI
- `backend-address` must point at a TLS-terminating backend when `tls-mode = "passthrough"`; it receives plaintext when `tls-mode = "terminate"`
- when `[client.acme]` is configured, `acme-tls/1` challenge connections for **Public hostnames** arrive through the Server's normal Visitor routing path and are handled by the Client's ACME resolver alongside regular TLS connections for those hostnames

## Stream lifecycle

Runewarp uses symmetric close behavior:

- a TCP FIN maps to QUIC `STREAM_FIN` in the same direction
- a QUIC `STREAM_FIN` maps to TCP half-close in the same direction
- resets or connection loss terminate the stream immediately

When a QUIC connection drops, all streams on that connection are lost. They are not migrated elsewhere.

## Retry behavior

Client reconnect behavior is:

1. retry immediately once after disconnect
2. if that fails, wait the runtime reconnect interval
3. keep retrying on that runtime reconnect interval

The current runtime reconnect interval is **1 second** after the first immediate retry. This cadence is runtime-owned rather than configurable.

Unauthorized **Client identity** failures are treated differently: after the rejection, the Client skips the extra immediate retry and waits for the normal runtime reconnect interval before trying again.

If a new authenticated connection replaces an older connection for the same **Tunnel**, the older connection closes and any streams on it are lost.

## Runtime invariants

- each **Client instance** has exactly one **Tunnel connection**
- the runtime keeps one active connection per **Tunnel**
- the runtime does not validate cross-side hostname coverage under **Hostname mirroring**
- there is no pre-flight **Local backend** health check
- multiple Client instances across different Tunnels are supported
