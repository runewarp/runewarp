# Protocol

This document describes the committed Runewarp wire behavior and runtime invariants.

## Listener model

| Listener | Traffic | Behavior |
| --- | --- | --- |
| `443/tcp` | Visitor TLS | Read ClientHello, extract SNI, and route raw bytes without terminating customer TLS |
| `443/tcp` | ACME for the **Server hostname** | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `443/udp` | Client **Tunnel connections** | QUIC/TLS with ALPN `runewarp/1` |

## Public TLS routing

For each inbound TCP connection on port `443`:

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

The buffered ClientHello must never be logged or echoed back in diagnostics. When logs are enabled, diagnostics may log the normalized **Public hostname** and the routing outcome only.

## Drop conditions

| Condition | Result |
| --- | --- |
| Non-TLS traffic on `443/tcp` | Drop immediately |
| TLS without SNI | Drop immediately |
| Application traffic addressed to the **Server hostname** | Drop unless it is ACME TLS-ALPN-01 |
| Unauthorized **Public hostname** | Drop immediately |
| No active **Tunnel connection** for the selected **Tunnel** | Drop immediately |
| No matching Client **Service** | Reject the stream on the Client |

## Tunnel connection handshake

Each **Client instance** establishes one long-lived QUIC connection to `server-hostname:443` over UDP:

1. Resolve `client.server-hostname`.
2. Dial UDP port `443`.
3. Negotiate QUIC with ALPN `runewarp/1`.
4. Validate the Server certificate for the **Server hostname**, using either system trust or the exclusive configured `server-ca-file`.
5. Present the Client certificate and authenticate the pinned `client-identity` from its public key.

Rules:

- QUIC **0-RTT is disabled**
- reconnect attempts re-resolve `server-hostname` every time, including the first immediate retry
- idle timeout should stay in the **5-10 minute** range
- keepalive pings should be sent every **2-3 minutes** to survive common NATs and mobile carriers

## Client-side Service selection

When the Client receives a new QUIC stream:

1. Buffer the forwarded ClientHello and parse it using the same **16 KB** cap.
2. Extract and normalize the SNI hostname.
3. If there is exactly one configured **Service** and it omits `public-hostnames`, select that **Catch-all Service**.
4. Otherwise, match the hostname to `client.services[*].public-hostnames`.
5. If no Service matches, reject the stream immediately.
6. Open a TCP connection to the selected `backend-address`.
7. Forward the buffered ClientHello bytes, then continue streaming in both directions.

Notes:

- the ClientHello may span multiple reads on both TCP and QUIC streams
- the parser must accumulate bytes until the TLS record is complete before attempting to extract SNI
- `backend-address` must point at a TLS-terminating backend

## Stream lifecycle

Runewarp uses symmetric close behavior:

- a TCP FIN maps to QUIC `STREAM_FIN` in the same direction
- a QUIC `STREAM_FIN` maps to TCP half-close in the same direction
- resets or connection loss terminate the stream immediately

When a QUIC connection drops, all streams on that connection are lost. They are not migrated elsewhere.

## Retry behavior

Client reconnect behavior is:

1. retry immediately once after disconnect
2. if that fails, wait `reconnect-interval`
3. keep retrying every `reconnect-interval` seconds

`reconnect-interval` must be at least **1 second**.

If a new authenticated connection replaces an older connection for the same **Tunnel**, the older connection closes and any streams on it are lost.

## Runtime invariants

- each **Client instance** has exactly one **Tunnel connection**
- the runtime keeps one active connection per **Tunnel**
- the runtime does not validate cross-side hostname coverage under **Hostname mirroring**
- there is no pre-flight **Local backend** health check
- multiple Client instances across different Tunnels are supported
