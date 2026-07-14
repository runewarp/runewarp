# Protocol

This document describes Runewarp's wire behavior and runtime invariants.

## Listener model

| Listener | Traffic | Behavior |
| --- | --- | --- |
| `server.public-bind-address` (default `0.0.0.0:443/tcp`) | Visitor TLS | Read ClientHello, extract SNI, and route raw bytes without terminating customer TLS |
| `server.public-bind-address` (same TCP listener) | ACME for the **Server hostname** | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `server.tunnel-bind-address` (default `0.0.0.0:443/udp`) | Client **Tunnel connections** | QUIC/TLS with ALPN `runewarp/1` |

## Public TLS routing

For each inbound TCP connection on the configured `server.public-bind-address`:

1. Acquire one pre-routing admission slot before starting per-Visitor work.
2. Buffer bytes until the TLS ClientHello can be parsed, up to a hard cap of **16 KB** and a **5-second** completion deadline.
3. Release pre-routing capacity as soon as ClientHello parsing succeeds or fails; routed Visitor streams do not retain it.
4. If the deadline or byte cap is hit before SNI is extracted, drop the connection.
5. If the bytes are not valid TLS, drop the connection.
6. If TLS is valid but SNI is missing, drop the connection.
7. If SNI equals `server.hostname` and ALPN is `acme-tls/1`, handle the ACME challenge.
8. If SNI equals `server.hostname` and ALPN is anything else, drop the connection.
9. Otherwise, select a **Tunnel** by exact normalized **Public hostname** from `server.tunnels[].public-hostnames`.
10. If no Tunnel owns that hostname, drop the connection.
11. If the selected Tunnel has no active **Tunnel connection**, drop the connection.
12. Open a bidirectional stream on the selected Tunnel connection, forward the buffered ClientHello bytes, then continue streaming in both directions.

The buffered ClientHello must never be logged or echoed back in diagnostics. With top-level `log-level = "debug"`, stderr diagnostics may log the normalized **Public hostname** using stable event plus key=value fields such as `public-hostname`, `backend-address`, and `reason`. `acme-tls/1` traffic for the **Server hostname** is logged as `server acme challenge handled` with `server-hostname=...`, while Client-side `acme-tls/1` traffic for terminating **Public hostnames** is logged as distinct ACME challenge handling rather than ordinary terminate routing. Runtime tunnel failure causes keep separate full-detail lines whose operator-facing `warn` lines are shortened.
The buffered ClientHello must never be logged or echoed back in diagnostics.

At `log-level = "debug"`, stderr may include:

- the normalized **Public hostname**
- stable key=value fields such as `public-hostname`, `backend-address`, and `reason`
- `server acme challenge handled` with `server-hostname=...` for `acme-tls/1` traffic on the **Server hostname**
- separate Client ACME challenge handling lines for terminating **Public hostnames**

It must not include HTTP headers, bodies, decrypted application plaintext, or the raw buffered ClientHello.

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

## Server admission and overload

Server admission uses fixed production limits; these are runtime safety policy, not operator configuration.

| Work | Limit | Saturation behavior |
| --- | ---: | --- |
| Visitor pre-routing work | **4,096** globally | Close the newest accepted socket before spawning its handler |
| Visitor pre-routing work from one accepted peer IP | **256** | Close the newest socket from that source before spawning its handler |
| Concurrent Server-side QUIC handshakes | **256** | Refuse the newest QUIC `Incoming` before spawning handshake work |
| Active Tunnel connections | **4,096** globally | Complete authentication, then close the newest connection |
| Active Tunnel connections in one Tunnel pool | **256** | Close the newest connection; keep existing pool members |
| Active Tunnel connections for one Client identity | **64** globally | Close the newest connection; keep existing connections for that identity |

The per-source Visitor limit uses only the peer IP returned by the accepted TCP socket. Behind a load balancer, many Visitors may therefore share one source bucket. Core does not trust `Forwarded`, `X-Forwarded-For`, PROXY protocol, or any other application-supplied source identity. Completed ClientHellos release both Visitor admission slots before Tunnel selection and proxying, so saturation does not consume capacity from already-routed Visitor traffic.

Tunnel handshake slots are released on every handshake success, rejection, timeout, cancellation, and listener shutdown path. Active Tunnel slots are retained for the connection lifetime, including Authorization pool realignment, and released after connection termination. If realignment combines previously admitted pools above the per-Tunnel limit, those existing healthy connections remain grandfathered; new connections are rejected until churn returns the pool below its limit. Reaching any active-connection limit during admission rejects the newest connection without evicting a healthy pool member.

Transient public-listener accept failures retry after `10ms`, doubling to a maximum `1s`. A successful accept resets the backoff to `10ms` and emits recovery. Errors outside the transient socket/resource classes remain fatal: readiness drops and the Server exits according to its existing fatal-error policy.

Admission saturation warnings include the active-work count and limit and are limited to one line per scope every **10 seconds**. Repetitive unauthorized-identity and QUIC handshake-failure warnings use the same bound. The first successful admission or handshake after a corresponding failure emits one recovery line. Timeout and routing rejection details remain debug-level events, while accepted and terminated Tunnel connections retain their existing lifecycle events.

## Tunnel connection handshake

Each **Client instance** establishes one long-lived QUIC connection per effective **Server address** over UDP. Effective **Server addresses** come from either `client.server-address`, `client.server-addresses`, or repeated runtime `--server-address` flags. An **Address controller** owns one worker per normalized address so static fanout and Managed-session assignment changes cannot start duplicate dial loops for the same target:

1. Resolve the hostname portion of one effective **Server address**.
2. Dial the UDP port from that **Server address**, defaulting to `443` when the port is omitted.
3. Negotiate QUIC with ALPN `runewarp/1`.
4. Validate the Server certificate for that **Server address**'s **Server hostname**, using either system trust or `client.server-trust = "ca-file"` with an exclusive CA bundle.
5. Present the Client certificate and authenticate one of the Tunnel's pinned `client-identity` values from its public key.

Rules:

- QUIC **0-RTT is disabled**
- reconnect attempts re-resolve the hostname portion of each effective **Server address** every time, including the first jittered retry window
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

For orderly local shutdown that the runtime controls:

- when `server.readiness-bind-address` is configured, **Server readiness** is a probe-only TCP listener whose accept success means the Server is eligible for new ingress admission
- the **Server** drops **Server readiness** immediately when orderly shutdown begins
- the **Server** stops accepting new Visitor TCP traffic, new **Tunnel connections**, and new streams on already-open **Tunnel connections** before it closes active **Tunnel connections**
- **Graceful shutdown** lets only already-landed Visitor streams continue, up to `server.graceful-shutdown-duration`
- when that graceful deadline expires, the **Server** force-closes remaining active **Tunnel connections**
- **Fast shutdown** skips the longer graceful-drain window
- the **Client instance** stops new dial and retry work before it closes its active **Tunnel connection**
- both orderly shutdown modes still send the normal QUIC connection close and then wait the short fixed runtime-owned **QUIC close flush duration** before exit

## Retry behavior

Client instance reconnect behavior is:

1. after any failed or closed **Tunnel connection**, pick the next runtime-owned retry window from this exact sequence: `1, 2, 3, 5, 8, 12, 18, 27, 41, 60`
2. apply full jitter over `0..window` for that retry and sleep for the chosen delay
3. keep using the same sequence, capped at `60` seconds, until an authenticated **Tunnel connection** succeeds
4. reset back to the first `1` second window after every successful authenticated **Tunnel connection**

This reconnect policy is fixed. There is no reconnect tuning knob in the config or the CLI-only startup path.

Unauthorized **Client identity** failures use the same reconnect policy as every other reconnect failure. There is no dedicated immediate-retry exception for that case.

Failure and reconnect logs report the chosen next retry delay as `next-retry-delay=<Ns>`. The runtime rounds that displayed value up to whole seconds and never shows `0s`, even when jitter selects a sub-second delay.

When the remote **Server** exits gracefully, the **Client instance** still treats the closed **Tunnel connection** as an ordinary disconnect and keeps the same reconnect model above. There is no shutdown-specific reconnect branch.

When more than one authenticated connection is live for the same **Tunnel** on one **Server** node, those connections form a **Tunnel pool**. Each new Visitor stream is placed onto the pool member with the fewest active proxied streams, with round-robin tie-breaking when load is equal. If the chosen member dies before the proxied stream is established, the Visitor connection fails immediately; the Server does not retry placement onto a different pool member.

## Managed-session Control protocol

In **Managed mode**, each Server or Client runtime opens one mutually authenticated HTTP/2 **Managed session** to the configured **Control address**: one role-specific SSE downlink (`GET /v1/server/events` or `GET /v1/client/events`) plus one revision-only state acknowledgment (`PUT /v1/server/state` or `PUT /v1/client/state`) for each successfully handled snapshot on the same connection.

The 60-second first-snapshot/silence windows and Tunnel reconnect backoff apply as documented in [`managed.md`](managed.md). Quiet SSE downlinks use Control-owned comment keepalives; Core sends no periodic state heartbeat. That document is the canonical Core contract for endpoints, SSE framing, input schemas, revision semantics, Server authorization, Client assignment/Retiring, failure taxonomy, wire examples, and Control interoperability.

## Runtime invariants

- each **Client instance** has one or more **Tunnel connections** once dialing has succeeded
- in static Client mode, Client-ready means at least one configured **Server address** has an authenticated live **Tunnel connection**; managed Client mode uses **Assignment convergence** instead (see [`managed.md`](managed.md))
- failure, retry, and recovery stay isolated per effective **Server address**
- a **Tunnel** may have one or more authenticated live **Tunnel connections** on one **Server** node
- a **Tunnel** stays available while at least one of those **Tunnel connections** remains live
- active-stream placement within a same-**Tunnel** pool is least-active with round-robin tie-breaking
- once placed, a proxied stream stays bound to its chosen **Tunnel connection**; there is no live stream migration
- the runtime does not validate cross-side hostname coverage under **Hostname mirroring**
- there is no pre-flight **Local backend** health check
- multiple Client instances across different Tunnels are supported
- orderly runtime shutdown closes active **Tunnel connections** but does not add stream migration or draining guarantees
