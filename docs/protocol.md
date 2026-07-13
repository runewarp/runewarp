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

In **Managed mode**, each Server or Client runtime establishes one mutually authenticated HTTPS session to the configured **Control address**:

1. Load the role identity certificate/key and Control trust roots for that connection attempt (Client identity for Clients; Server identity for Servers). Material is reloaded for each new connection, not per request.
2. Dial the Control hostname, require ALPN-negotiated HTTP/2 (`h2`), and never fall back to HTTP/1.1.
3. Open exactly one role-specific SSE downlink: `GET /v1/server/events` or `GET /v1/client/events`. The request carries no role selector, hostname selector, session ID, or runtime-instance ID.
4. Accept the SSE response only for status `200` with media type `text/event-stream`. Redirects, status `204`, other non-success statuses, and wrong media types fail the session.
5. Parse standard SSE framing. Comment lines are keepalives. `id` and `retry` fields are ignored. Every data event must be `event: snapshot` with JSON that includes a non-empty opaque `revision` and an `input` object; unknown JSON fields in a known v1 snapshot are ignored. Malformed framing, invalid UTF-8/JSON, missing required fields, empty revisions, and unknown event types fail the session.
6. The first valid snapshot has an independent 60-second deadline that keepalive comments cannot extend. Any 60-second silence without SSE bytes also replaces the session.
7. Validate role-specific `input` before reconciliation. Server input uses canonical plural `tunnels` entries with `public_hostnames` and `client_identities` only. Client input uses canonical plural `server_addresses`. Empty overall collections are valid. Invalid input is not acknowledged: the SSE stream stays open and the prior successfully applied revision is retained.
8. Reconciliation is latest-state and non-preemptive. Equal applied revisions skip apply. Previously applied non-current revisions remain valid rollback candidates. While an apply runs, newer complete snapshots collapse to one pending candidate. Server reconciliation emits Received, Applying, Applied, Rejected, and Superseded runtime events; a Server revision is acknowledged only after the atomic authorization swap and dispatch of required local revocation work, without awaiting peer acknowledgment or closure. Live continuity is derived from Client identity and Public hostname authorization (no Cloud Tunnel ID): removing a Client identity denies new handshakes and closes its live Tunnel connections and streams; removing only a Public hostname resets matching Visitor streams; unrelated authorized work survives. Surviving Tunnel connections are remapped when Tunnel ordinals change so identity continuity is preserved.
9. After the first successful apply, report the last successfully applied revision with `PUT /v1/server/state` or `PUT /v1/client/state` on the same authenticated HTTP/2 connection. The JSON body contains only `revision`. State writes begin only after the matching downlink is active, succeed only for exact status `204` with an empty body, report immediately after apply, and repeat every 20 seconds. A failed state write leaves the SSE stream undisturbed and retries on the next heartbeat without a second backoff machine. Before the first successful Server apply, the managed Server stays Unready and admits no Tunnel or Visitor work; after apply, Control loss retains the last authorization and readiness while the session reconnects. On graceful Server shutdown, readiness is lost immediately but the Managed session, snapshot application, and revision reporting remain active through the bounded drain so Authorization changes still apply immediately and do not inherit the graceful-drain deadline; the ephemeral session ends when the HTTP/2 connection closes at final process exit without a special offline/delete request. Fast shutdown may close the session immediately. A pre-commit failure retains prior authorization; an unrecoverable failure after commit begins never restores revoked authorization—readiness drops and the process exits nonzero.
10. Any downlink failure closes the entire HTTP/2 connection before reconnect. Reconnect uses the same full-jitter windows capped at 60 seconds as Tunnel reconnect; the policy resets only after a valid snapshot establishes the new session. Applied revision state is memory-only and does not survive process restart.

## Runtime invariants

- each **Client instance** has one or more **Tunnel connections**
- readiness means at least one configured **Server address** has an authenticated live **Tunnel connection**
- failure, retry, and recovery stay isolated per effective **Server address**
- a **Tunnel** may have one or more authenticated live **Tunnel connections** on one **Server** node
- a **Tunnel** stays available while at least one of those **Tunnel connections** remains live
- active-stream placement within a same-**Tunnel** pool is least-active with round-robin tie-breaking
- once placed, a proxied stream stays bound to its chosen **Tunnel connection**; there is no live stream migration
- the runtime does not validate cross-side hostname coverage under **Hostname mirroring**
- there is no pre-flight **Local backend** health check
- multiple Client instances across different Tunnels are supported
- orderly runtime shutdown closes active **Tunnel connections** but does not add stream migration or draining guarantees
