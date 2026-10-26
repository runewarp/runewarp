# Protocol

This document describes Runewarp's wire behavior and runtime invariants.

## Listener model

| Listener | Traffic | Behavior |
| --- | --- | --- |
| `server.public-bind-address` / `server.public-bind-addresses` (default `0.0.0.0:443/tcp`) | Visitor TLS | Read ClientHello, extract SNI, and route raw bytes without terminating customer TLS |
| `server.public-bind-address` / `server.public-bind-addresses` (same TCP listeners) | ACME for the **Server hostname** | Terminate only when SNI matches `server.hostname` and ALPN is `acme-tls/1` |
| `server.tunnel-bind-address` / `server.tunnel-bind-addresses` (default `0.0.0.0:443/udp`) | Client **Tunnel connections** | HTTP/3 over QUIC/TLS with ALPN `h3` |

Each transport has mutually exclusive singular and plural bind keys. `server.public-bind-address` and `server.tunnel-bind-address` accept only one literal socket address string; `server.public-bind-addresses` and `server.tunnel-bind-addresses` accept only arrays of 1 to 8 distinct addresses. Supplying both members of a pair is an error even when either value is empty or invalid. Public and Tunnel forms can be mixed independently; omitting both members of a pair uses `0.0.0.0:443`. Each address owns a listener; every listener shares the same Server authorization, Tunnel pools, runtime generation and admission limits. Startup binds all addresses before accepting work; any bind failure releases the earlier sockets and fails startup. Shutdown stops intake across all listeners and drains their Tunnel connections under one shared deadline. Tunnel ports are operator-selected, defaulting to UDP 443 with ALPN `h3` on every listener.

## Public TLS routing

For each inbound TCP connection on any configured `server.public-bind-address` or `server.public-bind-addresses` listener:

1. Acquire one pre-routing admission slot before starting per-Visitor work.
2. In direct mode, derive the canonical Visitor tuple from the socket. In strict PROXY v2 mode, verify the accepted peer against configured CIDRs and consume a bounded valid header.
3. Buffer bytes until the TLS ClientHello can be parsed. PROXY header plus ClientHello intake shares a **5-second** deadline; each has a **16 KB** cap.
4. Release pre-routing capacity as soon as ClientHello parsing succeeds or fails; routed Visitor streams do not retain it.
5. If the deadline or byte cap is hit before SNI is extracted, drop the connection.
6. If the bytes are not valid TLS, drop the connection.
7. If TLS is valid but SNI is missing, drop the connection.
8. If SNI equals `server.hostname` and ALPN is `acme-tls/1`, handle the ACME challenge.
9. If SNI equals `server.hostname` and ALPN is anything else, drop the connection.
10. Otherwise, select a **Tunnel** by exact normalized **Public hostname** from the current **Authorization snapshot**. Static config supplies `server.tunnels[].public-hostnames`; Managed mode receives authorization from Control.
11. If no Tunnel owns that hostname, drop the connection.
12. If the selected Tunnel has no active **Tunnel connection**, drop the connection.
13. Acquire one pending stream-open permit, then wait up to **5 seconds** for permit-backed QUIC credit to open a WebTransport Visitor stream on the selected Tunnel connection. On success, acquire one active routed-stream permit, release the pending permit, write a regenerated PROXY v2 header containing the canonical Visitor TCP tuple, then forward the buffered ClientHello as raw WebTransport stream bytes and continue streaming in both directions. A failed or expired stream open drops the Visitor without retrying another pool member. Successfully established proxies have no additional lifetime or idle deadline.

At `log-level = "debug"`, stderr may include:

- the normalized **Public hostname**
- stable key=value fields such as `public-hostname`, `backend-address`, and `reason`
- `server acme challenge handled` with `server-hostname=...` for `acme-tls/1` traffic on the **Server hostname**
- separate Client ACME challenge handling lines for terminating **Public hostnames**

It must not include HTTP headers, bodies, decrypted application plaintext, or the raw buffered ClientHello.

Runtime tunnel failures keep full detail at debug level while operator-facing warning lines remain concise.

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

Server admission uses fixed production maxima; these are runtime safety policy, not operator configuration. Unix startup can lower pending Visitor, pending-open and active routed-stream capacities to fit the fd allowance, as documented in [configuration](configuration.md#file-descriptor-capacity).

| Work | Limit | Saturation behavior |
| --- | ---: | --- |
| Visitor pre-routing work | **4,096** globally | Close the newest accepted socket before spawning its handler |
| Visitor pre-routing work from one canonical source IP | **256** | Close the newest socket from that source after direct/proxied tuple resolution |
| Concurrent Server-side QUIC handshakes | **256** | Refuse the newest QUIC `Incoming` before spawning handshake work |
| Pending Server Visitor stream opens | **4,096** | Drop the newest Visitor before waiting for Visitor stream credit |
| Active routed Visitor streams | **65,536** | Drop and reset the newest assigned Tunnel stream before proxying |
| Active Tunnel connections | **4,096** globally | Complete authentication, then close the newest connection |
| Active Tunnel connections in one Tunnel pool | **256** | Close the newest connection; keep existing pool members |
| Active Tunnel connections for one Client identity | **64** globally | Close the newest connection; keep existing connections for that identity |

The global slot protects PROXY header and ClientHello intake. The per-source slot uses the direct socket source or the validated tuple from a trusted strict-PROXY peer. Core never trusts `Forwarded`, `X-Forwarded-For`, or PROXY bytes from an untrusted peer. Completed ClientHellos release both slots before Tunnel selection and proxying.

Pending stream-open capacity is acquired immediately before waiting for Visitor stream credit and released on assignment, failure, the **5-second** stream-open deadline, active-stream rejection, cancellation, and shutdown. Tunnel selection reserves registration at the active-Visitor-work gate before the stream open. After a successful open, synchronous registration under that gate requires the route's Authorization snapshot to remain current and revalidates its Public hostname and Client identity, then atomically converts the reservation into one lease owning active routed-stream capacity, Tunnel-pool member load, routing identity, revocation, and cleanup for the proxy lifetime. Authorization commit and selective revocation use the same gate, so old-route registration cannot escape a replacement scan. Shutdown seals the gate; later registration is rejected and resets the assigned Tunnel stream. Normal return, error, revocation, cancellation, panic, and unpolled drop all release accounting exactly once. Graceful shutdown waits through event notification until both pre-seal reservations and leases are gone, not periodic polling. Established proxies have no additional lifetime or idle deadline in this policy.

Tunnel handshake slots are released on every handshake success, rejection, timeout, cancellation, and listener shutdown path. Active Tunnel slots are retained for the connection lifetime, including Authorization pool realignment, and released after connection termination. If realignment combines previously admitted pools above the per-Tunnel limit, those existing healthy connections remain grandfathered; new connections are rejected until churn returns the pool below its limit. Reaching any active-connection limit during admission rejects the newest connection without evicting a healthy pool member.

Transient public-listener accept failures retry after `10ms`, doubling to a maximum `1s`. A successful accept resets the backoff to `10ms` and emits recovery. Errors outside the transient socket/resource classes remain fatal: readiness drops and the Server exits according to its existing fatal-error policy.

Admission saturation warnings include the active-work count and limit and are limited to one line per scope every **10 seconds**. Repetitive unauthorized-identity and QUIC handshake-failure warnings use the same bound. The first successful admission or handshake after a corresponding failure emits one recovery line. Timeout and routing rejection details remain debug-level events, while accepted and terminated Tunnel connections retain their existing lifecycle events.

## Tunnel connection handshake

Each **Client instance** establishes one long-lived QUIC connection per effective **Server address** over UDP. During a replacement, a [candidate](#candidate-tunnel-connections) can add a second connection to the same address. Effective **Server addresses** come from `client.server-address`, `client.server-addresses`, repeated runtime `--server-address` flags, or a Control-published Managed assignment. Config validation prepares **Client admission** (static vs managed) once from Control address presence; Client startup wires one **Address controller** from that outcome. The controller owns the complete assigned Server-address lifecycle (one worker per normalized address, maintenance intent, production Retiring / reconnect-vs-exit policy, Assignment convergence, apply acknowledgment, and shutdown) so static fanout and Managed-session assignment changes cannot start duplicate dial loops for the same target. Every worker uses the same production Tunnel-connection-attempt implementation, which owns resolution, per-attempt material reload, QUIC and HTTP/3 establishment, the event-stream gate and WebTransport session, typed failure/connection-end classification, and reporting context:

1. Resolve the hostname portion of one effective **Server address**.
2. Dial the UDP port from that **Server address**, defaulting to `443` when the port is omitted.
3. Negotiate QUIC with ALPN `h3`.
4. Validate the Server certificate for that **Server address**'s **Server hostname**, using either system trust or `client.server-trust = "ca-file"` with an exclusive CA bundle.
5. Present the Client certificate and authenticate one of the Tunnel's pinned `client-identity` values from its public key.
6. Start HTTP/3 with Extended CONNECT, WebTransport draft07 and H3 Datagrams enabled in both peers' SETTINGS. The Client opens a bodyless `GET /v1/tunnel/events` and waits for the first valid snapshot. No Runewarp-specific SETTINGS marker is sent or required.
7. After that gate, establish exactly one WebTransport session with Extended CONNECT to `https://<Server hostname>/v1/tunnel/session`. Only then reserve permits and offer Visitor credit and return a successful connection attempt. A failed gate, negotiation or CONNECT is an ordinary attempt failure under the same retry policy. Static Client readiness and Managed Assignment convergence count only connections with an established WebTransport session.

Rules:

- QUIC **0-RTT is disabled**
- when DNS returns multiple addresses, the Client selects the first result in resolver order without preferring an address family
- reconnect attempts re-resolve the hostname portion of each effective **Server address** every time, including the first jittered retry window
- every attempt reloads the selected system or exclusive-CA trust roots and the Client certificate/key; exclusive-CA mode never loads or combines system roots
- QUIC handshakes time out after **10 seconds** on both sides; Server HTTP/3 establishment shares that handshake deadline and admission permit
- the Client allows **60 seconds** for the first valid event-stream snapshot after HTTP/3 setup, then **60 seconds** for WebTransport negotiation and CONNECT
- idle timeout is **60 seconds**
- only the Client sends QUIC keepalive pings, every **20 seconds**
- both peers advertise a **16 KiB decoded HTTP/3 field-section limit**, with **64 MiB connection receive credit** and **1,250,000 bytes of stream receive credit**

## WebTransport session

Both peers pin only WebTransport draft07: the max-sessions SETTINGS identifier is `0xc671706a` with value `1`, the Extended CONNECT token is `webtransport`, and the bidirectional stream signal is `0x41`. A WebTransport session ID is the full CONNECT stream ID: GET on stream `0` followed by CONNECT on stream `4` creates WebTransport session `4`, never `1`. Both peers enable Extended CONNECT, WebTransport and H3 Datagrams and enforce the fork's `Limits.sessions = 1`. The connection requires the existing pinned Client-identity mTLS; a WebTransport session grants no additional identity or Public-hostname authority.

The WebTransport session CONNECT uses the Server hostname as authority on its HTTPS origin and path `/v1/tunnel/session`. It remains open for the Tunnel connection lifetime. The Server returns bodyless `404` for another WebTransport session path, `421` for a different authority, and `400` for an unsupported Extended CONNECT protocol or invalid WebTransport request or negotiation. The fork's invalid-request and settings rejections remain bodyless `400`; its exhausted WebTransport session cap remains bodyless `429`. Rejections create no WebTransport session and leave ordinary signaling usable. The WebTransport CONNECT response and admission run under the signaling request deadline.

The Server opens one bidirectional WebTransport stream per Visitor through `SessionOpener::open_bi`; the Client receives it through its established session's `accept_bi`. The fork validates the full session ID and resets wrong, stale and truncated prefixes without delivering them. Client-originated WebTransport streams are rejected. Runewarp sends no datagrams. H3 Datagram SETTINGS reserve the draft-required capability for later Public QUIC work; they do not implement packet forwarding.

A close capsule or CONNECT stream end observed by either peer closes the whole Tunnel connection with `H3_NO_ERROR`, even if a peer withholds FIN after a close capsule. The Client's ordinary address worker reconnects; no WebTransport session is reopened on an existing connection. Connection loss ends the WebTransport session, and Authorization revocation closes the connection and WebTransport session immediately. GOAWAY alone leaves the established WebTransport session alive while already-placed Visitors drain. After local Visitor work and earlier signaling requests finish, the Server sends `DRAIN_WEBTRANSPORT_SESSION` without terminating the session. The Client releases its remaining Visitor leases, including streams queued for application acceptance and unread final bytes, then sends CLOSE. The Server closes the whole Tunnel on observing that CLOSE. The original graceful deadline bounds both phases; expiry, revocation and fast shutdown still close immediately.

## Visitor streams and credit

The Client grants the Server zero bidirectional credit during the QUIC handshake. After its WebTransport session is established, one connection task acquires permits from the Client-instance budget to maintain up to **T = 256 idle Visitor credits**, named `MAX_IDLE_VISITOR_CREDIT`. Every idle credit and active Visitor holds one permit from the same configured budget, **16,384 permits by default before Unix fd sizing**, shared across every connection of that Client instance. An arrival transfers an idle permit into its `TunnelStream`; a background acquisition replenishes idle credit when a permit becomes available. The accept task delivers streams without awaiting handler work. Active concurrency can exceed T and reach the entire budget on one connection. A quiet connection can reserve up to T permits, reducing capacity available to its peers. T bounds the initial burst per connection per credit round trip, about 12,800 arrivals per second at a 20 ms RTT before other costs.

All credit updates serialize under the connection controller's state mutex. After each update, the configured Quinn target equals active plus idle held permits. The update sets that held target, temporarily sets zero, then restores the held target before returning. It never sets a target above held permits. Quinn 0.11.11 with quinn-proto 0.11.19 otherwise batches increments of at most configured concurrency / 8, which can withhold the last reserved credit indefinitely. The temporary zero target queues already-allocated unsent credit with a zero batching threshold. This dependency on the pinned Quinn setter and batching behavior is covered by the raw eight-to-nine regression and full-budget tests; see [ADR 0007](adr/0007-webtransport-visitor-streams.md) and the [approved amendment](https://github.com/runewarp/runewarp/issues/256#issuecomment-6392362183).

At stream-budget saturation, completing or aborting one Visitor may leave replacement credit unadvertised even after its permit becomes available. A waiting Visitor can reach the Server's five-second open deadline and lose its connection while existing Visitors can continue forwarding. Single-release recovery is a known early-alpha availability limitation tracked in [#267](https://github.com/runewarp/runewarp/issues/267). The held/zero/held workaround and no-wait admission guard remain; no transport fix or reliable single-release recovery is claimed.

The three public calls acquire separate Quinn locks and are not atomic to its driver or concurrent FIN, ACK and EOF processing. Lowering never revokes already-issued credit. A transport completion during the zero interval allocates no replacement until restore; a completion before or after it can issue irrevocable replacement credit even while its handler retains a permit. Such credit does not reserve new handler capacity. An arrival without an idle permit tries the aggregate budget exactly once without waiting. Failure resets and stops the stream before handing it to a handler, using the existing saturation log rate limit. Normal burst and full-budget simultaneous admission have zero guard rejections. At an exhausted budget, FIN/ACK/EOF can permit a replacement before the previous handler releases its final half, including under production scheduling. That arrival is rejected by the guard. Concurrent tests cover load with handler headroom and saturated rounds whose handlers release before replacement work, separately from the deterministic retained-handler rejection case. No behavior depends on a received reset code.

Both application halves share a resource lease. The final half's Drop lowers the configured target before releasing its transport fields. The actual semaphore permit remains in the lease until both halves' transport fields have dropped, including when their Drops run concurrently. Finished or failed write handles stay retained until application Drop. Transport state can still be freed before application Drop, so the over-issue guard remains necessary.

GOAWAY preserves idle reservations and maintenance because a committed Visitor can arrive on an independently ordered stream after GOAWAY. On WebTransport DRAIN, the Client cancels its pending semaphore acquisition, stops replenishment and lowers the configured target before releasing all idle permits to sibling connections. Successful Server proxies have already observed Client FIN before local completion, so their Client streams own active or application-queued leases before DRAIN. Those leases remain tracked until both halves drop; intake and the no-wait guard remain live. Aborted proxies gain no delivery guarantee. A terminal wake from the session drain API still takes the immediate termination path, including CLOSE without peer FIN. Connection teardown also releases idle permits; active permits return when their stream halves drop.

The Client fork limits for incoming streams, pending prefixes and validated streams per session are each **256**, so the initial T burst does not exceed its queues. The application handoff queue is bounded by held permits rather than waiting on handlers. The Server admits **eight Client-initiated bidirectional request streams** for signaling, including the session CONNECT. Plain CONNECT receive slots are removed and receive bodyless `400`. Each peer permits eight unidirectional streams for HTTP/3 control, QPACK and reserved-stream headroom.

With no budget permit, credit maintenance waits and emits saturation warnings at most once every **10 seconds**. The next acquired permit emits one recovery line only if a saturation warning was emitted; suppressed warnings do not arm another recovery.

## Tunnel events

The Tunnel event stream follows the [SSE profile](sse.md). That document owns framing, the line and event-type limits, keepalive and silence timing, delivery, and versioning. This section covers only what is specific to the Tunnel link.

`GET /v1/tunnel/events` targets the Server hostname's HTTPS origin and ends its request with FIN, without DATA or trailers. The Client sends `Accept: text/event-stream`; the Server ignores `Accept`. The response is `200`, `content-type: text/event-stream`, and `cache-control: no-store`. Every data event has type `snapshot` and JSON data with the Server's full current state:

```text
event: snapshot
data: {"generation":"01928f3e-7b6a-7c3d-8e4f-0123456789ab","replacement_generation":"01928f3e-9c1d-7fed-9cba-9876543210fe"}

```

`generation` is required. The Server mints a fresh UUIDv7 at every start and sends it in canonical form: 36 lowercase characters with hyphens (`8-4-4-4-12`), version 7, and the RFC 9562 variant. Uppercase, unhyphenated, braced, URN, and other-version forms are invalid. Clients compare generations for equality only. A UUIDv7 embeds its mint time, so a generation reveals when that Server runtime started. `replacement_generation` is an optional **Replacement hint** with the same encoding. When present, it names another Server runtime generation behind the same Server address; absent means no hint. `null`, another JSON type, or an invalid encoding makes the snapshot malformed. Unknown fields are ignored. Snapshots carry no configuration, addresses, or credentials.

The Server writes the initial snapshot, then a new full snapshot whenever the advertised hint changes. All Tunnel connections on one Server runtime follow the same current snapshot. Each subscription holds at most one pending snapshot: a change published while a write is blocked replaces any unwritten one, so the next write carries only the latest snapshot. A blocked Server event write is cancelled after **60 seconds**. A new subscription supersedes the old one and starts with the current snapshot. Event data is capped at **4 KiB**.

Static Servers never send a hint. In Managed mode, Control supplies the hint in the Server input; a value equal to the Server's own generation is not advertised (see [`managed.md`](managed.md#server-input)). A Client acts on a hint by opening a candidate connection; see [candidate Tunnel connections](#candidate-tunnel-connections).

The first-snapshot deadline starts after HTTP/3 setup. After a stream end, failure, or **60 seconds of silence**, the Client waits **one second** and resubscribes while the connection remains usable and GOAWAY permits requests. A malformed snapshot, unexpected event type, or changed generation on the same connection closes the connection with `H3_GENERAL_PROTOCOL_ERROR`.

A Tunnel subscription failure only resubscribes; it never replaces the connection. The Tunnel connection carries live Visitor streams, and the event stream holds no state those Visitors depend on, so closing the connection would cost traffic and gain nothing. A Managed-session downlink failure replaces the whole HTTP/2 connection instead, because that connection carries only the downlink and its acknowledgments.

Oversized request header sections receive bodyless `431` before request-handler work is spawned; the connection remains usable. Signaling host mismatches receive bodyless `421`; unknown paths receive `404`; another method on the events resource receives `405` with `Allow: GET`, and on the withdrawal resource `405` with `Allow: PUT`. Validly declared positive content, otherwise valid DATA content, or trailers on a bodyless signaling request receive `400`. Malformed messages use the applicable HTTP/3 error, including `H3_MESSAGE_ERROR` for invalid content length. Bodyless-request intake has a **5-second** deadline from request headers and returns `408` on expiry. After a withdrawal `400` or `408`, the Server stops any still-open request intake without resetting the completed response.

## Placement withdrawal

A Client withdraws one Tunnel connection from Visitor placement with a bodyless `PUT /v1/tunnel/withdrawal` on a fresh request stream to the Server hostname's HTTPS origin, ending the request with FIN. Withdrawal is terminal and connection-scoped: it neither withdraws the Client identity nor affects other Tunnel connections. Graceful Client shutdown is its only trigger.

- **Commit:** withdrawal commits once the Server has validated the complete bodyless request. Cancelling or resetting the request stream afterwards never reverses it. A request that is cancelled, incomplete, rejected or timed out first does not commit.
- **Placement commitment:** a Visitor commits to a connection when its WebTransport stream opens. That commitment and the withdrawal commit are serialized, so a Visitor either committed first and may finish, or is never placed there. After commit the Server opens no new Visitor stream on the connection, even on credit it already holds; pending opens still waiting for credit end, and those Visitors are dropped without re-placement. Pool placement skips withdrawn members. Later Authorization changes or pool realignment never restore eligibility.
- **Quiescence:** the connection is quiescent when it is withdrawn with no committed Visitor stream left on the Server. The Server then sends bodyless `204` and FIN. A withdrawal before any Visitor is immediately quiescent.
- **Duplicates:** every valid concurrent or later request joins the same transition and receives `204` at the same quiescence point; invalid duplicates receive their own status.
- **Close:** the Server waits a fixed **5 seconds** after the first `204` completes locally, or after quiescence if every valid request was cancelled before any `204` completed, then closes the connection with `H3_NO_ERROR`. Later duplicates never restart that timer. Server shutdown deadlines and Fast escalation still close earlier.

When graceful shutdown withdraws a connection, the Client immediately stops replenishing idle credit and cancels any pending budget acquisition, but keeps the idle permits it already offered. The Server may still commit Visitors on that credit until its withdrawal commit, and the Client honors them; it never declines an assignment because its request is in flight. The Client confirms quiescence only on a bodyless `204` followed by response FIN, without content, trailers, `transfer-encoding` or a nonzero `content-length`; a `204` with such fields is stopped with `H3_MESSAGE_ERROR`. On confirmation it records the result, returns its idle permits to the Client-instance budget, waits for its local Visitor leases to drain so final bytes already in flight reach their handlers, and closes with `H3_NO_ERROR`. A deadline or Fast escalation during that local wait keeps the confirmation.

| Withdrawal result | Client classification |
| --- | --- |
| `204` with FIN and no content or trailers | Confirmed |
| Response-less stream failure or `408` while the connection is usable | Retry once on a fresh request stream of the same connection, within the shared deadline |
| A second response-less failure or `408` | Unconfirmed drain |
| GOAWAY forbids the request, the connection closes (including revocation), the deadline expires or Fast shutdown supersedes it | Unconfirmed drain |
| `400`, `404`, `405`, `421`, any other status, or a `204` declaring or carrying content or trailers | Withdrawal protocol failure |

An unconfirmed drain logs a warning with the Server address and closes that connection; active Visitors on it may have been terminated. A withdrawal protocol failure logs an error and closes that connection; other connections keep draining and the process exits nonzero after teardown, reporting the first failure. The Client never opens or reconnects a Tunnel connection to withdraw. GOAWAY does not trigger withdrawal. Authorization revocation always takes effect immediately: if it closes the connection first the drain is unconfirmed, and if its cleanup leaves the connection open and quiescent the `204` still completes.

## Candidate Tunnel connections

A **Candidate Tunnel connection** moves one Server address to another Server runtime without migrating streams. While the primary connection's snapshot carries a hint, the address worker keeps at most one candidate toward the hinted generation. A validated candidate joins as a second active connection; both carry Visitors until one goes away.

- **Start:** a valid primary snapshot whose `replacement_generation` differs from the primary's own generation starts one candidate attempt after a full-jitter delay from the first reconnect window. A hint naming the primary's generation is ignored.
- **Attempt:** the candidate uses the ordinary attempt on a new UDP socket: fresh DNS resolution, trust and certificate reload, QUIC and HTTP/3, pinned-identity mTLS and the event-stream gate. Its first snapshot must name the hinted generation before the WebTransport session.
- **Wrong generation:** any other generation, including the primary's (for example when NAT or a load balancer maps the new socket to the old runtime), closes only the candidate with `H3_NO_ERROR` and schedules a retry. Hints in the candidate's own snapshots are ignored while it is not the primary.
- **Join:** a validated candidate establishes its WebTransport session but offers no credit until the worker confirms the primary still hints that generation, unpaused. It then offers permit-backed credit from the shared Client-instance budget and becomes a second active connection. The Client sends no withdrawal on the old connection.
- **Leave:** a connection that receives GOAWAY drains under the [Server-drain rules](#stream-lifecycle). When the primary closes or is lost, for any reason, while a second connection is active, that connection becomes the primary without a reconnect. Otherwise the ordinary reconnect runs. While a second connection is active, no further candidate starts.
- **Retry:** failed candidates retry through the [reconnect sequence](#retry-behavior) with full jitter for as long as the same hint stands. Admission-limit closes are ordinary candidate failures. The sequence restarts after a join or a hint change.
- **Hint changes:** the same hint again is a no-op. A different hint aborts an unvalidated candidate and starts one for the new generation. A snapshot without a hint aborts an unvalidated candidate. A hint change never affects a joined connection.
- **Abort:** closes the candidate with `H3_NO_ERROR`. An unvalidated candidate carried no Visitor and holds no credit, so abort affects no traffic.
- **Subscription failure:** when the primary's subscription fails after a valid snapshot, no candidate joins until the Client learns why. The Client resubscribes under the one-second rule and aborts any unvalidated candidate. The resubscribed snapshot decides whether replacement restarts. The primary and its Visitors stay up.
- **GOAWAY on the primary:** the Client stops resubscribing. The last valid hint stands, and an in-flight candidate continues and may join. A candidate that completed while the Client was still finding out retries.
- **Retiring and shutdown:** removing the address from a Managed assignment aborts its candidate, and a Retiring address starts none; its active connections stay until remote close or shutdown. Re-adding it re-adopts them, and the standing hint can start a candidate again. Client graceful and fast shutdown abort candidates at once; graceful shutdown then [withdraws](#placement-withdrawal) every active connection, both during an overlap.

Unvalidated candidates never count for Static Client readiness or Managed Assignment convergence, which stay per Server address. A restarted runtime has a new generation, so candidates toward the old hint keep failing on the wrong generation until the hint changes or is withdrawn.

At `info`, the Client logs `client tunnel candidate starting`, `joined` and `aborted` with the `server-address`, plus the generation or abort `reason`, and `client tunnel handed over` when a second connection takes over from the primary. Rejected (`reason=wrong-generation`) and failed candidates log a warning with `next-retry-delay`.

## Client-side Service selection

When a WebTransport Visitor stream arrives:

1. Deliver its Tunnel stream to the Client handler. The stream already holds one Client-instance budget permit, retained until both stream halves drop.
2. Validate and consume the mandatory internal PROXY v2 header, then buffer the forwarded ClientHello. Header and ClientHello intake share a **5-second** completion deadline and have separate **16 KB** caps.
3. Extract the canonical Visitor TCP tuple from the header and the normalized SNI hostname from the ClientHello.
4. If there is exactly one configured **Service** and it omits `public-hostnames`, select that **Catch-all Service**.
5. Otherwise, match the hostname to `client.services[*].public-hostnames`.
6. If no Service matches, reject the stream immediately.
7. If the matched Service has `tls-mode = "passthrough"` (default):
   a. Open a TCP connection to the selected `backend-address` with a **5-second** connect deadline.
   b. Forward the buffered ClientHello bytes with a **5-second** initial-write deadline, then continue streaming in both directions.
8. If the matched Service has `tls-mode = "terminate"`:
   a. Complete the TLS handshake with the Visitor within **5 seconds** using the per-hostname certificate — from `client.public-cert-dir` (manual path) or from `[client.acme]` (ACME path). If `[client.acme]` is in use and the certificate for that hostname is not yet ready, the TLS handshake fails immediately (fail closed); there is no fallback to passthrough. ACME `acme-tls/1` challenge handshakes use the same **5-second** bound.
   b. Open a TCP connection to the selected `backend-address` with a **5-second** connect deadline.
   c. Proxy decrypted data between the TLS stream and the plaintext backend connection.

The Client-instance semaphore bounds idle Visitor credits and handler work together across every Tunnel connection. Rejecting an assigned stream drops it and resets its unfinished write direction. Successfully established proxies have no additional lifetime or idle deadline.

Notes:

- the ClientHello may span multiple reads on both TCP and Tunnel streams
- the parser must accumulate bytes until the TLS record is complete before attempting to extract SNI
- `backend-address` must point at a TLS-terminating backend when `tls-mode = "passthrough"`; it receives plaintext when `tls-mode = "terminate"`
- when `[client.acme]` is configured, `acme-tls/1` challenge connections for **Public hostnames** arrive through the Server's normal Visitor routing path and are handled by the Client's ACME resolver alongside regular TLS connections for those hostnames
- Client ACME challenge success is logged as soon as the TLS handshake completes. Best-effort shutdown and drain have a separate **5-second** bound; a validator reset or teardown timeout does not change that success.

## Stream lifecycle

Every Visitor stream begins its Server-to-Client bytes with a regenerated PROXY protocol v2 header containing the canonical Visitor TCP source and original destination. The Client validates and consumes it before parsing the Visitor ClientHello; original TLS bytes follow immediately. Invalid metadata rejects only that stream.

One internal Tunnel-framing module owns this ordering for Server encoding and Client decoding. Backend PROXY emission is separate and independently controlled per Service.

Tunnel connections support only ALPN `h3`. There is no fallback or dual protocol. Both peers require the WebTransport Visitor carrier; older receive-slot binaries cannot carry Visitors with this version. Operators must upgrade Clients and Servers together. Old `runewarp/1` binaries are incompatible in both directions.

Runewarp uses symmetric close behavior:

- a TCP FIN maps to WebTransport stream FIN in the same direction
- a WebTransport stream FIN maps to TCP half-close in the same direction
- errors, aborts, or dropping an unfinished write half reset the stream; connection loss terminates all its streams
- proxy writes flush before waiting for the peer and finish their write direction after copying to EOF
- each TCP/Tunnel proxy direction owns its halves and completes independently; a failure in one direction does not cancel copying in the other, and the proxy returns its error after both directions finish
- a Visitor remains in flight until both TCP directions finish; receiving the backend response or its TLS close notification does not close the Visitor's TCP write direction, which can keep graceful shutdown or Managed drain waiting until the deadline
- no peer depends on a received STOP_SENDING or RESET_STREAM code; any stop or reset ends that direction or stream

When a QUIC connection drops, all streams on that connection are lost. They are not migrated elsewhere.

For orderly local shutdown that the runtime controls:

- when `server.readiness-bind-address` is configured, **Server readiness** is a probe-only TCP listener whose accept success means the Server is eligible for new ingress admission
- the **Server** drops **Server readiness** immediately when orderly shutdown begins
- the **Server** stops accepting new Visitor TCP traffic, new **Tunnel connections**, and new streams on already-open **Tunnel connections** before it closes active **Tunnel connections**
- **Graceful shutdown** concurrently sends GOAWAY on every Tunnel connection using stock `shutdown(1)`, seals new Visitor opens, ends the event stream, and lets already-placed Visitors finish within one `server.graceful-shutdown-duration` window
- GOAWAY carries the fork's first unprocessed Client request-stream ID; Runewarp evicts pending classifiers, allows already-returned request resolvers to finish under their original deadlines, and rejects later requests, including the boundary ID, with `H3_REQUEST_REJECTED`. The Client opens no new requests afterward
- after Server-local work completes, the Server sends the WebTransport DRAIN capsule and waits for the Client to release its Visitors and send CLOSE, then closes with `H3_NO_ERROR` (`0x100`); idle Visitor credit does not prolong drain
- when that graceful deadline expires, the **Server** force-closes remaining active **Tunnel connections**
- a **Managed drain** runs the same graceful steps when Control requests it with `drain: true`, then keeps the process running and reporting. To a Client, a drained Server looks exactly like one in graceful shutdown: GOAWAY, DRAIN, then close. Nothing Tunnel-specific is added to the wire (see [`managed.md`](managed.md#managed-drain))
- **Fast shutdown** and graceful-to-fast escalation close immediately with `H3_NO_ERROR`
- the **Client instance** stops new dial and retry work before it withdraws or closes active **Tunnel connections**
- **Graceful Client shutdown** stops offering Visitor credit and withdraws every live Tunnel connection concurrently under one Client-instance-wide `client.graceful-shutdown-duration` deadline, which defaults to `60s` and starts with shutdown; see [placement withdrawal](#placement-withdrawal). Each connection closes after its confirmation; the rest close at the deadline as unconfirmed. `0s` makes graceful Client shutdown behave as fast
- **Fast Client shutdown** skips withdrawal and closes every connection at once. Graceful-to-fast escalation cancels outstanding withdrawals, keeps confirmations already received and reports the rest unconfirmed. `SIGTERM` and the first `Ctrl-C` start graceful Client shutdown; `SIGQUIT` on Unix starts fast shutdown, and after a first `Ctrl-C`, a second `Ctrl-C` or `SIGQUIT` escalates to fast
- both orderly shutdown modes still send the normal QUIC connection close and then wait the short fixed runtime-owned **QUIC close flush duration** before exit

## Retry behavior

Client instance reconnect behavior is:

1. after any failed or closed **Tunnel connection**, pick the next runtime-owned retry window from this exact sequence: `1, 2, 3, 5, 8, 12, 18, 27, 41, 60`
2. apply full jitter over `0..window` for that retry and sleep for the chosen delay
3. keep using the same sequence, capped at `60` seconds, until an authenticated **Tunnel connection** succeeds
4. reset back to the first `1` second window after every successful authenticated **Tunnel connection**

This reconnect policy is fixed. There is no reconnect tuning knob in the config or the CLI-only startup path.

Unauthorized **Client identity** failures are classified from the TLS access-denied alert and use the same reconnect policy as every other reconnect failure. There is no dedicated immediate-retry exception for that case.

Failure and reconnect logs report the chosen next retry delay as `next-retry-delay=<Ns>`. The runtime rounds that displayed value up to whole seconds and never shows `0s`, even when jitter selects a sub-second delay.

When the remote **Server** exits gracefully, the **Client instance** still treats the closed **Tunnel connection** as an ordinary disconnect and keeps the same reconnect model above. There is no shutdown-specific reconnect branch.

When more than one authenticated connection is live for the same **Tunnel** on one **Server** node, those connections form a **Tunnel pool**. Each new Visitor stream is placed onto the eligible pool member with the fewest active proxied streams; withdrawn or GOAWAY members are skipped but stay registered until they close, with round-robin tie-breaking when load is equal. If the chosen member dies before the proxied stream is established, the Visitor connection fails immediately; the Server does not retry placement onto a different pool member.

## Managed-session Control protocol

In **Managed mode**, each Server or Client runtime opens one mutually authenticated HTTP/2 **Managed session** to the configured **Control address**: one role-specific SSE downlink (`GET /v1/server/events` or `GET /v1/client/events`) plus full state documents (`PUT /v1/server/state` or `PUT /v1/client/state`) on the same connection, sent after each successfully handled snapshot and when a reported fact changes, at most once per second. The downlink follows the same [SSE profile](sse.md) as the Tunnel event stream.

The 60-second first-snapshot/silence windows and Tunnel reconnect backoff apply as documented in [`managed.md`](managed.md). Quiet SSE downlinks use Control-owned comment keepalives; Core sends no periodic state heartbeat. That document is the canonical Core contract for endpoints, SSE framing, input schemas, revision semantics, state documents, Managed drain, Server authorization, Client assignment/Retiring, failure taxonomy, wire examples, and Control interoperability.

## Runtime invariants

- each **Client instance** has one or more **Tunnel connections** once dialing has succeeded
- in Static mode, the Client emits one **Client readiness** signal when the first configured **Server address** passes the event-stream gate and establishes its WebTransport session; Managed mode uses **Assignment convergence** instead (see [`managed.md`](managed.md))
- failure, retry, and recovery stay isolated per effective **Server address**
- a **Tunnel** may have one or more authenticated live **Tunnel connections** on one **Server** node
- a **Tunnel** stays available while at least one of those **Tunnel connections** remains live
- active-stream placement within a same-**Tunnel** pool is least-active with round-robin tie-breaking
- once placed, a proxied stream stays bound to its chosen **Tunnel connection**; there is no live stream migration
- the runtime does not validate cross-side hostname coverage under **Hostname mirroring**
- there is no pre-flight **Local backend** health check
- multiple Client instances across different Tunnels are supported
- orderly runtime shutdown offers a bounded graceful-drain opportunity but does not guarantee stream completion or migration
