# Managed session protocol

This is the Core contract for **Managed mode**: how a Runewarp **Server** or **Client instance** talks to a **Control** endpoint, applies versioned full-input snapshots, and reports its state, including the successfully applied opaque revision.

Use it when you operate managed Server or Client runtimes, or when you implement a compatible Control service. Operator config keys live in [`configuration.md`](configuration.md). Tunnel wire behavior stays in [`protocol.md`](protocol.md). Trust boundaries are in [`security.md`](security.md). System shape is in [`architecture.md`](architecture.md). Domain terms are in [`CONTEXT.md`](../CONTEXT.md).

This document describes what Core implements today. Product policy (lifecycle labels, persistence, certificate issuance, identity cardinality) is out of scope and called out explicitly.

## Contract at a glance

- **Audience:** Control implementers and Core runtime integrators
- **Session:** one mutually authenticated HTTP/2 connection per Server or Client runtime
- **Downlink:** one role-specific SSE stream carrying versioned full snapshots, with one required `runewarp-session-id` response header echoed on every state PUT
- **State document:** a full role state document carrying the applied revision, sent after each successfully handled snapshot and when a reported fact changes, at most once per second; no periodic heartbeat
- **Role inputs:** Server authorization and Client Server-address assignment use separate schemas
- **Failure model:** protocol or reporting failure replaces the session; reconnect retains last-applied in-memory state after the first successful apply

## Related documentation

| Document | What it owns |
| --- | --- |
| [`architecture.md`](architecture.md) | System shape, data paths, and trust model |
| [`protocol.md`](protocol.md) | Tunnel/QUIC wire behavior and stream lifecycle |
| [`sse.md`](sse.md) | SSE profile shared by the downlink and the Tunnel event stream |
| [`security.md`](security.md) | Authentication and revocation boundaries |
| [`configuration.md`](configuration.md) | `[control]`, identity directories, and validation |
| [`usage.md`](usage.md) | Operator workflows and static-first setup |
| [`CONTEXT.md`](../CONTEXT.md) | Canonical domain vocabulary |
| [`roadmap.md`](roadmap.md) | Forward-looking work outside this implemented contract |

## Domain boundary

| Term | Role in managed mode |
| --- | --- |
| **Control** | HTTPS endpoint that publishes desired inputs and observes applied revisions |
| **Control address** | DNS hostname with optional port; HTTPS is mandatory and inferred |
| **Managed mode** | Startup-selected shape when an effective Control address is present |
| **Managed session** | Authenticated live relationship between one Server or Client instance and Control for versioned snapshots and state documents; Core implements it as one mutually authenticated HTTP/2 connection behind the `ManagedSession` domain seam |
| **Server** / **Client instance** | Runtimes that open a Managed session; they still own the data-path listeners and Tunnel connections |
| **Tunnel connection** | QUIC data-path session between Client and Server; separate from the Managed session |
| **Authorization snapshot** | Server-side Public-hostname routing plus trusted Client identities applied from Control; managed tunnels are keyed by **Tunnel ID** |
| **Tunnel ID** | Control-owned opaque identifier for one managed Server **Tunnel**; continuity key for live pools; absent in static mode |
| **Address controller** | Client-owned complete assigned Server-address lifecycle (intent, workers, production Retiring policy, Assignment convergence, apply completion, reported connection generations, static Client readiness, shutdown) |
| **Client admission** | Prepared Client static-vs-managed outcome set once during Config validation; startup wires the Address controller from it |
| **Assignment convergence** | Client aggregate of whether assigned Server addresses are Connected (separate from the reported revision) |
| **Retiring** | Connected address removed from assignment intent: reconnect stops; live Tunnel connection stays until remote Server closure |
| **Server readiness** | Ingress-admission signal; gated on first successful Server input apply in managed mode |
| **Managed drain** | One-way, bounded drain of a running Managed Server, requested by `drain: true` in its input; the Server keeps running and reporting until the process is terminated |

Visitor TLS and Tunnel QUIC traffic never share the Control connection.

## Mode selection and configuration

Managed mode is enabled when an effective Control address is present after config and CLI preparation. There is no separate boolean.

| Concern | Behavior |
| --- | --- |
| Config key | `control.address` under `[control]` |
| Runtime override | `runewarp server --control-address` / `runewarp client --control-address` (runtime commands only) |
| Precedence | CLI flag, then config |
| Address shape | DNS hostname with optional port; default port `443`; schemes, paths, and IP literals rejected |
| Trust | `control.trust = "system"` (default) or `"ca-file"` with exclusive `control.ca-file` |
| Static exclusivity | Managed Server forbids `[[server.tunnels]]`; managed Client forbids `client.server-address`, `client.server-addresses`, and `--server-address` |
| Server identity | Managed Server requires `server.identity-dir` (or XDG default), distinct from `server.cert-dir` |
| Client identity | Managed Client reuses `client.identity-dir` for Tunnel and Control mTLS |
| Mode switch | Static↔managed requires config replacement plus process restart; no in-process switch or static fallback |
| Restart | Applied input and revision are memory-only; a fresh process waits for a new first snapshot |

Relative Control CA and identity paths resolve from the selected config file. Omitted paths use the XDG defaults in [`configuration.md`](configuration.md).

## Trust and identities

| Plane | Credential | Purpose |
| --- | --- | --- |
| Control (Server role) | **Server identity** material in `server.identity-dir` (`server.crt`, `server.key`, `server-identity.txt`) | Authenticates the Server to Control |
| Control (Client role) | Client identity material in `client.identity-dir` | Authenticates the Client to Control |
| Control endpoint | `control.trust` / `control.ca-file` | Validates the Control server certificate |
| Tunnel endpoint | **Server certificate** / Client identity | Unchanged data-path trust; separate from Control |

**Server identity** is not the **Server certificate**. Core validates and loads Server identity material but does not initialize, renew, rotate, or watch it. Core does not overwrite Client identity certificates for managed credentials. Identity and trust material are reloaded for each new Managed-session connection attempt, not per HTTP request.

## Transport contract

Each Managed session:

1. Dials the Control hostname over TLS with ALPN `h2` only (no HTTP/1.1 fallback).
2. Presents the role identity certificate and validates Control through the configured trust mode.
3. Opens exactly one role-specific SSE downlink on that connection.
4. Validates exactly one canonical UUIDv7 `runewarp-session-id` response header before reading snapshots or applying input.
5. Sends every state document with that exact ID on additional HTTP/2 streams of the same connection.
6. On any downlink or state-document failure, closes the entire HTTP/2 connection before reconnecting.

Core does not follow redirects, honor `Retry-After`, or attach runtime-instance IDs or hostname selectors to requests. The credential and role path select the input. The session incarnation only correlates reports to the accepted downlink.

## Endpoints

| Role | Method | Path | Success | Notes |
| --- | --- | --- | --- | --- |
| Server | `GET` | `/v1/server/events` | `200` + `Content-Type: text/event-stream` (optional charset) + one `runewarp-session-id` | Core sends `Accept: text/event-stream`, which Control ignores; empty body |
| Client | `GET` | `/v1/client/events` | same | same |
| Server | `PUT` | `/v1/server/state` | `204` with empty body | `Content-Type: application/json` + one `runewarp-session-id`; Server state document |
| Client | `PUT` | `/v1/client/state` | same | `Content-Type: application/json` + one `runewarp-session-id`; Client state document |

SSE status `204`, redirects, other non-success statuses, missing `Content-Type`, and wrong media types all fail the session and trigger reconnect. A state write that is not exact `204` with an already-ended empty body also fails the session and triggers reconnect.

## Session incarnation

Control mints a fresh UUIDv7 for every admitted Server or Client downlink, including reconnects on the same process or HTTP/2 connection and after Control restart. It sends exactly one `runewarp-session-id` response header on a successful events GET. The value must be lowercase, hyphenated, 36-character UUIDv7 with the RFC variant, for example `01928f3e-7b6a-7c3d-8e4f-0123456789ab`. Missing, duplicate, comma-joined, uppercase, other-version and other noncanonical forms fail the connection before Core accepts snapshots, applies input or sends state. Validation remains inside the existing 60-second connection/first-snapshot deadline and reconnect policy. There is no compatibility fallback.

Every state PUT echoes exactly one `runewarp-session-id` for that successful downlink, including fact changes, repeated revisions and the first report after reconnect. The connection owns this value; retaining an applied revision never retains the old ID. Control must atomically compare the exact incarnation before revision, generation or report mutation, while preserving identity, role and source-connection checks. A missing, malformed, duplicate, stale or nonmatching request ID receives an ended empty `409` without modifying or closing the current session. Ordinary malformed-report handling may use `400`; a stale ID must never close a current recipient for an unknown revision.

The incarnation identifies a session, not a process. It grants no authentication, authorization, timestamp ordering, replacement or rollout authority. It belongs in HTTP headers, outside the revisioned input and report bodies, so snapshot revisions remain unchanged. UUIDv7 reveals its mint time and must not be treated as a secret. Compatible Control, Server and Client versions must upgrade together; older peers cannot bypass the requirement. Static mode has no Managed-session handshake and keeps its existing behavior.

## SSE framing

The downlink follows the [SSE profile](sse.md), which owns framing, the line and event-type limits, keepalive and silence timing, delivery, and versioning. Downlink specifics:

- accumulated event data, and so a complete snapshot, is capped at **1 MiB**
- the first-snapshot deadline starts at connection start, so it also bounds dial, TLS, and opening the SSE request
- missing required snapshot fields, an empty revision, invalid JSON, and input limit violations fail the session like framing errors do

Every v1 data event must be `event: snapshot`. The first data event on every connection must be a snapshot. V1 never emits patches.

### Snapshot envelope

```json
{
  "revision": "<non-empty opaque string>",
  "input": { }
}
```

`revision` uses the same opaque-string rules as **Tunnel ID**: non-empty, at most 128 Unicode scalars, no ASCII whitespace or control characters. Core compares equality only.

Unknown JSON fields in a known v1 snapshot are ignored. Within `/v1/`, Control may add only fields an older Core can safely ignore; any other change needs a new path version.

### Server `input`

```json
{
  "tunnels": [
    {
      "id": "<opaque Tunnel ID>",
      "public_hostnames": ["app.example.com"],
      "client_identities": ["4f7b6f7a9b0f0d2b91e92c8a5df6a44e0123456789abcdef0123456789abcdef"]
    }
  ],
  "replacement_generation": "01928f3e-9c1d-7fed-9cba-9876543210fe",
  "drain": true
}
```

Rules (as implemented):

- `tunnels` is required and may be `[]`
- each entry requires non-empty `id`, plural `public_hostnames`, and `client_identities` (no singular aliases)
- `id` is a **Tunnel ID**: non-empty opaque string, at most 128 Unicode scalars, no ASCII whitespace or control characters; unique across the whole set
- normalized Public hostnames and Client identities must be unique across the whole set
- cardinality is bounded (see [Input and reporting limits](#input-and-reporting-limits)): at most 4,096 tunnels, 4,096 Public hostnames total / 256 per Tunnel, and 4,096 Client identities total / 64 per Tunnel
- unknown per-tunnel JSON fields are ignored
- `replacement_generation` is optional. It is a **Replacement hint** naming another **Server runtime generation** behind the same Server address, in the same canonical UUIDv7 form as the Tunnel event stream (see [`protocol.md`](protocol.md#tunnel-events)). `null`, another JSON type, or an invalid encoding makes the input `Rejected` and keeps the prior authorization and hint.
- `drain` is optional and must be a boolean. `true` starts a [Managed drain](#managed-drain). Drain is one-way: a later input with `false` or without `drain` is applied as usual but does not resume serving. Any other JSON type makes the input `Rejected`.
- a `replacement_generation` equal to the Server's own generation means no hint on that runtime, so Control can publish the same input to the old and new runtime. Any other value is advertised on every live Tunnel event stream of that runtime (see [`protocol.md`](protocol.md#tunnel-events)). Omitting or changing the value advertises a new full snapshot.

### Client `input`

```json
{
  "server_addresses": ["tunnel-a.example.com", "tunnel-b.example.com:8443"]
}
```

Rules (as implemented):

- `server_addresses` is required and may be `[]`
- each entry is a DNS hostname with optional port (default `443`); IP literals and URL schemes are rejected
- addresses must be unique after normalization
- at most 256 Server addresses (see [Input and reporting limits](#input-and-reporting-limits))

## Revision and reconciliation

| Rule | Behavior |
| --- | --- |
| Opacity | Revisions and Tunnel IDs are opaque strings; Core compares equality only |
| Immutability expectation | A revision always names one complete role input; changed input needs a changed revision (Control responsibility) |
| Tunnel ID | Required on every managed Server tunnel; keys live Tunnel pools across applies; static mode has no Tunnel ID |
| Desired versus applied | Control owns desired publication and any drift comparison; Core reports the applied revision in every state document |
| Equal while idle | Skip apply; report the snapshot again |
| Rollback | Previously applied non-current revisions remain valid candidates |
| Latest-state | One apply at a time; newer snapshots collapse to a single pending candidate; superseded revisions emit `Superseded` |
| Invalid input / apply error | Emit `Rejected`; do not report the revision; keep SSE open; retain prior applied revision and live state |
| Memory-only | Applied revision does not survive process restart |

Runtime reconciliation events (no status endpoint):

| Event | Meaning |
| --- | --- |
| Received (`Snapshot`) | A valid snapshot envelope arrived |
| `Applying` | Role adapter apply started |
| `Applied` | Apply succeeded; state documents report the revision |
| `Rejected` | Input validation or apply failed |
| `Superseded` | A queued snapshot was discarded for a newer candidate |
| `Reconnecting` | The Managed session is replacing the HTTP/2 connection |

A Server state document reports a revision only after the atomic authorization swap, dispatch of required local revocation work, publication of the input's replacement hint to Tunnel event streams, and the start of any requested drain, without awaiting peer closure, event writes, or drain completion. A Client state document reports a revision after Address-controller maintenance intent is replaced, without awaiting DNS, handshake, or connection success.

## State documents

`PUT .../state` carries the peer's full current state document. There is no separate acknowledgment or heartbeat: the document reports the applied revision together with the role's facts.

Server document:

```json
{"revision":"srv-42","generation":"01928f3e-7b6a-7c3d-8e4f-0123456789ab","draining":false,"tunnels":{"<tunnel id>":2},"visitors":17}
```

- `generation` is the **Server runtime generation** as a canonical lowercase hyphenated UUIDv7.
- `draining` is `true` from the start of a [Managed drain](#managed-drain) until the process ends.
- `tunnels` maps every authorized **Tunnel ID** to the number of its open Tunnel connections that have established their WebTransport session, which is when a Client offers Visitor credit. A Tunnel with no such connection reports `0`. Connections leave the count when they close, not at GOAWAY or withdrawal.
- `visitors` counts in-flight Visitors placed on this Server.
- Quiescence is `draining` with `visitors` equal to `0`.

Client document:

```json
{"revision":"cli-7","servers":{"tunnel-a.example.com:443":["01928f3e-7b6a-7c3d-8e4f-0123456789ab"]}}
```

- `servers` maps every assigned **Server address**, written as normalized `host:port` with the port always present, to the sorted generations of its Tunnel connections that are carrying Visitor credit. An assigned address with no such connection reports `[]`. Retiring addresses are not assigned and are not reported.
- A connection carries credit from the moment it starts offering credit until it ends. A validated candidate counts once it joins; an unvalidated candidate never counts.

Both documents put `revision` first, then the role facts in the order shown. Their size is bounded by the existing Authorization and assignment limits. Control must ignore unknown fields: later `/v1/` versions may add facts.

Sending rules:

1. Echo the current downlink's `runewarp-session-id` on every request. Send a document after each valid snapshot envelope whose revision is newly applied or already matches the applied revision, and whenever a reported fact changes. Before a connection reports its first revision, fact changes send nothing; that connection's first snapshot sends the full document.
2. Every document is complete, so the first request on every new session gives Control the full current facts without polling.
3. Keep at most one request in flight and at most one pending. The pending document is rendered when its request starts, so a newer change replaces an unsent one.
4. Start at most one request per second on a connection. Bursts of fact changes coalesce into the next request.
5. Treat exact `204` with an already-ended empty body as success. Non-204 and body-bearing responses are rejected without collecting an unbounded body.
6. On any state-write failure or deadline miss, replace the whole Managed session while retaining the latest successfully applied revision in memory for reporting after reconnect.

Rejected and superseded revisions are never reported. Documents never include desired revision, **Server readiness**, the **Assignment convergence** aggregate, or rejection reasons. Control health and staleness classification remain outside this protocol. SSE reads, snapshot application, silence/first-snapshot timers, and Authorization revocations stay responsive while a state request is slow or failed.

## Input and reporting limits

Core enforces fixed production limits (injectable smaller values in tests only; no operator configuration or wire negotiation). The [SSE profile](sse.md#limits) adds its 4 KiB line and 64 B event-type limits:

| Limit | Production default |
| --- | --- |
| Accumulated SSE event data / complete snapshot | **1 MiB** |
| Cumulative decoded allocation | **2 MiB** |
| Revision / Tunnel ID | **128** Unicode scalars |
| Tunnels | **4,096** |
| Public hostnames (total / per Tunnel) | **4,096 / 256** |
| Client identities (total / per Tunnel) | **4,096 / 64** |
| Server addresses | **256** |
| State request deadline (through response headers) | **5 s** |
| State response deadline (ended body) | **5 s** |

Static Client configuration uses the same production ceiling of 256 Server addresses to bound assigned-address fanout, with a minimum of one. Managed assignments still allow an empty list.

Limit violations fail the entire Managed session and reconnect; Core never partially applies an oversized snapshot. Rejection logs include only bounded metadata (limit name and counts), never full snapshots or attacker-sized payloads.

## Timing and reconnect

| Window | Value | Notes |
| --- | --- | --- |
| First-snapshot deadline | **60 s** from connection start | Bounds dial + TLS + SSE open + first valid snapshot envelope; keepalive comments do not extend it |
| Silence timeout | **60 s** without any SSE bytes | Per the [SSE profile](sse.md#timing) |
| State request deadline | **5 s** | Bounds `PUT .../state` through response headers |
| State request spacing | **1 s** | Minimum time between the starts of two state requests on one connection |
| State response deadline | **5 s** | Bounds classifying an already-ended bodyless `204` |
| Control keepalive cadence | Less than **60 s** between SSE bytes | Per the [SSE profile](sse.md#timing); **20 s** is recommended, not required |
| Reconnect backoff | `1, 2, 3, 5, 8, 12, 18, 27, 41, 60` s | Full jitter over `0..window`; same policy as Tunnel reconnect |

Any downlink or state-document failure closes the whole connection. That connection carries only the downlink and its state documents, so replacing it costs no traffic. A Tunnel event-stream failure only resubscribes, because the Tunnel connection carries live Visitors. Reconnect backoff resets after a valid snapshot envelope establishes the new session, even when its role input is later rejected. On reconnection, the first fresh full snapshot must confirm currency: an equal already-applied revision is acknowledged without reconciliation churn.

## Managed Server behavior

1. Startup validates local credentials and binds listeners, but **Server readiness** stays unavailable and no Tunnel or Visitor work is admitted until the first successful Server input apply. Server ACME additionally requires a usable validated Server certificate.
2. Authorization replacement is one Server operation on managed authorization: a candidate is validated beside the live **Authorization snapshot**, then committed atomically across Public-hostname routing and Client-identity handshake admission, Tunnel-ID-keyed pool realignment, selective live-work revocation, and first-success **Server readiness**. Static authorization is startup-only and has no Tunnel IDs. Config validation prepares Server admission (static vs managed) once; startup builds Authorization and readiness from that outcome. The Managed Server role adapter supplies validated input and observes success or failure; it does not coordinate those phases.
3. A valid empty `tunnels` collection may keep **Server readiness** available while authorizing no work.
4. Live continuity uses **Tunnel ID** for pool identity, plus Client identity and Public hostname facts for admission and revocation:
   - surviving Tunnel pools are rematched by Tunnel ID when Control reorders tunnels
   - a Client identity that moves to another Tunnel ID is rehomed without closing the live Tunnel connection
   - removing a Client identity denies new handshakes and closes that identity's live Tunnel connections and streams
   - removing only a Public hostname resets matching Visitor streams
   - unrelated authorized work survives
5. After the first successful apply, Control loss retains the last authorization and readiness while the session reconnects, subject to the independent Server ACME certificate safety gate.
6. The Server role runtime owns Server and Managed-session completion together. **Graceful shutdown** drops readiness immediately but keeps the Managed session, snapshot application, and state documents active through bounded drain so Authorization changes still apply; the session ends when the HTTP/2 connection closes at final process exit. **Fast shutdown** may close the session immediately.
7. A [Managed drain](#managed-drain) runs the graceful shutdown steps without ending the process.
8. A pre-commit failure retains prior authorization. An unrecoverable failure after commit begins never restores revoked authorization: readiness drops and the process exits nonzero.

## Managed drain

Control drains a Managed Server by publishing an input with `drain: true`. The drain starts once that input applies, before the state document reports its revision. The Server then:

1. stops admitting new Tunnel connections and new Visitor placement, before any state document reports `draining: true`, so `draining` with zero `visitors` always means no Visitor can still land;
2. drops **Server readiness** and closes its public and Tunnel listeners, as graceful shutdown does;
3. sends GOAWAY on every Tunnel connection, so Clients leave it under the Server-drain rules in [`protocol.md`](protocol.md);
4. lets in-flight Visitors finish within `server.graceful-shutdown-duration`, measured from the start of the drain, then closes the remaining Tunnel connections;
5. keeps running, applying input, and sending state documents until the process is terminated. `tunnels` falls to `0` per Tunnel as connections close, and `visitors` reaching `0` marks quiescence.

Drain is one-way for the life of the process. A later input without `drain` updates authorization and the replacement hint as usual, but the Server never reopens its listeners or readiness. Process shutdown during a drain joins it under the drain's original deadline; a second signal still escalates to Fast shutdown. Static Servers have no Control and never drain this way.

With Server ACME, completion of drain stops local ACME polling and challenge handling, but process-held certificate ownership is retained until actual exit. A replacement must acquire that lock and observe its consumed Server-hostname challenge route before driving ACME. A retained validated serving snapshot can support overlap; it transfers no authorization or order state. Finite certificate recovery can fast-stop the replacement without reviving the drained process. Certificate controls and caller budget obligations are described in [Server certificate ownership](server-certificates.md); they add no fields to Managed inputs or reports.

## Managed Client behavior

1. Before the first successful Client apply, the Client maintains no Server connections.
2. Each apply atomically replaces Address-controller maintenance intent for the complete `server_addresses` set.
3. Added addresses start independent connect/reconnect loops.
4. Removing an Establishing or Reconnecting address cancels unresolved DNS, handshake, or backoff work immediately.
5. Removing a Connected address marks it **Retiring** without local closure; remote Server shutdown owns Tunnel-connection closure. Assignment removal is not **Infrastructure drain**.
6. Re-adding a Retiring address before remote closure re-adopts that connection without duplicate dialing.
7. A valid empty assignment applies and is Converged; it does not locally close Retiring connections.
8. **Assignment convergence** is separate from applied revision: Unconverged / Partially converged / Converged; empty assignments are Converged; Retiring connections are excluded.
9. Healthy assigned Servers keep serving during partial convergence; one unavailable address never blocks others.
10. After the first successful apply, Control loss retains the last assignment and independent reconnect loops while the session reconnects.
11. Process restart restores no managed input or applied revision and dials nothing until a fresh snapshot applies.
12. Managed Client mode emits per-address Establishing, Connected, Reconnecting, Retiring, Closed, and failed-attempt events plus convergence transitions. It does not emit the Static-mode one-shot Client readiness event.

Service selection, Services, Local backends, and TLS mode remain Client-local configuration.

## Failure taxonomy

| Condition | Outcome |
| --- | --- |
| Invalid local config / missing initial identity material / listener bind failure | Exit nonzero at startup |
| SSE / invalid session-incarnation header / silence / first-snapshot / malformed or unknown event / connection loss | Close HTTP/2 connection; reconnect in-process |
| Invalid snapshot input or apply error | `Rejected`; SSE stays open; prior live state retained |
| State `PUT` failure | Close HTTP/2 connection; reconnect in-process; report the new connection's first snapshot |
| Post-start TLS material reload failure | Recoverable in-process via reconnect |
| Per-address DNS / connect / authorization failures (Client) | Isolated worker retry |
| Unrecoverable Client controller or worker-task failure | Exit nonzero |
| Unrecoverable Server failure after authorization commit begins | Drop readiness; exit nonzero |
| Control loss after first apply | Retain last authorization / assignment; reconnect |

Before the first successful apply, remote and protocol failures keep the process alive but inactive or Unready. After apply, Managed-session failure preserves last-applied data-plane behavior while reconnecting.

## Wire examples

### Server snapshot

```text
event: snapshot
data: {"revision":"srv-42","input":{"tunnels":[{"id":"550e8400-e29b-41d4-a716-446655440000","public_hostnames":["app.example.com"],"client_identities":["4f7b6f7a9b0f0d2b91e92c8a5df6a44e0123456789abcdef0123456789abcdef"]}],"replacement_generation":"01928f3e-9c1d-7fed-9cba-9876543210fe"}}

```

### Client snapshot

```text
event: snapshot
data: {"revision":"cli-7","input":{"server_addresses":["tunnel.example.com"]}}

```

### Keepalive comment

```text
: keepalive

```

### State documents

```http
PUT /v1/server/state HTTP/2
Host: control.example.com
runewarp-session-id: 01928f3e-7b6a-7c3d-8e4f-0123456789ab
Content-Type: application/json

{"revision":"srv-42","generation":"01928f3e-7b6a-7c3d-8e4f-0123456789ab","draining":false,"tunnels":{"550e8400-e29b-41d4-a716-446655440000":2},"visitors":17}
```

```http
PUT /v1/client/state HTTP/2
Host: control.example.com
runewarp-session-id: 01928f3e-7b6a-7c3d-8e4f-0123456789ab
Content-Type: application/json

{"revision":"cli-7","servers":{"tunnel.example.com:443":["01928f3e-7b6a-7c3d-8e4f-0123456789ab"]}}
```

Successful response: `204` with an empty body.

### Representative failures

| Example | Core behavior | Covered by |
| --- | --- | --- |
| `event: patch` | Session failure → reconnect | Black-box / integration fixtures |
| Client `server_addresses` containing an IP literal | `Rejected`; SSE stays open | `tests/managed_session_apply.rs` |
| Server `replacement_generation` in the retired 32-hex form | `Rejected`; prior authorization and hint retained | `tests/managed_server_authorization.rs` |
| SSE response `307` redirect | Session failure → reconnect (redirects not followed) | `tests/managed_session_downlink.rs` |
| State response `500` | Session failure → reconnect; equal first snapshot is reported again without re-apply | `tests/managed_session_apply.rs` |
| 60 s silence after first snapshot | Session failure → reconnect | `tests/managed_session_downlink.rs` |
| Snapshot with empty `"revision":""` | Session failure → reconnect | Unit coverage in `src/managed_session/snapshot.rs` |

Black-box fixtures under `tests/managed_session_*.rs`, `tests/managed_server_authorization.rs`, and `tests/managed_client_assignment.rs` are the executable reference for session, Server, and Client outcomes.

## Interoperability checklist for Control

Label each requirement as **Control must** (wire contract Control implements) or **Core does** (runtime behavior Control can rely on).

### Control must

- [ ] Serve HTTPS with a certificate the runtime trusts under `control.trust`
- [ ] Require client certificates and authorize by role identity
- [ ] Negotiate HTTP/2 (`h2`); reject HTTP/1.1-only peers
- [ ] Expose exact paths `/v1/server/events`, `/v1/client/events`, `/v1/server/state`, `/v1/client/state`
- [ ] Accept exactly one SSE downlink per connection for the matching role path
- [ ] Respond to SSE with status `200` and `Content-Type: text/event-stream`, ignoring `Accept`
- [ ] Mint one fresh canonical UUIDv7 `runewarp-session-id` per accepted downlink and require its exact echo alongside identity/source binding on every state PUT
- [ ] Reject missing, malformed, duplicate or stale request IDs with empty ended `409` before mutation or unknown-revision closure of the current session
- [ ] Emit `event: snapshot` full documents only (no v1 patches)
- [ ] Send a current full snapshot as the first data event on every connection
- [ ] Use non-empty opaque `revision` values that identify immutable complete inputs (max 128 Unicode scalars; no ASCII whitespace or controls)
- [ ] Require unique opaque `tunnels[].id` (**Tunnel ID**) on every managed Server tunnel (same opaque-string rules as revision)
- [ ] Use plural-only Server fields `tunnels[].public_hostnames` / `tunnels[].client_identities` and Client field `server_addresses`
- [ ] Allow empty overall `tunnels` / `server_addresses` collections
- [ ] Send Server `replacement_generation` only as a canonical lowercase hyphenated UUIDv7, and omit it when there is no hint
- [ ] Send Server `drain` only as a boolean, and treat drain as one-way: a drained Server never serves again
- [ ] Emit SSE comment keepalives often enough that silence stays under 60 s (20 s cadence recommended)
- [ ] Accept state `PUT` only after the matching downlink is active on that connection
- [ ] Respond to successful state writes with exact `204` and an already-ended empty body
- [ ] Keep snapshots within Core's documented size and cardinality limits ([SSE profile](sse.md#limits) 4 KiB line and 64 B event type, 1 MiB snapshot / event data, 2 MiB decoded allocation, 4,096 tunnels, 4,096/256 Public hostnames, 4,096/64 Client identities, 256 Server addresses)
- [ ] Accept the Server and Client state documents shown above, and ignore unknown fields
- [ ] Do not rely on Core following redirects or honoring `Retry-After`
- [ ] Do not rely on SSE `id` / `retry` / Last-Event-ID replay

### Core does

- [ ] Open one Managed session per runtime with one SSE downlink and full state documents
- [ ] Validate one canonical response incarnation before snapshot acceptance and echo that downlink's ID on every state report, including after reconnect
- [ ] Fail the session on malformed/unknown SSE events, size/cardinality limit violations, and reconnect with the shared backoff policy
- [ ] Ignore unknown JSON fields in known v1 snapshots
- [ ] Skip apply on equal already-applied revisions and report the snapshot again
- [ ] Collapse mid-apply snapshots to the newest candidate
- [ ] Report only successfully applied revisions
- [ ] Send a state document when a reported fact changes, keeping one request in flight, one pending, and at most one start per second, off the reconciliation critical path
- [ ] Send no periodic state heartbeat
- [ ] Gate managed Server readiness on the first successful apply; retain authorization through later Control loss
- [ ] Keep **Server readiness** available for a valid empty Tunnel collection while authorizing no work
- [ ] Maintain managed Client assignments independently per address; Retire removals without local close; re-adopt on re-add
- [ ] Keep applied state memory-only across process restart
- [ ] Keep the Managed session active through Server graceful shutdown until final process exit, and after a Managed drain until the process is terminated
- [ ] Finish a Managed drain within `server.graceful-shutdown-duration` of its start
- [ ] Leave desired-versus-applied drift comparison and health classification to Control; report only the applied revision and the documented role facts
- [ ] Suppress a Server `replacement_generation` equal to the Server's own generation; publish any other hint to Tunnel event streams before reporting the revision

## Outside the Core contract

The following remain outside this contract and must not be assumed from Core:

- hosting topology, persistence, publication transactions, and desired-versus-applied comparison
- Warming / Degraded / staleness product labels and health classification
- Certificate issuance, enrollment, offline/delete APIs, and identity-cardinality policy
- Lifecycle classification, capacity ownership, and the policy for when to drain a Server
- v1 patch events, capability negotiation, HTTP/3 Control, and browser EventSource compatibility

Process termination still uses Core's graceful process shutdown path. A Managed drain reuses those steps without ending the process.
