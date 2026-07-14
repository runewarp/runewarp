# Managed session protocol

This is the Core contract for **Managed mode**: how a Runewarp **Server** or **Client instance** talks to a **Control** endpoint, applies versioned full-input snapshots, and reports the last successfully applied opaque revision.

Use it when you operate managed Server or Client runtimes, or when you implement a compatible Control service. Operator config keys live in [`configuration.md`](configuration.md). Tunnel wire behavior stays in [`protocol.md`](protocol.md). Trust boundaries are in [`security.md`](security.md). System shape is in [`architecture.md`](architecture.md). Domain terms are in [`CONTEXT.md`](../CONTEXT.md).

This document describes what Core implements today. Control-owned product policy (Cloud lifecycle labels, persistence, certificate issuance, identity cardinality) is out of scope and called out explicitly.

## Domain boundary

| Term | Role in managed mode |
| --- | --- |
| **Control** | HTTPS endpoint that publishes desired inputs and observes applied revisions |
| **Control address** | DNS hostname with optional port; HTTPS is mandatory and inferred |
| **Managed mode** | Startup-selected shape when an effective Control address is present |
| **Managed session** | Authenticated live relationship between one Server or Client instance and Control for versioned snapshots and revision reports; Core implements it as one mutually authenticated HTTP/2 connection |
| **Server** / **Client instance** | Runtimes that open a Managed session; they still own the data-path listeners and Tunnel connections |
| **Tunnel connection** | QUIC data-path session between Client and Server; separate from the Managed session |
| **Authorization snapshot** | Server-side Public-hostname routing plus trusted Client identities applied from Control; managed tunnels are keyed by **Tunnel ID** |
| **Tunnel ID** | Control-owned opaque identifier for one managed Server **Tunnel**; continuity key for live pools; absent in static mode |
| **Address controller** | Client-side maintenance of at most one worker per normalized Server address |
| **Assignment convergence** | Client aggregate of whether assigned Server addresses are Connected (separate from revision acknowledgment) |
| **Retiring** | Connected address removed from assignment intent: reconnect stops; live Tunnel connection stays until remote Server closure |
| **Server readiness** | Ingress-admission signal; gated on first successful Server input apply in managed mode |
| **Infrastructure drain** | Provider process shutdown (for example Kubernetes termination); never initiated by managed assignment or authorization removal |

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
4. After the downlink is active, acknowledges each successfully handled snapshot with one `PUT` on an additional HTTP/2 stream of the same connection.
5. On any downlink or state-acknowledgment failure, closes the entire HTTP/2 connection before reconnecting.

Core does not follow redirects, honor `Retry-After`, or attach session IDs / runtime-instance IDs / hostname selectors to requests. The credential and role path select the input.

## Endpoints

| Role | Method | Path | Success | Notes |
| --- | --- | --- | --- | --- |
| Server | `GET` | `/v1/server/events` | `200` + `Content-Type: text/event-stream` (optional charset) | `Accept: text/event-stream`; empty body |
| Client | `GET` | `/v1/client/events` | same | same |
| Server | `PUT` | `/v1/server/state` | `204` with empty body | `Content-Type: application/json`; body `{"revision":"..."}` only |
| Client | `PUT` | `/v1/client/state` | same | same |

SSE status `204`, redirects, other non-success statuses, missing `Content-Type`, and wrong media types all fail the session and trigger reconnect. A state write that is not exact `204` with an empty body also fails the session and triggers reconnect.

## SSE framing

Core uses standard SSE framing, not the browser EventSource connection lifecycle:

- `event:` sets the event type
- `data:` lines join with `\n`
- lines starting with `:` are comment keepalives (byte activity only; no event)
- `id`, `retry`, and unknown fields are ignored
- empty dispatched events (no type and empty data) are skipped
- invalid UTF-8, malformed framing, missing required snapshot fields, empty revision, invalid JSON, and unknown event types fail the session

Every v1 data event must be `event: snapshot`. The first data event on every connection must be a snapshot. V1 never emits patches; patch delivery requires a future protocol version.

### Snapshot envelope

```json
{
  "revision": "<non-empty opaque string>",
  "input": { }
}
```

`revision` uses the same opaque-string rules as **Tunnel ID**: non-empty, at most 128 Unicode scalars, no ASCII whitespace or control characters. Core compares equality only.

Unknown JSON fields in a known v1 snapshot are ignored. Behavior-changing fields require a new protocol version.

### Server `input`

```json
{
  "tunnels": [
    {
      "id": "<opaque Tunnel ID>",
      "public_hostnames": ["app.example.com"],
      "client_identities": ["4f7b6f7a9b0f0d2b..."]
    }
  ]
}
```

Rules (as implemented):

- `tunnels` is required and may be `[]`
- each entry requires non-empty `id`, plural `public_hostnames`, and `client_identities` (no singular aliases)
- `id` is a **Tunnel ID**: non-empty opaque string, at most 128 Unicode scalars, no ASCII whitespace or control characters; unique across the whole set
- normalized Public hostnames and Client identities must be unique across the whole set
- unknown per-tunnel JSON fields are ignored

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

## Revision and reconciliation

| Rule | Behavior |
| --- | --- |
| Opacity | Revisions and Tunnel IDs are opaque strings; Core compares equality only |
| Immutability expectation | A revision always names one complete role input; changed input needs a changed revision (Control responsibility) |
| Tunnel ID | Required on every managed Server tunnel; keys live Tunnel pools across applies; static mode has no Tunnel ID |
| Desired versus applied | Control owns desired publication and any drift comparison; Core acknowledges successfully handled snapshots with the applied revision |
| Equal while idle | Skip apply; acknowledge the snapshot again |
| Rollback | Previously applied non-current revisions remain valid candidates |
| Latest-state | One apply at a time; newer snapshots collapse to a single pending candidate; superseded revisions emit `Superseded` |
| Invalid input / apply error | Emit `Rejected`; do not acknowledge; keep SSE open; retain prior applied revision and live state |
| Memory-only | Applied revision does not survive process restart |

Runtime reconciliation events (no status endpoint):

| Event | Meaning |
| --- | --- |
| Received (`Snapshot`) | A valid snapshot envelope arrived |
| `Applying` | Role adapter apply started |
| `Applied` | Apply succeeded; revision becomes acknowledgeable |
| `Rejected` | Input validation or apply failed |
| `Superseded` | A queued snapshot was discarded for a newer candidate |
| `Reconnecting` | The Managed session is replacing the HTTP/2 connection |

A Server revision is acknowledged only after the atomic authorization swap and dispatch of required local revocation work, without awaiting peer closure. A Client revision is acknowledged after Address-controller maintenance intent is replaced, without awaiting DNS, handshake, or connection success.

## State acknowledgment

For each valid snapshot that names a successfully applied revision:

1. Apply a new revision, or skip apply when the revision already matches the process's applied revision.
2. Send one `PUT .../state` with body `{"revision":"<applied>"}`.
3. Treat exact `204` with an empty body as acknowledgment success.
4. On any state-write failure, replace the whole Managed session. The new connection's required first snapshot is applied or recognized as equal, then acknowledged again.

Rejected and superseded revisions are never acknowledged. Acknowledgments never include desired revision, **Server readiness**, **Assignment convergence**, rejection reasons, or richer role state. Core sends no periodic state heartbeat; Control health and staleness classification remain outside this protocol.

## Timing and reconnect

| Window | Value | Notes |
| --- | --- | --- |
| First-snapshot deadline | **60 s** from connection start | Bounds dial + TLS + SSE open + first valid snapshot; keepalive comments do not extend it |
| Silence timeout | **60 s** without any SSE bytes | Reset by any SSE bytes, including `:` comments |
| Control keepalive cadence | Less than **60 s** between SSE bytes | `:` comments keep quiet sessions active; **20 s** is recommended, not required |
| Reconnect backoff | `1, 2, 3, 5, 8, 12, 18, 27, 41, 60` s | Full jitter over `0..window`; same policy as Tunnel reconnect |

Any downlink or state-acknowledgment failure closes the whole connection. Reconnect resets only after a valid snapshot establishes the new session. On reconnection, the first fresh full snapshot must confirm currency: an equal already-applied revision is acknowledged without reconciliation churn.

## Managed Server behavior

1. Startup validates local credentials and binds listeners, but **Server readiness** stays unavailable and no Tunnel or Visitor work is admitted until the first successful Server input apply.
2. Candidates are prepared beside the live **Authorization snapshot** and committed atomically across Public-hostname routing and Client-identity handshake admission.
3. A valid empty `tunnels` collection may keep **Server readiness** available while authorizing no work.
4. Live continuity uses **Tunnel ID** for pool identity, plus Client identity and Public hostname facts for admission and revocation:
   - surviving Tunnel pools are rematched by Tunnel ID when Control reorders tunnels
   - a Client identity that moves to another Tunnel ID is rehomed without closing the live Tunnel connection
   - removing a Client identity denies new handshakes and closes that identity's live Tunnel connections and streams
   - removing only a Public hostname resets matching Visitor streams
   - unrelated authorized work survives
5. After the first successful apply, Control loss retains the last authorization and readiness while the session reconnects.
6. **Graceful shutdown** drops readiness immediately but keeps the Managed session, snapshot application, and revision reporting active through bounded drain so Authorization changes still apply; the session ends when the HTTP/2 connection closes at final process exit. **Fast shutdown** may close the session immediately.
7. A pre-commit failure retains prior authorization. An unrecoverable failure after commit begins never restores revoked authorization: readiness drops and the process exits nonzero.

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
12. Managed Client mode emits per-address Establishing, Connected, Reconnecting, Retiring, Closed, and failed-attempt events plus convergence transitions. It does not emit the static one-shot Client-ready event.

Service selection, Services, Local backends, and TLS mode remain Client-local configuration.

## Failure taxonomy

| Condition | Outcome |
| --- | --- |
| Invalid local config / missing initial identity material / listener bind failure | Exit nonzero at startup |
| SSE / silence / first-snapshot / malformed or unknown event / connection loss | Close HTTP/2 connection; reconnect in-process |
| Invalid snapshot input or apply error | `Rejected`; SSE stays open; prior live state retained |
| State `PUT` failure | Close HTTP/2 connection; reconnect in-process; acknowledge the new connection's first snapshot |
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
data: {"revision":"srv-42","input":{"tunnels":[{"id":"550e8400-e29b-41d4-a716-446655440000","public_hostnames":["app.example.com"],"client_identities":["4f7b6f7a9b0f0d2b91e92c8a5df6a44e0123456789abcdef0123456789abcdef"]}]}}

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

### Applied-state acknowledgment

```http
PUT /v1/client/state HTTP/2
Host: control.example.com
Content-Type: application/json

{"revision":"cli-7"}
```

Successful response: `204` with an empty body.

### Representative failures

| Example | Core behavior | Covered by |
| --- | --- | --- |
| `event: patch` | Session failure → reconnect | Black-box / integration fixtures |
| Client `server_addresses` containing an IP literal | `Rejected`; SSE stays open | `tests/managed_session_apply.rs` |
| SSE response `307` redirect | Session failure → reconnect (redirects not followed) | `tests/managed_session_downlink.rs` |
| State response `500` | Session failure → reconnect; equal first snapshot is re-acknowledged without re-apply | `tests/managed_session_apply.rs` |
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
- [ ] Respond to SSE with status `200` and `Content-Type: text/event-stream`
- [ ] Emit `event: snapshot` full documents only (no v1 patches)
- [ ] Send a current full snapshot as the first data event on every connection
- [ ] Use non-empty opaque `revision` values that identify immutable complete inputs (max 128 Unicode scalars; no ASCII whitespace or controls)
- [ ] Require unique opaque `tunnels[].id` (**Tunnel ID**) on every managed Server tunnel (same opaque-string rules as revision)
- [ ] Use plural-only Server fields `tunnels[].public_hostnames` / `tunnels[].client_identities` and Client field `server_addresses`
- [ ] Allow empty overall `tunnels` / `server_addresses` collections
- [ ] Emit SSE comment keepalives often enough that silence stays under 60 s (20 s cadence recommended)
- [ ] Accept state `PUT` only after the matching downlink is active on that connection
- [ ] Respond to successful state writes with exact `204` and an empty body
- [ ] Treat state body as revision-only; ignore unknown future keys defensively if you add none today
- [ ] Do not rely on Core following redirects or honoring `Retry-After`
- [ ] Do not rely on SSE `id` / `retry` / Last-Event-ID replay

### Core does

- [ ] Open one Managed session per runtime with one SSE downlink and snapshot-triggered state writes
- [ ] Fail the session on malformed/unknown SSE events and reconnect with the shared backoff policy
- [ ] Ignore unknown JSON fields in known v1 snapshots
- [ ] Skip apply on equal already-applied revisions and acknowledge the snapshot again
- [ ] Collapse mid-apply snapshots to the newest candidate
- [ ] Acknowledge only successfully applied revisions
- [ ] Send no periodic state heartbeat
- [ ] Gate managed Server readiness on the first successful apply; retain authorization through later Control loss
- [ ] Keep **Server readiness** available for a valid empty Tunnel collection while authorizing no work
- [ ] Maintain managed Client assignments independently per address; Retire removals without local close; re-adopt on re-add
- [ ] Keep applied state memory-only across process restart
- [ ] Keep the Managed session active through Server graceful drain until final process exit
- [ ] Leave desired-versus-applied drift comparison and health classification to Control; acknowledge only the applied revision

## Outside the Core contract

The following remain Control- or Cloud-owned and must not be assumed from Core:

- Phoenix, Fly topology, Cloud persistence, publication transactions, and desired-versus-applied comparison
- Warming / Degraded / staleness product labels and health classification
- Certificate issuance, enrollment, offline/delete APIs, and identity-cardinality policy
- Lifecycle classification, capacity ownership, and Terraform/provider drain orchestration
- v1 patch events, capability negotiation, HTTP/3 Control, and browser EventSource compatibility

Infrastructure drain uses Core's existing graceful process shutdown path. Managed input adds no drain field, SSE event, or state-acknowledgment field.

## Related documentation

| Document | What it covers relative to managed mode |
| --- | --- |
| [`architecture.md`](architecture.md) | System shape, trust model, and managed runtime limits |
| [`protocol.md`](protocol.md) | Tunnel/QUIC wire behavior; summary pointer to this contract |
| [`security.md`](security.md) | Control authentication and managed revocation boundaries |
| [`configuration.md`](configuration.md) | `[control]`, identity dirs, validation, and examples |
| [`usage.md`](usage.md) | Operator workflow; static path remains the default get-started |
| [`CONTEXT.md`](../CONTEXT.md) | Canonical domain language |
| [`roadmap.md`](roadmap.md) | Forward-looking managed-service ideas beyond this Core contract |
