# SSE profile

Runewarp uses one Server-Sent Events profile on both of its event links:

- the Tunnel event stream, `GET /v1/tunnel/events` over HTTP/3 on each **Tunnel connection** ([`protocol.md`](protocol.md#tunnel-events));
- the Managed-session downlink, `GET /v1/server/events` or `GET /v1/client/events` over HTTP/2 to Control ([`managed.md`](managed.md#sse-framing)).

This document owns the rules the two links share. Each link document states only its own data cap, payload, deadline start points, and failure handling. The profile uses standard SSE framing. It does not follow the browser EventSource connection lifecycle.

## Requests and responses

The subscriber sends a bodyless `GET` with `Accept: text/event-stream`. The publisher ignores `Accept`, because each event resource has one representation. A successful response is `200` with `Content-Type: text/event-stream`; a `charset` parameter is allowed. Any other status or media type fails the subscription.

## Framing

- `event:` sets the event type. `data:` lines join with `\n`. A blank line dispatches the event.
- An event with no type and empty data, such as the blank line after a comment, dispatches nothing.
- A line starting with `:` is a comment. Comments count as stream activity for the silence timeout but are never events, so they never satisfy a first-event deadline.
- `id` and `retry` are ignored. They cannot steer state, revision, or reconnect timing.
- Unknown fields are ignored, as the SSE grammar requires.
- Unknown event types fail the subscription. Each link defines exactly one data event type, `snapshot`.
- Invalid UTF-8 or malformed framing fails the subscription.
- LF, CR, and CRLF line endings are accepted. The parser enforces size limits incrementally across fragmented chunks, so an oversized line fails before it completes.

## Limits

| Limit | Value |
| --- | --- |
| Unfinished line | **4 KiB** |
| Event type | **64 B** |
| Accumulated event data | Per link: Tunnel **4 KiB**, Managed **1 MiB** |

Exceeding a limit fails the subscription.

## Timing

| Window | Value | Notes |
| --- | --- | --- |
| First-event deadline | **60 s** | Ends when the first valid `snapshot` arrives. Each link defines when it starts. |
| Silence timeout | **60 s** | Any received bytes reset it, including comments |
| Keepalive comments | Every **20 s** on a quiet stream | Core's Tunnel Server sends `: keepalive` at this cadence. Control must keep silence under 60 s; 20 s is recommended. |

## Delivery

Every data event is a full snapshot of the publisher's current state. There are no patches, no event history, and no `Last-Event-ID` replay. A new subscription always starts with the current snapshot, so a subscriber that missed events loses nothing by reconnecting.

## Versioning

The path version, `/v1/`, governs compatibility. Snapshots carry no in-band version field. Within `/v1/`, a publisher may add fields that an older subscriber can safely ignore. Any other change, including a new event type or a field whose absence changes behavior, needs a new path version.
