# Public QUIC relay substrates over HTTP/3

## Question and constraints

Which HTTP/3 substrate should carry opaque Visitor QUIC packets through an authenticated Client–Server Tunnel connection?

This research assumes the settled direction in [Wayfinder: Tunnel-association signaling over HTTP/3](https://github.com/runewarp/runewarp/issues/167): Public QUIC shares the ordinary-H3 Client–Server transport. It also treats [Research maintained Rust HTTP/3 implementation paths for signaling](https://github.com/runewarp/runewarp/issues/238) as the stack-level evidence; this note does not repeat that comparison. The carrier must not expose generic destination selection or turn CONNECT-UDP into a Core product mode.

## Recommendation

Use **HTTP/3 Datagrams over QUIC DATAGRAM** for opaque Visitor QUIC packets, under one dedicated, long-lived **Runewarp Extended CONNECT** request on the existing authenticated H3 connection. Define only the narrow Runewarp profile needed to bind packets and lifecycle to authorized inbound Visitors:

1. The Client opens an Extended CONNECT request with a Runewarp-specific protocol token. A successful 2xx response establishes the carrier. This is not `connect-udp`: it carries no caller-selected target host or port and grants no forwarding authority. CONNECT-UDP explicitly identifies a target through URI-template host and port variables; Runewarp must not adopt those semantics ([RFC 9298, Section 3](https://www.rfc-editor.org/rfc/rfc9298.html#section-3)).
2. The HTTP/3 Datagram Quarter Stream ID identifies that carrier request. A Runewarp-defined variable-length **Context ID** at the start of the HTTP Datagram Payload identifies one active Visitor QUIC association; the remaining bytes are one unmodified inner QUIC UDP payload. HTTP/3 Datagrams already bind every datagram to a request using Quarter Stream ID, while their payload semantics belong to the defining HTTP extension ([RFC 9297, Sections 2 and 2.1](https://www.rfc-editor.org/rfc/rfc9297.html#section-2)).
3. The Server allocates Context IDs because it accepts the public Visitor flow. Reliable Runewarp Capsules on the CONNECT stream register and close contexts. This follows the standards-provided division: QUIC DATAGRAM for unreliable packet data; Capsules for reliable, bidirectional request-related control ([RFC 9297, Sections 3 and 3.5](https://www.rfc-editor.org/rfc/rfc9297.html#section-3)).
4. If QUIC DATAGRAM or HTTP/3 Datagram negotiation is unavailable, Public QUIC is unavailable on that Tunnel connection. **Do not fall back to DATAGRAM Capsules for Visitor packet data.** Such a fallback changes loss, ordering, flow-control, and path-MTU behavior.

This keeps the wire image ordinary H3 and reuses the authenticated connection, standard request association, standard datagram framing, and standard Capsule envelope. Only the Runewarp protocol token, Context ID meaning, and lifecycle Capsule types are private.

## Candidate comparison

| Candidate | Semantics and context | Transport behavior | Interoperability | Verdict |
| --- | --- | --- | --- | --- |
| HTTP/3 Datagram over QUIC DATAGRAM | Quarter Stream ID selects an HTTP request; the defining extension owns the payload, so a Context ID can select a Visitor | Unreliable, unordered, not retransmitted; connection-congestion-controlled and paced; no QUIC flow-control credit | Standard H3/QUIC framing and negotiation; Runewarp peers alone understand the private profile | **Select** |
| DATAGRAM Capsule carrying packet data | Bound to a CONNECT data stream; can carry the same HTTP Datagram Payload | Reliably and in-order delivered on a flow-controlled stream; an intermediary may later re-encode it unreliably | Standard envelope, but wrong end-to-end behavior for inner QUIC packets | **Reject as packet carrier**; retain Capsules for lifecycle only |
| H3 DATA or another reliable stream encoding | Request stream supplies context; a private record layer would delimit packets | Reliable ordered delivery introduces head-of-line blocking and outer retransmission beneath inner QUIC recovery | Ordinary H3 frames but a wholly private application framing | **Reject** |
| WebTransport over H3 | Session ID and datagram support solve a broader browser-facing session problem | Adds streams and session machinery beyond opaque packet relay | Still an active Internet-Draft as of revision 15 and requires additional H3 extensions ([IETF draft](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)) | **Reject** |
| CONNECT-UDP | Standard Extended CONNECT, Context ID, Capsule, and HTTP Datagram model | Appropriate packet behavior when QUIC DATAGRAM is used | Broad MASQUE UDP proxy semantics include a caller-selected target | **Evidence only**; do not expose as Core mode |
| Raw QUIC DATAGRAM or a private QUIC frame outside H3 | Runewarp must invent connection-wide demultiplexing | Could preserve unreliability | Collides with or bypasses H3's registered use of QUIC DATAGRAM and fails the ordinary-H3 constraint | **Reject** |

HTTP Datagrams are expressly intended for HTTP extensions rather than direct application use, so a named Runewarp extension is required; emitting arbitrary DATAGRAM payloads beside H3 is not sufficient ([RFC 9297, Abstract and Section 2](https://www.rfc-editor.org/rfc/rfc9297.html)). Extended CONNECT supplies the protocol-selection seam and standard unknown-protocol failure behavior ([RFC 9220, Section 3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3)).

## Detailed contract and consequences

### Context identification

The wire payload should be:

```text
QUIC DATAGRAM frame
  HTTP/3 Quarter Stream ID   -> Runewarp carrier CONNECT request
  Runewarp Context ID        -> one active Visitor QUIC association
  Opaque Visitor QUIC packet -> unchanged inner UDP payload
```

Use a connection-local, never-reused Context ID for the lifetime of the carrier request. Server allocation avoids allocator races because only the Server admits public Visitor flows. The reliable registration Capsule must describe enough local state to bind the Context ID to the Server-owned public UDP flow; it must not disclose or accept a destination chosen by the Client.

Reliable registration and unreliable data can reorder across QUIC streams and DATAGRAM frames. CONNECT-UDP's context design explicitly permits temporary buffering on the order of one RTT for an unknown Context ID and requires resource bounds ([RFC 9298, Sections 4 and 5](https://www.rfc-editor.org/rfc/rfc9298.html#section-4)). Runewarp should use the same bounded rule: an unknown-context datagram may be dropped immediately or buffered for at most one RTT under strict per-connection byte and count limits. It must never create a context implicitly.

### MTU and packet boundaries

Each HTTP/3 Datagram must contain exactly one complete inner UDP payload. QUIC DATAGRAM frames cannot be fragmented, and their usable size is constrained by the peer's `max_datagram_frame_size`, the outer QUIC maximum UDP payload, current path MTU, and the Quarter Stream ID plus Context ID overhead ([RFC 9221, Sections 3 and 5](https://www.rfc-editor.org/rfc/rfc9221.html#section-5)).

Inner QUIC creates a hard admission constraint: QUIC Initial datagrams must be at least 1200 bytes, while the outer datagram needs additional QUIC and Runewarp framing ([RFC 9000, Sections 14 and 14.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-14)). Therefore:

- advertise Public QUIC capacity only when the live outer `max_datagram_size`, minus HTTP/3 and Runewarp context overhead, can carry at least a 1200-byte inner payload;
- recompute that bound when the outer path-MTU estimate changes;
- drop an oversized inner packet and expose a metric; never convert it to a reliable Capsule;
- preserve packet boundaries and avoid IP fragmentation;
- prototype whether the practical path budget is sufficient for common inner QUIC PMTUs and how the Client-side UDP endpoint communicates a smaller usable size to its inner QUIC implementation.

RFC 9297 specifically warns that converting an oversized QUIC DATAGRAM into a reliable DATAGRAM Capsule falsifies end-to-end loss properties and defeats DPLPMTUD ([RFC 9297, Section 3.5](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.5)).

### Loss, pacing, and nested congestion

QUIC DATAGRAM is ack-eliciting but is not retransmitted. It uses the outer QUIC connection's congestion controller and pacing; when congestion blocks transmission, the implementation must delay or drop it ([RFC 9221, Sections 5.2 and 5.4](https://www.rfc-editor.org/rfc/rfc9221.html#section-5.2)). The inner QUIC connection independently detects loss, retransmits, paces, and reduces its congestion window. This creates two nested congestion controllers.

RFC 9298 identifies this exact condition for QUIC carried through an HTTP UDP tunnel. It requires the outer connection to retain congestion control unless there is out-of-band certainty that inner traffic is congestion-controlled, and recommends avoiding queueing that increases burstiness ([RFC 9298, Section 6](https://www.rfc-editor.org/rfc/rfc9298.html#section-6)). Runewarp knows the declared carrier is QUIC, but the Rust APIs surveyed do not provide a portable per-datagram congestion-control bypass. Start with outer congestion control enabled, do not batch beyond immediate I/O needs, and prefer dropping stale packets over waiting behind a growing queue. Measure throughput, fairness against signaling streams, and recovery under loss before considering any optimization.

### Flow and resource limits

QUIC DATAGRAM has no explicit flow control and consumes neither stream nor connection flow-control credit. A receiver may drop data it cannot process ([RFC 9221, Section 5.3](https://www.rfc-editor.org/rfc/rfc9221.html#section-5.3)). The Runewarp profile therefore needs explicit local bounds, not an on-wire credit protocol in its first version:

- maximum active Context IDs per Tunnel connection;
- per-context and per-connection receive queue bytes and datagram counts;
- maximum accepted payload derived from the live outer datagram limit;
- fair scheduling across contexts so one Visitor cannot monopolize the carrier;
- immediate drop policy for unknown, closed, oversized, expired, or over-budget datagrams;
- metrics for every drop class without logging opaque payloads or Visitor identifiers.

The exact values need a prototype and load evidence. A new credit protocol should be added only if bounded queues and fair drop scheduling prove insufficient.

### Lifecycle signaling

The dedicated carrier request has three levels of lifecycle:

1. Extended CONNECT request plus 2xx response establishes the carrier and its Capsule Protocol. Non-2xx rejects it.
2. Server-issued registration and close Capsules establish and retire individual Context IDs. A close should include a compact reason code, be idempotent, and make later datagrams for that Context ID droppable without error.
3. FIN, reset, H3 connection close, or Tunnel connection loss retires all contexts. Standard Extended CONNECT maps orderly closure to FIN and exceptional closure to an H3 stream error ([RFC 9220, Section 3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3)).

Keep this Visitor-carrier lifecycle separate from the settled Tunnel-association drain and placement semantics in [Define Tunnel-association signaling semantics](https://github.com/runewarp/runewarp/issues/225). The carrier may react to that lifecycle, but must not redefine it.

### Interoperability boundary

This design interoperates with standard QUIC and H3 machinery for ALPN, request streams, SETTINGS, QUIC DATAGRAM, HTTP/3 Datagram demultiplexing, and Capsules. It does **not** promise application interoperability with MASQUE or WebTransport implementations. Generic intermediaries can only forward the carrier if they support unknown Extended CONNECT protocols and Capsule forwarding; direct authenticated Client–Server use remains the required deployment shape.

The IETF's active QUIC-aware proxy draft validates HTTP Datagrams plus reliable Capsules as the current substrate for tunneled QUIC and explores later CID-aware forwarding to recover MTU efficiency. It is experimental work built as an extension to CONNECT-UDP, so Runewarp should monitor it, not adopt its proxy product semantics or forwarded mode now ([QUIC-Aware Proxying Using HTTP, revision 08](https://datatracker.ietf.org/doc/draft-ietf-masque-quic-proxy/)).

## Rust implementation maturity

The underlying QUIC datagram APIs are substantially more mature than the H3 extension layer:

- Runewarp's current Quinn 0.11.11 exposes `send_datagram`, `send_datagram_wait`, `read_datagram`, `max_datagram_size`, and send-buffer space. Its immediate send API may discard older queued datagrams to admit newer ones; the waiting API instead prioritizes old datagrams, so neither should be adopted without an explicit stale-packet policy ([Quinn 0.11.11 `Connection`](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html)).
- Hyperium's `h3-datagram` 0.0.2 implements RFC 9297 Quarter Stream ID encoding and integrates with `h3-quinn`'s `datagram` feature, but its own README calls it experimental, incomplete, and subject to change ([source at the reviewed revision](https://github.com/hyperium/h3/tree/c916ed5af1c6818c74fb86cc05a18e51ecc1fcb1/h3-datagram)). It covers H3 Datagram transport, not the Runewarp lifecycle Capsules.
- quiche 0.29.3 enables QUIC DATAGRAM with bounded send/receive queues and makes H3 advertise `SETTINGS_H3_DATAGRAM`; applications still provide the HTTP Datagram payload framing and policy ([quiche 0.29.3 H3 source](https://github.com/cloudflare/quiche/blob/0.29.3/quiche/src/h3/mod.rs), [QUIC datagram source](https://github.com/cloudflare/quiche/blob/0.29.3/quiche/src/lib.rs)). Its broader migration cost remains the decision described in [Research maintained Rust HTTP/3 implementation paths for signaling](https://github.com/runewarp/runewarp/issues/238).

The carrier choice therefore does **not** force a quiche migration. Quinn already has the necessary QUIC primitive; preserving Quinn/rustls requires owning or upstreaming a small H3 Datagram/Capsule adapter alongside the separate signaling extension seam. The implementation-boundary decision should compare that combined maintenance surface against quiche, rather than treating carrier support alone as decisive.

## Unresolved risks and required proof

Before specifying implementation, resolve these risks with a focused prototype and decision ticket:

1. **Minimum payload viability:** prove a 1200-byte inner Initial fits across supported outer paths after all framing overhead, and define capability withdrawal when it stops fitting.
2. **Inner PMTU feedback:** determine how the Client's inner QUIC endpoint learns the usable relayed MTU without relying on nonexistent end-to-end ICMP across the opaque carrier.
3. **Nested congestion:** benchmark loss, fairness, and latency when Visitor QUIC competes with Tunnel signaling on the same outer congestion controller.
4. **Queue semantics:** choose newest-wins, expiry, and fair scheduling behavior deliberately across Quinn and any alternate stack.
5. **Context lifecycle races:** specify registration-before-datagram buffering, close idempotency, Context ID exhaustion, and no reuse.
6. **H3 adapter ownership:** validate the smallest maintainable surface for SETTINGS negotiation, Quarter Stream ID routing, Capsules, and stream teardown in the chosen Rust stack.
7. **Security limits:** threat-model Context ID guessing, stale injection, unauthenticated public-source spoofing at the Server UDP edge, resource exhaustion, and privacy-safe observability.

## Conclusion

The route is clear at the substrate level: **standard HTTP/3 Datagrams over QUIC DATAGRAM for packets, reliable Capsules for per-Visitor lifecycle, wrapped in a narrow Runewarp Extended CONNECT profile on the existing authenticated H3 connection**. Reliable DATA or DATAGRAM Capsules are the wrong packet carrier; raw QUIC extensions violate the ordinary-H3 goal; WebTransport is broader and immature; CONNECT-UDP supplies useful standards evidence but the wrong product authority model.

The remaining uncertainty is implementation and operational proof—especially the 1200-byte inner QUIC minimum, nested congestion, and the H3 adapter ownership boundary—not the carrier family.
