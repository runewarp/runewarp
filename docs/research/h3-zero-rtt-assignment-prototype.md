# H3 zero-round-trip assignment prototype

This is a test-only artifact for [the HTTP/3 Tunnel-association map](https://github.com/runewarp/runewarp/issues/167), not a production protocol specification.

Run the in-memory state-model companion with:

```sh
cargo run --example h3_receive_slots_prototype
```

It is explicitly throwaway. Its full-screen state view makes capacity,
assignment, backend start, one re-placement, and drain transitions observable
by hand; it does not open a network connection or persist any state.

## Exercised carrier: Client-preopened receive slots

`tests/h3_zero_rtt_assignment.rs` establishes a local, mutually authenticated QUIC/TLS connection with ALPN `h3`, then creates an HTTP/3 association using `h3` 0.0.8 and `h3-quinn` 0.0.10.

The Client advertises receive/start capacity by opening a client-initiated `CONNECT` request to a Runewarp-specific path and leaving its response pending. That open request is one independently flow-controlled bidirectional stream. On a simulated Visitor arrival, the Server consumes the already-advertised slot and sends a successful response, assignment bytes, and the buffered ClientHello immediately. The test asserts that Client receives both byte sequences without first sending a per-Visitor acceptance request.

The second test opens an unassigned slot, sends a connection-scoped drain request, and waits for the Server's acknowledgement before it may assign more work. This models the acknowledgement as a placement-withdrawal barrier only; it does not claim active Visitor completion.

The harness uses mTLS, but the generated Client certificate is only a local fixture. Production identity pinning and Server authorization are intentionally not reused or changed.

## What this establishes

- Client-initiated H3 request streams can remain open as receive/start slots.
- A Server response can carry assignment framing and initial Visitor bytes on that already-open stream.
- This path adds no Client-to-Server exchange after Visitor arrival; the response and initial bytes travel together from Server to Client.
- H3 stream-level flow control and cancellation are available per assigned Visitor stream.

## Constraints and unanswered work

- The `CONNECT` target and byte framing are Runewarp-specific. This is ordinary H3 framing, not generic MASQUE or Reverse CONNECT interoperability.
- The test does not select a Tunnel-pool member, connect a Local backend, or exercise one re-placement before backend setup. Those are carrier-neutral lifecycle concerns that need a later end-to-end prototype.
- The test does not benchmark latency, allocations, flow-control stalls, cancellation races, or capacity replenishment under load.
- The Client must bound and replenish idle slots. Each consumes a bidirectional QUIC stream plus H3 request state before it is assigned.
- The `h3` 0.0.8 server API accepts client-initiated requests and exposes no negotiated extension API for Server-initiated bidirectional request streams. `h3-quinn` can expose raw Quinn streams, but an unsolicited Server-initiated bidirectional stream is not an HTTP/3 request stream and would violate ordinary H3 unless both endpoints define a further extension. This prototype therefore does **not** claim that carrier is supported.
- The stack exposes H3 DATA framing but does not provide a Runewarp Capsule codec, control-channel contract, or typed lifecycle/error vocabulary. Those must be designed and independently tested before any production adoption.

## Interpretation

Preopened receive slots are technically viable as a rough H3 carrier for immediate assignment. They do not by themselves decide whether H3 should replace `runewarp/1`; strict Reverse CONNECT remains the paired reference, and a selected carrier still needs protocol framing, performance evidence, lifecycle proof, and a deliberate cutover decision.
