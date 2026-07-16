# Throwaway H3 Reverse CONNECT reference

## Question

Can a Client-authenticated HTTP/3 association carry the strict reference
sequence—listen, Server connection request, Client accept confirmation, then
Visitor bytes—without changing the production `runewarp/1` runtime?

## Run

```sh
cargo test --test h3_reverse_connect_reference
```

The test is the throwaway prototype. Its in-memory trace exposes this state:

```text
tunnel-mtls-established
h3-connect-listen-accepted
visitor-initial-bytes-buffered
connection-request-sent
connect-accept-received
connect-accept-confirmed
visitor-bytes-forwarded-to-backend
backend-bytes-forwarded-to-visitor
```

It creates an H3 ALPN `h3` QUIC association with Client certificate
authentication, a local Visitor TCP socket, and a local echo backend. The
Visitor's `ping` is buffered at the Server, travels only after the Client's
`connect-accept` receives its final `200`, and returns as `pong`.

## Reference framing

This is a **strict-sequence reference**, not a production protocol or an
interoperable Reverse CONNECT implementation:

1. Client opens `POST /connect-listen`; Server replies `200` and keeps its H3
   response stream open.
2. Server writes `CONNECTION_REQUEST:1` as H3 DATA on that stream.
3. Client opens `POST /connect-accept/1`.
4. Server replies `200`, then writes the buffered Visitor bytes as H3 DATA.
5. Client begins the local TCP connection only after that `200`; it forwards
   the response on the request body.

Each operation is on a valid client-initiated bidirectional H3 request stream;
H3 DATA is carried over the corresponding QUIC stream and its native flow
control. The test keeps the association alive until Server receipt, preventing
an H3 connection close from racing the final request body.

## Result and constraints

The reference answers **yes** for the basic substrate and exposes the strict
acceptance dependency: the Client cannot start its backend work until it has
received the `connect-accept` final response. That is a per-Visitor
Client–Server exchange on the critical path.

`h3` 0.0.8 / `h3-quinn` 0.0.10 are adequate for this H3 framing proof but do
not expose arbitrary extended-CONNECT `:protocol` values: the public `h3`
API supplies only `webtransport` and `connect-udp`. They also expose no
Capsule API used by this prototype. Therefore the paths and DATA payload above
stand in for draft-specific `connect-listen`, `connect-accept`, and Capsules;
this branch makes no third-party interoperability claim.

The test's trust setup proves Client certificate authentication, not
Runewarp's production pinned-identity admission verifier. It deliberately
does not measure latency, allocations, packet overhead, stream limits, or
real Capsule parsing. Those are still required before choosing any H3 carrier.

Delete this test and note once the selected carrier has an implementation
specification; do not absorb its HTTP paths or payload strings into production
runtime code.
