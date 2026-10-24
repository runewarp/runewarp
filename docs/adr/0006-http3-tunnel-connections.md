# Ordinary HTTP/3 Tunnel connections

Runewarp uses ordinary HTTP/3 on git-pinned `h3`, `h3-quinn` and `h3-webtransport` from the `runewarp/h3` fork, with ALPN `h3`, required pinned Client-identity mTLS, and no application 0-RTT. This replaces raw `runewarp/1` streams with a hard lockstep break: old and new Clients and Servers are incompatible, and deployments must upgrade both together. There is no dual ALPN, fallback, or compatibility shim.

The Client's first valid `GET /v1/tunnel/events` state is the compatibility gate. No custom SETTINGS marker is required. After passing the gate, the Client establishes the mandatory WebTransport draft07 session on `/v1/tunnel/session` before offering plain-CONNECT receive slots. The session owns Tunnel connection lifetime, while receive slots still carry Visitors. Reserving a concrete slot assigns one Visitor, whose PROXY v2 envelope and buffered ClientHello follow the Server's `200` response as DATA without a per-Visitor Client round trip. ADR 0005's canonical-address and backend-emission boundaries remain in force.

One deep transport module owns HTTP/3 state, event subscription, slot maintenance, FIN/reset adaptation, and stock `shutdown(1)` GOAWAY with Runewarp enforcing rejection at or above the first-unprocessed boundary. The event stream carries version and a fresh generation per Server runtime, never configuration. No peer depends on received STOP_SENDING or RESET_STREAM codes. This accepts delayed detection of abandoned idle slots in exchange for using ordinary HTTP/3 receive slots without a private wire extension.

The [#261 session integration](https://github.com/runewarp/runewarp/issues/261) adds one draft07 session per Tunnel connection through the fork's separate Server driver and admission handle. Session termination closes the entire connection with `H3_NO_ERROR`; GOAWAY alone preserves the session during Visitor drain.

The [#253 decision](https://github.com/runewarp/runewarp/issues/253) selects the `runewarp/h3` fork while retaining receive slots and the wire behavior above.

The settled decisions are recorded in [#225](https://github.com/runewarp/runewarp/issues/225), [#226](https://github.com/runewarp/runewarp/issues/226), [#239](https://github.com/runewarp/runewarp/issues/239), and the [#246 amendment](https://github.com/runewarp/runewarp/issues/246).
