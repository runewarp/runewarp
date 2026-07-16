# Server-initiated H3 association streams under ordinary H3

Research asset for [Research Server-initiated H3 association streams under ordinary H3](https://github.com/runewarp/runewarp/issues/224). Feeds [Specify the selected H3 carrier and framing](https://github.com/runewarp/runewarp/issues/222). Does not select a production carrier.

## Question

Can Server-initiated bidirectional association streams be expressed as standards-conforming HTTP/3 under Runewarp's ordinary-H3 observation target, or does every maintainable path leave that target?

## Verdict

**Base HTTP/3 forbids Server-initiated bidirectional streams treated as request streams.** That is a standards hard stop, not a library accident. An extension may define a use for those streams only after negotiation ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)). The published model is WebTransport over HTTP/3 ([draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3)).

A SETTINGS-negotiated extension that stays inside encrypted H3 **still satisfies** the ordinary-H3 wire-observation target from [Define the ordinary-H3 wire-observation target](https://github.com/runewarp/runewarp/issues/170): ALPN remains `h3`; SETTINGS and stream bytes are encrypted; no private QUIC version, frame, or transport parameter is required.

**Maintainable stock request/DATA stacks do not expose this carrier.** On `h3` 0.0.8 / `h3-quinn` 0.0.10, opening raw Quinn bidirectional streams without an H3 extension negotiation fails ordinary H3 (clients must close with `H3_STREAM_CREATION_ERROR`). Experimental `h3-webtransport` can open Server bidirectional WebTransport session streams, but that is an unstable extension path, not ordinary H3 request-stream framing. Cloudflare quiche has no production WebTransport H3 support.

Therefore: Server-initiated association streams are standards-reachable only as a **negotiated H3 extension** (WebTransport-class or a private SETTINGS peer). They are not reachable as vanilla H3 request streams. That conclusion matches the prototype evidence in [Prototype zero-round-trip H3 assignment carriers](https://github.com/runewarp/runewarp/issues/223).

## Ordinary-H3 observation target (context)

From the resolution of [Define the ordinary-H3 wire-observation target](https://github.com/runewarp/runewarp/issues/170):

- Passive observer is a passive classifier between Client and Server.
- Negotiate standard `h3`; no private ALPN.
- Runewarp semantics live in encrypted H3 mechanisms (Extended CONNECT, fields, Capsules, streams, HTTP Datagrams).
- No private QUIC version, visible transport parameter, QUIC frame, or other plaintext Runewarp marker.
- This is a protocol-conformance target, not browser-traffic indistinguishability.

Encrypted SETTINGS and encrypted stream payloads are therefore in-bounds for the target. Leaving the target means introducing a non-H3 carrier, private QUIC markers, or stream usage that a conforming H3 peer must treat as a connection error.

## Standards survey

### 1. HTTP/3 request streams and Server-initiated bidirectional streams

[RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1): a client sends an HTTP request on a **request stream**, defined as a **client-initiated bidirectional** QUIC stream.

[RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1):

> All client-initiated bidirectional streams are used for HTTP requests and responses. … These streams are referred to as request streams.
>
> HTTP/3 does not use server-initiated bidirectional streams, though an extension could define a use for these streams. Clients MUST treat receipt of a server-initiated bidirectional stream as a connection error of type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated.

Implication for Runewarp associations framed as H3 **request** streams (HEADERS / DATA / CONNECT request–response): the Server cannot open them. That rule is normative in base HTTP/3.

Server push is not a substitute: [RFC 9114 §4.1 / §6.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2) send pushed responses on **server-initiated unidirectional** streams, not bidirectional association streams.

### 2. HTTP/3 extensions and SETTINGS

[RFC 9114 §9](https://www.rfc-editor.org/rfc/rfc9114.html#section-9): extensions may add frame types, settings, error codes, and unidirectional stream types. Extensions that change existing semantics **MUST be negotiated** before use. [RFC 9114 §7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4) places SETTINGS on the encrypted control stream.

Combined with §6.1: a SETTINGS-negotiated Runewarp (or WebTransport) extension that defines Server-initiated bidirectional stream rules is **standards-conforming HTTP/3 extension behavior**. It does not require a private ALPN or plaintext QUIC marker, so it remains compatible with the #170 observation target.

It is **not** “ordinary request-stream H3.” Peers that have not negotiated the extension must treat unsolicited Server bidirectional streams as `H3_STREAM_CREATION_ERROR`.

### 3. Extended CONNECT

[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) ports Extended CONNECT to HTTP/3 via `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08). It enables client-sent CONNECT requests with a `:protocol` pseudo-header. It does **not** authorize Server-opened bidirectional request streams.

### 4. Capsule Protocol and HTTP Datagrams

[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) defines HTTP Datagrams and the Capsule Protocol on an HTTP request’s **data stream** after a successful upgrade / Extended CONNECT exchange. Capsules are tied to an existing (client-initiated) request stream. They do not create Server-initiated bidirectional streams.

### 5. Reverse CONNECT (comparison only)

[draft-rosomakho-masque-reverse-connect](https://datatracker.ietf.org/doc/html/draft-rosomakho-masque-reverse-connect) states that the Listener Control Channel exists because “the HTTP protocol inherently expects the client to initiate connections,” and therefore carries connection requests in Capsules so the **client** can open `connect-accept` on a new stream. Association streams remain client-initiated. This matches prior map evidence that Reverse CONNECT is not an immediate Server-open stream carrier ([Prototype strict Reverse CONNECT as the H3 reference](https://github.com/runewarp/runewarp/issues/173)).

### 6. WebTransport over HTTP/3

[draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3) is the standards-track model that **does** define Server-initiated bidirectional streams under H3:

- Negotiate with `SETTINGS_WT_ENABLED`, Extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL`), and `SETTINGS_H3_DATAGRAM` (and related requirements in the draft).
- Client establishes a WebTransport session with Extended CONNECT.
- After that, **either endpoint** may open bidirectional streams for the session.
- Streams begin with signal value `0x41` (`WT_STREAM`) plus session ID; body is application payload, not a HEADERS/DATA request exchange.

These are **WebTransport session streams**, not HTTP/3 request streams. Wire image remains ALPN `h3` with encrypted SETTINGS and stream data, so the #170 passive-observation target can still hold. Decrypted traces would show WebTransport framing rather than only request/DATA association streams.

## Does a SETTINGS-negotiated Runewarp extension leave the #170 target?

| Path | Standards status | Passive `h3` image (#170) | Notes |
| --- | --- | --- | --- |
| Server opens bi stream as H3 request (HEADERS/DATA) with no extension | Forbidden ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)) | Leaves target (conforming client closes connection) | Hard stop |
| Raw Quinn Server `open_bi` while speaking stock H3 | Same as above | Leaves target | Transport can open the stream; H3 peers must reject it |
| SETTINGS-negotiated private Runewarp extension defining Server bi streams | Allowed by §6.1 + §9 | Satisfies target if ALPN stays `h3` and no private QUIC markers | Encrypted semantics only; both peers must implement |
| WebTransport session streams after WT CONNECT | Defined by webtrans-http3 draft | Satisfies target on the same terms | Session streams, not request streams; draft + stack cost |
| Client-preopened receive slots (CONNECT left pending) | Ordinary client-initiated request streams | Satisfies target | Proven in #223; Server does not initiate the stream |

**Answer to part 2 of the ticket:** a SETTINGS-negotiated Runewarp extension that lets the Server open bidirectional association streams **can** remain inside the ordinary-H3 observation target. It does **not** make those streams base-HTTP/3 request streams. Using raw Server bidirectional streams without negotiating such an extension **does** leave the target.

## Rust stack support

### `h3` 0.0.8 / `h3-quinn` 0.0.10 (prototype stack)

Primary sources:

- [`h3` 0.0.8 docs](https://docs.rs/h3/0.0.8/h3/): server `Connection` exposes `accept` / `shutdown` only — no API to open Server bidirectional H3 request streams.
- [`h3` client connection source (v0.0.8)](https://github.com/hyperium/h3/blob/h3-v0.0.8/h3/src/client/connection.rs): explicitly implements RFC 9114 §6.1 — if `poll_accept_bi` becomes ready, the client raises `H3_STREAM_CREATION_ERROR` (“client received a server-initiated bidirectional stream”).
- [`h3` `ext` module](https://docs.rs/h3/0.0.8/h3/ext/index.html): Extended CONNECT `:protocol` helpers only; no Server-open association API.
- [`h3-quinn` 0.0.10](https://docs.rs/h3-quinn/0.0.10/h3_quinn/): Quinn transport can `open_bi` / `accept_bi` at the QUIC layer. That alone is not H3 request framing and, without a negotiated extension, trips the client rule above.

`h3` remains at **0.0.8** on crates.io / docs.rs as of this research. The README still describes the crate as experimental ([hyperium/h3 README](https://github.com/hyperium/h3/blob/master/README.md)).

This confirms the #223 prototype finding: lack of Server-initiated H3 **request** streams on this stack tracks the RFC, and raw Quinn would abandon ordinary H3.

### Experimental WebTransport on the same family

- [`h3-webtransport` 0.1.2](https://docs.rs/h3-webtransport/0.1.2/h3_webtransport/) (published; README: experimental, API subject to change) wraps an H3 connection after a WebTransport CONNECT and exposes `open_bi` / `accept_bi` for session streams ([server source](https://github.com/hyperium/h3/blob/master/h3-webtransport/src/server.rs)).
- Upstream issues remain open for first-class support and a general extension API: [hyperium/h3#71](https://github.com/hyperium/h3/issues/71), [hyperium/h3#293](https://github.com/hyperium/h3/issues/293). Maintainers historically treated Server bidirectional streams as non-trivial work beyond core request/response H3.

Near-term maintainable production claim for Server-initiated association streams on stock `h3`/`h3-quinn` request APIs: **no**. A WebTransport-shaped path exists experimentally and would still be an extension carrier, not ordinary request/DATA association framing.

### quiche

- [quiche HTTP/3 module docs](https://docs.rs/quiche/latest/quiche/h3/) document client `send_request` and server request/response polling — conventional H3 request streams.
- [cloudflare/quiche#1114](https://github.com/cloudflare/quiche/issues/1114) (WebTransport support) remains open; maintainers have stated interest without a committed timeline. Comments note that WebTransport requires H3-layer changes (e.g. `WT_STREAM` / `0x41` handling), not a thin application wrapper ([related discussion in #1150](https://github.com/cloudflare/quiche/issues/1150)).
- Open PRs around extra SETTINGS for WebTransport (e.g. C API settings work) do not equal production Server-initiated association support.

quiche is not a near-term maintainable alternative for Server-initiated H3 association streams under ordinary H3.

## Relation to prior map evidence

- [#170](https://github.com/runewarp/runewarp/issues/170): encrypted H3 extensions are allowed; private QUIC markers are not.
- [#221](https://github.com/runewarp/runewarp/issues/221): carrier-neutral contract lists Server-initiated bidirectional streams as a candidate **where the library supports them**.
- [#223](https://github.com/runewarp/runewarp/issues/223): Client-preopened receive slots work on ordinary H3; Server-initiated H3 request streams were unavailable on `h3` 0.0.8 / `h3-quinn` 0.0.10 without leaving ordinary H3.
- This ticket: that prototype result is **standards-correct** for request streams. The only standards-conforming Server-open path is a negotiated extension (WebTransport or private SETTINGS peer), which still meets the #170 wire target but is not maintained as stock request/DATA H3.

## Inputs for carrier selection (#222)

1. Do **not** expect Server-initiated streams framed as ordinary H3 request streams.
2. Treat Client-preopened receive slots as the maintainable ordinary-H3 request/DATA zero-RTT candidate already prototyped.
3. Treat Server-initiated streams as viable only if #222 deliberately selects a **negotiated extension carrier** (WebTransport-class or private SETTINGS) and accepts experimental / custom stack cost.
4. Raw Quinn Server `open_bi` without H3 extension negotiation is out of bounds for the ordinary-H3 observation target.

## Sources

- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html), especially §§4.1, 6.1, 6.2.2, 7.2.4, 9
- [RFC 9220 — Bootstrapping WebSockets with HTTP/3](https://www.rfc-editor.org/rfc/rfc9220.html) (Extended CONNECT setting)
- [RFC 9297 — HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297.html)
- [draft-ietf-webtrans-http3 — WebTransport over HTTP/3](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3)
- [draft-rosomakho-masque-reverse-connect — Reverse HTTP CONNECT](https://datatracker.ietf.org/doc/html/draft-rosomakho-masque-reverse-connect)
- [h3 0.0.8](https://docs.rs/h3/0.0.8/h3/), [h3-quinn 0.0.10](https://docs.rs/h3-quinn/0.0.10/h3_quinn/), [h3-webtransport 0.1.2](https://docs.rs/h3-webtransport/0.1.2/h3_webtransport/)
- [hyperium/h3 client §6.1 enforcement](https://github.com/hyperium/h3/blob/h3-v0.0.8/h3/src/client/connection.rs), [hyperium/h3#71](https://github.com/hyperium/h3/issues/71), [hyperium/h3#293](https://github.com/hyperium/h3/issues/293)
- [quiche h3 docs](https://docs.rs/quiche/latest/quiche/h3/), [cloudflare/quiche#1114](https://github.com/cloudflare/quiche/issues/1114)
