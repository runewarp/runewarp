<div align="center">
  <h1>
    Runewarp
  </h1>
  <p>
    <strong>
      Private tunneling for TLS passthrough
    </strong>
  </p>
</div>

Runewarp is a self-hostable tunnel for TLS passthrough. A public Runewarp Server reads enough of the Visitor's TLS ClientHello to route by SNI, then forwards the original encrypted stream to a Runewarp Client beside the operator's TLS-terminating backend.

## Current status

The repository currently ships the phase-1 data path as a library-first `Server` and `Client` runtime with end-to-end tests.

Today that means:

- public TCP passthrough works end to end
- each Client instance connects to the Server over QUIC using one Tunnel connection
- the current implementation only keeps one Client instance active at a time
- the binary is not operator-ready yet: config loading, CLI subcommands, ACME, and Client authentication land in later phases

Phase 1 is not ready for public deployment without the planned authentication hardening.

## Getting started

```bash
cargo build --release
cargo test
./target/release/runewarp
```

The current binary only reports the repository status. The working implementation lives in the library API and is exercised by the test suite.

## Design boundaries

- TLS passthrough is the product boundary; Runewarp does not terminate customer TLS on public hostnames
- The Server is the routing authority for Public hostnames
- Hostname mirroring is intentional: operators repeat Public hostnames on both sides so the Server can choose a Tunnel and the Client can choose a Service from the forwarded ClientHello
- Plain HTTP backends and edge TLS termination are out of scope

## Documentation

- [`CONTEXT.md`](CONTEXT.md)
- [`docs/configuration.md`](docs/configuration.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/protocol.md`](docs/protocol.md)
- [`docs/security.md`](docs/security.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/adr/0001-server-authoritative-routing-with-hostname-mirroring.md`](docs/adr/0001-server-authoritative-routing-with-hostname-mirroring.md)
- [`AGENTS.md`](AGENTS.md)

## Inspiration

Runewarp is inspired in part by [rathole](https://github.com/rathole-org/rathole), especially in keeping the operator experience and configuration surface small.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
