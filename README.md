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

The repository now ships the phase-1 data path plus the phase-2 Catch-all operator surface.

Today that means:

- public TCP passthrough works end to end
- `runewarp client identity init --directory ...` currently generates a Client private key, an initial self-signed Client certificate, and `client-identity.txt`
- `runewarp server` and `runewarp client` still load `./config.toml` by default and boot the Catch-all single-Tunnel design using the corrected runtime config names plus either `[server.cert].directory` or `[server.acme]`
- ACME TLS-ALPN-01 now provisions and refreshes the Server hostname certificate from `server.acme.state-directory`
- each Client instance connects to the Server over QUIC using one Tunnel connection
- the current implementation only keeps one Client instance active at a time
- exact-match routing and later multi-Tunnel operator work still land in later phases

## Getting started

```bash
cargo build --release
cargo test
./target/release/runewarp client identity init --directory ./client-identity
./target/release/runewarp server --config ./config.toml
./target/release/runewarp client --config ./config.toml
```

`runewarp server` and `runewarp client` default to `./config.toml` when `--config` is omitted. Client identity provisioning uses `runewarp client identity init --directory ...`, and Server operators can choose either `[server.cert]` manual certificates or `[server.acme]` for the Server hostname.

## Design boundaries

- TLS passthrough is the product boundary; Runewarp does not terminate customer TLS on public hostnames
- The Server is the routing authority for Public hostnames and should only route hostnames explicitly authorized on a Tunnel
- Client-side routing can use Hostname mirroring or one Catch-all Service, depending on whether the Client also needs per-host local routing
- Plain HTTP backends and edge TLS termination are out of scope

## Documentation

- [`CONTEXT.md`](CONTEXT.md)
- [`docs/configuration.md`](docs/configuration.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/protocol.md`](docs/protocol.md)
- [`docs/security.md`](docs/security.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/adr/0001-server-authoritative-routing-with-hostname-mirroring.md`](docs/adr/0001-server-authoritative-routing-with-hostname-mirroring.md)
- [`docs/adr/0002-manual-server-ca-and-exclusive-client-trust.md`](docs/adr/0002-manual-server-ca-and-exclusive-client-trust.md)
- [`AGENTS.md`](AGENTS.md)

## Inspiration

Runewarp is inspired in part by [rathole](https://github.com/rathole-org/rathole), especially in keeping the operator experience and configuration surface small.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
