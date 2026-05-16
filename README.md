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

The repository now ships the phase-1 data path plus the first phase-2 operator surface.

Today that means:

- public TCP passthrough works end to end
- `runewarp client identity init --directory ...` currently generates a Client private key, an initial self-signed Client certificate, and `client-identity.txt`
- `runewarp server` and `runewarp client` still load `./config.toml` by default and boot the Catch-all single-Tunnel design using the corrected runtime config names and `[server.cert].directory` manual mode
- the remaining corrected operator surface still needs `runewarp server cert ...`, Client authentication, Client certificate renewal, and the working ACME path
- each Client instance connects to the Server over QUIC using one Tunnel connection
- the current implementation only keeps one Client instance active at a time
- exact-match routing, ACME, Client certificate renewal, pinned Client-identity enforcement, and the rest of the corrected operator surface still land in later phase-2 work

The current build is still not ready for public deployment without Client authentication hardening.

## Getting started

```bash
cargo build --release
cargo test
./target/release/runewarp client identity init --directory ./client-identity
./target/release/runewarp server --config ./config.toml
./target/release/runewarp client --config ./config.toml
```

`runewarp server` and `runewarp client` default to `./config.toml` when `--config` is omitted. Client identity provisioning now uses `runewarp client identity init --directory ...`, while the remaining corrected phase-2 runtime surface still lands in follow-on work.

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
