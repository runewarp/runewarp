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

The repository now ships the phase-1 data path, the corrected phase-2 operator surface, and the phase-3 explicit Server-authorized hostname routing model.

Today that means:

- public TCP passthrough works end to end
- `runewarp client identity init --directory ...` currently generates a Client private key, an initial self-signed Client certificate, and `client-identity.txt`
- `runewarp server` and `runewarp client` load `./config.toml` by default and boot the explicit Server-authorized routing model with `server.tunnels[].public-hostnames`, multiple Tunnels, multiple Client instances across those Tunnels, and either `[server.cert].directory` or `[server.acme]`
- ACME TLS-ALPN-01 now provisions and refreshes the Server hostname certificate from `server.acme.state-directory`
- Client certificate freshness is checked before the initial Tunnel connection and before reconnect attempts, without background renewal polling
- each Client instance connects to the Server over QUIC using one Tunnel connection
- the runtime keeps one active Tunnel connection per Tunnel, and a newer authenticated connection replaces the older connection only for that same Tunnel
- Client-side routing supports either Hostname mirroring with exact-match Services or one Catch-all Service behind an explicit Server-authorized Tunnel
- human-readable Server and Client routing diagnostics are enabled by default and can be disabled with `server.logs` and `client.logs`

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
- The Server is the routing authority for Public hostnames
- The runtime keeps Server-side Public hostname authorization explicit with `server.tunnels[].public-hostnames`
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
