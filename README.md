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

Runewarp is a self-hostable tunnel for TLS passthrough. The public server routes by SNI and forwards the original encrypted stream to a client running beside your TLS backend.

The repository now implements the core phase-1 data path as a library-first runtime with end-to-end tests. Config loading, operator-facing `server` / `client` / `keygen` commands, and tunnel authentication hardening still land in later phases.

## Getting started

```bash
cargo build --release
cargo test
./target/release/runewarp
```

The current binary only reports the repository status. The working phase-1 implementation lives in the library and is exercised by the test suite while config-driven operator flows are still phase-2 work.

## Documentation

- [`docs/configuration.md`](docs/configuration.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/protocol.md`](docs/protocol.md)
- [`docs/security.md`](docs/security.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`AGENTS.md`](AGENTS.md)

## Inspiration

Runewarp is inspired in part by [rathole](https://github.com/rathole-org/rathole), especially in keeping the operator experience and configuration surface small.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
