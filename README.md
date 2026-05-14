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

The codebase is early. Use the docs in `docs/` and the roadmap to track what is already implemented versus what is still planned.

## Getting started

```bash
cargo build --release
./target/release/runewarp --help
./target/release/runewarp keygen --out-dir ./certs
```

1. Point your public hostname at the tunnel server, for example `app.example.com CNAME tunnel.example.com`.
2. Write your server and client config files.
3. Run `runewarp server --config config.toml` on the public host.
4. Run `runewarp client --config config.toml` beside your local TLS backend.

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
