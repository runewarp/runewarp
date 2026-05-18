FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --bin runewarp

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /app/target/release/runewarp /usr/local/bin/runewarp

USER nonroot:nonroot
EXPOSE 443/tcp
EXPOSE 443/udp
ENTRYPOINT ["/usr/local/bin/runewarp"]
