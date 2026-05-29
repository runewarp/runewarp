FROM rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked --bin runewarp

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e1fd250ce83d94603e9887ec991156a6c26905a6b0001039b7a43699018c0733

COPY --from=builder /app/target/release/runewarp /usr/local/bin/runewarp

USER nonroot:nonroot
EXPOSE 443/tcp
EXPOSE 443/udp
ENTRYPOINT ["/usr/local/bin/runewarp"]
