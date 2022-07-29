FROM rust:1.61.0 AS base
RUN apt update && apt install musl-tools -y
WORKDIR /app

FROM base as builder
RUN rustup target add x86_64-unknown-linux-musl
COPY . .
RUN RUSTFLAGS='-Clinker=rust-lld' cargo build --release --bin phase1-coordinator --target x86_64-unknown-linux-musl --features="parallel"

FROM debian:buster-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
RUN update-ca-certificates

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/phase1-coordinator /usr/local/bin
COPY --from=builder /app/Rocket.toml /rocket/Rocket.toml
COPY --from=builder /app/system_version.json /rocket/status.json

ENV ROCKET_CONFIG=/rocket/Rocket.toml
ENV RUST_LOG=info
ENV HEALTH_PATH=/rocket

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/phase1-coordinator"]
