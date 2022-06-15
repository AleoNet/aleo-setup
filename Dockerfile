FROM rust:1.61.0 AS base
WORKDIR /app

FROM base as builder
RUN rustup target add x86_64-unknown-linux-musl
COPY . .
RUN docker/compile.sh

FROM debian:buster-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/phase1-coordinator /usr/local/bin
EXPOSE 1337
ENTRYPOINT ["/usr/local/bin/phase1-coordinator"]