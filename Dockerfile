FROM rust:1.95 AS builder
WORKDIR /usr/src/connection-service
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt update && \
    apt install -y curl procps && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/connection-service/target/release/connect-you-geo /usr/local/bin/connect-you-geo

CMD ["connect-you-geo"]
