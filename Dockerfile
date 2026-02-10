FROM rust:1.93
WORKDIR /usr/src/connection-service
COPY . .
RUN cargo install --path .
RUN du -h /usr/local/cargo/bin/connect-you-geo
CMD ["connect-you-geo"]
