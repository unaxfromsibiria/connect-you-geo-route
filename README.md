# connect-you-geo-route

## About

A simple network service with Geo IP that redirects TCP connections based on allowed cities. The service is written in `Rust` using [Tokio](https://docs.rs/tokio/latest/tokio/index.html) for connection handling. It allows you to specify a list of allowed cities and a target socket where all matching TCP connections will be forwarded. Connections from other locations can be redirected to an alternative socket.

The application is designed for efficient traffic throttling with filtering by IP addresses, subnets, and GeoIP data.

The service also tracks traffic statistics and outputs them at regular intervals (default is once per minute, but this can be configured with `STAT_SHOW_INTERVAL`).

## Prerequisites

This service requires the MaxMind GeoLite2 City database file (`GeoLite2-City.mmdb`) to function correctly.

1. Download the `GeoLite2-City.mmdb` file (approx. 65MB) from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb).
2. Copy the downloaded file into the current directory where the service runs.

## Using

Edit the `docker-compose.yml` there is an example how to build and use the service.
