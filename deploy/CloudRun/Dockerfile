# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM rust:1.92-alpine AS build
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache musl-dev protobuf-dev

# Binary name (configurable via build-arg)
ARG BIN=auth-service

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/

# Copy the rest
COPY . .

# Build fully static binary with musl
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/${BIN} /app/service

# ---- Runtime stage ----
# Chainguard static: ~2MB, no shell, no libc, CVE-free, SBOM included
FROM cgr.dev/chainguard/static:latest
WORKDIR /srv

# Copy binary
COPY --from=build /app/service /srv/service

# Copy GeoIP database
COPY --from=build /app/assets/GeoLite2-Country.mmdb /srv/assets/GeoLite2-Country.mmdb

ENV RUST_LOG=info
ENV GEOIP_DB_PATH=/srv/assets/GeoLite2-Country.mmdb

EXPOSE 8080
ENTRYPOINT ["/srv/service"]
