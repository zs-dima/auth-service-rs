# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM rust:1.92-bookworm AS build
WORKDIR /app

# Binary name (configurable via build-arg)
ARG BIN=auth-service

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/

# Copy the rest
COPY . .

# Build with BuildKit cache mounts (fast incremental builds)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/${BIN} /app/service

# ---- Runtime stage ----
# Distroless: minimal attack surface, includes TLS certs
FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /srv

# Copy binary
COPY --from=build /app/service /srv/service

# Copy GeoIP database (optional, comment out if not needed)
COPY --from=build /app/assets/GeoLite2-Country.mmdb /srv/assets/GeoLite2-Country.mmdb

# Cloud Run injects $PORT; server must listen on 0.0.0.0:$PORT
ENV RUST_LOG=info
ENV GEOIP_DB_PATH=/srv/assets/GeoLite2-Country.mmdb

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/srv/service"]
