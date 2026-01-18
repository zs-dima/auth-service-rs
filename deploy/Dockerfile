# syntax=docker/dockerfile:1.12

# ---- Build stage ----
FROM rust:1.92-alpine AS build
WORKDIR /app

RUN apk add --no-cache musl-dev protobuf-dev

ARG BIN=auth-service

# Copy source and build manifests
# Note: GitHub Actions gha cache handles layer caching effectively
# For advanced dependency caching, consider cargo-chef
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY crates crates
COPY proto proto
COPY assets assets

# Build static musl binary (lto + strip configured in Cargo.toml)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/${BIN} /service

# ---- Runtime stage ----
# scratch: 0 bytes base, smallest possible image
FROM scratch

COPY --from=build /service /service
COPY --from=build /app/assets/GeoLite2-Country.mmdb /assets/GeoLite2-Country.mmdb

ENV RUST_LOG=info
ENV GEOIP_DB_PATH=/assets/GeoLite2-Country.mmdb

EXPOSE 8080
ENTRYPOINT ["/service"]
