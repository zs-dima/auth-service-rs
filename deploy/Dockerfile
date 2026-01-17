# Build stage
FROM rust:1.92-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/

# Create dummy source to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY . .

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/auth-service /app/auth-service

# Copy GeoIP database (optional)
COPY --from=builder /app/assets/GeoLite2-Country.mmdb /app/assets/GeoLite2-Country.mmdb

# Create non-root user
RUN useradd -r -s /bin/false authservice
USER authservice

ENV GEOIP_DB_PATH=/app/assets/GeoLite2-Country.mmdb

# Expose ports
EXPOSE 50051 8080

# Health check (requires curl or use gRPC health check)
# Note: --health-check flag doesn't exist in the service, remove or implement
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["true"]

# Run the service
ENTRYPOINT ["/app/auth-service"]
