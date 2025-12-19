.PHONY: build run test clean proto docker

# Build the project
build:
	cargo build --release

# Run in development mode
run:
	cargo run

# Run with release optimizations
run-release:
	cargo run --release

# Run tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Clean build artifacts
clean:
	cargo clean

# Generate protobuf code (done automatically by build.rs)
proto:
	cargo build

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Run linter
lint:
	cargo clippy -- -D warnings

# Build Docker image
docker:
	docker build -t auth-service:latest .

# Build Docker image for ARM
docker-arm:
	docker buildx build --platform linux/arm64 -t auth-service:latest-arm -f Dockerfile.arm .

# Run Docker container
docker-run:
	docker run -p 50051:50051 -p 8080:8080 --env-file .env auth-service:latest

# Database migrations (requires sqlx-cli)
migrate:
	sqlx migrate run

# Generate SQLx offline data
sqlx-prepare:
	cargo sqlx prepare

# Check SQLx queries
sqlx-check:
	cargo sqlx prepare --check

# Install development tools
dev-tools:
	cargo install sqlx-cli --no-default-features --features rustls,postgres
	cargo install cargo-watch

# Watch and run on changes
watch:
	cargo watch -x run

# Generate documentation
doc:
	cargo doc --open

# Security audit
audit:
	cargo audit

# All checks before commit
pre-commit: fmt-check lint test
	@echo "All checks passed!"
