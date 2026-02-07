.PHONY: build run run-release clean watch fmt fmt-check lint audit doc pre-commit

# Build the project
build:
	cargo build --release

# Run in development mode
run:
	powershell -Command "Get-Content configs/development.env | ForEach-Object { if ($$_ -match '^([^#=]+)=(.*)$$') { [Environment]::SetEnvironmentVariable($$matches[1], $$matches[2], 'Process') } }; cargo run --color always"

# Run with release optimizations
run-release:
	powershell -Command "Get-Content configs/development.env | ForEach-Object { if ($$_ -match '^([^#=]+)=(.*)$$') { [Environment]::SetEnvironmentVariable($$matches[1], $$matches[2], 'Process') } }; cargo run --color always --release"

# Clean build artifacts
clean:
	cargo clean

# Watch and run on changes
watch:
	cargo watch -x run

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Run linter
lint:
	cargo clippy -- -D warnings

# Security audit
audit:
	cargo audit

# Generate documentation
doc:
	cargo doc --open

# All checks before commit
pre-commit: fmt-check lint test openapi-check
	@echo "All checks passed!"
