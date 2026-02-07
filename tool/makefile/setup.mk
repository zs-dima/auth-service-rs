.PHONY: dev-tools setup

# Install development tools
dev-tools:
	cargo install sqlx-cli --no-default-features --features rustls,postgres
	cargo install cargo-watch
	cargo install cargo-audit
	@echo "Install buf CLI from: https://buf.build/docs/installation"

# Initial project setup
setup: dev-tools
	@echo "Development tools installed!"
