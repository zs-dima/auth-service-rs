.PHONY: version outdated upgrade tree

# Check Rust/Cargo version
version:
	@rustc --version
	@cargo --version

# Check outdated dependencies
outdated:
	cargo outdated

# Upgrade dependencies
upgrade:
	cargo update

# Show dependency tree
tree:
	cargo tree
