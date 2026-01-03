.PHONY: proto

# Generate Rust code from proto files (via build.rs in auth-proto crate)
proto:
	cd crates/proto && cargo build -p auth-proto