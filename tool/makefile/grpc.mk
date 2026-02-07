.PHONY: proto openapi openapi-lint openapi-check proto-breaking proto-sync

# Generate Rust code from proto files (via build.rs in auth-proto crate)
proto:
	cd crates/proto && cargo build -p auth-proto

# Lint proto files before generation
openapi-lint:
	buf lint

# Detect breaking changes against the main branch.
# Uses buf.yaml `breaking.use: [FILE]` rules to enforce wire compatibility.
# Run in CI as a gate before merge.
proto-breaking:
	buf breaking --against '.git#branch=main'

# Sync vendored proto dependencies from Buf Schema Registry.
# Updates api/proto/google/api/ and api/proto/validate/ from BSR to keep them
# in sync with buf.yaml deps. Vendored copies are needed by build.rs
# which resolves includes from local paths.
#
# Requires: buf CLI (https://buf.build/docs/installation)
proto-sync:
	@echo "Syncing proto dependencies from BSR..."
	buf dep update
	buf export buf.build/googleapis/googleapis --output api/proto --path google/api/annotations.proto --path google/api/http.proto --path google/api/httpbody.proto
	buf export buf.build/envoyproxy/protoc-gen-validate --output api/proto --path validate/validate.proto
	@echo "Proto dependencies synced from BSR"

# Generate OpenAPI 3.1 spec from proto files with google.api.http annotations.
#
# Pipeline: buf lint → buf generate (gnostic 3.0.3) → xtask patch (3.1.0)
#
# Version is extracted from Cargo.toml automatically by xtask.
# Cross-platform: no bash, no yq — pure Rust via cargo xtask.
# Requires: buf CLI (https://buf.build/docs/installation)
openapi:
	cargo xtask openapi

# Verify the committed spec matches what generation produces.
# Runs openapi-lint + checks for drift. Use in CI or pre-commit.
openapi-check: openapi-lint openapi
	@git diff --exit-code api/openapi/v1/openapi.yaml || (echo "ERROR: openapi.yaml is out of date — run 'make openapi' and commit" && exit 1)