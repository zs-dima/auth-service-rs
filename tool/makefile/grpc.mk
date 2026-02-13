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
# Uses the `generate` subcommand which runs the full pipeline:
#   1. buf lint
#   2. Inject Cargo.toml version into a copy of buf.gen.yaml
#   3. buf generate (gnostic → OpenAPI 3.0.3)
#   4. buf build → proto descriptor set
#   5. Discover + patch (3.0.3 → 3.1, validation, security, etc.)
#
# The original buf.gen.yaml is never modified.
# Cross-platform: no bash, no yq — pure Rust + buf CLI.
# Requires: buf CLI (https://buf.build/docs/installation)

# Allow overriding the CLI command (e.g. installed binary via `cargo install tonic-rest-openapi --features cli`)
# or use local OPENAPI_CLI ?= cargo run --manifest-path ../tonic-rest/Cargo.toml -p tonic-rest-openapi --features cli --
OPENAPI_CLI ?= tonic-rest-openapi
OPENAPI_CONFIG := api/openapi/config.yaml

openapi:
	$(OPENAPI_CLI) generate --config $(OPENAPI_CONFIG) --cargo-toml Cargo.toml

# Verify the committed spec matches what generation produces.
# Runs the full openapi pipeline + checks for drift. Use in CI or pre-commit.
openapi-check: openapi
	@git diff --exit-code api/openapi/v1/openapi.yaml || (echo "ERROR: openapi.yaml is out of date — run 'make openapi' and commit" && exit 1)