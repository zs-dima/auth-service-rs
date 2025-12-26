.PHONY: test test-verbose

# Run tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture
