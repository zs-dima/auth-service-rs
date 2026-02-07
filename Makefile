.PHONY: help

# Auth Service (Rust) - Help
help:
	@echo "Auth Service (Rust) - Available commands:"
	@echo ""
	@echo "  Build & Run:    build, run, run-release, watch, clean"
	@echo "  Code Gen:       proto, openapi, openapi-lint, proto-breaking, proto-sync, db, db-prepare, migrate"
	@echo "  Quality:        fmt, fmt-check, lint, audit, pre-commit"
	@echo "  Testing:        test, test-verbose"
	@echo "  Docker:         docker, docker-run, docker-arm"
	@echo "  Docs & Setup:   doc, dev-tools"

-include tool/makefile/*.mk
