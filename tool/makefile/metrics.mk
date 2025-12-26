.PHONY: stats

# Code statistics
stats:
	@echo "* Running cloc *"
	@cloc --exclude-dir=target .
