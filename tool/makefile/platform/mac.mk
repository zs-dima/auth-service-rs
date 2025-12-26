.PHONY: _echo_os

_echo_os:
	@echo "Running Makefile on macOS"

# macOS-specific: launchd service management
service-install-mac:
	@cp deploy/com.auth-service.plist ~/Library/LaunchAgents/
	@launchctl load ~/Library/LaunchAgents/com.auth-service.plist

service-uninstall-mac:
	@launchctl unload ~/Library/LaunchAgents/com.auth-service.plist
	@rm ~/Library/LaunchAgents/com.auth-service.plist

# macOS: Open documentation in browser
doc-open:
	@cargo doc
	@open target/doc/auth_service/index.html
