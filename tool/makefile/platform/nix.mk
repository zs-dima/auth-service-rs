.PHONY: _echo_os

_echo_os:
	@echo "Running Makefile on Linux"

# Linux-specific: systemd service management
service-install:
	@sudo cp deploy/auth-service.service /etc/systemd/system/
	@sudo systemctl daemon-reload

service-start:
	@sudo systemctl start auth-service

service-stop:
	@sudo systemctl stop auth-service

service-status:
	@sudo systemctl status auth-service
