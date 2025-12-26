.PHONY: _echo_os

_echo_os:
	@echo "Running Makefile on Windows"

# Windows-specific: Use PowerShell for docker commands
docker-logs-win:
	@powershell -Command "docker logs $$(docker ps -q --filter ancestor=auth-service:latest)"

docker-stop-win:
	@powershell -Command "docker stop $$(docker ps -q --filter ancestor=auth-service:latest)"
