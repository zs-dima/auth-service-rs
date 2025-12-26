.PHONY: docker docker-run docker-arm docker-stop docker-logs

# Build Docker image
docker:
	docker build -t auth-service:latest -f deploy/Dockerfile .

# Run Docker container
docker-run:
	docker run -p 50051:50051 -p 8080:8080 --env-file .env auth-service:latest

# Build Docker image for ARM
docker-arm:
	docker buildx build --platform linux/arm64 -t auth-service:latest-arm -f deploy/Dockerfile.arm .

# Stop Docker container
docker-stop:
	docker stop $$(docker ps -q --filter ancestor=auth-service:latest) 2>/dev/null || true

# View Docker logs
docker-logs:
	docker logs $$(docker ps -q --filter ancestor=auth-service:latest)
