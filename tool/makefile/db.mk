.PHONY: db db-prepare migrate db-reset

# Load development environment and construct DATABASE_URL
# Usage: make db-prepare or make db
include configs/development.env
export DATABASE_URL := $(subst :@,:$(DB_PASSWORD)@,$(DB_URL))

# SQLx query verification
db:
	cargo sqlx prepare --check

# Generate SQLx offline data
db-prepare:
	cargo sqlx prepare

# Run database migrations
db-migrate:
	sqlx migrate run

# Reset database (drop and recreate)
db-reset:
	sqlx database drop -y
	sqlx database create
	sqlx migrate run
