.PHONY: db db-prepare migrate db-reset

# Load development environment and construct DATABASE_URL
# Usage: make db-prepare or make db
include configs/development.env
export DATABASE_URL := $(subst :@,:$(DB_PASSWORD)@,$(DB_URL))

# SQLx query verification
db:
	cd crates/db && cargo sqlx prepare --check

# Generate SQLx offline data
db-prepare:
	cd crates/db && cargo sqlx prepare

# Run database migrations
db-migrate:
	sqlx migrate run --source crates/db/migrations --database-url "$(DATABASE_URL)"

# Reset database (drop and recreate)
db-reset:
	sqlx database drop -y --database-url "$(DATABASE_URL)"
	sqlx database create --database-url "$(DATABASE_URL)"
	sqlx migrate run --source crates/db/migrations --database-url "$(DATABASE_URL)"
