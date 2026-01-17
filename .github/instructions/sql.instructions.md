---
applyTo: "**/*.sql"
---

# SQL Guidelines (PostgreSQL + SQLx)

## Naming
- Tables: snake_case plural (e.g., `users`, `sessions`)
- Columns: snake_case
- Enums: Define as PostgreSQL `TYPE` with lowercase values

## Patterns
- Primary keys: `id UUID DEFAULT gen_random_uuid()`
- Timestamps: `created_at TIMESTAMPTZ DEFAULT NOW()`, `updated_at TIMESTAMPTZ`
- Soft delete: `deleted_at TIMESTAMPTZ NULL`

## SQLx
- Use `-- name: query_name :return_type` comments for sqlx-ts
- Parameters: `$1`, `$2`, etc.
- Return types: `:one`, `:many`, `:exec`
