# New Database Query

Add a new SQLx query to the database layer.

## Steps
1. Add SQL to `crates/db/sql/db.sql` or create new `.sql` file
2. Add model struct in `crates/db/src/models.rs` if needed
3. Add repository method in `crates/db/src/repository.rs`
4. Run `make db-prepare` to verify and cache query

## Query Example
```sql
-- name: get_user_by_email :one
SELECT id, email, display_name, status
FROM users
WHERE email = $1 AND deleted_at IS NULL;
```

## Repository Method
```rust
pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
    sqlx::query_as!(User, r#"SELECT ... FROM users WHERE email = $1"#, email)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user")
}
```
