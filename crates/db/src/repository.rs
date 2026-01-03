//! Database repository layer with connection pooling.

use std::time::Duration;

use auth_core::AppError;
use chrono::Utc;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::info;
use uuid::Uuid;

use super::models::{
    CreateUserParams, SaveUserSessionParams, UpdateUserParams, User, UserInfo, UserRole,
};

/// Database configuration.
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    pub pool_min: u32,
    pub pool_max: u32,
    pub connect_timeout: Duration,
}

/// Create database connection pool.
pub async fn create_pool(config: &DbConfig) -> Result<PgPool, AppError> {
    PgPoolOptions::new()
        .min_connections(config.pool_min)
        .max_connections(config.pool_max)
        .acquire_timeout(config.connect_timeout)
        .connect(&config.url)
        .await
        .map_err(|e| AppError::Unavailable(format!("Database connection failed: {e}")))
}

/// User repository for database operations.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get active user by email.
    pub async fn get_active_user(&self, email: &str) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   password,
                   deleted_at
              FROM "user"
             WHERE email = $1
               AND (deleted_at IS NULL OR deleted_at > NOW())
             LIMIT 1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {email}")))
    }

    /// Get user by ID.
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   password,
                   deleted_at
              FROM "user"
             WHERE id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {user_id}")))
    }

    /// Create a new user.
    pub async fn create_user(&self, params: CreateUserParams) -> Result<Uuid, AppError> {
        let deleted_at = params.deleted.then(Utc::now);
        sqlx::query_scalar!(
            r#"
            INSERT INTO "user" (id, role, name, email, password, deleted_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            params.id,
            params.role as UserRole,
            &params.name,
            &params.email,
            &params.password,
            deleted_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Update an existing user.
    pub async fn update_user(&self, params: UpdateUserParams) -> Result<(), AppError> {
        let deleted_at = params.deleted.then(Utc::now);
        sqlx::query!(
            r#"
            UPDATE "user"
               SET role = $2,
                   name = $3,
                   email = $4,
                   deleted_at = $5
             WHERE id = $1
            "#,
            params.id,
            params.role as UserRole,
            &params.name,
            &params.email,
            deleted_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Update user password.
    pub async fn update_user_password(
        &self,
        email: &str,
        password_hash: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query!(
            r#"
            UPDATE "user"
               SET password = $2
             WHERE email = $1
            "#,
            email,
            password_hash
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("User not found: {email}")));
        }
        Ok(())
    }

    /// Soft delete a user.
    #[allow(dead_code)]
    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE "user"
               SET deleted_at = NOW()
             WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Stream all users.
    pub fn stream_all_users(
        &self,
    ) -> impl tokio_stream::Stream<Item = Result<UserInfo, sqlx::Error>> + '_ {
        sqlx::query_as!(
            UserInfo,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   (deleted_at IS NOT NULL AND deleted_at < NOW()) AS "deleted!"
              FROM "user"
             ORDER BY name
            "#
        )
        .fetch(&self.pool)
    }

    /// Stream users by IDs.
    pub fn stream_users_by_ids(
        &self,
        user_ids: Vec<Uuid>,
    ) -> impl tokio_stream::Stream<Item = Result<UserInfo, sqlx::Error>> + '_ {
        sqlx::query_as::<_, UserInfo>(
            r#"
            SELECT id,
                   role AS "role",
                   name,
                   email,
                   (deleted_at IS NOT NULL AND deleted_at < NOW()) AS "deleted"
              FROM "user"
             WHERE id = ANY($1)
             ORDER BY name
            "#,
        )
        .bind(user_ids)
        .fetch(&self.pool)
    }
}

/// Session repository for refresh token operations.
#[derive(Debug, Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Save or update user session.
    pub async fn save_user_session(&self, params: SaveUserSessionParams) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            INSERT INTO user_session (user_id, refresh_token, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT(user_id) DO UPDATE SET
                refresh_token = excluded.refresh_token,
                expires_at = excluded.expires_at
            "#,
            params.user_id,
            &params.refresh_token,
            params.expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// End user session.
    pub async fn end_user_session(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE user_session
               SET refresh_token = '',
                   expires_at = NOW()
             WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Load refresh token for a user.
    pub async fn load_refresh_token(&self, user_id: Uuid) -> Result<String, AppError> {
        sqlx::query_scalar!(
            r#"
            SELECT refresh_token
              FROM user_session
             WHERE user_id = $1
               AND expires_at > NOW()
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Session not found or expired".to_string()))
    }
}

/// Combined database context.
#[derive(Debug, Clone)]
pub struct Database {
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pool: PgPool,
}

impl Database {
    pub fn new(pool: PgPool) -> Self {
        info!("Database initialized");
        Self {
            users: UserRepository::new(pool.clone()),
            sessions: SessionRepository::new(pool.clone()),
            pool,
        }
    }

    /// Check database health.
    pub async fn health_check(&self) -> bool {
        sqlx::query_scalar!("SELECT 1 AS one")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}
