use chrono::Utc;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use super::models::*;
use crate::config::Config;
use crate::error::AppError;

/// Database repository for user operations
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get an active user by email
    pub async fn get_active_user(&self, email: &str) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   password,
                   blurhash,
                   deleted_at
              FROM "user"
             WHERE email = $1
               AND (deleted_at IS NULL OR deleted_at > NOW())
             LIMIT 1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {}", email)))
    }

    /// Get a user by ID (regardless of deleted status)
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   password,
                   blurhash,
                   deleted_at
              FROM "user"
             WHERE id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {}", user_id)))
    }

    /// Load a single user's info with deleted status flag
    pub async fn get_user_info(&self, user_id: Uuid) -> Result<UserInfo, AppError> {
        sqlx::query_as!(
            UserInfo,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   blurhash,
                   (deleted_at IS NOT NULL AND deleted_at < NOW()) AS "deleted!"
              FROM "user"
             WHERE id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {}", user_id)))
    }

    /// Load all users with deleted status
    #[allow(dead_code)]
    pub async fn load_users(&self) -> Result<Vec<UserInfo>, AppError> {
        sqlx::query_as!(
            UserInfo,
            r#"
            SELECT id,
                   role AS "role: UserRole",
                   name,
                   email,
                   blurhash,
                   (deleted_at IS NOT NULL AND deleted_at < NOW()) AS "deleted!"
              FROM "user"
             ORDER BY name
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a new user
    pub async fn create_user(&self, params: CreateUserParams) -> Result<Uuid, AppError> {
        let deleted_at = if params.deleted {
            Some(Utc::now())
        } else {
            None
        };

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
        .map_err(Into::into)
    }

    /// Update an existing user
    pub async fn update_user(&self, params: UpdateUserParams) -> Result<(), AppError> {
        let deleted_at = if params.deleted {
            Some(Utc::now())
        } else {
            None
        };

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
        .await?;

        Ok(())
    }

    /// Update user password
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
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("User not found: {}", email)));
        }

        Ok(())
    }

    /// Update user blurhash
    #[allow(dead_code)]
    pub async fn update_user_blurhash(
        &self,
        user_id: Uuid,
        blurhash: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE "user"
               SET blurhash = $2
             WHERE id = $1
            "#,
            user_id,
            blurhash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a user (soft delete)
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
        .await?;

        Ok(())
    }

    /// Stream all users info (for admin endpoints)
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
                   blurhash,
                   (deleted_at IS NOT NULL AND deleted_at < NOW()) AS "deleted!"
              FROM "user"
             ORDER BY name
            "#
        )
        .fetch(&self.pool)
    }
}

/// Database repository for user session operations
#[derive(Debug, Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Save or update user session
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
        .await?;

        Ok(())
    }

    /// End user session
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
        .await?;

        Ok(())
    }

    /// Load refresh token for a user
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
        .await?
        .ok_or_else(|| AppError::NotFound("Session not found or expired".to_string()))
    }
}

/// Database repository for user photo operations
#[derive(Debug, Clone)]
pub struct PhotoRepository {
    pool: PgPool,
}

impl PhotoRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Save or update user photo and blurhash
    pub async fn save_user_photo(
        &self,
        params: SaveUserPhotoParams,
        blurhash: &str,
    ) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;

        // Update blurhash on user table
        sqlx::query!(
            r#"UPDATE "user" SET blurhash = $2 WHERE id = $1"#,
            params.user_id,
            blurhash
        )
        .execute(&mut *tx)
        .await?;

        // Upsert photo
        sqlx::query!(
            r#"
            INSERT INTO user_photo (user_id, avatar, photo)
            VALUES ($1, $2, $3)
            ON CONFLICT(user_id) DO UPDATE SET
                avatar = excluded.avatar,
                photo = excluded.photo
            "#,
            params.user_id,
            &params.avatar,
            &params.photo
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Load user avatars for given user IDs
    pub async fn load_user_avatars(&self, user_ids: &[Uuid]) -> Result<Vec<UserAvatar>, AppError> {
        sqlx::query_as!(
            UserAvatar,
            r#"
            SELECT user_id, avatar
              FROM user_photo
             WHERE user_id = ANY($1)
            "#,
            user_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Load all user avatars
    #[allow(dead_code)]
    pub async fn load_all_avatars(&self) -> Result<Vec<UserAvatar>, AppError> {
        sqlx::query_as!(
            UserAvatar,
            r#"
            SELECT user_id, avatar
              FROM user_photo
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}

/// Combined database context with all repositories
#[derive(Debug, Clone)]
pub struct Database {
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub photos: PhotoRepository,
    pool: PgPool,
}

impl Database {
    pub fn new(pool: PgPool) -> Self {
        Self {
            users: UserRepository::new(pool.clone()),
            sessions: SessionRepository::new(pool.clone()),
            photos: PhotoRepository::new(pool.clone()),
            pool,
        }
    }

    /// Get the underlying connection pool
    #[allow(dead_code)]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check database health by executing a simple query
    pub async fn health_check(&self) -> bool {
        sqlx::query_scalar!("SELECT 1 AS one")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}

/// Create database connection pool with configuration
pub async fn create_pool(config: &Config) -> Result<PgPool, AppError> {
    // Replace :@ with :PASSWORD@ in the DB URL (similar to Go implementation)
    let db_url = match &config.db_password {
        Some(password) => {
            let encoded_password = urlencoding::encode(password);
            config
                .db_url
                .replacen(":@", &format!(":{}@", encoded_password), 1)
        }
        None => config.db_url.clone(),
    };

    PgPoolOptions::new()
        .min_connections(config.db_pool_min)
        .max_connections(config.db_pool_max)
        .acquire_timeout(config.db_connect_timeout())
        .connect(&db_url)
        .await
        .map_err(Into::into)
}
