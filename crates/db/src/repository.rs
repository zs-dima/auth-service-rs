//! Database repository layer with connection pooling for the auth schema.

use std::time::Duration;

use auth_core::AppError;
use ipnetwork::IpNetwork;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::info;
use uuid::Uuid;

use super::models::{
    ConsumedOAuthState, CreateOAuthStateParams, CreatePasswordResetTokenParams,
    CreateSessionParams, CreateUserWithProfileParams, LinkOAuthProviderParams, OAuthProvider,
    SessionInfo, TouchSessionResult, UpdateUserParams, UpdateUserProfileParams, User, UserInfo,
    UserStatus, UserWithProfile,
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

/// User repository for database operations on `auth.users` and `auth.user_profiles`.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get active user with profile by email.
    pub async fn get_active_user_by_email(&self, email: &str) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.email = $1
               AND u.status = 'active'
               AND u.deleted_at IS NULL
             LIMIT 1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {email}")))
    }

    /// Get user with profile by ID.
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("User not found: {user_id}")))
    }

    /// Get raw user by ID (without profile).
    pub async fn get_raw_user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role,
                   email,
                   email_verified,
                   phone,
                   phone_verified,
                   status AS "status: UserStatus",
                   password,
                   failed_login_attempts,
                   locked_until,
                   created_at,
                   updated_at,
                   deleted_at
              FROM auth.users
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

    /// Create a new user with profile using the database function.
    pub async fn create_user_with_profile(
        &self,
        params: CreateUserWithProfileParams,
    ) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            SELECT auth.create_user_with_profile($1, $2, $3::TEXT::auth.role_name, $4, $5, $6) AS "id!"
            "#,
            params.email,
            params.password_hash,
            params.role,
            params.display_name,
            params.locale,
            params.timezone
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("unique_violation")
                || e.to_string().contains("duplicate key")
            {
                AppError::AlreadyExists(format!("User already exists: {}", params.email))
            } else {
                AppError::Unavailable(e.to_string())
            }
        })
    }

    /// Update an existing user.
    pub async fn update_user(&self, params: UpdateUserParams) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET role = $2::TEXT::auth.role_name,
                   email = $3::TEXT::auth.email,
                   email_verified = $4,
                   phone = $5::TEXT::auth.phone_e164,
                   phone_verified = $6,
                   status = $7
             WHERE id = $1
            "#,
            params.id,
            params.role,
            params.email,
            params.email_verified,
            params.phone,
            params.phone_verified,
            params.status as UserStatus
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Update user profile.
    pub async fn update_user_profile(
        &self,
        params: UpdateUserProfileParams,
    ) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.user_profiles
               SET display_name = $2,
                   avatar_url = $3,
                   locale = $4,
                   timezone = $5
             WHERE id_user = $1
            "#,
            params.id_user,
            params.display_name,
            params.avatar_url,
            params.locale,
            params.timezone
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
            UPDATE auth.users
               SET password = $2
             WHERE email = $1
               AND deleted_at IS NULL
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

    /// Increment failed login attempts.
    pub async fn increment_failed_login(&self, user_id: Uuid) -> Result<i16, AppError> {
        sqlx::query_scalar!(
            r#"
            UPDATE auth.users
               SET failed_login_attempts = failed_login_attempts + 1
             WHERE id = $1
            RETURNING failed_login_attempts
            "#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Reset failed login attempts.
    pub async fn reset_failed_login(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET failed_login_attempts = 0,
                   locked_until = NULL
             WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Soft delete a user.
    #[allow(dead_code)]
    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET deleted_at = NOW(),
                   status = 'deleted'
             WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Stream all users with profile info.
    pub fn stream_all_users(
        &self,
    ) -> impl tokio_stream::Stream<Item = Result<UserInfo, sqlx::Error>> + '_ {
        sqlx::query_as!(
            UserInfo,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   p.display_name,
                   (u.deleted_at IS NOT NULL) AS "deleted!"
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             ORDER BY p.display_name
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
            SELECT u.id,
                   u.role,
                   u.email,
                   p.display_name,
                   (u.deleted_at IS NOT NULL) AS deleted
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.id = ANY($1)
             ORDER BY p.display_name
            "#,
        )
        .bind(user_ids)
        .fetch(&self.pool)
    }

    /// Link OAuth provider to user.
    pub async fn link_oauth_provider(
        &self,
        params: LinkOAuthProviderParams,
    ) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            SELECT auth.link_oauth_provider($1, $2, $3, $4, $5, $6, $7) AS "id_user!"
            "#,
            params.id_user,
            params.provider as OAuthProvider,
            params.provider_uid,
            params.email,
            params.name,
            params.avatar_url,
            params.provider_data
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }
}

/// Session repository for `auth.sessions` operations.
#[derive(Debug, Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new session.
    pub async fn create_session(&self, params: CreateSessionParams) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO auth.sessions (
                id_user, refresh_token, expires_at,
                device_id, device_name, device_type, client_version,
                ip_created_by, ip_address, ip_country, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10)",
        )
        .bind(params.id_user)
        .bind(&params.refresh_token_hash)
        .bind(params.expires_at)
        .bind(params.device_id)
        .bind(params.device_name)
        .bind(params.device_type)
        .bind(params.client_version)
        .bind(params.ip_address)
        .bind(params.ip_country)
        .bind(&params.metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// Touch session (validate and extend expiration).
    /// Returns the session owner and new expiry if valid.
    pub async fn touch_session(
        &self,
        token_hash: &[u8],
        ip_address: Option<IpNetwork>,
        ip_country: Option<&str>,
    ) -> Result<TouchSessionResult, AppError> {
        let result = sqlx::query_as!(
            TouchSessionResult,
            r#"
            SELECT id_user, expires_at
              FROM auth.touch_session($1, INTERVAL '7 days', $2, $3)
            "#,
            token_hash,
            ip_address,
            ip_country
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        // The DB function returns an empty result if session not found/expired
        match result {
            Some(r) if r.id_user.is_some() => Ok(r),
            _ => Err(AppError::NotFound(
                "Session not found or expired".to_string(),
            )),
        }
    }

    /// Revoke a single session by token hash.
    pub async fn revoke_session(&self, token_hash: &[u8]) -> Result<Option<Uuid>, AppError> {
        sqlx::query_scalar!(
            r#"
            DELETE FROM auth.sessions
             WHERE refresh_token = $1
            RETURNING id_user
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<i64, AppError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM auth.sessions
             WHERE id_user = $1
               AND expires_at > NOW()
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(result.rows_affected() as i64)
    }

    /// Revoke all sessions except current.
    pub async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        current_token_hash: &[u8],
    ) -> Result<i64, AppError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM auth.sessions
             WHERE id_user = $1
               AND refresh_token <> $2
               AND expires_at > NOW()
            "#,
            user_id,
            current_token_hash
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(result.rows_affected() as i64)
    }

    /// List all active sessions for a user.
    pub async fn list_user_sessions(
        &self,
        user_id: Uuid,
        current_token_hash: &[u8],
    ) -> Result<Vec<SessionInfo>, AppError> {
        sqlx::query_as::<_, SessionInfo>(
            "SELECT device_id,
                    device_name,
                    device_type,
                    client_version,
                    ip_created_by,
                    ip_address,
                    ip_country,
                    created_at,
                    last_seen_at,
                    expires_at,
                    activity_count,
                    metadata,
                    (refresh_token = $2) AS is_current
               FROM auth.sessions
              WHERE id_user = $1
                AND expires_at > NOW()
              ORDER BY last_seen_at DESC",
        )
        .bind(user_id)
        .bind(current_token_hash)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Revoke a session by device_id for a specific user.
    pub async fn revoke_session_by_device_id(
        &self,
        user_id: Uuid,
        device_id: &str,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "DELETE FROM auth.sessions
              WHERE id_user = $1
                AND device_id = $2
                AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke all sessions except the one with the given device_id.
    pub async fn revoke_sessions_except_device(
        &self,
        user_id: Uuid,
        current_device_id: &str,
    ) -> Result<i64, AppError> {
        let result = sqlx::query(
            "DELETE FROM auth.sessions
              WHERE id_user = $1
                AND (device_id IS NULL OR device_id <> $2)
                AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(current_device_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
        Ok(result.rows_affected() as i64)
    }
}

/// OAuth state repository for `auth.oauth_states` operations.
#[derive(Debug, Clone)]
pub struct OAuthStateRepository {
    pool: PgPool,
}

impl OAuthStateRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new OAuth state.
    pub async fn create_state(&self, params: CreateOAuthStateParams) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            INSERT INTO auth.oauth_states (state, code_verifier, provider, redirect_uri)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
            params.state,
            params.code_verifier,
            params.provider as OAuthProvider,
            params.redirect_uri
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Consume OAuth state (atomic get-and-delete).
    pub async fn consume_state(&self, state: &str) -> Result<ConsumedOAuthState, AppError> {
        let result = sqlx::query_as!(
            ConsumedOAuthState,
            r#"
            SELECT code_verifier,
                   provider AS "provider: OAuthProvider",
                   redirect_uri
              FROM auth.consume_oauth_state($1)
            "#,
            state
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        // The DB function returns an empty result if state not found/expired
        match result {
            Some(r) if r.code_verifier.is_some() => Ok(r),
            _ => Err(AppError::NotFound(
                "OAuth state not found or expired".to_string(),
            )),
        }
    }
}

/// Combined database context.
#[derive(Debug, Clone)]
pub struct Database {
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub oauth_states: OAuthStateRepository,
    pub password_resets: PasswordResetRepository,
    pool: PgPool,
}

impl Database {
    pub fn new(pool: PgPool) -> Self {
        info!("Database initialized with auth schema");
        Self {
            users: UserRepository::new(pool.clone()),
            sessions: SessionRepository::new(pool.clone()),
            oauth_states: OAuthStateRepository::new(pool.clone()),
            password_resets: PasswordResetRepository::new(pool.clone()),
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

    /// Get the underlying connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// =============================================================================
// Password Reset Repository
// =============================================================================

/// Password reset token repository for `auth.password_reset_tokens` operations.
#[derive(Debug, Clone)]
pub struct PasswordResetRepository {
    pool: PgPool,
}

impl PasswordResetRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new password reset token.
    /// Invalidates any existing tokens for the user.
    pub async fn create_token(
        &self,
        params: CreatePasswordResetTokenParams,
    ) -> Result<Uuid, AppError> {
        // First, invalidate any existing unused tokens for this user
        sqlx::query!(
            r#"
            UPDATE auth.password_reset_tokens
               SET used_at = NOW()
             WHERE id_user = $1
               AND used_at IS NULL
               AND expires_at > NOW()
            "#,
            params.id_user
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        // Create new token
        sqlx::query_scalar!(
            r#"
            INSERT INTO auth.password_reset_tokens (id_user, token_hash, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            params.id_user,
            &params.token_hash,
            params.expires_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))
    }

    /// Validate and consume a password reset token.
    /// Returns the user_id if valid, marks token as used.
    pub async fn consume_token(&self, token_hash: &[u8]) -> Result<Uuid, AppError> {
        let result = sqlx::query_scalar!(
            r#"
            UPDATE auth.password_reset_tokens
               SET used_at = NOW()
             WHERE token_hash = $1
               AND used_at IS NULL
               AND expires_at > NOW()
            RETURNING id_user
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        result.ok_or_else(|| AppError::NotFound("Invalid or expired reset token".to_string()))
    }

    /// Check if a token hash is valid without consuming it.
    pub async fn validate_token(&self, token_hash: &[u8]) -> Result<Uuid, AppError> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT id_user
              FROM auth.password_reset_tokens
             WHERE token_hash = $1
               AND used_at IS NULL
               AND expires_at > NOW()
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        result.ok_or_else(|| AppError::NotFound("Invalid or expired reset token".to_string()))
    }

    /// Cleanup expired tokens (run periodically).
    pub async fn cleanup_expired(&self) -> Result<i64, AppError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM auth.password_reset_tokens
             WHERE expires_at < NOW() - INTERVAL '1 day'
                OR used_at < NOW() - INTERVAL '1 day'
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;

        Ok(result.rows_affected() as i64)
    }
}
