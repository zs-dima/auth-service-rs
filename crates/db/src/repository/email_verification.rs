//! Email verification token repository for `auth.email_verification_tokens` operations.

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::{AppError, CreateEmailVerificationTokenParams, DbError, UserWithProfile};

/// Email verification token repository for `auth.email_verification_tokens` operations.
#[derive(Debug, Clone)]
pub struct EmailVerificationRepository {
    pool: PgPool,
}

impl EmailVerificationRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new email verification token.
    /// Atomically invalidates any existing tokens and creates the new one.
    pub async fn create_token(
        &self,
        params: CreateEmailVerificationTokenParams<'_>,
    ) -> Result<Uuid, AppError> {
        // Atomic: invalidate existing tokens and create new one in single statement
        // Uses CTE to ensure atomicity and prevent race conditions
        sqlx::query_scalar::<_, Uuid>(
            r"
            WITH invalidated AS (
                UPDATE auth.email_verification_tokens
                   SET used_at = NOW()
                 WHERE id_user = $1
                   AND used_at IS NULL
                   AND expires_at > NOW()
            )
            INSERT INTO auth.email_verification_tokens (id_user, token_hash, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id
            ",
        )
        .bind(params.id_user)
        .bind(params.token_hash)
        .bind(params.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DbError(e).into())
    }

    /// Validate and consume an email verification token.
    /// Returns the `user_id` if valid, marks token as used.
    pub async fn consume_token(&self, token_hash: &[u8]) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            UPDATE auth.email_verification_tokens
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
        .map_err(DbError)?
        .ok_or_else(|| AppError::token_invalid("verification token"))
    }

    /// Check if a token hash is valid without consuming it.
    pub async fn validate_token(&self, token_hash: &[u8]) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            SELECT id_user
              FROM auth.email_verification_tokens
             WHERE token_hash = $1
               AND used_at IS NULL
               AND expires_at > NOW()
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::token_invalid("verification token"))
    }

    /// Cleanup expired tokens (run periodically).
    pub async fn cleanup_expired(&self) -> Result<u64, AppError> {
        sqlx::query!(
            r#"
            DELETE FROM auth.email_verification_tokens
             WHERE expires_at < NOW() - INTERVAL '1 day'
                OR used_at < NOW() - INTERVAL '1 day'
            "#
        )
        .execute(&self.pool)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| DbError(e).into())
    }

    /// Atomically verify email using DB function.
    ///
    /// Validates token, checks user status, consumes token, marks email verified,
    /// activates pending accounts, and returns user data for session creation.
    ///
    /// # Errors
    /// - `AppError::NotFound` - Token invalid, expired, or already used
    /// - `AppError::PermissionDenied` - Account is suspended or deleted
    pub async fn verify_email(&self, token_hash: &[u8]) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT id AS "id!",
                   role AS "role!",
                   email,
                   email_verified AS "email_verified!",
                   phone,
                   phone_verified AS "phone_verified!",
                   status AS "status!: _",
                   password,
                   failed_login_attempts AS "failed_login_attempts!",
                   locked_until,
                   created_at AS "created_at!",
                   updated_at AS "updated_at!",
                   deleted_at,
                   display_name AS "display_name!",
                   avatar_url,
                   locale AS "locale!",
                   timezone AS "timezone!"
              FROM auth.verify_email($1)
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("TOKEN_INVALID") {
                AppError::token_invalid("verification token")
            } else if msg.contains("ACCOUNT_SUSPENDED") {
                AppError::PermissionDenied("Account is suspended or deleted".to_string())
            } else if msg.contains("USER_NOT_FOUND") {
                AppError::NotFound("User not found".to_string())
            } else {
                DbError(e).into()
            }
        })?
        .ok_or_else(|| AppError::token_invalid("verification token"))
    }
}
