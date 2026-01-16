//! Email verification token repository for `auth.email_verification_tokens` operations.

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::{AppError, CreateEmailVerificationTokenParams, DbError};

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
    /// Invalidates any existing tokens for the user.
    pub async fn create_token(
        &self,
        params: CreateEmailVerificationTokenParams<'_>,
    ) -> Result<Uuid, AppError> {
        // Invalidate any existing unused tokens for this user
        sqlx::query!(
            r#"
            UPDATE auth.email_verification_tokens
               SET used_at = NOW()
             WHERE id_user = $1
               AND used_at IS NULL
               AND expires_at > NOW()
            "#,
            params.id_user
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;

        // Create new token
        sqlx::query_scalar!(
            r#"
            INSERT INTO auth.email_verification_tokens (id_user, token_hash, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            params.id_user,
            params.token_hash,
            params.expires_at
        )
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
}
