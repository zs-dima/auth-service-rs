//! Session repository for `auth.sessions` operations.

use ipnetwork::IpNetwork;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::{AppError, CreateSessionParams, DbError, SessionInfo, TouchSessionResult};

/// Session repository for `auth.sessions` operations.
#[derive(Debug, Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new session.
    pub async fn create_session(&self, params: CreateSessionParams<'_>) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO auth.sessions (
                id_user, refresh_token, expires_at,
                device_id, device_name, device_type, client_version,
                ip_created_by, ip_address, ip_country, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10)",
        )
        .bind(params.id_user)
        .bind(params.refresh_token_hash)
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
        .map_err(DbError)?;
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
        sqlx::query_as!(
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
        .map_err(DbError)?
        .filter(|r| r.id_user.is_some())
        .ok_or_else(|| AppError::token_invalid("session token"))
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
        .map_err(|e| DbError(e).into())
    }

    /// Revoke all sessions for a user.
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        sqlx::query!(
            r#"
            DELETE FROM auth.sessions
             WHERE id_user = $1
               AND expires_at > NOW()
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| DbError(e).into())
    }

    /// Revoke all sessions except current.
    pub async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        current_token_hash: &[u8],
    ) -> Result<u64, AppError> {
        sqlx::query!(
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
        .map(|r| r.rows_affected())
        .map_err(|e| DbError(e).into())
    }

    /// List all active sessions for a user.
    ///
    /// Uses `current_token_hash` to accurately identify the current session.
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
        .map_err(|e| DbError(e).into())
    }

    /// Revoke a session by `device_id` for a specific user.
    pub async fn revoke_session_by_device_id(
        &self,
        user_id: Uuid,
        device_id: &str,
    ) -> Result<bool, AppError> {
        sqlx::query(
            "DELETE FROM auth.sessions
              WHERE id_user = $1
                AND device_id = $2
                AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DbError(e).into())
    }

    /// Revoke all sessions except the one with the given `device_id`.
    pub async fn revoke_sessions_except_device(
        &self,
        user_id: Uuid,
        current_device_id: &str,
    ) -> Result<u64, AppError> {
        sqlx::query(
            "DELETE FROM auth.sessions
              WHERE id_user = $1
                AND (device_id IS NULL OR device_id <> $2)
                AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(current_device_id)
        .execute(&self.pool)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| DbError(e).into())
    }
}
