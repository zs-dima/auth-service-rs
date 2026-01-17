//! OAuth state repository for `auth.oauth_states` operations.

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::{AppError, ConsumedOAuthState, CreateOAuthStateParams, DbError, OAuthProvider};

/// OAuth state repository for `auth.oauth_states` operations.
#[derive(Debug, Clone)]
pub struct OAuthStateRepository {
    pool: PgPool,
}

impl OAuthStateRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new OAuth state.
    pub async fn create_state(&self, params: CreateOAuthStateParams<'_>) -> Result<Uuid, AppError> {
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
        .map_err(|e| DbError(e).into())
    }

    /// Consume OAuth state (atomic get-and-delete).
    pub async fn consume_state(&self, state: &str) -> Result<ConsumedOAuthState, AppError> {
        sqlx::query_as!(
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
        .map_err(DbError)?
        .filter(|r| r.code_verifier.is_some())
        .ok_or_else(|| AppError::token_invalid("OAuth state"))
    }
}
