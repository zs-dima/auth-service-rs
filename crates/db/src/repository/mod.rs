//! Database repository layer with connection pooling for the auth schema.
//!
//! # Error Handling
//!
//! All repository methods return `Result<T, AppError>` where errors are:
//! - `AppError::Unavailable` - Database connection or query failures
//! - `AppError::NotFound` - Requested entity does not exist
//! - `AppError::AlreadyExists` - Entity already exists (for creation methods)
//! - `AppError::InvalidArgument` - Invalid input parameters

#![expect(
    clippy::missing_errors_doc,
    reason = "error handling documented at module level"
)]

mod config;
mod email_verification;
mod oauth_state;
mod password_reset;
mod session;
mod user;

use sqlx::postgres::PgPool;

pub use config::{DbConfig, create_pool};
pub use email_verification::EmailVerificationRepository;
pub use oauth_state::OAuthStateRepository;
pub use password_reset::PasswordResetRepository;
pub use session::SessionRepository;
pub use user::UserRepository;

/// Combined database context.
#[derive(Debug, Clone)]
pub struct Database {
    pub users: UserRepository,
    pub sessions: SessionRepository,
    pub oauth_states: OAuthStateRepository,
    pub password_resets: PasswordResetRepository,
    pub email_verifications: EmailVerificationRepository,
    pool: PgPool,
}

impl Database {
    /// Creates a new database context with all repositories.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            users: UserRepository::new(pool.clone()),
            sessions: SessionRepository::new(pool.clone()),
            oauth_states: OAuthStateRepository::new(pool.clone()),
            password_resets: PasswordResetRepository::new(pool.clone()),
            email_verifications: EmailVerificationRepository::new(pool.clone()),
            pool,
        }
    }

    /// Check database health by executing a simple query.
    pub async fn health_check(&self) -> bool {
        sqlx::query_scalar!("SELECT 1 AS one")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    /// Returns a reference to the underlying connection pool.
    #[inline]
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}
