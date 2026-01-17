//! Database layer with SQLx for auth services.
//!
//! Provides:
//! - Connection pool management via [`create_pool`]
//! - Repository pattern for data access via [`Database`]
//! - Type-safe models with automatic proto conversion
//!
//! # Example
//!
//! ```ignore
//! use auth_db::{create_pool, Database, DbConfig};
//! use std::time::Duration;
//!
//! let config = DbConfig::new(
//!     "postgres://localhost/auth".into(),
//!     1,
//!     10,
//!     Duration::from_secs(5),
//! );
//! let pool = create_pool(&config).await?;
//! let db = Database::new(pool);
//!
//! // Use repositories
//! let user = db.users.get_user_by_id(user_id).await?;
//! ```

#![expect(clippy::doc_markdown, reason = "SQLx capitalization is intentional")]

mod models;
mod repository;

use auth_core::AppError;

// =============================================================================
// Internal helpers
// =============================================================================

/// Database error wrapper for ergonomic error conversion.
///
/// Wraps `sqlx::Error` to enable automatic conversion to `AppError`
/// via the `?` operator throughout repository methods.
#[derive(Debug)]
struct DbError(sqlx::Error);

impl From<sqlx::Error> for DbError {
    #[inline]
    fn from(e: sqlx::Error) -> Self {
        Self(e)
    }
}

impl From<DbError> for AppError {
    #[inline]
    fn from(e: DbError) -> Self {
        Self::Unavailable(e.0.to_string())
    }
}

// =============================================================================
// Public exports - Enums
// =============================================================================

pub use models::{OAuthProvider, UserStatus};

// =============================================================================
// Public exports - Role helpers
// =============================================================================

pub use models::{proto_to_role, proto_to_role_or_status, role_to_proto, roles, status_to_proto};

// =============================================================================
// Public exports - Database models (own their data)
// =============================================================================

pub use models::{
    ConsumedOAuthState, EmailVerificationToken, OAuthState, PasswordResetToken, Provider, Role,
    Session, SessionInfo, TouchSessionResult, User, UserInfo, UserProfile, UserWithProfile,
};

// =============================================================================
// Public exports - Parameter types (borrow from caller)
// =============================================================================

pub use models::{
    CreateEmailVerificationTokenParams, CreateOAuthStateParams, CreatePasswordResetTokenParams,
    CreateSessionParams, CreateUserWithProfileParams, LinkOAuthProviderParams, UpdateUserParams,
    UpdateUserProfileParams,
};

// =============================================================================
// Public exports - Repository and config
// =============================================================================

pub use repository::{
    Database, DbConfig, EmailVerificationRepository, OAuthStateRepository, PasswordResetRepository,
    SessionRepository, UserRepository, create_pool,
};
