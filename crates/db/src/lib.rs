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

pub mod models;
pub mod repository;

pub use models::*;
pub use repository::*;
