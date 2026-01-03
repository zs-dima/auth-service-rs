//! Database layer with SQLx for auth services.
//!
//! Provides:
//! - Connection pool management
//! - Repository pattern for data access
//! - Type-safe models with automatic proto conversion

pub mod models;
pub mod repository;

pub use models::*;
pub use repository::*;
