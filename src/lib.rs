//! Auth service library.
//!
//! Re-exports commonly used types for convenience.

pub mod config;
pub mod core;
pub mod middleware;
pub mod routes;
pub mod services;
pub mod startup;

// Re-export crates for downstream usage
pub use auth_core;
pub use auth_db;
pub use auth_proto;
pub use auth_storage;
