pub mod auth;
#[path = "_core/mod.rs"]
pub mod core;
pub mod db;
pub mod middlewares;
pub mod proto;
pub mod services;
pub mod tools;

// Re-export commonly used types from core for convenience
pub use core::{config, error, extensions, telemetry, validation};
