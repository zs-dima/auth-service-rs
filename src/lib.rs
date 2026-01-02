#[path = "_core/mod.rs"]
pub mod core;
pub mod auth;
pub mod db;
pub mod middleware;
pub mod proto;
pub mod service;
pub mod util;

// Re-export commonly used types from core for convenience
pub use core::{config, error, extensions, telemetry, validation};
