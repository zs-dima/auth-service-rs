//! Database configuration and pool creation.

use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::AppError;

/// Database configuration.
#[derive(Debug, Clone)]
#[must_use]
pub struct DbConfig {
    pub url: String,
    pub pool_min: u32,
    pub pool_max: u32,
    pub connect_timeout: Duration,
}

impl DbConfig {
    /// Default minimum pool connections.
    pub const DEFAULT_POOL_MIN: u32 = 1;
    /// Default maximum pool connections.
    pub const DEFAULT_POOL_MAX: u32 = 10;
    /// Default connection timeout.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Creates a new database configuration.
    pub const fn new(url: String, pool_min: u32, pool_max: u32, connect_timeout: Duration) -> Self {
        Self {
            url,
            pool_min,
            pool_max,
            connect_timeout,
        }
    }

    /// Creates a configuration from a URL with default pool settings.
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            pool_min: Self::DEFAULT_POOL_MIN,
            pool_max: Self::DEFAULT_POOL_MAX,
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// Create database connection pool.
pub async fn create_pool(config: &DbConfig) -> Result<PgPool, AppError> {
    PgPoolOptions::new()
        .min_connections(config.pool_min)
        .max_connections(config.pool_max)
        .acquire_timeout(config.connect_timeout)
        .connect(&config.url)
        .await
        .map_err(|e| AppError::Unavailable(format!("Database connection failed: {e}")))
}
