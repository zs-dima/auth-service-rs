//! Configuration with validation at compile time and runtime.

use std::time::Duration;

use clap::Parser;
use secrecy::{ExposeSecret, SecretString};

/// Minimum required JWT secret length for security (256 bits).
const MIN_JWT_SECRET_LEN: usize = 32;

/// Authentication gRPC service configuration.
///
/// All values can be set via environment variables or CLI arguments.
#[derive(Debug, Clone, Parser)]
#[command(name = "auth-service", about = "Authentication gRPC service")]
pub struct Config {
    /// Server address (gRPC + REST on single port)
    #[arg(long, env = "GRPC_ADDRESS", default_value = "0.0.0.0:50051")]
    pub grpc_address: String,

    /// Enable gRPC-Web support
    #[arg(long, env = "GRPC_WEB", default_value = "true")]
    pub grpc_web: bool,

    /// CORS allowed origins (comma-separated, or "*" for any)
    #[arg(long, env = "CORS_ALLOW_ORIGINS")]
    pub cors_allow_origins: Option<String>,

    /// Enable gRPC reflection API
    #[arg(long, env = "GRPC_API_REFLECTION", default_value = "false")]
    pub grpc_reflection: bool,

    /// JWT secret key for signing tokens (min 32 chars)
    #[arg(long, env = "JWT_SECRET_KEY")]
    pub jwt_secret_key: SecretString,

    /// Access token TTL in minutes
    #[arg(long, env = "ACCESS_TOKEN_TTL_MINUTES", default_value = "15")]
    pub access_token_ttl_minutes: u64,

    /// Refresh token TTL in days
    #[arg(long, env = "REFRESH_TOKEN_TTL_DAYS", default_value = "7")]
    pub refresh_token_ttl_days: i64,

    /// Database connection URL
    #[arg(long, env = "DB_URL")]
    pub db_url: String,

    /// Database password (URL-encoded and inserted into DB_URL)
    #[arg(long, env = "DB_PASSWORD")]
    pub db_password: Option<String>,

    /// Database pool minimum connections
    #[arg(long, env = "DB_POOL_MIN", default_value = "2")]
    pub db_pool_min: u32,

    /// Database pool maximum connections
    #[arg(long, env = "DB_POOL_MAX", default_value = "10")]
    pub db_pool_max: u32,

    /// Database connection timeout in seconds
    #[arg(long, env = "DB_CONNECT_TIMEOUT", default_value = "30")]
    pub db_connect_timeout_secs: u64,

    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[arg(long, env = "LOG_LEVEL", default_value = "INFO")]
    pub log_level: String,

    /// Use JSON log format
    #[arg(long, env = "JSON_LOGS", default_value = "true")]
    pub json_logs: bool,

    /// OpenTelemetry OTLP endpoint
    #[arg(long, env = "OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Sentry DSN for error tracking
    #[arg(long, env = "SENTRY_DSN")]
    pub sentry_dsn: Option<String>,

    /// Environment name (e.g., "production", "development")
    #[arg(long, env = "ENVIRONMENT")]
    pub environment: Option<String>,

    /// Max concurrent requests
    #[arg(long, env = "CONCURRENCY_LIMIT", default_value = "100")]
    pub rate_limit_rps: u64,

    /// Max photo upload size in bytes (default: 2MB)
    #[arg(long, env = "MAX_PHOTO_BYTES", default_value = "2097152")]
    pub max_photo_bytes: usize,

    /// S3 endpoint URL (e.g., http://localhost:9000/bucket-name/)
    #[arg(long, env = "S3_URL")]
    pub s3_url: Option<String>,

    /// S3 access key ID
    #[arg(long, env = "S3_ACCESS_KEY_ID")]
    pub s3_access_key_id: Option<String>,

    /// S3 secret access key
    #[arg(long, env = "S3_SECRET_ACCESS_KEY")]
    pub s3_secret_access_key: Option<String>,
}

/// Configuration validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("JWT secret must be at least {MIN_JWT_SECRET_LEN} characters")]
    JwtSecretTooShort,
    #[error("Access token TTL must be > 0")]
    InvalidAccessTokenTtl,
    #[error("Refresh token TTL must be > 0")]
    InvalidRefreshTokenTtl,
    #[error("Database pool max ({max}) must be >= min ({min})")]
    InvalidPoolSize { min: u32, max: u32 },
    #[error("Concurrency limit must be > 0")]
    InvalidConcurrencyLimit,
}

impl Config {
    /// Parse and validate configuration.
    pub fn init() -> anyhow::Result<Self> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.jwt_secret_key.expose_secret().len() < MIN_JWT_SECRET_LEN {
            return Err(ConfigError::JwtSecretTooShort);
        }
        if self.access_token_ttl_minutes == 0 {
            return Err(ConfigError::InvalidAccessTokenTtl);
        }
        if self.refresh_token_ttl_days <= 0 {
            return Err(ConfigError::InvalidRefreshTokenTtl);
        }
        if self.db_pool_max < self.db_pool_min {
            return Err(ConfigError::InvalidPoolSize {
                min: self.db_pool_min,
                max: self.db_pool_max,
            });
        }
        if self.rate_limit_rps == 0 {
            return Err(ConfigError::InvalidConcurrencyLimit);
        }
        Ok(())
    }

    /// Get database connection timeout as Duration.
    #[inline]
    pub const fn db_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.db_connect_timeout_secs)
    }

    /// Build the database URL with password substitution.
    pub fn database_url(&self) -> String {
        match &self.db_password {
            Some(password) => {
                let encoded = urlencoding::encode(password);
                self.db_url.replacen(":@", &format!(":{encoded}@"), 1)
            }
            None => self.db_url.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            grpc_address: "0.0.0.0:50051".to_string(),
            grpc_web: true,
            cors_allow_origins: None,
            grpc_reflection: false,
            jwt_secret_key: SecretString::from("this_is_a_very_long_secret_key_32"),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 7,
            db_url: "postgres://user:@localhost/auth".to_string(),
            db_password: Some("secret".to_string()),
            db_pool_min: 2,
            db_pool_max: 10,
            db_connect_timeout_secs: 30,
            log_level: "INFO".to_string(),
            json_logs: false,
            otlp_endpoint: None,
            sentry_dsn: None,
            environment: None,
            rate_limit_rps: 100,
            max_photo_bytes: 2 * 1024 * 1024,
            s3_url: None,
            s3_access_key_id: None,
            s3_secret_access_key: None,
        }
    }

    #[test]
    fn valid_config_passes_validation() {
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn database_url_substitutes_password() {
        let config = test_config();
        assert!(config.database_url().contains(":secret@"));
    }

    #[test]
    fn jwt_secret_too_short_fails() {
        let mut config = test_config();
        config.jwt_secret_key = SecretString::from("short");
        assert!(matches!(
            config.validate(),
            Err(ConfigError::JwtSecretTooShort)
        ));
    }

    #[test]
    fn invalid_pool_size_fails() {
        let mut config = test_config();
        config.db_pool_min = 10;
        config.db_pool_max = 5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidPoolSize { .. })
        ));
    }
}
