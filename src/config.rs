use std::time::Duration;

use clap::Parser;

/// Authentication gRPC service configuration
#[derive(Debug, Clone, Parser)]
#[command(name = "auth-service", about = "Authentication gRPC service")]
pub struct Config {
    /// gRPC server address
    #[arg(long, env = "GRPC_ADDRESS", default_value = "0.0.0.0:50051")]
    pub grpc_address: String,

    /// HTTP server address for file operations (optional)
    #[arg(long, env = "HTTP_ADDRESS")]
    pub http_address: Option<String>,

    /// Enable gRPC-Web support (allows browser clients without Envoy proxy)
    #[arg(long, env = "GRPC_WEB", default_value = "true")]
    pub grpc_web: bool,

    /// CORS allowed origins (comma-separated, or "*" for any)
    #[arg(long, env = "CORS_ALLOW_ORIGINS")]
    pub cors_allow_origins: Option<String>,

    /// Enable gRPC reflection API
    #[arg(long, env = "GRPC_API_REFLECTION", default_value = "false")]
    pub grpc_reflection: bool,

    /// JWT secret key for signing tokens
    #[arg(long, env = "JWT_SECRET_KEY")]
    pub jwt_secret_key: String,

    /// Access token TTL in minutes (default: 15 minutes)
    #[arg(long, env = "ACCESS_TOKEN_TTL_MINUTES", default_value = "15")]
    pub access_token_ttl_minutes: u64,

    /// Refresh token TTL in days (default: 7 days)
    #[arg(long, env = "REFRESH_TOKEN_TTL_DAYS", default_value = "7")]
    pub refresh_token_ttl_days: i64,

    /// Database connection URL
    #[arg(long, env = "DB_URL")]
    pub db_url: String,

    /// Database password (will be URL-encoded and inserted into DB_URL)
    #[arg(long, env = "DB_PASSWORD")]
    pub db_password: Option<String>,

    /// Database connection pool minimum size
    #[arg(long, env = "DB_POOL_MIN", default_value = "2")]
    pub db_pool_min: u32,

    /// Database connection pool maximum size
    #[arg(long, env = "DB_POOL_MAX", default_value = "10")]
    pub db_pool_max: u32,

    /// Database connection timeout in seconds
    #[arg(long, env = "DB_CONNECT_TIMEOUT", default_value = "30")]
    pub db_connect_timeout_secs: u64,

    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[arg(long, env = "LOG_LEVEL", default_value = "INFO")]
    pub log_level: String,

    /// Use JSON log format (vs human-readable)
    #[arg(long, env = "JSON_LOGS", default_value = "true")]
    pub json_logs: bool,

    /// OpenTelemetry OTLP endpoint (e.g., http://localhost:4317)
    #[arg(long, env = "OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Concurrency limit: max concurrent requests
    #[arg(long, env = "CONCURRENCY_LIMIT", default_value = "100")]
    pub rate_limit_rps: u64,
}

/// Configuration validation errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("JWT secret key must be at least 32 characters")]
    JwtSecretTooShort,

    #[error("Access token TTL must be greater than 0")]
    InvalidAccessTokenTtl,

    #[error("Refresh token TTL must be greater than 0")]
    InvalidRefreshTokenTtl,

    #[error("Database pool max must be >= min")]
    InvalidPoolSize,

    #[error("Concurrency limit must be greater than 0")]
    InvalidConcurrencyLimit,
}

impl Config {
    /// Parse configuration from command line args and environment variables
    pub fn init() -> anyhow::Result<Self> {
        let config = Config::parse();
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jwt_secret_key.len() < 32 {
            return Err(ConfigError::JwtSecretTooShort);
        }
        if self.access_token_ttl_minutes == 0 {
            return Err(ConfigError::InvalidAccessTokenTtl);
        }
        if self.refresh_token_ttl_days <= 0 {
            return Err(ConfigError::InvalidRefreshTokenTtl);
        }
        if self.db_pool_max < self.db_pool_min {
            return Err(ConfigError::InvalidPoolSize);
        }
        if self.rate_limit_rps == 0 {
            return Err(ConfigError::InvalidConcurrencyLimit);
        }
        Ok(())
    }

    /// Get access token TTL as Duration
    pub fn access_token_ttl(&self) -> Duration {
        Duration::from_secs(self.access_token_ttl_minutes * 60)
    }

    /// Get database connect timeout as Duration
    pub fn db_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.db_connect_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            grpc_address: "0.0.0.0:50051".to_string(),
            http_address: None,
            grpc_web: true,
            cors_allow_origins: None,
            grpc_reflection: false,
            jwt_secret_key: "this_is_a_very_long_secret_key_32".to_string(),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 7,
            db_url: "postgres://localhost/auth".to_string(),
            db_password: None,
            db_pool_min: 2,
            db_pool_max: 10,
            db_connect_timeout_secs: 30,
            log_level: "INFO".to_string(),
            json_logs: false,
            otlp_endpoint: None,
            rate_limit_rps: 100,
        }
    }

    #[test]
    fn test_valid_config() {
        let config = valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_access_token_ttl() {
        let config = valid_config();
        assert_eq!(config.access_token_ttl(), Duration::from_secs(15 * 60));
    }

    #[test]
    fn test_jwt_secret_too_short() {
        let mut config = valid_config();
        config.jwt_secret_key = "short".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::JwtSecretTooShort)
        ));
    }

    #[test]
    fn test_invalid_access_token_ttl() {
        let mut config = valid_config();
        config.access_token_ttl_minutes = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAccessTokenTtl)
        ));
    }

    #[test]
    fn test_invalid_pool_size() {
        let mut config = valid_config();
        config.db_pool_min = 10;
        config.db_pool_max = 5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidPoolSize)
        ));
    }
}
