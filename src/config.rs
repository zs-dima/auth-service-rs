//! Configuration with validation at compile time and runtime.
//!
//! Secrets can be provided via environment variables or files (for Docker/K8s secrets).
//! File-based secrets take precedence: `DB_PASSWORD_FILE` overrides `DB_PASSWORD`.

use std::fs;
use std::time::Duration;

use auth_core::JwtValidator;
use clap::Parser;
use secrecy::{ExposeSecret, SecretString};
use tracing::debug;

/// Minimum required JWT secret length for security (256 bits).
const MIN_JWT_SECRET_LEN: usize = 32;

/// Read a secret from a file, trimming whitespace.
fn read_secret_file(path: &str) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(e) => {
            debug!(path, error = %e, "Failed to read secret file");
            None
        }
    }
}

/// Resolve a secret: file path takes precedence over direct value.
fn resolve_secret(file_path: Option<&str>, direct_value: Option<&str>) -> Option<String> {
    file_path
        .and_then(read_secret_file)
        .or_else(|| direct_value.map(String::from))
}

/// Authentication gRPC service configuration.
///
/// All values can be set via environment variables or CLI arguments.
/// Secrets support `*_FILE` variants for Docker/Kubernetes secrets.
#[derive(Debug, Clone, Parser)]
#[command(name = "auth-service", about = "Authentication gRPC service")]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Cloud Run `PORT` (takes precedence over `GRPC_ADDRESS`).
    #[arg(long, env = "PORT")]
    pub port: Option<u16>,

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

    // =========================================================================
    // Secrets (support both direct value and _FILE variants)
    // =========================================================================
    /// JWT secret key for signing tokens (min 32 chars)
    #[arg(long, env = "JWT_SECRET_KEY")]
    jwt_secret_key: Option<SecretString>,

    /// Path to file containing JWT secret key
    #[arg(long, env = "JWT_SECRET_KEY_FILE")]
    jwt_secret_key_file: Option<String>,

    /// Database password (inserted into `DB_URL`)
    #[arg(long, env = "DB_PASSWORD")]
    db_password: Option<String>,

    /// Path to file containing database password
    #[arg(long, env = "DB_PASSWORD_FILE")]
    db_password_file: Option<String>,

    /// S3 secret access key
    #[arg(long, env = "S3_SECRET_ACCESS_KEY")]
    s3_secret_access_key: Option<String>,

    /// Path to file containing S3 secret access key
    #[arg(long, env = "S3_SECRET_ACCESS_KEY_FILE")]
    s3_secret_access_key_file: Option<String>,

    /// SMTP password (separate from `SMTP_URL` for security)
    #[arg(long, env = "SMTP_PASSWORD")]
    smtp_password: Option<String>,

    /// Path to file containing SMTP password
    #[arg(long, env = "SMTP_PASSWORD_FILE")]
    smtp_password_file: Option<String>,

    // =========================================================================
    // Token TTLs
    // =========================================================================
    /// Access token TTL in minutes
    #[arg(long, env = "ACCESS_TOKEN_TTL_MINUTES", default_value = "60")]
    pub access_token_ttl_minutes: u64,

    /// Refresh token TTL in days
    #[arg(long, env = "REFRESH_TOKEN_TTL_DAYS", default_value = "90")]
    pub refresh_token_ttl_days: i64,

    /// Password reset token expiration in minutes (default: 60)
    #[arg(long, env = "PASSWORD_RESET_TTL_MINUTES", default_value = "60")]
    pub password_reset_ttl_minutes: u32,

    /// Email verification token expiration in hours (default: 24)
    #[arg(long, env = "EMAIL_VERIFICATION_TTL_HOURS", default_value = "24")]
    pub email_verification_ttl_hours: u32,

    /// Maximum failed login attempts before account lockout (default: 5)
    #[arg(long, env = "MAX_FAILED_LOGIN_ATTEMPTS", default_value = "5")]
    pub max_failed_login_attempts: u16,

    /// Account lockout duration in minutes (default: 15)
    #[arg(long, env = "LOCKOUT_DURATION_MINUTES", default_value = "15")]
    pub lockout_duration_minutes: u32,

    // =========================================================================
    // Database Configuration
    // =========================================================================
    /// Database connection URL (password placeholder: user:@host)
    #[arg(long, env = "DB_URL")]
    pub db_url: String,

    /// Database pool minimum connections
    #[arg(long, env = "DB_POOL_MIN", default_value = "2")]
    pub db_pool_min: u32,

    /// Database pool maximum connections
    #[arg(long, env = "DB_POOL_MAX", default_value = "10")]
    pub db_pool_max: u32,

    /// Database connection timeout in seconds
    #[arg(long, env = "DB_CONNECT_TIMEOUT", default_value = "30")]
    pub db_connect_timeout_secs: u64,

    // =========================================================================
    // Logging & Observability
    // =========================================================================
    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[arg(long, env = "LOG_LEVEL", default_value = "INFO")]
    pub log_level: String,

    /// Use JSON log format
    #[arg(long, env = "JSON_LOGS", default_value = "true")]
    pub json_logs: bool,

    /// Enable Prometheus metrics endpoint (/metrics)
    #[arg(long, env = "METRICS_ENABLED", default_value = "false")]
    pub metrics_enabled: bool,

    /// OpenTelemetry OTLP endpoint
    #[arg(long, env = "OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Sentry DSN for error tracking
    #[arg(long, env = "SENTRY_DSN")]
    pub sentry_dsn: Option<String>,

    /// Environment name (e.g., "production", "development")
    #[arg(long, env = "ENVIRONMENT")]
    pub environment: Option<String>,

    // =========================================================================
    // Rate Limiting & Limits
    // =========================================================================
    /// Max concurrent requests
    #[arg(long, env = "CONCURRENCY_LIMIT", default_value = "100")]
    pub rate_limit_rps: u64,

    /// Max photo upload size in bytes (default: 2MB)
    #[arg(long, env = "MAX_PHOTO_BYTES", default_value = "2097152")]
    pub max_photo_bytes: usize,

    // =========================================================================
    // S3 Storage Configuration
    // =========================================================================
    /// S3 endpoint URL (e.g., `http://localhost:9000/bucket-name/`)
    #[arg(long, env = "S3_URL")]
    pub s3_url: Option<String>,

    /// S3 access key ID
    #[arg(long, env = "S3_ACCESS_KEY_ID")]
    pub s3_access_key_id: Option<String>,

    // =========================================================================
    // GeoIP Configuration
    // =========================================================================
    /// `GeoIP` database path (`MaxMind` `GeoLite2-Country.mmdb`)
    #[arg(long, env = "GEOIP_DB_PATH")]
    pub geoip_db_path: Option<String>,

    // =========================================================================
    // Email Configuration
    // =========================================================================
    /// Email provider: "smtp" (default) or "mailjet"
    #[arg(long, env = "EMAIL_PROVIDER", default_value = "smtp")]
    pub email_provider: String,

    /// Application domain (used for email links and sender address)
    #[arg(long, env = "DOMAIN")]
    pub domain: Option<String>,

    /// Email sender: "Name <email@example.com>"
    #[arg(long, env = "EMAIL_SENDER")]
    pub email_sender: Option<String>,

    /// SMTP URL (without password): `smtp://user@host:port?tls=starttls`
    /// Password is provided separately via `SMTP_PASSWORD` or `SMTP_PASSWORD_FILE`
    #[arg(long, env = "SMTP_URL")]
    pub smtp_url: Option<String>,

    /// Mailjet API key (public key) - alternative to SMTP
    #[arg(long, env = "MAILJET_API_KEY")]
    pub mailjet_api_key: Option<String>,

    /// Mailjet API secret (private key)
    #[arg(long, env = "MAILJET_API_SECRET")]
    mailjet_api_secret: Option<String>,

    /// Path to file containing Mailjet API secret
    #[arg(long, env = "MAILJET_API_SECRET_FILE")]
    mailjet_api_secret_file: Option<String>,

    /// Mailjet template ID for password reset emails
    #[arg(long, env = "MAILJET_PASSWORD_RECOVERY_START_TEMPLATE_ID")]
    pub mailjet_password_recovery_start_template_id: Option<u64>,

    /// Mailjet template ID for welcome emails (optional)
    #[arg(long, env = "MAILJET_WELCOME_TEMPLATE_ID")]
    pub mailjet_welcome_template_id: Option<u64>,

    /// Mailjet template ID for email verification emails (optional)
    #[arg(long, env = "MAILJET_EMAIL_VERIFICATION_TEMPLATE_ID")]
    pub mailjet_email_verification_template_id: Option<u64>,

    /// Mailjet template ID for password changed confirmation (optional)
    #[arg(long, env = "MAILJET_PASSWORD_CHANGED_TEMPLATE_ID")]
    pub mailjet_password_changed_template_id: Option<u64>,
}

/// Configuration validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("JWT secret must be at least {MIN_JWT_SECRET_LEN} characters")]
    JwtSecretTooShort,
    #[error("JWT secret is required (set JWT_SECRET_KEY or JWT_SECRET_KEY_FILE)")]
    JwtSecretMissing,
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
    ///
    /// # Errors
    ///
    /// Returns error if configuration validation fails.
    pub fn init() -> anyhow::Result<Self> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<(), ConfigError> {
        let jwt_secret = self.jwt_secret_key();
        if jwt_secret.is_none() {
            return Err(ConfigError::JwtSecretMissing);
        }
        if jwt_secret.map_or(0, |s| s.expose_secret().len()) < MIN_JWT_SECRET_LEN {
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

    // =========================================================================
    // Secret Accessors (file takes precedence over direct value)
    // =========================================================================

    /// Get JWT secret key (from file or env var).
    #[must_use]
    pub fn jwt_secret_key(&self) -> Option<SecretString> {
        self.jwt_secret_key_file
            .as_deref()
            .and_then(read_secret_file)
            .map(SecretString::from)
            .or_else(|| self.jwt_secret_key.clone())
    }

    /// Get database password (from file or env var).
    #[must_use]
    pub fn db_password(&self) -> Option<String> {
        resolve_secret(
            self.db_password_file.as_deref(),
            self.db_password.as_deref(),
        )
    }

    /// Get S3 secret access key (from file or env var).
    #[must_use]
    pub fn s3_secret_access_key(&self) -> Option<String> {
        resolve_secret(
            self.s3_secret_access_key_file.as_deref(),
            self.s3_secret_access_key.as_deref(),
        )
    }

    /// Get SMTP password (from file or env var).
    #[must_use]
    pub fn smtp_password(&self) -> Option<String> {
        resolve_secret(
            self.smtp_password_file.as_deref(),
            self.smtp_password.as_deref(),
        )
    }

    /// Get Mailjet API secret (from file or env var).
    #[must_use]
    pub fn mailjet_api_secret(&self) -> Option<String> {
        resolve_secret(
            self.mailjet_api_secret_file.as_deref(),
            self.mailjet_api_secret.as_deref(),
        )
    }

    // =========================================================================
    // Derived Configuration
    // =========================================================================

    /// Get database connection timeout as Duration.
    #[inline]
    #[must_use]
    pub const fn db_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.db_connect_timeout_secs)
    }

    /// Get effective server address.
    ///
    /// Cloud Run's `PORT` env var takes precedence over `GRPC_ADDRESS`.
    #[must_use]
    pub fn server_address(&self) -> String {
        match self.port {
            Some(port) => format!("0.0.0.0:{port}"),
            None => self.grpc_address.clone(),
        }
    }

    /// Build the database URL with password substitution.
    #[must_use]
    pub fn database_url(&self) -> String {
        match self.db_password() {
            Some(password) => {
                let encoded = urlencoding::encode(&password);
                self.db_url.replacen(":@", &format!(":{encoded}@"), 1)
            }
            None => self.db_url.clone(),
        }
    }

    /// Build SMTP URL with password inserted.
    /// Takes smtp://user@host:port and inserts password as smtp://user:pass@host:port
    #[must_use]
    pub fn smtp_url_with_password(&self) -> Option<String> {
        let url = self.smtp_url.as_ref()?;
        match self.smtp_password() {
            Some(password) => {
                let encoded = urlencoding::encode(&password);
                // Insert password after username: user@ -> user:pass@
                Some(url.replacen('@', &format!(":{encoded}@"), 1))
            }
            None => Some(url.clone()),
        }
    }

    /// Check if email sending is configured (SMTP or Mailjet).
    #[allow(dead_code)]
    #[must_use]
    pub fn email_enabled(&self) -> bool {
        self.domain.is_some() && (self.smtp_enabled() || self.mailjet_enabled())
    }

    /// Check if SMTP is configured.
    #[must_use]
    pub fn smtp_enabled(&self) -> bool {
        self.smtp_url.is_some() && self.email_sender.is_some()
    }

    /// Check if Mailjet is configured.
    #[must_use]
    pub fn mailjet_enabled(&self) -> bool {
        self.mailjet_api_key.is_some()
            && self.mailjet_api_secret().is_some()
            && self.email_sender.is_some()
            && self.mailjet_password_recovery_start_template_id.is_some()
    }

    /// Parse email sender into (name, email) tuple.
    /// Format: "Name <email@example.com>" or just "email@example.com"
    #[must_use]
    pub fn parse_email_sender(&self) -> Option<(String, String)> {
        let sender = self.email_sender.as_ref()?;
        // Parse "Name <email>" format
        if let Some(start) = sender.find('<')
            && let Some(end) = sender.find('>')
        {
            let name = sender[..start].trim().to_string();
            let email = sender[start + 1..end].trim().to_string();
            return Some((name, email));
        }
        // Just email address
        Some((String::new(), sender.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            port: None,
            grpc_address: "0.0.0.0:50051".to_string(),
            grpc_web: true,
            cors_allow_origins: None,
            grpc_reflection: false,
            jwt_secret_key: Some(SecretString::from("this_is_a_very_long_secret_key_32")),
            jwt_secret_key_file: None,
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 7,
            password_reset_ttl_minutes: 30,
            email_verification_ttl_hours: 24,
            db_url: "postgres://user:@localhost/auth".to_string(),
            db_password: Some("secret".to_string()),
            db_password_file: None,
            db_pool_min: 2,
            db_pool_max: 10,
            db_connect_timeout_secs: 30,
            log_level: "INFO".to_string(),
            json_logs: false,
            otlp_endpoint: None,
            metrics_enabled: false,
            sentry_dsn: None,
            environment: None,
            rate_limit_rps: 100,
            max_photo_bytes: 2 * 1024 * 1024,
            s3_url: None,
            s3_access_key_id: None,
            s3_secret_access_key: None,
            s3_secret_access_key_file: None,
            geoip_db_path: None,
            email_provider: "mailjet".to_string(),
            domain: Some("example.com".to_string()),
            email_sender: Some("Test App <test@example.com>".to_string()),
            smtp_url: None,
            smtp_password: None,
            smtp_password_file: None,
            mailjet_api_key: None,
            mailjet_api_secret: None,
            mailjet_api_secret_file: None,
            mailjet_welcome_template_id: None,
            mailjet_email_verification_template_id: None,
            mailjet_password_recovery_start_template_id: None,
            mailjet_password_changed_template_id: None,
            max_failed_login_attempts: 5,
            lockout_duration_minutes: 15,
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
    fn jwt_secret_missing_fails() {
        let mut config = test_config();
        config.jwt_secret_key = None;
        config.jwt_secret_key_file = None;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::JwtSecretMissing)
        ));
    }

    #[test]
    fn jwt_secret_too_short_fails() {
        let mut config = test_config();
        config.jwt_secret_key = Some(SecretString::from("short"));
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

    #[test]
    fn email_enabled_when_all_configured() {
        let mut config = test_config();
        config.smtp_url = Some("smtp://user@localhost:25".to_string());
        config.email_sender = Some("Test <test@example.com>".to_string());
        config.domain = Some("example.com".to_string());
        assert!(config.email_enabled());
    }

    #[test]
    fn email_disabled_when_missing_config() {
        let config = test_config();
        assert!(!config.email_enabled());
    }

    #[test]
    fn server_address_uses_port_when_set() {
        let mut config = test_config();
        config.port = Some(8080);
        assert_eq!(config.server_address(), "0.0.0.0:8080");
    }

    #[test]
    fn server_address_uses_grpc_address_when_port_not_set() {
        let config = test_config();
        assert_eq!(config.server_address(), "0.0.0.0:50051");
    }

    #[test]
    fn smtp_url_with_password_inserts_password() {
        let mut config = test_config();
        config.smtp_url = Some("smtp://user@smtp.example.com:587".to_string());
        config.smtp_password = Some("mypass".to_string());

        let url = config.smtp_url_with_password().unwrap();
        assert!(url.contains("user:mypass@"));
    }

    #[test]
    fn smtp_url_without_password_returns_original() {
        let mut config = test_config();
        config.smtp_url = Some("smtp://localhost:25".to_string());
        config.smtp_password = None;

        let url = config.smtp_url_with_password().unwrap();
        assert_eq!(url, "smtp://localhost:25");
    }
}

// =============================================================================
// Auth Service Configuration
// =============================================================================

/// Runtime configuration for the auth service.
///
/// Groups JWT validation and token TTLs. Database, email, and URLs are in `ServiceContext`.
#[derive(Clone)]
pub struct AuthServiceConfig {
    /// JWT validator for token operations.
    pub jwt_validator: JwtValidator,
    /// Access token time-to-live in minutes.
    pub access_token_ttl_minutes: u64,
    /// Refresh token time-to-live in days.
    pub refresh_token_ttl_days: i64,
    /// Password reset token TTL in minutes.
    pub password_reset_ttl_minutes: u32,
    /// Email verification token TTL in hours.
    pub email_verification_ttl_hours: u32,
    /// Maximum failed login attempts before account lockout.
    pub max_failed_login_attempts: u16,
    /// Account lockout duration in minutes.
    pub lockout_duration_minutes: u32,
}

// =============================================================================
// User Service Configuration
// =============================================================================

/// Runtime configuration for the user service.
#[derive(Clone)]
pub struct UserServiceConfig {
    /// Email verification token TTL in hours.
    pub email_verification_ttl_hours: u32,
}
