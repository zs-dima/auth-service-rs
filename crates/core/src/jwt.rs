//! JWT token generation, validation, and claims.
//!
//! Centralizes all JWT handling with a shared validator for encoding and decoding.
//! Uses a pre-compiled validator with cached keys for optimal performance.
//!
//! This module is database-agnostic: implement `JwtSubject` for your user type.

use std::sync::Arc;

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tonic::Status;
use tracing::warn;
use uuid::Uuid;

use crate::AppError;

/// JWT issuer identifier.
const ISSUER: &str = "auth-service";
/// JWT audience identifier.
const AUDIENCE: &str = "auth-service";
/// Length of refresh token in bytes (256 bits of entropy).
const REFRESH_TOKEN_BYTES: usize = 32;

/// Trait for types that can be used as JWT subjects.
///
/// Implement this trait for your user model to enable JWT generation
/// without coupling the JWT module to specific database models.
pub trait JwtSubject {
    /// User's unique identifier.
    fn user_id(&self) -> Uuid;
    /// User's email address.
    fn email(&self) -> &str;
    /// User's display name.
    fn name(&self) -> &str;
    /// User's role as a string (e.g., "administrator", "user").
    fn role(&self) -> &str;
}

/// User role abstraction for authorization checks.
///
/// This is the runtime representation used in `AuthInfo`.
/// Database crates should implement conversion from their role enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    Administrator,
    User,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Administrator => "administrator",
            Self::User => "user",
        })
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "administrator" => Ok(Self::Administrator),
            "user" => Ok(Self::User),
            _ => Err(format!("Unknown role: {s}")),
        }
    }
}

/// Validated authentication info from JWT.
///
/// Single source of truth for auth context across middleware and services.
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub user_id: Uuid,
    pub email: String,
    #[allow(dead_code)] // Used by consumers for display
    pub name: String,
    pub role: UserRole,
    pub device_id: Uuid,
    pub installation_id: Uuid,
}

impl AuthInfo {
    /// Check if user has admin role.
    #[inline]
    #[must_use]
    pub const fn is_admin(&self) -> bool {
        matches!(self.role, UserRole::Administrator)
    }

    /// Check if user can access the target user's resource.
    #[inline]
    #[must_use]
    pub fn can_access(&self, target_user_id: Uuid) -> bool {
        self.user_id == target_user_id || self.is_admin()
    }

    /// Require access to target user, returning Status error if denied.
    pub fn require_access(&self, target: Uuid, action: &str) -> Result<(), Status> {
        if self.can_access(target) {
            Ok(())
        } else {
            warn!(user_id = %self.user_id, target = %target, action, "Permission denied");
            Err(Status::permission_denied(format!(
                "Cannot {action} for other users"
            )))
        }
    }
}

/// JWT claims structure following RFC 7519.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Issuer
    pub iss: String,
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Not before time (Unix timestamp) - token is not valid before this time
    pub nbf: i64,

    // Custom claims
    /// User role
    pub role: String,
    /// User email
    pub email: String,
    /// User name
    pub name: String,
    /// Device ID
    pub device_id: String,
    /// Installation ID
    pub installation_id: String,
}

/// JWT validation errors.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("missing authorization header")]
    MissingHeader,
    #[error("invalid authorization format")]
    InvalidFormat,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("invalid claim: {0}")]
    InvalidClaim(&'static str),
}

impl TryFrom<Claims> for AuthInfo {
    type Error = JwtError;

    fn try_from(claims: Claims) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: Uuid::parse_str(&claims.sub).map_err(|_| JwtError::InvalidClaim("sub"))?,
            device_id: Uuid::parse_str(&claims.device_id)
                .map_err(|_| JwtError::InvalidClaim("device_id"))?,
            installation_id: Uuid::parse_str(&claims.installation_id)
                .map_err(|_| JwtError::InvalidClaim("installation_id"))?,
            role: claims
                .role
                .parse()
                .map_err(|_| JwtError::InvalidClaim("role"))?,
            email: claims.email,
            name: claims.name,
        })
    }
}

/// Pre-compiled JWT validator with cached encoding/decoding keys.
///
/// Thread-safe and cloneable via `Arc`. Creating keys is expensive,
/// so this caches them for the lifetime of the application.
#[derive(Clone)]
pub struct JwtValidator {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    validation: Validation,
}

impl JwtValidator {
    /// Create a new validator from a secret.
    #[must_use]
    pub fn new(secret: &SecretString) -> Self {
        let secret_bytes = secret.expose_secret().as_bytes();

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        Self {
            encoding_key: Arc::new(EncodingKey::from_secret(secret_bytes)),
            decoding_key: Arc::new(DecodingKey::from_secret(secret_bytes)),
            validation,
        }
    }

    /// Generate an access token for any type implementing `JwtSubject`.
    pub fn generate_access_token<T: JwtSubject>(
        &self,
        subject: &T,
        device_id: &Uuid,
        installation_id: &Uuid,
        ttl_minutes: u64,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(ttl_minutes as i64);

        let claims = Claims {
            // Standard claims
            sub: subject.user_id().to_string(),
            aud: AUDIENCE.to_string(),
            iss: ISSUER.to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(), // Token valid immediately

            // Custom claims
            role: subject.role().to_string(),
            email: subject.email().to_string(),
            name: subject.name().to_string(),
            device_id: device_id.to_string(),
            installation_id: installation_id.to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("JWT encoding failed: {e}")))
    }

    /// Validate a JWT and extract auth info.
    pub fn validate(&self, token: &str) -> Result<AuthInfo, JwtError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| JwtError::InvalidToken)?;

        token_data.claims.try_into()
    }
}

/// Refresh token generator.
pub struct TokenGenerator;

impl TokenGenerator {
    /// Generate a refresh token (random URL-safe base64 string).
    ///
    /// # Arguments
    /// * `ttl_days` - Token time-to-live in days
    ///
    /// # Returns
    /// Tuple of (token, expiration_time)
    pub fn generate_refresh_token(
        ttl_days: i64,
    ) -> Result<(String, chrono::DateTime<Utc>), AppError> {
        let expires_at = Utc::now() + Duration::days(ttl_days);

        let mut bytes = [0u8; REFRESH_TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);

        let token =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);

        Ok((token, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test implementation of JwtSubject for unit tests.
    struct TestUser {
        id: Uuid,
        email: String,
        name: String,
        role: String,
    }

    impl JwtSubject for TestUser {
        fn user_id(&self) -> Uuid {
            self.id
        }
        fn email(&self) -> &str {
            &self.email
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn role(&self) -> &str {
            &self.role
        }
    }

    fn test_user() -> TestUser {
        TestUser {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            role: "user".to_string(),
        }
    }

    fn test_secret() -> SecretString {
        SecretString::from("test_secret_key_minimum_32_chars!")
    }

    #[test]
    fn generate_and_validate_access_token() {
        let user = test_user();
        let device_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let validator = JwtValidator::new(&test_secret());

        let token = validator
            .generate_access_token(&user, &device_id, &installation_id, 15)
            .unwrap();

        let auth_info = validator.validate(&token).unwrap();

        assert_eq!(auth_info.email, user.email);
        assert_eq!(auth_info.name, user.name);
        assert_eq!(auth_info.user_id, user.id);
    }

    #[test]
    fn generate_refresh_token() {
        let (token, expires_at) = TokenGenerator::generate_refresh_token(7).unwrap();

        assert!(!token.is_empty());
        assert!(expires_at > Utc::now());
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
    }

    #[test]
    fn claims_roundtrip() {
        let user = test_user();
        let device_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let validator = JwtValidator::new(&test_secret());

        let token = validator
            .generate_access_token(&user, &device_id, &installation_id, 15)
            .unwrap();

        let auth_info = validator.validate(&token).unwrap();

        assert_eq!(auth_info.user_id, user.id);
        assert_eq!(auth_info.device_id, device_id);
        assert_eq!(auth_info.installation_id, installation_id);
    }

    #[test]
    fn invalid_token_rejected() {
        let validator = JwtValidator::new(&test_secret());
        assert!(validator.validate("invalid.token.here").is_err());
    }

    #[test]
    fn auth_info_access_control() {
        let admin = AuthInfo {
            user_id: Uuid::new_v4(),
            email: "admin@test.com".to_string(),
            name: "Admin".to_string(),
            role: UserRole::Administrator,
            device_id: Uuid::new_v4(),
            installation_id: Uuid::new_v4(),
        };

        let user = AuthInfo {
            user_id: Uuid::new_v4(),
            email: "user@test.com".to_string(),
            name: "User".to_string(),
            role: UserRole::User,
            device_id: Uuid::new_v4(),
            installation_id: Uuid::new_v4(),
        };

        let other_id = Uuid::new_v4();

        assert!(admin.is_admin());
        assert!(!user.is_admin());
        assert!(admin.can_access(other_id));
        assert!(!user.can_access(other_id));
        assert!(user.can_access(user.user_id));
    }

    #[test]
    fn user_role_parsing() {
        assert_eq!(
            "administrator".parse::<UserRole>().unwrap(),
            UserRole::Administrator
        );
        assert_eq!("user".parse::<UserRole>().unwrap(), UserRole::User);
        assert_eq!(
            "ADMINISTRATOR".parse::<UserRole>().unwrap(),
            UserRole::Administrator
        );
        assert!("invalid".parse::<UserRole>().is_err());
    }
}
