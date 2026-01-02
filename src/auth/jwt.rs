use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::error::AppError;
use crate::db::models::User;

/// JWT issuer identifier
pub const ISSUER: &str = "auth-service";
/// JWT audience identifier
pub const AUDIENCE: &str = "auth-service";
/// Length of refresh token in bytes (256 bits of entropy)
const REFRESH_TOKEN_BYTES: usize = 32;

/// JWT claims structure following RFC 7519 with custom claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    // Standard claims (RFC 7519)
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

/// Token generator for creating access and refresh tokens
pub struct TokenGenerator;

impl TokenGenerator {
    /// Generate an access token (JWT) for a user
    ///
    /// # Arguments
    /// * `user` - The user to generate the token for
    /// * `device_id` - The device ID
    /// * `installation_id` - The app installation ID
    /// * `jwt_secret_key` - The secret key for signing
    /// * `ttl_minutes` - Token time-to-live in minutes
    pub fn generate_access_token(
        user: &User,
        device_id: &Uuid,
        installation_id: &Uuid,
        jwt_secret_key: &str,
        ttl_minutes: u64,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(ttl_minutes as i64);

        let claims = Claims {
            // Standard claims
            sub: user.id.to_string(),
            aud: AUDIENCE.to_string(),
            iss: ISSUER.to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(), // Token valid immediately

            // Custom claims
            role: user.role.to_string(),
            email: user.email.clone(),
            name: user.name.clone(),
            device_id: device_id.to_string(),
            installation_id: installation_id.to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret_key.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("JWT encoding failed: {e}")))
    }

    /// Generate a refresh token (random URL-safe base64 string)
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
    use crate::db::models::UserRole;
    use jsonwebtoken::{DecodingKey, Validation, decode};

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            role: UserRole::User,
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "hash".to_string(),
            deleted_at: None,
        }
    }

    #[test]
    fn test_generate_and_validate_access_token() {
        let user = test_user();
        let device_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let secret = "test_secret_key_minimum_32_chars!";

        let token =
            TokenGenerator::generate_access_token(&user, &device_id, &installation_id, secret, 15)
                .unwrap();

        let mut validation = Validation::default();
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);

        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .unwrap();

        assert_eq!(token_data.claims.email, user.email);
        assert_eq!(token_data.claims.name, user.name);
        assert_eq!(token_data.claims.sub, user.id.to_string());
    }

    #[test]
    fn test_generate_refresh_token() {
        let (token, expires_at) = TokenGenerator::generate_refresh_token(7).unwrap();

        assert!(!token.is_empty());
        assert!(expires_at > Utc::now());
        // URL-safe base64 should not contain +, /, or =
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
    }

    #[test]
    fn test_claims_roundtrip() {
        let user = test_user();
        let device_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let secret = "test_secret_key_minimum_32_chars!";

        let token =
            TokenGenerator::generate_access_token(&user, &device_id, &installation_id, secret, 15)
                .unwrap();

        let mut validation = Validation::default();
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);

        let claims = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .unwrap()
        .claims;

        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.device_id, device_id.to_string());
        assert_eq!(claims.installation_id, installation_id.to_string());
    }
}
