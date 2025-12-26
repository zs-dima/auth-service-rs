use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::models::{User, UserRole};
use crate::error::AppError;

/// JWT issuer identifier
pub const ISSUER: &str = "auth-service";
/// JWT audience identifier
pub const AUDIENCE: &str = "auth-service";
/// Length of refresh token in bytes
const REFRESH_TOKEN_BYTES: usize = 32;

/// JWT claims structure
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
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
}

/// User info extracted from JWT
#[derive(Debug, Clone)]
pub struct JwtUserInfo {
    pub id: Uuid,
    pub role: UserRole,
    pub email: String,
    #[allow(dead_code)]
    pub name: String,
}

/// Full auth info extracted from JWT
#[derive(Debug, Clone)]
pub struct JwtAuthInfo {
    pub user_info: JwtUserInfo,
    pub device_id: Uuid,
    pub installation_id: Uuid,
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
            sub: user.id.to_string(),
            aud: AUDIENCE.to_string(),
            iss: ISSUER.to_string(),
            jti: Uuid::new_v4().to_string(),
            role: user.role.to_string(),
            email: user.email.clone(),
            name: user.name.clone(),
            device_id: device_id.to_string(),
            installation_id: installation_id.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret_key.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("JWT encoding error: {}", e)))?;

        Ok(token)
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

        let mut token_bytes = [0u8; REFRESH_TOKEN_BYTES];
        rand::rng().fill_bytes(&mut token_bytes);

        let token = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &token_bytes,
        );

        Ok((token, expires_at))
    }

    /// Validate and decode a JWT token
    pub fn validate_token(token: &str, jwt_secret_key: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::default();
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret_key.as_bytes()),
            &validation,
        )
        .map_err(|e| AppError::Unauthenticated(format!("Invalid token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Extract auth info from JWT claims
    pub fn extract_auth_info(claims: &Claims) -> Result<JwtAuthInfo, AppError> {
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthenticated("Invalid user ID in token".to_string()))?;

        let device_id = Uuid::parse_str(&claims.device_id)
            .map_err(|_| AppError::Unauthenticated("Invalid device ID in token".to_string()))?;

        let installation_id = Uuid::parse_str(&claims.installation_id).map_err(|_| {
            AppError::Unauthenticated("Invalid installation ID in token".to_string())
        })?;

        let role = claims
            .role
            .parse::<UserRole>()
            .map_err(|_| AppError::Unauthenticated("Invalid role in token".to_string()))?;

        Ok(JwtAuthInfo {
            user_info: JwtUserInfo {
                id: user_id,
                role,
                email: claims.email.clone(),
                name: claims.name.clone(),
            },
            device_id,
            installation_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            role: UserRole::User,
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "hash".to_string(),
            blurhash: None,
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

        let claims = TokenGenerator::validate_token(&token, secret).unwrap();
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.name, user.name);
        assert_eq!(claims.sub, user.id.to_string());
    }

    #[test]
    fn test_generate_refresh_token() {
        let (token, expires_at) = TokenGenerator::generate_refresh_token(7).unwrap();
        assert!(!token.is_empty());
        assert!(expires_at > Utc::now());
        // Should be URL-safe base64 (no +, /, or =)
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
    }

    #[test]
    fn test_extract_auth_info() {
        let user = test_user();
        let device_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let secret = "test_secret_key_minimum_32_chars!";

        let token =
            TokenGenerator::generate_access_token(&user, &device_id, &installation_id, secret, 15)
                .unwrap();

        let claims = TokenGenerator::validate_token(&token, secret).unwrap();
        let auth_info = TokenGenerator::extract_auth_info(&claims).unwrap();

        assert_eq!(auth_info.user_info.id, user.id);
        assert_eq!(auth_info.user_info.email, user.email);
        assert_eq!(auth_info.device_id, device_id);
        assert_eq!(auth_info.installation_id, installation_id);
    }
}
