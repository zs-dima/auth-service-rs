//! Database models and parameter types for the auth schema.

use auth_core::JwtSubject;
use auth_proto::auth::UserRole as ProtoUserRole;
use auth_proto::core::Uuid as ProtoUuid;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use tonic::Status;
use uuid::Uuid;

/// User role enum matching PostgreSQL enum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    Pending,
    #[default]
    Active,
    Suspended,
    Deleted,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        })
    }
}

/// OAuth provider enum matching PostgreSQL `auth.oauth_provider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "oauth_provider", rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    GitHub,
    Microsoft,
    Apple,
    Facebook,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Microsoft => "microsoft",
            Self::Apple => "apple",
            Self::Facebook => "facebook",
        })
    }
}

impl std::str::FromStr for OAuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            "microsoft" => Ok(Self::Microsoft),
            "apple" => Ok(Self::Apple),
            "facebook" => Ok(Self::Facebook),
            _ => Err(format!("Unknown OAuth provider: {s}")),
        }
    }
}

// =============================================================================
// Role helpers (role is now a TEXT FK, not enum)
// =============================================================================

/// Well-known role names.
pub mod roles {
    pub const ADMIN: &str = "admin";
    pub const USER: &str = "user";
    pub const GUEST: &str = "guest";
}

/// Convert role string to proto enum for backwards compatibility.
pub fn role_to_proto(role: &str) -> i32 {
    match role {
        roles::ADMIN => ProtoUserRole::Administrator as i32,
        _ => ProtoUserRole::User as i32,
    }
}

/// Convert proto enum to role string.
pub fn proto_to_role(proto: i32) -> Result<&'static str, Status> {
    match proto {
        0 => Ok(roles::ADMIN),
        1 => Ok(roles::USER),
        _ => Err(Status::invalid_argument(format!("Invalid role: {proto}"))),
    }
}

// =============================================================================
// Database models
// =============================================================================

/// Role model from `auth.roles` table.
#[derive(Debug, Clone, FromRow)]
pub struct Role {
    pub id: String,
    pub description: Option<String>,
    pub permissions: JsonValue,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User model from `auth.users` table.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub role: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub status: UserStatus,
    pub password: Option<String>,
    pub failed_login_attempts: i16,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User profile model from `auth.user_profiles` table.
#[derive(Debug, Clone, FromRow)]
pub struct UserProfile {
    pub id_user: Uuid,
    pub display_name: String,
    pub display_name_normalized: Option<String>,
    pub avatar_url: Option<String>,
    pub locale: String,
    pub timezone: String,
    pub metadata: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Combined user with profile for common queries.
#[derive(Debug, Clone, FromRow)]
pub struct UserWithProfile {
    pub id: Uuid,
    pub role: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub status: UserStatus,
    pub password: Option<String>,
    pub failed_login_attempts: i16,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    // Profile fields
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub locale: String,
    pub timezone: String,
}

/// Implement JwtSubject for UserWithProfile to enable JWT generation.
impl JwtSubject for UserWithProfile {
    fn user_id(&self) -> Uuid {
        self.id
    }

    fn email(&self) -> &str {
        self.email.as_deref().unwrap_or("")
    }

    fn name(&self) -> &str {
        &self.display_name
    }

    fn role(&self) -> &str {
        // Convert DB role name to JWT role name expected by UserRole::FromStr
        match self.role.as_str() {
            roles::ADMIN => "administrator",
            _ => "user",
        }
    }
}

/// OAuth provider link from `auth.providers` table.
#[derive(Debug, Clone, FromRow)]
pub struct Provider {
    pub id_user: Uuid,
    pub provider: OAuthProvider,
    pub provider_uid: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub provider_data: JsonValue,
    pub scopes: JsonValue,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// OAuth state for PKCE flow from `auth.oauth_states` table.
#[derive(Debug, Clone, FromRow)]
pub struct OAuthState {
    pub id: Uuid,
    pub state: String,
    pub code_verifier: String,
    pub provider: OAuthProvider,
    pub redirect_uri: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Session model from `auth.sessions` table.
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id_user: Uuid,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub client_version: Option<String>,
    pub ip_created_by: Option<IpNetwork>,
    pub ip_address: Option<IpNetwork>,
    pub ip_country: Option<String>,
    pub refresh_token: Vec<u8>, // BYTEA - SHA-256 hash (32 bytes)
    pub metadata: JsonValue,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub activity_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Session info for listing (excludes sensitive token hash).
#[derive(Debug, Clone, FromRow)]
pub struct SessionInfo {
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub client_version: Option<String>,
    pub ip_created_by: Option<IpNetwork>,
    pub ip_address: Option<IpNetwork>,
    pub ip_country: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub activity_count: i32,
    pub metadata: JsonValue,
    pub is_current: bool,
}

// =============================================================================
// User info types (for API responses)
// =============================================================================

/// User info without sensitive fields.
#[derive(Debug, Clone, FromRow)]
pub struct UserInfo {
    pub id: Uuid,
    pub role: String,
    pub email: Option<String>,
    pub display_name: String,
    pub deleted: bool,
}

/// Convert Uuid to ProtoUuid.
pub trait ToProtoUuid {
    fn to_proto(&self) -> ProtoUuid;
}

impl ToProtoUuid for Uuid {
    fn to_proto(&self) -> ProtoUuid {
        ProtoUuid {
            value: self.to_string(),
        }
    }
}

impl From<UserInfo> for auth_proto::auth::UserInfo {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name,
            email: u.email.unwrap_or_default(),
            role: role_to_proto(&u.role),
            deleted: u.deleted,
        }
    }
}

impl From<UserInfo> for auth_proto::auth::User {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name,
            email: u.email.unwrap_or_default(),
            role: role_to_proto(&u.role),
            deleted: u.deleted,
        }
    }
}

// =============================================================================
// Parameter types for repository operations
// =============================================================================

/// Parameters for creating a user with profile (uses DB function).
#[derive(Debug, Clone)]
pub struct CreateUserWithProfileParams {
    pub email: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub display_name: Option<String>,
    pub locale: String,
    pub timezone: String,
}

impl Default for CreateUserWithProfileParams {
    fn default() -> Self {
        Self {
            email: String::new(),
            password_hash: None,
            role: roles::USER.to_string(),
            display_name: None,
            locale: "en".to_string(),
            timezone: "UTC".to_string(),
        }
    }
}

/// Parameters for updating a user.
#[derive(Debug, Clone)]
pub struct UpdateUserParams {
    pub id: Uuid,
    pub role: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub status: UserStatus,
}

/// Parameters for updating user profile.
#[derive(Debug, Clone)]
pub struct UpdateUserProfileParams {
    pub id_user: Uuid,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub locale: String,
    pub timezone: String,
}

/// Parameters for creating a session.
#[derive(Debug, Clone)]
pub struct CreateSessionParams {
    pub id_user: Uuid,
    pub refresh_token_hash: Vec<u8>, // SHA-256 hash (32 bytes)
    pub expires_at: DateTime<Utc>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub client_version: Option<String>,
    pub ip_address: Option<IpNetwork>,
    pub ip_country: Option<String>,
    pub metadata: JsonValue, // Contains user_agent, device model, os info, etc.
}

/// Parameters for linking OAuth provider.
#[derive(Debug, Clone)]
pub struct LinkOAuthProviderParams {
    pub id_user: Uuid,
    pub provider: OAuthProvider,
    pub provider_uid: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub provider_data: JsonValue,
}

/// Parameters for creating OAuth state.
#[derive(Debug, Clone)]
pub struct CreateOAuthStateParams {
    pub state: String,
    pub code_verifier: String,
    pub provider: OAuthProvider,
    pub redirect_uri: Option<String>,
}

/// Result from consuming OAuth state.
/// Note: Fields are Option because the DB function returns a table that may be empty.
#[derive(Debug, Clone, FromRow)]
pub struct ConsumedOAuthState {
    pub code_verifier: Option<String>,
    pub provider: Option<OAuthProvider>,
    pub redirect_uri: Option<String>,
}

/// Result from touching a session.
/// Note: Fields are Option because the DB function returns a table that may be empty.
#[derive(Debug, Clone, FromRow)]
pub struct TouchSessionResult {
    pub id_user: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

// =============================================================================
// Password Reset Token
// =============================================================================

/// Password reset token from `auth.password_reset_tokens` table.
#[derive(Debug, Clone, FromRow)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub id_user: Uuid,
    pub token_hash: Vec<u8>, // SHA-256 hash (32 bytes)
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a password reset token.
#[derive(Debug, Clone)]
pub struct CreatePasswordResetTokenParams {
    pub id_user: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}
