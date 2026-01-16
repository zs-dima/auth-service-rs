//! Database models and parameter types for the auth schema.

use auth_core::{JwtSubject, ToProtoTimestamp, ToProtoUuid};
use auth_proto::core::UserRole as ProtoUserRole;
use auth_proto::core::UserStatus as ProtoUserStatus;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use tonic::Status;
use uuid::Uuid;

/// User status enum matching `PostgreSQL` `auth.user_status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
#[non_exhaustive]
pub enum UserStatus {
    Pending,
    #[default]
    Active,
    Suspended,
    Deleted,
}

impl UserStatus {
    /// Returns the string representation as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OAuth provider enum matching `PostgreSQL` `auth.oauth_provider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "oauth_provider", rename_all = "lowercase")]
#[non_exhaustive]
pub enum OAuthProvider {
    Google,
    GitHub,
    Microsoft,
    Apple,
    Facebook,
}

impl OAuthProvider {
    /// Returns the string representation as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Microsoft => "microsoft",
            Self::Apple => "apple",
            Self::Facebook => "facebook",
        }
    }
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
            other => Err(format!("Unknown OAuth provider: {other}")),
        }
    }
}

// =============================================================================
// Role helpers (role is now a TEXT FK, not enum)
// =============================================================================

/// Well-known role names as compile-time constants.
pub mod roles {
    pub const ADMIN: &str = "admin";
    pub const USER: &str = "user";
    pub const GUEST: &str = "guest";
}

/// Convert role string to proto enum for backwards compatibility.
#[must_use]
pub const fn role_to_proto(role: &str) -> i32 {
    match role.as_bytes() {
        b"admin" => ProtoUserRole::Admin as i32,
        b"user" => ProtoUserRole::User as i32,
        _ => ProtoUserRole::Guest as i32,
    }
}

/// Convert proto enum to role string.
///
/// # Errors
/// Returns an error string if the proto value is invalid.
pub const fn proto_to_role(proto: i32) -> Result<&'static str, &'static str> {
    match proto {
        1 => Ok(roles::ADMIN),
        2 => Ok(roles::USER),
        3 => Ok(roles::GUEST),
        _ => Err("Invalid role"),
    }
}

/// Convert proto enum to role string, returning a tonic `Status` on error.
///
/// # Errors
/// Returns `Status::invalid_argument` if the proto value is invalid.
pub fn proto_to_role_or_status(proto: i32) -> Result<&'static str, Status> {
    proto_to_role(proto).map_err(|_| Status::invalid_argument(format!("Invalid role: {proto}")))
}

/// Convert `UserStatus` to proto enum value.
#[must_use]
pub const fn status_to_proto(status: UserStatus) -> i32 {
    match status {
        UserStatus::Pending => ProtoUserStatus::Pending as i32,
        UserStatus::Active => ProtoUserStatus::Active as i32,
        UserStatus::Suspended => ProtoUserStatus::Suspended as i32,
        UserStatus::Deleted => ProtoUserStatus::Deleted as i32,
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

/// Implements [`JwtSubject`] for `UserWithProfile` to enable JWT generation.
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
        // JWT UserRole::FromStr accepts both "admin" and "administrator"
        &self.role
    }
}

/// Convert `UserWithProfile` to proto `users::User` for full user responses.
impl From<&UserWithProfile> for auth_proto::users::User {
    fn from(u: &UserWithProfile) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name.clone(),
            email: u.email.clone().unwrap_or_default(),
            phone: u.phone.clone().unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: status_to_proto(u.status),
            email_verified: u.email_verified,
            phone_verified: u.phone_verified,
            mfa_enabled: false, // TODO: Implement MFA
            has_password: u.password.is_some(),
            avatar_url: u.avatar_url.clone().unwrap_or_default(),
            locale: u.locale.clone(),
            timezone: u.timezone.clone(),
            created_at: Some(u.created_at.to_proto_timestamp()),
            updated_at: Some(u.updated_at.to_proto_timestamp()),
        }
    }
}

impl From<UserWithProfile> for auth_proto::users::User {
    fn from(u: UserWithProfile) -> Self {
        Self::from(&u)
    }
}

/// Convert `UserWithProfile` to proto `users::UserInfo` for lightweight responses.
impl From<&UserWithProfile> for auth_proto::users::UserInfo {
    fn from(u: &UserWithProfile) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name.clone(),
            email: u.email.clone().unwrap_or_default(),
            phone: u.phone.clone().unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: status_to_proto(u.status),
            avatar_url: u.avatar_url.clone().unwrap_or_default(),
            locale: u.locale.clone(),
            timezone: u.timezone.clone(),
        }
    }
}

impl From<UserWithProfile> for auth_proto::users::UserInfo {
    fn from(u: UserWithProfile) -> Self {
        Self::from(&u)
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

impl From<&UserInfo> for auth_proto::users::UserInfo {
    fn from(u: &UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name.clone(),
            email: u.email.clone().unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: if u.deleted {
                ProtoUserStatus::Deleted as i32
            } else {
                ProtoUserStatus::Active as i32
            },
            // Fields not available from UserInfo (minimal query)
            phone: String::new(),
            avatar_url: String::new(),
            locale: String::new(),
            timezone: String::new(),
        }
    }
}

impl From<UserInfo> for auth_proto::users::UserInfo {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name,
            email: u.email.unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: if u.deleted {
                ProtoUserStatus::Deleted as i32
            } else {
                ProtoUserStatus::Active as i32
            },
            // Fields not available from UserInfo (minimal query)
            phone: String::new(),
            avatar_url: String::new(),
            locale: String::new(),
            timezone: String::new(),
        }
    }
}

impl From<&UserInfo> for auth_proto::users::User {
    fn from(u: &UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name.clone(),
            email: u.email.clone().unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: if u.deleted {
                ProtoUserStatus::Deleted as i32
            } else {
                ProtoUserStatus::Active as i32
            },
            // Fields not available from UserInfo (minimal query)
            phone: String::new(),
            email_verified: false,
            phone_verified: false,
            mfa_enabled: false,
            has_password: false,
            avatar_url: String::new(),
            locale: String::new(),
            timezone: String::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

impl From<UserInfo> for auth_proto::users::User {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.display_name,
            email: u.email.unwrap_or_default(),
            role: role_to_proto(&u.role),
            status: if u.deleted {
                ProtoUserStatus::Deleted as i32
            } else {
                ProtoUserStatus::Active as i32
            },
            // Fields not available from UserInfo (minimal query)
            phone: String::new(),
            email_verified: false,
            phone_verified: false,
            mfa_enabled: false,
            has_password: false,
            avatar_url: String::new(),
            locale: String::new(),
            timezone: String::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

// =============================================================================
// Parameter types for repository operations
// =============================================================================

/// Parameters for creating a user with profile (uses DB function).
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateUserWithProfileParams<'a> {
    pub email: Option<&'a str>,
    pub phone: Option<&'a str>,
    pub password_hash: Option<&'a str>,
    /// Defaults to `roles::USER` if empty.
    pub role: &'a str,
    pub display_name: Option<&'a str>,
    /// Defaults to `"en"` if empty.
    pub locale: &'a str,
    /// Defaults to `"UTC"` if empty.
    pub timezone: &'a str,
}

/// Parameters for updating a user.
#[derive(Debug, Clone, Copy)]
pub struct UpdateUserParams<'a> {
    pub id: Uuid,
    pub role: &'a str,
    pub email: Option<&'a str>,
    pub email_verified: bool,
    pub phone: Option<&'a str>,
    pub phone_verified: bool,
    pub status: UserStatus,
}

/// Parameters for updating user profile.
#[derive(Debug, Clone, Copy)]
pub struct UpdateUserProfileParams<'a> {
    pub id_user: Uuid,
    pub display_name: &'a str,
    pub avatar_url: Option<&'a str>,
    pub locale: &'a str,
    pub timezone: &'a str,
}

/// Parameters for creating a session.
#[derive(Debug, Clone)]
pub struct CreateSessionParams<'a> {
    pub id_user: Uuid,
    pub refresh_token_hash: &'a [u8], // SHA-256 hash (32 bytes)
    pub expires_at: DateTime<Utc>,
    pub device_id: Option<&'a str>,
    pub device_name: Option<&'a str>,
    pub device_type: Option<&'a str>,
    pub client_version: Option<&'a str>,
    pub ip_address: Option<IpNetwork>,
    pub ip_country: Option<&'a str>,
    pub metadata: JsonValue, // Contains user_agent, device model, os info, etc.
}

/// Parameters for linking OAuth provider.
#[derive(Debug, Clone)]
pub struct LinkOAuthProviderParams<'a> {
    pub id_user: Uuid,
    pub provider: OAuthProvider,
    pub provider_uid: &'a str,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub provider_data: JsonValue,
}

/// Parameters for creating OAuth state.
#[derive(Debug, Clone, Copy)]
pub struct CreateOAuthStateParams<'a> {
    pub state: &'a str,
    pub code_verifier: &'a str,
    pub provider: OAuthProvider,
    pub redirect_uri: Option<&'a str>,
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
#[derive(Debug, Clone, Copy)]
pub struct CreatePasswordResetTokenParams<'a> {
    pub id_user: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: DateTime<Utc>,
}

// =============================================================================
// Email Verification Token
// =============================================================================

/// Email verification token from `auth.email_verification_tokens` table.
#[derive(Debug, Clone, FromRow)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub id_user: Uuid,
    pub token_hash: Vec<u8>, // SHA-256 hash (32 bytes)
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating an email verification token.
#[derive(Debug, Clone, Copy)]
pub struct CreateEmailVerificationTokenParams<'a> {
    pub id_user: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: DateTime<Utc>,
}
