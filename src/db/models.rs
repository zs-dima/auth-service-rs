use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tonic::Status;
use uuid::Uuid;

use crate::extensions::ToProtoUuid;
use crate::proto::auth::UserRole as ProtoUserRole;

/// User role enum matching PostgreSQL enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Administrator,
    User,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

impl From<UserRole> for i32 {
    fn from(role: UserRole) -> i32 {
        match role {
            UserRole::Administrator => ProtoUserRole::Administrator as i32,
            UserRole::User => ProtoUserRole::User as i32,
        }
    }
}

impl TryFrom<i32> for UserRole {
    type Error = Status;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UserRole::Administrator),
            1 => Ok(UserRole::User),
            _ => Err(Status::invalid_argument(format!("Invalid role: {value}"))),
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Administrator => write!(f, "administrator"),
            UserRole::User => write!(f, "user"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "administrator" => Ok(UserRole::Administrator),
            "user" => Ok(UserRole::User),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// User model representing the user table
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub role: UserRole,
    pub name: String,
    pub email: String,
    pub password: String,
    pub blurhash: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User info without password - for listing users
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub role: UserRole,
    pub name: String,
    pub email: String,
    pub blurhash: Option<String>,
    pub deleted: bool,
}

impl From<UserInfo> for crate::proto::auth::UserInfo {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.name,
            email: u.email,
            role: u.role.into(),
            blurhash: u.blurhash,
            deleted: u.deleted,
        }
    }
}

impl From<UserInfo> for crate::proto::auth::User {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.name,
            email: u.email,
            role: u.role.into(),
            blurhash: u.blurhash,
            deleted: u.deleted,
        }
    }
}

/// User session model for refresh tokens
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: Uuid,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

/// User photo model
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserPhoto {
    pub user_id: Uuid,
    pub avatar: Option<Vec<u8>>,
    pub photo: Option<Vec<u8>>,
}

/// User avatar - subset of UserPhoto for loading
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserAvatar {
    pub user_id: Uuid,
    pub avatar: Option<Vec<u8>>,
}

impl From<UserAvatar> for crate::proto::auth::UserAvatar {
    fn from(a: UserAvatar) -> Self {
        Self {
            user_id: Some(a.user_id.to_proto()),
            avatar: a.avatar,
        }
    }
}

/// Parameters for creating a new user
#[derive(Debug, Clone)]
pub struct CreateUserParams {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub deleted: bool,
}

/// Parameters for updating a user
#[derive(Debug, Clone)]
pub struct UpdateUserParams {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: UserRole,
    pub deleted: bool,
}

/// Parameters for saving user session
#[derive(Debug, Clone)]
pub struct SaveUserSessionParams {
    pub user_id: Uuid,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Parameters for saving user photo
#[derive(Debug, Clone)]
pub struct SaveUserPhotoParams {
    pub user_id: Uuid,
    pub avatar: Vec<u8>,
    pub photo: Vec<u8>,
}
