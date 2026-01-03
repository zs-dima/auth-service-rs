//! Database models and parameter types.

use auth_core::JwtSubject;
use auth_proto::auth::UserRole as ProtoUserRole;
use auth_proto::core::Uuid as ProtoUuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tonic::Status;
use uuid::Uuid;

/// User role enum matching PostgreSQL enum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Administrator,
    #[default]
    User,
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
            0 => Ok(Self::Administrator),
            1 => Ok(Self::User),
            _ => Err(Status::invalid_argument(format!("Invalid role: {value}"))),
        }
    }
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

/// User model.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub role: UserRole,
    pub name: String,
    pub email: String,
    pub password: String,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Implement JwtSubject for User to enable JWT generation.
impl JwtSubject for User {
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
        match self.role {
            UserRole::Administrator => "administrator",
            UserRole::User => "user",
        }
    }
}

/// User info without password.
#[derive(Debug, Clone, FromRow)]
pub struct UserInfo {
    pub id: Uuid,
    pub role: UserRole,
    pub name: String,
    pub email: String,
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
            name: u.name,
            email: u.email,
            role: u.role.into(),
            deleted: u.deleted,
        }
    }
}

impl From<UserInfo> for auth_proto::auth::User {
    fn from(u: UserInfo) -> Self {
        Self {
            id: Some(u.id.to_proto()),
            name: u.name,
            email: u.email,
            role: u.role.into(),
            deleted: u.deleted,
        }
    }
}

/// Parameters for creating a user.
#[derive(Debug, Clone)]
pub struct CreateUserParams {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub deleted: bool,
}

/// Parameters for updating a user.
#[derive(Debug, Clone)]
pub struct UpdateUserParams {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: UserRole,
    pub deleted: bool,
}

/// Parameters for saving user session.
#[derive(Debug, Clone)]
pub struct SaveUserSessionParams {
    pub user_id: Uuid,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}
