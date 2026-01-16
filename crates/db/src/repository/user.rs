//! User repository for database operations on `auth.users` and `auth.user_profiles`.

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::{
    AppError, CreateUserWithProfileParams, DbError, LinkOAuthProviderParams, OAuthProvider,
    UpdateUserParams, UpdateUserProfileParams, User, UserInfo, UserStatus, UserWithProfile,
};

/// User repository for database operations on `auth.users` and `auth.user_profiles`.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get active user with profile by email.
    pub async fn get_active_user_by_email(&self, email: &str) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.email = $1
               AND u.status = 'active'
               AND u.deleted_at IS NULL
             LIMIT 1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User", email))
    }

    /// Get active user with profile by phone (E.164 format).
    pub async fn get_active_user_by_phone(&self, phone: &str) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.phone = $1
               AND u.status = 'active'
               AND u.deleted_at IS NULL
             LIMIT 1
            "#,
            phone
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User by phone", phone))
    }

    /// Get user by email (any status, for existence checks).
    pub async fn get_user_by_email(&self, email: &str) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.email = $1
             LIMIT 1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User", email))
    }

    /// Get user by phone (any status, for existence checks).
    pub async fn get_user_by_phone(&self, phone: &str) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.phone = $1
             LIMIT 1
            "#,
            phone
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User by phone", phone))
    }

    /// Get user with profile by ID.
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<UserWithProfile, AppError> {
        sqlx::query_as!(
            UserWithProfile,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   u.email_verified,
                   u.phone,
                   u.phone_verified,
                   u.status AS "status: UserStatus",
                   u.password,
                   u.failed_login_attempts,
                   u.locked_until,
                   u.created_at,
                   u.updated_at,
                   u.deleted_at,
                   p.display_name,
                   p.avatar_url,
                   p.locale,
                   p.timezone
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User", user_id))
    }

    /// Get raw user by ID (without profile).
    pub async fn get_raw_user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id,
                   role,
                   email,
                   email_verified,
                   phone,
                   phone_verified,
                   status AS "status: UserStatus",
                   password,
                   failed_login_attempts,
                   locked_until,
                   created_at,
                   updated_at,
                   deleted_at
              FROM auth.users
             WHERE id = $1
             LIMIT 1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError)?
        .ok_or_else(|| AppError::not_found("User", user_id))
    }

    /// Create a new user with profile.
    /// Supports email-based or phone-based registration.
    ///
    /// # Errors
    /// Returns `AppError::InvalidArgument` if neither email nor phone is provided.
    /// Returns `AppError::AlreadyExists` if the user already exists.
    pub async fn create_user_with_profile(
        &self,
        params: CreateUserWithProfileParams<'_>,
    ) -> Result<Uuid, AppError> {
        // Fail fast if neither identifier is provided
        if params.email.is_none() && params.phone.is_none() {
            return Err(AppError::InvalidArgument(
                "Either email or phone must be provided".to_string(),
            ));
        }

        let identifier = params.email.or(params.phone).unwrap_or("unknown");

        sqlx::query_scalar!(
            r#"
            SELECT auth.create_user_with_profile($1, $2, $3, $4::TEXT::auth.role_name, $5, $6, $7) AS "id!"
            "#,
            params.email,
            params.phone,
            params.password_hash,
            params.role,
            params.display_name,
            params.locale,
            params.timezone
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique_violation") || msg.contains("duplicate key") {
                AppError::AlreadyExists(format!("User already exists: {identifier}"))
            } else {
                AppError::Unavailable(msg)
            }
        })
    }

    /// Update an existing user.
    pub async fn update_user(&self, params: UpdateUserParams<'_>) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET role = $2::TEXT::auth.role_name,
                   email = $3::TEXT::auth.email,
                   email_verified = $4,
                   phone = $5::TEXT::auth.phone_e164,
                   phone_verified = $6,
                   status = $7::TEXT::auth.user_status
             WHERE id = $1
            "#,
            params.id,
            params.role,
            params.email,
            params.email_verified,
            params.phone,
            params.phone_verified,
            params.status as UserStatus
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;
        Ok(())
    }

    /// Update user profile.
    pub async fn update_user_profile(
        &self,
        params: UpdateUserProfileParams<'_>,
    ) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.user_profiles
               SET display_name = $2,
                   avatar_url = $3,
                   locale = $4,
                   timezone = $5
             WHERE id_user = $1
            "#,
            params.id_user,
            params.display_name,
            params.avatar_url,
            params.locale,
            params.timezone
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;
        Ok(())
    }

    /// Update user password.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the user doesn't exist or is deleted.
    pub async fn update_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query!(
            r#"
            UPDATE auth.users
               SET password = $2
             WHERE id = $1
               AND deleted_at IS NULL
            "#,
            user_id,
            password_hash
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;

        if result.rows_affected() > 0 {
            Ok(())
        } else {
            Err(AppError::not_found("User", user_id))
        }
    }

    /// Set email_verified to true for a user.
    ///
    /// # Errors
    /// Returns `AppError::NotFound` if the user doesn't exist or is deleted.
    pub async fn set_email_verified(&self, user_id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query!(
            r#"
            UPDATE auth.users
               SET email_verified = TRUE
             WHERE id = $1
               AND deleted_at IS NULL
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;

        if result.rows_affected() > 0 {
            Ok(())
        } else {
            Err(AppError::not_found("User", user_id))
        }
    }

    /// Increment failed login attempts.
    pub async fn increment_failed_login(&self, user_id: Uuid) -> Result<i16, AppError> {
        sqlx::query_scalar!(
            r#"
            UPDATE auth.users
               SET failed_login_attempts = failed_login_attempts + 1
             WHERE id = $1
            RETURNING failed_login_attempts
            "#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DbError(e).into())
    }

    /// Reset failed login attempts.
    pub async fn reset_failed_login(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET failed_login_attempts = 0,
                   locked_until = NULL
             WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;
        Ok(())
    }

    /// Soft delete a user by setting `deleted_at` and status to `deleted`.
    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            UPDATE auth.users
               SET deleted_at = NOW(),
                   status = 'deleted'
             WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(DbError)?;
        Ok(())
    }

    /// Stream all users with profile info.
    pub fn stream_all_users(
        &self,
    ) -> impl tokio_stream::Stream<Item = Result<UserInfo, sqlx::Error>> + '_ {
        sqlx::query_as!(
            UserInfo,
            r#"
            SELECT u.id,
                   u.role,
                   u.email,
                   p.display_name,
                   (u.deleted_at IS NOT NULL) AS "deleted!"
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             ORDER BY p.display_name
            "#
        )
        .fetch(&self.pool)
    }

    /// Stream users by IDs.
    pub fn stream_users_by_ids(
        &self,
        user_ids: Vec<Uuid>,
    ) -> impl tokio_stream::Stream<Item = Result<UserInfo, sqlx::Error>> + '_ {
        sqlx::query_as::<_, UserInfo>(
            r"
            SELECT u.id,
                   u.role,
                   u.email,
                   p.display_name,
                   (u.deleted_at IS NOT NULL) AS deleted
              FROM auth.users u
              JOIN auth.user_profiles p ON p.id_user = u.id
             WHERE u.id = ANY($1)
             ORDER BY p.display_name
            ",
        )
        .bind(user_ids)
        .fetch(&self.pool)
    }

    /// Link OAuth provider to user.
    pub async fn link_oauth_provider(
        &self,
        params: LinkOAuthProviderParams<'_>,
    ) -> Result<Uuid, AppError> {
        sqlx::query_scalar!(
            r#"
            SELECT auth.link_oauth_provider($1, $2, $3, $4, $5, $6, $7) AS "id_user!"
            "#,
            params.id_user,
            params.provider as OAuthProvider,
            params.provider_uid,
            params.email,
            params.name,
            params.avatar_url,
            params.provider_data
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DbError(e).into())
    }
}
