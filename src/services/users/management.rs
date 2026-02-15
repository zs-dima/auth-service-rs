//! User management: CRUD operations (admin).

use async_stream::try_stream;
use auth_core::{AppError, StatusExt, StrExt, UuidExt, ValidateExt};
use auth_db::{
    CreateUserWithProfileParams, UpdateUserParams, UpdateUserProfileParams, UserStatus,
    proto_to_role,
};
use auth_proto::core::UserStatus as ProtoUserStatus;
use auth_proto::users::{
    CreateUserRequest, ListUsersRequest, UpdateUserRequest, User as ProtoUser,
    UserInfo as ProtoUserInfo,
};
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{error, info};
use uuid::Uuid;

use super::{StreamResult, UserService};
use crate::core::{canonical_email, canonical_phone, password};

impl UserService {
    /// Streams user info (admin only).
    pub(super) fn list_users_info(&self, req: &ListUsersRequest) -> StreamResult<ProtoUserInfo> {
        let user_ids: Vec<Uuid> = req
            .user_ids
            .iter()
            .filter_map(|id| Uuid::parse_str(&id.value).ok())
            .collect();

        let db = self.ctx.db().clone();

        let stream = try_stream! {
            if user_ids.is_empty() {
                let mut rows = db.users.stream_all_users();
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream user info");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUserInfo::from(user);
                }
            } else {
                let mut rows = db.users.stream_users_by_ids(user_ids);
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream user info");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUserInfo::from(user);
                }
            }
        };

        Box::pin(stream)
    }

    /// Streams full user records (admin gets all, user gets self only).
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn list_users(
        &self,
        req: ListUsersRequest,
        user_id: Uuid,
        is_admin: bool,
    ) -> StreamResult<ProtoUser> {
        let db = self.ctx.db().clone();

        // If user_id filter is provided, use those IDs; otherwise get all (admin) or just self
        let user_ids: Vec<Uuid> = req
            .user_ids
            .iter()
            .filter_map(|id| Uuid::parse_str(&id.value).ok())
            .collect();

        let stream = try_stream! {
            if is_admin && user_ids.is_empty() {
                let mut rows = db.users.stream_all_users();
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream users");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUser::from(user);
                }
            } else if is_admin {
                let mut rows = db.users.stream_users_by_ids(user_ids);
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream users");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUser::from(user);
                }
            } else {
                // Non-admin can only see themselves
                let mut rows = db.users.stream_users_by_ids(vec![user_id]);
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream users");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUser::from(user);
                }
            }
        };

        Box::pin(stream)
    }

    /// Creates a new user (admin only).
    pub(super) async fn create_user(
        &self,
        req: CreateUserRequest,
        admin_id: Uuid,
    ) -> Result<ProtoUser, Status> {
        req.validate_or_status()?;

        let email = (!req.email.is_empty()).then(|| canonical_email(&req.email));
        let phone = (!req.phone.is_empty()).then(|| canonical_phone(&req.phone));

        if email.is_none() && phone.is_none() {
            return Err(Status::invalid_argument(
                "Either email or phone must be provided",
            ));
        }

        info!(admin_id = %admin_id, email = ?email, phone = ?phone, "Creating user");

        let password_hash = (!req.password.is_empty())
            .then(|| password::hash(&req.password).status("Failed to hash password"))
            .transpose()?;
        let role = proto_to_role(req.role).map_err(Status::invalid_argument)?;

        let user_id = self
            .ctx
            .db()
            .users
            .create_user_with_profile(CreateUserWithProfileParams {
                email: email.as_deref(),
                phone: phone.as_deref(),
                password_hash: password_hash.as_deref(),
                role,
                display_name: Some(&req.name),
                locale: req.locale.or_str("en"),
                timezone: req.timezone.or_str("UTC"),
            })
            .await
            .status("Failed to create user")?;

        if let Some(ref email_addr) = email {
            let temp_password = (!req.password.is_empty()).then(|| req.password.clone());
            self.ctx.send_welcome_email(
                self.config.email_verification_ttl_hours,
                user_id,
                email_addr.clone(),
                req.name.clone(),
                temp_password,
            );
        }

        info!(user_id = %user_id, created_by = %admin_id, "User created");

        // Fetch and return the created user
        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .status("Failed to get created user")?;

        Ok(ProtoUser::from(user))
    }

    /// Updates an existing user (admin only).
    ///
    /// Follows Google AIP-134: if `update_mask` is set, only the listed field
    /// paths are applied. Otherwise all `optional` fields present in the
    /// request are applied (partial-update semantics).
    #[allow(clippy::too_many_lines)]
    pub(super) async fn update_user(
        &self,
        req: UpdateUserRequest,
        admin_id: Uuid,
    ) -> Result<ProtoUser, Status> {
        req.validate_or_status()?;

        let user_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;

        info!(admin_id = %admin_id, target_user_id = %user_id, "Updating user");

        let existing = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .map_err(|_| Status::not_found("User not found"))?;

        // AIP-134: when update_mask is present, only update the listed paths.
        // Mask paths use snake_case from the proto field names.
        let mask_paths: Option<Vec<&str>> = req
            .update_mask
            .as_ref()
            .map(|m| m.paths.iter().map(String::as_str).collect());

        let has_path = |path: &str| -> bool {
            match &mask_paths {
                Some(paths) => paths.contains(&path),
                // No mask → apply all present optional fields
                None => true,
            }
        };

        // Build updated values from optional fields, respecting the mask
        let email = if has_path("email") {
            req.email
                .as_ref()
                .map(|e| canonical_email(e))
                .or(existing.email.clone())
        } else {
            existing.email.clone()
        };

        let phone = if has_path("phone") {
            req.phone
                .as_ref()
                .map(|p| canonical_phone(p))
                .or(existing.phone.clone())
        } else {
            existing.phone.clone()
        };

        let role = if has_path("role") {
            req.role
                .map(|r| proto_to_role(r).map_err(Status::invalid_argument))
                .transpose()?
                .unwrap_or(existing.role.as_str())
        } else {
            existing.role.as_str()
        };

        let status = if has_path("status") {
            req.status.map_or(existing.status, |s| match s {
                s if s == ProtoUserStatus::Pending as i32 => UserStatus::Pending,
                s if s == ProtoUserStatus::Active as i32 => UserStatus::Active,
                s if s == ProtoUserStatus::Suspended as i32 => UserStatus::Suspended,
                s if s == ProtoUserStatus::Deleted as i32 => UserStatus::Deleted,
                _ => existing.status,
            })
        } else {
            existing.status
        };

        let name = if has_path("name") {
            req.name.as_deref().unwrap_or(&existing.display_name)
        } else {
            &existing.display_name
        };

        let locale = if has_path("locale") {
            req.locale.as_deref().unwrap_or(&existing.locale)
        } else {
            &existing.locale
        };

        let timezone = if has_path("timezone") {
            req.timezone.as_deref().unwrap_or(&existing.timezone)
        } else {
            &existing.timezone
        };

        // Reset verification flags when email/phone changes
        let email_verified = if email.as_deref() == existing.email.as_deref() {
            existing.email_verified
        } else {
            false
        };
        let phone_verified = if phone.as_deref() == existing.phone.as_deref() {
            existing.phone_verified
        } else {
            false
        };

        self.ctx
            .db()
            .users
            .update_user(UpdateUserParams {
                id: user_id,
                role,
                email: email.as_deref(),
                email_verified,
                phone: phone.as_deref(),
                phone_verified,
                status,
            })
            .await
            .status("Failed to update user")?;

        self.ctx
            .db()
            .users
            .update_user_profile(UpdateUserProfileParams {
                id_user: user_id,
                display_name: name,
                avatar_url: existing.avatar_url.as_deref(),
                locale,
                timezone,
            })
            .await
            .status("Failed to update user profile")?;

        info!(user_id = %user_id, updated_by = %admin_id, "User updated");

        // Fetch and return the updated user
        let updated_user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .status("Failed to get updated user")?;

        Ok(ProtoUser::from(updated_user))
    }

    /// Sets password for any user (admin only).
    pub(super) async fn set_password(
        &self,
        req: auth_proto::users::SetPasswordRequest,
        admin_id: Uuid,
    ) -> Result<(), Status> {
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;

        info!(admin_id = %admin_id, target_user_id = %target_id, "Admin setting password");

        self.ctx
            .db()
            .users
            .get_user_by_id(target_id)
            .await
            .map_err(|e| {
                tracing::warn!(target_user_id = %target_id, error = %e, "User not found");
                Status::not_found("User not found")
            })?;

        let hash = password::hash(&req.password).status("Failed to hash password")?;
        self.ctx
            .db()
            .users
            .update_user_password(target_id, &hash)
            .await
            .status("Failed to update password")?;

        if let Err(e) = self
            .ctx
            .db()
            .sessions
            .revoke_all_user_sessions(target_id)
            .await
        {
            tracing::warn!(target_user_id = %target_id, error = %e, "Failed to revoke sessions");
        }

        info!(target_user_id = %target_id, set_by = %admin_id, "Password set by admin");
        Ok(())
    }
}
