//! Password management: recovery and change.

use auth_core::{StatusExt, TokenGenerator, ValidateExt};
use auth_db::{CreatePasswordResetTokenParams, UserStatus};
use auth_proto::auth::{ChangePasswordRequest, RecoveryConfirmRequest, RecoveryStartRequest};
use chrono::Utc;
use tonic::Status;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::AuthService;
use crate::core::password;

impl AuthService {
    /// Starts password recovery by creating a reset token and sending email.
    /// Always returns success to prevent user enumeration (OWASP).
    #[allow(clippy::unused_async)] // Async needed for trait impl, actual work spawned
    pub(super) async fn recovery_start(&self, req: RecoveryStartRequest) -> Result<(), Status> {
        req.validate_or_status()?;

        let id_type = Self::resolve_identifier_type(req.identifier_type, &req.identifier);
        let identifier = Self::normalize_identifier(&req.identifier, id_type);

        debug!(identifier = %identifier, id_type = ?id_type, "Password reset requested");

        if id_type == auth_proto::auth::IdentifierType::Phone {
            warn!("Phone-based recovery not yet implemented");
            return Ok(());
        }

        let Some(email_service) = self.ctx.email().cloned() else {
            warn!("Password reset requested but email service not configured");
            return Ok(());
        };

        let db = self.ctx.db().clone();
        let password_reset_ttl_minutes = self.config.password_reset_ttl_minutes;
        let urls = self.ctx.urls().clone();

        // Spawn task to create token and send email (fire-and-forget for OWASP compliance)
        tokio::spawn(async move {
            let Ok(user) = db.users.get_active_user_by_email(&identifier).await else {
                debug!(identifier = %identifier, "User not found for password reset");
                return;
            };

            let token = TokenGenerator::generate_secure_token();
            let token_hash = TokenGenerator::hash_token(&token);
            let expires_at =
                Utc::now() + chrono::Duration::minutes(i64::from(password_reset_ttl_minutes));

            if let Err(e) = db
                .password_resets
                .create_token(CreatePasswordResetTokenParams {
                    id_user: user.id,
                    token_hash: &token_hash,
                    expires_at,
                })
                .await
            {
                error!(user_id = %user.id, error = %e, "Failed to create password reset token");
                return;
            }

            let reset_link = urls.password_reset(&token);

            if let Err(e) = email_service
                .send_password_reset(
                    &identifier,
                    &user.display_name,
                    &reset_link,
                    password_reset_ttl_minutes,
                )
                .await
            {
                error!(user_id = %user.id, error = %e, "Failed to send password reset email");
                return;
            }

            info!(user_id = %user.id, "Password reset email sent");
        });

        Ok(())
    }

    /// Confirms password recovery with token and sets new password.
    pub(super) async fn recovery_confirm(&self, req: RecoveryConfirmRequest) -> Result<(), Status> {
        req.validate_or_status()?;

        debug!(
            token_len = req.token.len(),
            "Password recovery confirmation attempt"
        );

        let token_hash = TokenGenerator::hash_token(&req.token);

        let user_id = self
            .ctx
            .db()
            .password_resets
            .consume_token(&token_hash)
            .await
            .map_err(|e| {
                warn!(error = %e, "Invalid or expired password reset token");
                Status::invalid_argument("Invalid or expired reset token")
            })?;

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .map_err(|_| {
                warn!(user_id = %user_id, "User not found during password reset");
                Status::invalid_argument("Invalid or expired reset token")
            })?;

        if user.status != UserStatus::Active {
            warn!(user_id = %user_id, status = ?user.status, "Password reset for non-active user");
            return Err(Status::permission_denied("Account is not active"));
        }

        let password_hash = password::hash(&req.new_password).status("Failed to hash password")?;

        self.ctx
            .db()
            .users
            .update_user_password(user_id, &password_hash)
            .await
            .status("Failed to update password")?;

        if let Err(e) = self
            .ctx
            .db()
            .sessions
            .revoke_all_user_sessions(user_id)
            .await
        {
            warn!(user_id = %user_id, error = %e, "Failed to revoke sessions after password reset");
        }

        info!(user_id = %user_id, "Password reset completed successfully");
        Ok(())
    }

    /// Changes password for authenticated user.
    pub(super) async fn change_password(
        &self,
        req: ChangePasswordRequest,
        user_id: Uuid,
        device_id: &str,
    ) -> Result<(), Status> {
        req.validate_or_status()?;

        debug!(user_id = %user_id, "Password change requested");

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .status("User not found")?;

        let current_hash = user.password.as_deref().ok_or_else(|| {
            warn!(user_id = %user_id, "User has no password - use recovery");
            Status::failed_precondition("No password set. Use password recovery.")
        })?;

        if !password::verify(&req.current_password, current_hash) {
            warn!(user_id = %user_id, "Invalid current password");
            return Err(Status::unauthenticated("Current password is incorrect"));
        }

        let password_hash = password::hash(&req.new_password).status("Failed to hash password")?;

        self.ctx
            .db()
            .users
            .update_user_password(user_id, &password_hash)
            .await
            .status("Failed to update password")?;

        if let Err(e) = self
            .ctx
            .db()
            .sessions
            .revoke_sessions_except_device(user_id, device_id)
            .await
        {
            warn!(user_id = %user_id, error = %e, "Failed to revoke other sessions");
        }

        info!(user_id = %user_id, "Password changed successfully");
        Ok(())
    }
}
