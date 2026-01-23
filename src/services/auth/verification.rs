//! Email/Phone verification: request and confirm.

use auth_core::{AppError, StatusExt, TokenGenerator, UuidExt, ValidateExt};
use auth_proto::auth::{
    AuthResponse, ConfirmVerificationRequest, RequestVerificationRequest, VerificationType,
};
use tonic::Status;
use tracing::{info, warn};
use uuid::Uuid;

use super::{AuthService, ClientContext};

impl AuthService {
    /// Request a new verification code/link for email or phone.
    ///
    /// Used to resend verification when token expires or for verified users
    /// changing their email/phone.
    pub(super) async fn request_verification(
        &self,
        req: RequestVerificationRequest,
        user_id: Uuid,
    ) -> Result<(), Status> {
        req.validate_or_status()?;

        let verification_type = VerificationType::try_from(req.r#type).unwrap_or_default();

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .status("User not found")?;

        match verification_type {
            VerificationType::Email => {
                let Some(email) = user.email.as_ref() else {
                    return Err(Status::failed_precondition("No email address on account"));
                };

                if user.email_verified {
                    return Err(Status::failed_precondition("Email already verified"));
                }

                self.ctx.send_verification_email(
                    self.config.email_verification_ttl_hours,
                    user_id,
                    email.clone(),
                    user.display_name.clone(),
                );

                info!(user_id = %user_id, "Verification email resent");
            }
            VerificationType::Phone => {
                return Err(Status::unimplemented(
                    "Phone verification not yet supported",
                ));
            }
            VerificationType::Unspecified => {
                return Err(Status::invalid_argument("Verification type required"));
            }
        }

        Ok(())
    }

    /// Confirm verification with token and auto-login user.
    ///
    /// Validates the token, marks email/phone as verified, and creates
    /// a new session with tokens for seamless login.
    pub(super) async fn confirm_verification(
        &self,
        req: ConfirmVerificationRequest,
        client_ctx: ClientContext,
    ) -> Result<AuthResponse, Status> {
        req.validate_or_status()?;

        let verification_type = VerificationType::try_from(req.r#type).unwrap_or_default();

        let installation_id: Uuid = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        match verification_type {
            VerificationType::Email => {
                self.confirm_email_verification(&req.token, &installation_id, client_ctx)
                    .await
            }
            VerificationType::Phone => Err(Status::unimplemented(
                "Phone verification not yet supported",
            )),
            VerificationType::Unspecified => {
                Err(Status::invalid_argument("Verification type required"))
            }
        }
    }

    /// Confirm email verification and return auth response with tokens.
    ///
    /// Uses DB function for atomic operation:
    /// validate token → check status → consume → verify → activate → return user
    async fn confirm_email_verification(
        &self,
        token: &str,
        installation_id: &Uuid,
        client_ctx: ClientContext,
    ) -> Result<AuthResponse, Status> {
        let token_hash = TokenGenerator::hash_token(token);

        // Atomic: validate → check status → consume → verify → load user
        let user = self
            .ctx
            .db()
            .email_verifications
            .verify_email(&token_hash)
            .await
            .map_err(|e| match e {
                AppError::PermissionDenied(msg) => {
                    warn!(error = %msg, "Cannot verify suspended/deleted account");
                    Status::permission_denied("Account is not active")
                }
                AppError::NotFound(_) => {
                    warn!("Invalid or expired verification token");
                    Status::invalid_argument("Invalid or expired verification token")
                }
                _ => {
                    warn!(error = %e, "Verification failed");
                    Status::internal("Verification failed")
                }
            })?;

        // Create session and return tokens
        let tokens = self
            .create_session(&user, installation_id, &client_ctx)
            .await?;

        info!(
            user_id = %user.id,
            ip = ?client_ctx.ip_address(),
            country = ?client_ctx.ip_country(),
            "Email verified and user logged in"
        );

        Ok(Self::success_auth(&user, tokens))
    }
}
