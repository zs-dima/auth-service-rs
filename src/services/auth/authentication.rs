//! Authentication: sign-in, sign-up, sign-out.

use auth_core::{StatusExt, StrExt, UuidExt, ValidateExt};
use auth_db::CreateUserWithProfileParams;
use auth_proto::auth::{AuthResponse, AuthenticateRequest, IdentifierType, SignUpRequest};
use tonic::Status;
use tracing::{info, warn};
use uuid::Uuid;

use super::{AuthService, ClientContext};
use crate::core::password;

impl AuthService {
    /// Authenticates user with identifier (email/phone) and password.
    pub(super) async fn authenticate(
        &self,
        req: AuthenticateRequest,
        client_ctx: ClientContext,
    ) -> Result<AuthResponse, Status> {
        req.validate_or_status()?;

        let id_type = Self::resolve_identifier_type(req.identifier_type, &req.identifier);
        let identifier = Self::normalize_identifier(&req.identifier, id_type);

        info!(identifier = %identifier, id_type = ?id_type, "Authentication attempt");

        let installation_id: Uuid = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        let user = match id_type {
            IdentifierType::Phone => {
                self.ctx
                    .db()
                    .users
                    .get_active_user_by_phone(&identifier)
                    .await
            }
            _ => {
                self.ctx
                    .db()
                    .users
                    .get_active_user_by_email(&identifier)
                    .await
            }
        };

        let Ok(user) = user else {
            warn!(identifier = %identifier, "User not found");
            return Ok(Self::failed_auth());
        };

        let Some(password_hash) = user.password.as_deref() else {
            warn!(identifier = %identifier, "User has no password (OAuth-only account)");
            return Ok(Self::failed_auth());
        };

        if !password::verify(&req.password, password_hash) {
            warn!(identifier = %identifier, "Invalid password");
            return Ok(Self::failed_auth());
        }

        let tokens = self
            .create_session(&user, &installation_id, &client_ctx)
            .await?;

        info!(
            user_id = %user.id,
            ip = ?client_ctx.ip_address(),
            country = ?client_ctx.ip_country(),
            "Authentication successful"
        );

        Ok(Self::success_auth(&user, tokens))
    }

    /// Registers a new user account.
    pub(super) async fn sign_up(
        &self,
        req: SignUpRequest,
        client_ctx: ClientContext,
    ) -> Result<AuthResponse, Status> {
        req.validate_or_status()?;

        let id_type = Self::resolve_identifier_type(req.identifier_type, &req.identifier);
        let identifier = Self::normalize_identifier(&req.identifier, id_type);

        info!(identifier = %identifier, id_type = ?id_type, "Sign up attempt");

        let installation_id: Uuid = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        let password_hash = password::hash(&req.password).status("Failed to hash password")?;

        let user_exists = match id_type {
            IdentifierType::Phone => self
                .ctx
                .db()
                .users
                .get_user_by_phone(&identifier)
                .await
                .is_ok(),
            _ => self
                .ctx
                .db()
                .users
                .get_user_by_email(&identifier)
                .await
                .is_ok(),
        };

        if user_exists {
            warn!(identifier = %identifier, "Registration attempted with existing identifier");
            return Err(Status::already_exists("Registration failed"));
        }

        let (email, phone) = match id_type {
            IdentifierType::Phone => (None, Some(identifier.as_str())),
            _ => (Some(identifier.as_str()), None),
        };

        let user_id = self
            .ctx
            .db()
            .users
            .create_user_with_profile(CreateUserWithProfileParams {
                email,
                phone,
                password_hash: Some(&password_hash),
                role: "user",
                display_name: Some(&req.display_name),
                locale: req.locale.or_str("en"),
                timezone: req.timezone.or_str("UTC"),
            })
            .await
            .status("Failed to create user")?;

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .status("Failed to load created user")?;

        let tokens = self
            .create_session(&user, &installation_id, &client_ctx)
            .await?;

        // Send welcome email with verification link for self-registration
        if let Some(email) = &user.email {
            self.ctx.send_welcome_email(
                self.config.email_verification_ttl_hours,
                user_id,
                email.clone(),
                user.display_name.clone(),
                None,
            );
        }

        info!(
            user_id = %user_id,
            ip = ?client_ctx.ip_address(),
            country = ?client_ctx.ip_country(),
            "Sign up successful"
        );

        Ok(Self::success_auth(&user, tokens))
    }

    /// Signs out user by revoking all sessions.
    pub(super) async fn sign_out(&self, user_id: Uuid) -> Result<(), Status> {
        info!(user_id = %user_id, "Signing out");

        self.ctx
            .db()
            .sessions
            .revoke_all_user_sessions(user_id)
            .await
            .status("Sign out failed")?;

        info!(user_id = %user_id, "Signed out");
        Ok(())
    }
}
