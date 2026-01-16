//! Token management: refresh and validation.

use auth_core::{SessionTokens, ValidateExt};
use auth_db::UserStatus;
use auth_proto::auth::RefreshTokensRequest;
use tonic::Status;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{AuthService, ClientContext, TokenGenerator};

impl AuthService {
    /// Refreshes access and refresh tokens.
    pub(super) async fn refresh_tokens(
        &self,
        req: RefreshTokensRequest,
        user_id: Uuid,
        device_id: &str,
        installation_id: &Uuid,
        client_ctx: ClientContext,
    ) -> Result<SessionTokens, Status> {
        req.validate_or_status()?;

        debug!(user_id = %user_id, "Refresh token request");

        let token_hash = TokenGenerator::hash_token(&req.refresh_token);

        self.ctx
            .db()
            .sessions
            .touch_session(
                token_hash.as_slice(),
                client_ctx.ip_network(),
                client_ctx.ip_country(),
            )
            .await
            .map_err(|e| {
                warn!(user_id = %user_id, error = %e, "Session not found or expired");
                Status::unauthenticated("Session expired")
            })?;

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .map_err(|e| {
                warn!(user_id = %user_id, error = %e, "User not found during token refresh");
                Status::unauthenticated("User not found")
            })?;

        if user.status != UserStatus::Active {
            warn!(user_id = %user_id, status = ?user.status, "Inactive user attempted token refresh");
            return Err(Status::permission_denied("Account is not active"));
        }

        let ctx = ClientContext::default()
            .with_ip(client_ctx.ip_address())
            .with_country(client_ctx.ip_country().map(ToString::to_string))
            .with_device_id(Some(device_id.to_string()));

        let tokens = self.create_session(&user, installation_id, &ctx).await?;

        info!(user_id = %user_id, ip = ?client_ctx.ip_address(), "Token refreshed");

        Ok(tokens)
    }

    /// Validates that credentials (JWT) belong to an active user.
    pub(super) async fn validate_credentials(&self, user_id: Uuid) -> Result<bool, Status> {
        debug!(user_id = %user_id, "Validating credentials");

        let user = self
            .ctx
            .db()
            .users
            .get_user_by_id(user_id)
            .await
            .map_err(|e| {
                warn!(user_id = %user_id, error = %e, "User validation failed");
                Status::unauthenticated("User not found")
            })?;

        if user.status != UserStatus::Active {
            warn!(user_id = %user_id, status = ?user.status, "Inactive user attempted validation");
            return Err(Status::permission_denied("Account is not active"));
        }

        Ok(true)
    }
}
