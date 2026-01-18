//! gRPC `AuthService` trait implementation.
//!
//! Thin handlers that extract auth/context and delegate to domain methods.

use auth_core::{RequestAuthExt, ToProtoTimestamp, TokenGenerator, ValidateExt};
use auth_proto::auth::auth_service_server::AuthService as AuthServiceTrait;
use auth_proto::auth::{
    AuthResponse, AuthenticateRequest, ChangePasswordRequest, ConfirmMfaSetupRequest,
    ConfirmMfaSetupResponse, ConfirmVerificationRequest, DisableMfaRequest,
    ExchangeOAuthCodeRequest, GetMfaStatusRequest, GetMfaStatusResponse, GetOAuthUrlRequest,
    GetOAuthUrlResponse, LinkOAuthProviderRequest, ListLinkedProvidersRequest,
    ListLinkedProvidersResponse, ListSessionsRequest, ListSessionsResponse, RecoveryConfirmRequest,
    RecoveryStartRequest, RefreshTokensRequest, RequestVerificationRequest,
    RevokeOtherSessionsRequest, RevokeSessionRequest, RevokeSessionsResponse, SetupMfaRequest,
    SetupMfaResponse, SignOutRequest, SignUpRequest, TokenPair, UnlinkOAuthProviderRequest,
    ValidateCredentialsRequest, ValidateCredentialsResponse, VerifyMfaRequest,
};
use tonic::{Request, Response, Status};
use tracing::instrument;

use super::AuthService;

#[tonic::async_trait]
impl AuthServiceTrait for AuthService {
    // ========================================================================
    // Authentication
    // ========================================================================

    #[instrument(skip(self, request), fields(identifier))]
    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let ctx = self.build_client_context(&request, request.get_ref().client_info.as_ref());
        let result = self.authenticate(request.into_inner(), ctx).await?;
        Ok(Response::new(result))
    }

    #[instrument(skip(self, request), fields(identifier))]
    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let ctx = self.build_client_context(&request, request.get_ref().client_info.as_ref());
        let result = self.sign_up(request.into_inner(), ctx).await?;
        Ok(Response::new(result))
    }

    #[instrument(skip(self, _request))]
    async fn verify_mfa(
        &self,
        _request: Request<VerifyMfaRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        Err(Status::unimplemented("MFA not yet supported"))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn sign_out(&self, request: Request<SignOutRequest>) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        self.sign_out(auth.user_id).await?;
        Ok(Response::new(()))
    }

    // ========================================================================
    // Token Management
    // ========================================================================

    #[instrument(skip(self, request), fields(user_id))]
    async fn refresh_tokens(
        &self,
        request: Request<RefreshTokensRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let ctx = self.extract_client_context(&request);
        let tokens = self
            .refresh_tokens(
                request.into_inner(),
                auth.user_id,
                &auth.device_id,
                &auth.installation_id,
                ctx,
            )
            .await?;

        Ok(Response::new(TokenPair {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Some(tokens.access_token_expires_at.to_proto_timestamp()),
        }))
    }

    #[instrument(skip(self, request))]
    async fn validate_credentials(
        &self,
        request: Request<ValidateCredentialsRequest>,
    ) -> Result<Response<ValidateCredentialsResponse>, Status> {
        let auth = request.auth()?;
        let valid = self.validate_credentials(auth.user_id).await?;
        Ok(Response::new(ValidateCredentialsResponse {
            valid,
            user: None,
        }))
    }

    // ========================================================================
    // Password Management
    // ========================================================================

    #[instrument(skip(self, request), fields(identifier))]
    async fn recovery_start(
        &self,
        request: Request<RecoveryStartRequest>,
    ) -> Result<Response<()>, Status> {
        self.recovery_start(request.into_inner()).await?;
        Ok(Response::new(()))
    }

    #[instrument(skip(self, request), fields(token_len))]
    async fn recovery_confirm(
        &self,
        request: Request<RecoveryConfirmRequest>,
    ) -> Result<Response<()>, Status> {
        self.recovery_confirm(request.into_inner()).await?;
        Ok(Response::new(()))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        self.change_password(request.into_inner(), auth.user_id, &auth.device_id)
            .await?;
        Ok(Response::new(()))
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    #[instrument(skip(self, request), fields(user_id))]
    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let req = request.into_inner();
        req.validate_or_status()?;

        let token_hash = TokenGenerator::hash_token(&req.refresh_token);
        let reply = self.list_sessions(auth.user_id, &token_hash).await?;
        Ok(Response::new(reply))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        self.revoke_session(request.into_inner(), auth.user_id)
            .await?;
        Ok(Response::new(()))
    }

    #[instrument(skip(self, request), fields(user_id))]
    async fn revoke_other_sessions(
        &self,
        request: Request<RevokeOtherSessionsRequest>,
    ) -> Result<Response<RevokeSessionsResponse>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let count = self
            .revoke_other_sessions(auth.user_id, &auth.device_id)
            .await?;
        Ok(Response::new(RevokeSessionsResponse {
            revoked_count: count,
        }))
    }

    // ========================================================================
    // OAuth 2.0 (Stubs)
    // ========================================================================

    #[instrument(skip(self, _request))]
    async fn get_o_auth_url(
        &self,
        _request: Request<GetOAuthUrlRequest>,
    ) -> Result<Response<GetOAuthUrlResponse>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn exchange_o_auth_code(
        &self,
        _request: Request<ExchangeOAuthCodeRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn link_o_auth_provider(
        &self,
        _request: Request<LinkOAuthProviderRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn unlink_o_auth_provider(
        &self,
        _request: Request<UnlinkOAuthProviderRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn list_linked_providers(
        &self,
        _request: Request<ListLinkedProvidersRequest>,
    ) -> Result<Response<ListLinkedProvidersResponse>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    // ========================================================================
    // Verification
    // ========================================================================

    #[instrument(skip(self, request), fields(user_id))]
    async fn request_verification(
        &self,
        request: Request<RequestVerificationRequest>,
    ) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        self.request_verification(request.into_inner(), auth.user_id)
            .await?;
        Ok(Response::new(()))
    }

    #[instrument(skip(self, request))]
    async fn confirm_verification(
        &self,
        request: Request<ConfirmVerificationRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let ctx = self.build_client_context(&request, request.get_ref().client_info.as_ref());
        let result = self.confirm_verification(request.into_inner(), ctx).await?;
        Ok(Response::new(result))
    }

    // ========================================================================
    // MFA (Stubs)
    // ========================================================================

    #[instrument(skip(self, _request))]
    async fn get_mfa_status(
        &self,
        _request: Request<GetMfaStatusRequest>,
    ) -> Result<Response<GetMfaStatusResponse>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn setup_mfa(
        &self,
        _request: Request<SetupMfaRequest>,
    ) -> Result<Response<SetupMfaResponse>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn confirm_mfa_setup(
        &self,
        _request: Request<ConfirmMfaSetupRequest>,
    ) -> Result<Response<ConfirmMfaSetupResponse>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    #[instrument(skip(self, _request))]
    async fn disable_mfa(
        &self,
        _request: Request<DisableMfaRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }
}
