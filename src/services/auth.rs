//! Auth service gRPC implementation.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::try_stream;
use auth_core::{AppError, OptionStatusExt, StatusExt, UuidExt, ValidateExt};
use auth_db::{
    CreateUserParams, Database, SaveUserSessionParams, UpdateUserParams, User,
    UserRole as DbUserRole,
};
use auth_proto::auth::auth_service_server::AuthService;
use auth_proto::auth::{
    AuthInfo, AvatarUploadUrl, ConfirmAvatarUploadRequest, CreateUserRequest,
    GetAvatarUploadUrlRequest, LoadUsersInfoRequest, RefreshTokenReply, RefreshTokenRequest,
    ResetPasswordRequest, SetPasswordRequest, SignInRequest, UpdateUserRequest, User as ProtoUser,
    UserId, UserInfo as ProtoUserInfo,
};
use auth_proto::core::ResultReply;
use auth_storage::S3Storage;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::core::{AuthInfo as CoreAuthInfo, Encryptor, JwtValidator, TokenGenerator};

/// Upload URL expiration (5 minutes).
const UPLOAD_URL_EXPIRES_SECS: u64 = 300;

/// Session tokens.
struct SessionTokens {
    access_token: String,
    refresh_token: String,
}

fn require_auth<T>(req: &Request<T>) -> Result<CoreAuthInfo, Status> {
    req.extensions()
        .get::<CoreAuthInfo>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Authentication required"))
}

fn require_admin<T>(req: &Request<T>) -> Result<CoreAuthInfo, Status> {
    let auth = require_auth(req)?;
    if !auth.is_admin() {
        return Err(Status::permission_denied("Admin access required"));
    }
    Ok(auth)
}

/// Auth service implementation.
pub struct AuthServiceImpl {
    jwt_validator: JwtValidator,
    access_token_ttl_minutes: u64,
    refresh_token_ttl_days: i64,
    db: Database,
    s3: Option<Arc<S3Storage>>,
}

impl AuthServiceImpl {
    pub fn new(
        jwt_validator: JwtValidator,
        access_token_ttl_minutes: u64,
        refresh_token_ttl_days: i64,
        db: Database,
        s3: Option<Arc<S3Storage>>,
    ) -> Self {
        Self {
            jwt_validator,
            access_token_ttl_minutes,
            refresh_token_ttl_days,
            db,
            s3,
        }
    }

    fn canonical_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Create session tokens for a user.
    async fn create_session(
        &self,
        user: &User,
        device_id: &Uuid,
        installation_id: &Uuid,
    ) -> Result<SessionTokens, Status> {
        let access_token = self
            .jwt_validator
            .generate_access_token(
                user,
                device_id,
                installation_id,
                self.access_token_ttl_minutes,
            )
            .status("Failed to generate access token")?;

        let (refresh_token, expires_at) =
            TokenGenerator::generate_refresh_token(self.refresh_token_ttl_days)
                .status("Failed to generate refresh token")?;

        let refresh_token_hash =
            Encryptor::hash(&refresh_token).status("Failed to hash refresh token")?;

        self.db
            .sessions
            .save_user_session(SaveUserSessionParams {
                user_id: user.id,
                refresh_token: refresh_token_hash,
                expires_at,
            })
            .await
            .status("Failed to save session")?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
        })
    }

    fn hash_password(password: &str) -> Result<String, Status> {
        Encryptor::hash(password).status("Failed to hash password")
    }

    fn require_s3(&self) -> Result<&Arc<S3Storage>, Status> {
        self.s3.as_ref().ok_or_else(|| {
            error!("S3 not configured");
            Status::internal("Storage not configured")
        })
    }

    async fn delete_avatar(&self, user_id: &Uuid) -> Result<(), Status> {
        if let Some(s3) = &self.s3 {
            s3.delete_avatar(user_id)
                .await
                .status("Failed to delete avatar")?;
            debug!(user_id = %user_id, "Avatar deleted from S3");
        }
        Ok(())
    }
}

type StreamResult<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    /// Sign in with email and password.
    #[instrument(skip(self, request), fields(email))]
    async fn sign_in(&self, request: Request<SignInRequest>) -> Result<Response<AuthInfo>, Status> {
        let req = request.into_inner();
        req.validate_or_status()?;

        let email = Self::canonical_email(&req.email);
        tracing::Span::current().record("email", &email);
        info!(email = %email, "Sign in attempt");

        let device_id = req
            .device_info
            .as_ref()
            .and_then(|d| d.id.as_ref())
            .parse_or_status_with_field("device_id")?;
        let installation_id = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        let user = self.db.users.get_active_user(&email).await.map_err(|e| {
            warn!(email = %email, error = %e, "User not found");
            Status::unauthenticated("Invalid credentials")
        })?;

        if !Encryptor::verify(&req.password, &user.password) {
            warn!(email = %email, "Invalid password");
            return Err(Status::unauthenticated("Invalid credentials"));
        }

        let tokens = self
            .create_session(&user, &device_id, &installation_id)
            .await?;
        info!(user_id = %user.id, "Sign in successful");

        Ok(Response::new(AuthInfo {
            user_id: Some(auth_db::models::ToProtoUuid::to_proto(&user.id)),
            user_name: user.name,
            user_role: user.role.into(),
            refresh_token: tokens.refresh_token,
            access_token: tokens.access_token,
        }))
    }

    /// Sign out the current user.
    #[instrument(skip(self, request), fields(user_id))]
    async fn sign_out(&self, request: Request<()>) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        info!(user_id = %auth.user_id, "Signing out");

        self.db
            .sessions
            .end_user_session(auth.user_id)
            .await
            .status("Sign out failed")?;
        info!(user_id = %auth.user_id, "Signed out");

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Refresh access and refresh tokens.
    #[instrument(skip(self, request), fields(user_id))]
    async fn refresh_tokens(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenReply>, Status> {
        let auth = require_auth(&request)?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        let req = request.into_inner();
        req.validate_or_status()?;

        debug!(user_id = %auth.user_id, "Refresh token request");

        let stored_hash = self
            .db
            .sessions
            .load_refresh_token(auth.user_id)
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, error = %e, "Session not found");
                Status::unauthenticated("Session expired")
            })?;

        if !Encryptor::verify(&req.refresh_token, &stored_hash) {
            warn!(user_id = %auth.user_id, "Invalid refresh token");
            return Err(Status::unauthenticated("Invalid refresh token"));
        }

        let email = Self::canonical_email(&auth.email);
        let user = self.db.users.get_active_user(&email).await.map_err(|e| {
            warn!(email = %email, error = %e, "User not found during token refresh");
            Status::unauthenticated("User not found")
        })?;

        let tokens = self
            .create_session(&user, &auth.device_id, &auth.installation_id)
            .await?;
        info!(user_id = %auth.user_id, "Token refreshed");

        Ok(Response::new(RefreshTokenReply {
            refresh_token: tokens.refresh_token,
            access_token: tokens.access_token,
        }))
    }

    /// Validate current credentials (auth check).
    #[instrument(skip(self, request))]
    async fn validate_credentials(
        &self,
        request: Request<()>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;

        debug!(user_id = %auth.user_id, "Validating credentials");

        let email = Self::canonical_email(&auth.email);

        self.db.users.get_active_user(&email).await.map_err(|e| {
            warn!(user_id = %auth.user_id, email = %email, error = %e, "User validation failed");
            Status::unauthenticated("User not found")
        })?;

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Request password reset.
    ///
    /// Always returns success to prevent user enumeration attacks.
    #[instrument(skip(self, request))]
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let req = request.into_inner();
        req.validate_or_status()?;

        let email = Self::canonical_email(&req.email);
        debug!(email = %email, "Password reset requested");

        let db = self.db.clone();
        tokio::spawn(async move {
            if let Ok(user) = db.users.get_active_user(&email).await {
                info!(user_id = %user.id, "Password reset token generated");
                // TODO: Send email
            }
        });

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Set a new password (requires admin or self).
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn set_password(
        &self,
        request: Request<SetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", &target_id.to_string());

        auth.require_access(target_id, "change password")?;

        let target = self.db.users.get_user_by_id(target_id).await.map_err(|e| {
            warn!(target_user_id = %target_id, error = %e, "User not found for password change");
            Status::not_found("User not found")
        })?;

        let email = Self::canonical_email(&req.email);
        if Self::canonical_email(&target.email) != email {
            warn!(
                target_user_id = %target_id,
                provided_email = %req.email,
                expected_email = %target.email,
                "Email mismatch in password change"
            );
            return Err(Status::invalid_argument("Email does not match user"));
        }

        let hash = Self::hash_password(&req.password)?;
        self.db
            .users
            .update_user_password(&email, &hash)
            .await
            .status("Failed to update password")?;

        info!(user_id = %target_id, "Password updated");
        Ok(Response::new(ResultReply { result: true }))
    }

    type LoadUsersInfoStream = StreamResult<ProtoUserInfo>;

    /// Load user info (streaming) - requires admin.
    #[instrument(skip(self, request), fields(user_id))]
    async fn load_users_info(
        &self,
        request: Request<LoadUsersInfoRequest>,
    ) -> Result<Response<Self::LoadUsersInfoStream>, Status> {
        let admin = require_admin(&request)?;
        tracing::Span::current().record("user_id", &admin.user_id.to_string());

        let user_ids: Vec<Uuid> = request
            .into_inner()
            .user_ids
            .iter()
            .filter_map(|id| Uuid::parse_str(&id.value).ok())
            .collect();

        debug!(
            user_id = %admin.user_id,
            filter_count = user_ids.len(),
            "Loading users info"
        );

        let db = self.db.clone();
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

        Ok(Response::new(Box::pin(stream)))
    }

    type LoadUsersStream = StreamResult<ProtoUser>;

    /// Load users (streaming).
    #[instrument(skip(self, request), fields(user_id))]
    async fn load_users(
        &self,
        request: Request<UserId>,
    ) -> Result<Response<Self::LoadUsersStream>, Status> {
        let auth = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        let db = self.db.clone();
        let is_admin = auth.is_admin();
        let user_id = auth.user_id;

        let stream = try_stream! {
            if is_admin {
                let mut rows = db.users.stream_all_users();
                while let Some(result) = rows.next().await {
                    let user = result.map_err(|e| {
                        error!(error = %e, "Failed to stream users");
                        Status::from(AppError::Unavailable(e.to_string()))
                    })?;
                    yield ProtoUser::from(user);
                }
            } else {
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

        Ok(Response::new(Box::pin(stream)))
    }

    /// Create a new user - requires admin.
    #[instrument(skip(self, request), fields(admin_id, new_user_id))]
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let admin = require_admin(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", &admin.user_id.to_string());
        tracing::Span::current().record("new_user_id", &user_id.to_string());
        info!(admin_id = %admin.user_id, new_user_id = %user_id, email = %email, "Creating user");

        let hash = Self::hash_password(&req.password)?;
        let role = DbUserRole::try_from(req.role)?;

        self.db
            .users
            .create_user(CreateUserParams {
                id: user_id,
                name: req.name,
                email,
                password: hash,
                role,
                deleted: req.deleted,
            })
            .await
            .status("Failed to create user")?;

        info!(user_id = %user_id, created_by = %admin.user_id, "User created");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Update an existing user - requires admin.
    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let admin = require_admin(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", &admin.user_id.to_string());
        tracing::Span::current().record("target_user_id", &user_id.to_string());
        info!(
            admin_id = %admin.user_id,
            target_user_id = %user_id,
            "Updating user"
        );

        let role = DbUserRole::try_from(req.role)?;

        self.db
            .users
            .update_user(UpdateUserParams {
                id: user_id,
                name: req.name,
                email,
                role,
                deleted: req.deleted,
            })
            .await
            .status("Failed to update user")?;

        info!(user_id = %user_id, updated_by = %admin.user_id, "User updated");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Get a presigned URL for uploading avatar directly to S3.
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn get_avatar_upload_url(
        &self,
        request: Request<GetAvatarUploadUrlRequest>,
    ) -> Result<Response<AvatarUploadUrl>, Status> {
        let auth = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", &target_id.to_string());

        auth.require_access(target_id, "upload avatar")?;
        self.db
            .users
            .get_user_by_id(target_id)
            .await
            .map_err(|_| Status::not_found("User not found"))?;

        let s3 = self.require_s3()?;
        let presigned = s3
            .presign_avatar_upload(
                &target_id,
                &req.content_type,
                req.content_size,
                UPLOAD_URL_EXPIRES_SECS,
            )
            .await
            .status("Failed to generate S3 upload URL")?;

        info!(user_id = %target_id, "Upload URL generated");
        Ok(Response::new(AvatarUploadUrl {
            upload_url: presigned.url,
            expires_in: presigned.expires_in_secs,
        }))
    }

    /// Confirm avatar upload completed.
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn confirm_avatar_upload(
        &self,
        request: Request<ConfirmAvatarUploadRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", &target_id.to_string());

        auth.require_access(target_id, "confirm avatar upload")?;

        let s3 = self.require_s3()?;

        s3.avatar_exists(&target_id)
            .await
            .status("Failed to check avatar")?
            .then_some(())
            .ok_or_not_found("Avatar not uploaded")?;

        info!(user_id = %target_id, "Avatar upload confirmed");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Delete user avatar from S3.
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn delete_user_avatar(
        &self,
        request: Request<UserId>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", &target_id.to_string());

        auth.require_access(target_id, "delete avatar")?;
        self.delete_avatar(&target_id).await?;

        info!(user_id = %target_id, "Avatar deleted");
        Ok(Response::new(ResultReply { result: true }))
    }
}
