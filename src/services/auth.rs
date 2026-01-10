//! Auth service gRPC implementation.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_stream::try_stream;
use auth_core::{
    AppError, OptionStatusExt, StatusExt, UuidExt, ValidateExt, json_to_proto_struct,
    proto_struct_to_json,
};
use auth_db::{
    CreatePasswordResetTokenParams, CreateSessionParams, CreateUserWithProfileParams, Database,
    UpdateUserParams, UpdateUserProfileParams, UserStatus, UserWithProfile, proto_to_role,
};
use auth_email::EmailService;
use auth_proto::auth::auth_service_server::AuthService;
use auth_proto::auth::{
    AuthInfo, AvatarUploadUrl, ConfirmAvatarUploadRequest, CreateUserRequest,
    GetAvatarUploadUrlRequest, ListSessionsReply, LoadUsersInfoRequest, RefreshTokenReply,
    RefreshTokenRequest, ResetPasswordRequest, RevokeSessionRequest, RevokeSessionsReply,
    SessionInfo as ProtoSessionInfo, SetPasswordRequest, SignInRequest, UpdateUserRequest,
    User as ProtoUser, UserId, UserInfo as ProtoUserInfo,
};
use auth_proto::core::ResultReply;
use auth_storage::S3Storage;
use chrono::Utc;
use ipnetwork::IpNetwork;
use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::core::{
    AuthInfo as CoreAuthInfo, Encryptor, GeolocationService, JwtValidator, TokenGenerator,
};
use crate::middleware::ClientIp;

/// Upload URL expiration (5 minutes).
const UPLOAD_URL_EXPIRES_SECS: u64 = 300;

/// Session tokens.
struct SessionTokens {
    access_token: String,
    refresh_token: String,
}

/// Client context extracted from request for session creation.
#[derive(Debug, Default)]
struct ClientContext {
    ip_address: Option<IpAddr>,
    ip_country: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    device_type: Option<String>,
    client_version: Option<String>,
    user_agent: Option<String>,
    metadata: Option<serde_json::Value>,
}

/// Hash a token with SHA-256 for storage.
fn hash_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
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
    password_reset_ttl_minutes: u32,
    db: Database,
    s3: Option<Arc<S3Storage>>,
    email: Option<Arc<EmailService>>,
    geolocation: GeolocationService,
}

impl AuthServiceImpl {
    pub fn new(
        jwt_validator: JwtValidator,
        access_token_ttl_minutes: u64,
        refresh_token_ttl_days: i64,
        password_reset_ttl_minutes: u32,
        db: Database,
        s3: Option<Arc<S3Storage>>,
        email: Option<Arc<EmailService>>,
        geolocation: GeolocationService,
    ) -> Self {
        Self {
            jwt_validator,
            access_token_ttl_minutes,
            refresh_token_ttl_days,
            password_reset_ttl_minutes,
            db,
            s3,
            email,
            geolocation,
        }
    }

    fn canonical_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Extract client context from request (IP address, geolocation, user-agent).
    fn extract_client_context<T>(&self, req: &Request<T>) -> ClientContext {
        // IP from ClientIp middleware (HTTP layer) or direct socket address
        let ip_address = req
            .extensions()
            .get::<ClientIp>()
            .and_then(ClientIp::ip)
            .or_else(|| req.remote_addr().map(|addr| addr.ip()));

        let ip_country = ip_address.and_then(|ip| self.geolocation.get_country_code(ip));

        let user_agent = req
            .metadata()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(500).collect());

        ClientContext {
            ip_address,
            ip_country,
            user_agent,
            ..Default::default()
        }
    }

    /// Build full client context from request and client info.
    fn build_client_context<T>(
        &self,
        req: &Request<T>,
        client_info: Option<&auth_proto::auth::ClientInfo>,
    ) -> ClientContext {
        let mut ctx = self.extract_client_context(req);

        if let Some(info) = client_info {
            ctx.device_id = if info.device_id.is_empty() {
                None
            } else {
                Some(info.device_id.clone())
            };
            // Use device_name from client directly; fallback to "Unknown device"
            ctx.device_name = if info.device_name.is_empty() {
                None
            } else {
                Some(info.device_name.clone())
            };
            ctx.device_type = if info.device_type.is_empty() {
                None
            } else {
                Some(info.device_type.clone())
            };
            ctx.client_version = if info.client_version.is_empty() {
                None
            } else {
                Some(info.client_version.clone())
            };
            ctx.metadata = info.metadata.as_ref().map(proto_struct_to_json);
        }

        ctx
    }

    /// Create session tokens for a user.
    async fn create_session(
        &self,
        user: &UserWithProfile,
        installation_id: &Uuid,
        ctx: &ClientContext,
    ) -> Result<SessionTokens, Status> {
        let device_id = ctx
            .device_id
            .as_deref()
            .ok_or_else(|| Status::invalid_argument("Missing device_id"))?;

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

        let refresh_token_hash = hash_token(&refresh_token);

        // Convert IP address to IpNetwork for storage
        let ip_network = ctx.ip_address.map(IpNetwork::from);

        // Build metadata JSON with user_agent and any additional client metadata
        let metadata = {
            let mut map = serde_json::Map::new();
            if let Some(ua) = &ctx.user_agent {
                map.insert(
                    "user_agent".to_string(),
                    serde_json::Value::String(ua.clone()),
                );
            }
            // Merge any additional client metadata
            if let Some(serde_json::Value::Object(extra)) = &ctx.metadata {
                for (k, v) in extra {
                    map.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(map)
        };

        self.db
            .sessions
            .create_session(CreateSessionParams {
                id_user: user.id,
                refresh_token_hash: refresh_token_hash.clone(),
                expires_at,
                device_id: Some(device_id.to_string()),
                device_name: ctx.device_name.clone(),
                device_type: ctx.device_type.clone(),
                client_version: ctx.client_version.clone(),
                ip_address: ip_network,
                ip_country: ctx.ip_country.clone(),
                metadata,
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
        // Extract client context before consuming request
        let client_ctx =
            self.build_client_context(&request, request.get_ref().client_info.as_ref());

        let req = request.into_inner();
        req.validate_or_status()?;

        let email = Self::canonical_email(&req.email);
        tracing::Span::current().record("email", &email);
        info!(email = %email, "Sign in attempt");

        let installation_id = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        let user = self
            .db
            .users
            .get_active_user_by_email(&email)
            .await
            .map_err(|e| {
                warn!(email = %email, error = %e, "User not found");
                Status::unauthenticated("Invalid credentials")
            })?;

        let password = user.password.as_deref().ok_or_else(|| {
            warn!(email = %email, "User has no password (OAuth-only account)");
            Status::unauthenticated("Invalid credentials")
        })?;

        if !Encryptor::verify(&req.password, password) {
            warn!(email = %email, "Invalid password");
            return Err(Status::unauthenticated("Invalid credentials"));
        }

        let tokens = self
            .create_session(&user, &installation_id, &client_ctx)
            .await?;

        info!(
            user_id = %user.id,
            ip = ?client_ctx.ip_address,
            country = ?client_ctx.ip_country,
            device_type = ?client_ctx.device_type,
            "Sign in successful"
        );

        Ok(Response::new(AuthInfo {
            user_id: Some(auth_db::models::ToProtoUuid::to_proto(&user.id)),
            user_name: user.display_name,
            user_role: auth_db::role_to_proto(&user.role),
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
            .revoke_all_user_sessions(auth.user_id)
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

        // Extract client context for session update
        let client_ctx = self.extract_client_context(&request);

        let req = request.into_inner();
        req.validate_or_status()?;

        debug!(user_id = %auth.user_id, "Refresh token request");

        // Hash the provided refresh token to compare with stored hash
        let token_hash = hash_token(&req.refresh_token);

        // Convert IP to IpNetwork for touch_session
        let ip_network = client_ctx.ip_address.map(IpNetwork::from);

        // Touch session validates and extends it, updates IP/country
        let _session = self
            .db
            .sessions
            .touch_session(&token_hash, ip_network, client_ctx.ip_country.as_deref())
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, error = %e, "Session not found or expired");
                Status::unauthenticated("Session expired")
            })?;

        let email = Self::canonical_email(&auth.email);
        let user = self
            .db
            .users
            .get_active_user_by_email(&email)
            .await
            .map_err(|e| {
                warn!(email = %email, error = %e, "User not found during token refresh");
                Status::unauthenticated("User not found")
            })?;

        // Build context with existing device info from JWT
        let ctx = ClientContext {
            ip_address: client_ctx.ip_address,
            ip_country: client_ctx.ip_country,
            device_id: Some(auth.device_id.to_string()),
            device_name: None, // Preserve existing from DB
            device_type: None,
            client_version: None,
            user_agent: None,
            metadata: None,
        };

        let tokens = self
            .create_session(&user, &auth.installation_id, &ctx)
            .await?;

        info!(
            user_id = %auth.user_id,
            ip = ?client_ctx.ip_address,
            "Token refreshed"
        );

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

        self.db
            .users
            .get_active_user_by_email(&email)
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, email = %email, error = %e, "User validation failed");
                Status::unauthenticated("User not found")
            })?;

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Request password reset.
    ///
    /// Always returns success to prevent user enumeration attacks.
    /// Sends password reset email asynchronously if user exists.
    #[instrument(skip(self, request), fields(email))]
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let req = request.into_inner();
        req.validate_or_status()?;

        let email = Self::canonical_email(&req.email);
        tracing::Span::current().record("email", &email);
        debug!(email = %email, "Password reset requested");

        // Check if email service is configured
        let Some(email_service) = self.email.clone() else {
            warn!("Password reset requested but email service not configured");
            // Still return success to prevent enumeration
            return Ok(Response::new(ResultReply { result: true }));
        };

        let db = self.db.clone();
        let password_reset_ttl_minutes = self.password_reset_ttl_minutes;

        // Process asynchronously to prevent timing attacks
        tokio::spawn(async move {
            // Look up user
            let user = match db.users.get_active_user_by_email(&email).await {
                Ok(user) => user,
                Err(_) => {
                    debug!(email = %email, "User not found for password reset");
                    return;
                }
            };

            // Generate secure token (URL-safe base64, 32 bytes of entropy)
            let token = TokenGenerator::generate_secure_token();
            let token_hash = hash_token(&token);

            // Calculate expiration
            let expires_at =
                Utc::now() + chrono::Duration::minutes(i64::from(password_reset_ttl_minutes));

            // Store token hash in database
            if let Err(e) = db
                .password_resets
                .create_token(CreatePasswordResetTokenParams {
                    id_user: user.id,
                    token_hash,
                    expires_at,
                })
                .await
            {
                error!(user_id = %user.id, error = %e, "Failed to create password reset token");
                return;
            }

            // Send email
            if let Err(e) = email_service
                .send_password_reset(&email, &user.display_name, &token, password_reset_ttl_minutes)
                .await
            {
                error!(user_id = %user.id, error = %e, "Failed to send password reset email");
                return;
            }

            info!(user_id = %user.id, "Password reset email sent");
        });

        // Always return success to prevent user enumeration
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
        let target_email = target.email.as_deref().map(Self::canonical_email);
        if target_email.as_deref() != Some(&email) {
            warn!(
                target_user_id = %target_id,
                provided_email = %req.email,
                expected_email = ?target.email,
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

        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", &admin.user_id.to_string());
        info!(admin_id = %admin.user_id, email = %email, "Creating user");

        let hash = Self::hash_password(&req.password)?;
        let role = proto_to_role(req.role)?;

        let user_id = self
            .db
            .users
            .create_user_with_profile(CreateUserWithProfileParams {
                email,
                password_hash: Some(hash),
                role: role.to_string(),
                display_name: Some(req.name),
                locale: "en".to_string(),
                timezone: "UTC".to_string(),
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

        let role = proto_to_role(req.role)?;
        let status = if req.deleted {
            UserStatus::Deleted
        } else {
            UserStatus::Active
        };

        self.db
            .users
            .update_user(UpdateUserParams {
                id: user_id,
                role: role.to_string(),
                email: Some(email.clone()),
                email_verified: true,
                phone: None,
                phone_verified: false,
                status,
            })
            .await
            .status("Failed to update user")?;

        // Update profile display name
        self.db
            .users
            .update_user_profile(UpdateUserProfileParams {
                id_user: user_id,
                display_name: req.name,
                avatar_url: None,
                locale: "en".to_string(),
                timezone: "UTC".to_string(),
            })
            .await
            .status("Failed to update user profile")?;

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

    // =========================================================================
    // Session Management
    // =========================================================================

    /// List all active sessions for the current user.
    #[instrument(skip(self, request), fields(user_id))]
    async fn list_sessions(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListSessionsReply>, Status> {
        let auth = require_auth(&request)?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        debug!(user_id = %auth.user_id, "Listing sessions");

        // We need the current session's token hash to mark it as current
        // Since we don't have it directly, we use a placeholder (empty) for now
        // The current session will be identified by device_id instead
        let sessions = self
            .db
            .sessions
            .list_user_sessions(auth.user_id, &[])
            .await
            .status("Failed to list sessions")?;

        let proto_sessions: Vec<ProtoSessionInfo> = sessions
            .into_iter()
            .map(|s| {
                // Mark as current if device_id matches
                let is_current = s.device_id.as_deref() == Some(&auth.device_id.to_string());

                ProtoSessionInfo {
                    device_id: s.device_id.unwrap_or_default(),
                    device_name: s.device_name.unwrap_or_default(),
                    device_type: s.device_type.unwrap_or_else(|| "unknown".to_string()),
                    client_version: s.client_version.unwrap_or_default(),
                    ip_address: s
                        .ip_address
                        .map(|ip| ip.ip().to_string())
                        .unwrap_or_default(),
                    ip_country: s.ip_country.unwrap_or_default(),
                    created_at: s.created_at.timestamp_millis(),
                    last_seen_at: s.last_seen_at.timestamp_millis(),
                    expires_at: s.expires_at.timestamp_millis(),
                    is_current,
                    ip_created_by: s
                        .ip_created_by
                        .map(|ip| ip.ip().to_string())
                        .unwrap_or_default(),
                    activity_count: s.activity_count,
                    metadata: json_to_proto_struct(s.metadata),
                }
            })
            .collect();

        info!(user_id = %auth.user_id, count = proto_sessions.len(), "Sessions listed");

        Ok(Response::new(ListSessionsReply {
            sessions: proto_sessions,
        }))
    }

    /// Revoke a specific session by device_id.
    #[instrument(skip(self, request), fields(user_id))]
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = require_auth(&request)?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        let req = request.into_inner();
        req.validate_or_status()?;

        debug!(user_id = %auth.user_id, device_id = %req.device_id, "Revoking session");

        // Revoke session by device_id for this user
        let revoked = self
            .db
            .sessions
            .revoke_session_by_device_id(auth.user_id, &req.device_id)
            .await
            .status("Failed to revoke session")?;

        if revoked {
            info!(user_id = %auth.user_id, device_id = %req.device_id, "Session revoked");
        } else {
            debug!(user_id = %auth.user_id, device_id = %req.device_id, "Session not found");
        }

        Ok(Response::new(ResultReply { result: revoked }))
    }

    /// Revoke all sessions except the current one.
    #[instrument(skip(self, request), fields(user_id))]
    async fn revoke_other_sessions(
        &self,
        request: Request<()>,
    ) -> Result<Response<RevokeSessionsReply>, Status> {
        let auth = require_auth(&request)?;
        tracing::Span::current().record("user_id", &auth.user_id.to_string());

        debug!(user_id = %auth.user_id, "Revoking other sessions");

        // Revoke all sessions except current device
        let count = self
            .db
            .sessions
            .revoke_sessions_except_device(auth.user_id, &auth.device_id.to_string())
            .await
            .status("Failed to revoke sessions")?;

        info!(user_id = %auth.user_id, count, "Other sessions revoked");

        Ok(Response::new(RevokeSessionsReply {
            revoked_count: count as i32,
        }))
    }
}
