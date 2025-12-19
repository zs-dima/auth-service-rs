use std::pin::Pin;
use std::sync::Arc;

use async_stream::try_stream;
use image::ImageFormat;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::auth::{Encryptor, TokenGenerator, require_admin, require_auth};
use crate::db::{
    CreateUserParams, Database, SaveUserPhotoParams, SaveUserSessionParams, UpdateUserParams, User,
    UserRole as DbUserRole,
};
use crate::error::{AppError, StatusExt};
use crate::extensions::{ToProtoUuid, UuidExt};
use crate::proto::auth::auth_service_server::AuthService;
use crate::proto::auth::{
    AuthInfo, CreateUserRequest, LoadUserAvatarRequest, RefreshTokenReply, RefreshTokenRequest,
    ResetPasswordRequest, SetPasswordRequest, SignInRequest, UpdateUserRequest, User as ProtoUser,
    UserAvatar as ProtoUserAvatar, UserId, UserInfo as ProtoUserInfo, UserPhoto,
};
use crate::proto::core::ResultReply;
use crate::util::to_avatar;
use crate::validation::ValidateExt;

/// Auth service configuration (only what the service needs)
#[derive(Debug, Clone)]
pub struct AuthServiceConfig {
    pub jwt_secret_key: String,
    pub access_token_ttl_minutes: u64,
    pub refresh_token_ttl_days: i64,
}

/// Auth service implementation
pub struct AuthServiceImpl {
    config: AuthServiceConfig,
    db: Arc<Database>,
}

/// Session tokens (access + refresh)
struct SessionTokens {
    access_token: String,
    refresh_token: String,
}

impl AuthServiceImpl {
    const MAX_PHOTO_BYTES: usize = 2 * 1024 * 1024;

    pub fn new(config: AuthServiceConfig, db: Arc<Database>) -> Self {
        Self { config, db }
    }

    fn canonical_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Create session tokens for a user (reduces duplication in sign_in/refresh_tokens)
    async fn create_session(
        &self,
        user: &User,
        device_id: &Uuid,
        installation_id: &Uuid,
    ) -> Result<SessionTokens, Status> {
        let access_token = TokenGenerator::generate_access_token(
            user,
            device_id,
            installation_id,
            &self.config.jwt_secret_key,
            self.config.access_token_ttl_minutes,
        )
        .status("Failed to generate access token")?;

        let (refresh_token, expires_at) =
            TokenGenerator::generate_refresh_token(self.config.refresh_token_ttl_days)
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

    /// Hash a password with error conversion
    fn hash_password(password: &str) -> Result<String, Status> {
        Encryptor::hash(password).status("Failed to hash password")
    }
}

/// Stream result type alias for gRPC streaming responses.
type StreamResult<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    /// Sign in with email and password
    #[instrument(skip(self, request), fields(email))]
    async fn sign_in(&self, request: Request<SignInRequest>) -> Result<Response<AuthInfo>, Status> {
        let req = request.into_inner();

        // Schema-level validation (email format, required fields, etc.)
        req.validate_or_status()?;

        let user_email = Self::canonical_email(&req.email);
        tracing::Span::current().record("email", &user_email);
        info!(email = %user_email, "Sign in attempt");

        let device_id = req
            .device_info
            .as_ref()
            .and_then(|d| d.id.as_ref())
            .parse_or_status_with_field("device_id")?;
        let installation_id = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        // Get user from database
        let user = self
            .db
            .users
            .get_active_user(&user_email)
            .await
            .map_err(|e| {
                warn!(email = %user_email, error = %e, "User not found");
                Status::unauthenticated("Invalid credentials")
            })?;

        // Validate password
        if !Encryptor::verify(&req.password, &user.password) {
            warn!(email = %user_email, "Invalid password");
            return Err(Status::unauthenticated("Invalid credentials"));
        }

        // Create session tokens
        let tokens = self
            .create_session(&user, &device_id, &installation_id)
            .await?;

        info!(user_id = %user.id, "Sign in successful");

        Ok(Response::new(AuthInfo {
            user_id: Some(user.id.to_proto()),
            user_name: user.name,
            user_role: user.role.into(),
            blurhash: user.blurhash,
            refresh_token: tokens.refresh_token,
            access_token: tokens.access_token,
        }))
    }

    /// Sign out the current user
    #[instrument(skip(self, request), fields(user_id))]
    async fn sign_out(&self, request: Request<()>) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_auth(&request)?;
        let user_id = auth_info.user_info.id;
        tracing::Span::current().record("user_id", user_id.to_string());

        info!(user_id = %user_id, "Sign out");

        self.db
            .sessions
            .end_user_session(user_id)
            .await
            .status("Sign out failed")?;

        debug!(user_id = %user_id, "Sign out successful");

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Refresh access and refresh tokens
    #[instrument(skip(self, request), fields(user_id))]
    async fn refresh_tokens(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenReply>, Status> {
        let auth_info = require_auth(&request)?;
        let user_id = auth_info.user_info.id;
        let device_id = auth_info.device_id;
        let installation_id = auth_info.installation_id;
        tracing::Span::current().record("user_id", user_id.to_string());

        let req = request.into_inner();

        // Schema-level validation
        req.validate_or_status()?;

        debug!(user_id = %user_id, "Refresh token request");

        // Load stored refresh token hash
        let refresh_token_hash =
            self.db
                .sessions
                .load_refresh_token(user_id)
                .await
                .map_err(|e| {
                    warn!(user_id = %user_id, error = %e, "Session not found");
                    Status::unauthenticated("Session expired")
                })?;

        // Validate provided refresh token
        if !Encryptor::verify(&req.refresh_token, &refresh_token_hash) {
            warn!(user_id = %user_id, "Invalid refresh token");
            return Err(Status::unauthenticated("Invalid refresh token"));
        }

        // Get user
        let email = Self::canonical_email(&auth_info.user_info.email);
        let user = self
            .db
            .users
            .get_active_user(&email)
            .await
            .map_err(|_| Status::unauthenticated("User not found"))?;

        // Create new session tokens
        let tokens = self
            .create_session(&user, &device_id, &installation_id)
            .await?;

        info!(user_id = %user_id, "Token refreshed");

        Ok(Response::new(RefreshTokenReply {
            refresh_token: tokens.refresh_token,
            access_token: tokens.access_token,
        }))
    }

    /// Validate current credentials (Auth check)
    #[instrument(skip(self, request))]
    async fn validate_credentials(
        &self,
        request: Request<()>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_auth(&request)?;

        debug!(user_id = %auth_info.user_info.id, "Validating credentials");

        // Verify user still exists and is active
        let email = Self::canonical_email(&auth_info.user_info.email);
        self.db
            .users
            .get_active_user(&email)
            .await
            .map_err(|_| Status::unauthenticated("User not found"))?;

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Request password reset (sends email link)
    ///
    /// Always returns success to prevent user enumeration attacks.
    /// Actual email sending should be done asynchronously.
    #[instrument(skip(self, request))]
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let req = request.into_inner();

        // Schema-level validation (email format)
        req.validate_or_status()?;

        let user_email = Self::canonical_email(&req.email);

        // Log attempt (without revealing if user exists)
        debug!("Password reset requested");

        // Spawn async task to handle reset - this prevents timing attacks
        // by always returning immediately regardless of user existence
        let db = self.db.clone();
        let email = user_email.clone();
        tokio::spawn(async move {
            match db.users.get_active_user(&email).await {
                Ok(user) => {
                    // TODO: Generate reset token and send email
                    // For now, just log the attempt
                    info!(user_id = %user.id, "Password reset token generated");
                }
                Err(_) => {
                    // User not found - silently ignore to prevent enumeration
                    debug!("Password reset requested for non-existent email");
                }
            }
        });

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Set a new password (requires admin or self)
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn set_password(
        &self,
        request: Request<SetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_auth(&request)?;
        let req = request.into_inner();

        // Schema-level validation (email format, password min length)
        req.validate_or_status()?;

        let target_user_id = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", auth_info.user_info.id.to_string());
        tracing::Span::current().record("target_user_id", target_user_id.to_string());

        // Authorization: user can change own password, admin can change any
        let is_self = auth_info.user_info.id == target_user_id;
        let is_admin = auth_info.user_info.role == DbUserRole::Administrator;

        if !is_self && !is_admin {
            warn!(
                user_id = %auth_info.user_info.id,
                target_user_id = %target_user_id,
                "Unauthorized password change attempt"
            );
            return Err(Status::permission_denied(
                "Can only change your own password",
            ));
        }

        // Verify target user exists and email matches user_id (prevents email substitution attack)
        let target_user = self
            .db
            .users
            .get_user_by_id(target_user_id)
            .await
            .map_err(|_| Status::not_found("User not found"))?;

        let email = Self::canonical_email(&req.email);
        if Self::canonical_email(&target_user.email) != email {
            warn!(
                user_id = %target_user_id,
                provided_email = %req.email,
                "Email mismatch in password change"
            );
            return Err(Status::invalid_argument("Email does not match user"));
        }

        let password_hash = Self::hash_password(&req.password)?;

        self.db
            .users
            .update_user_password(&email, &password_hash)
            .await
            .status("Failed to update password")?;

        info!(user_id = %target_user_id, "Password updated");

        Ok(Response::new(ResultReply { result: true }))
    }

    type LoadUsersInfoStream = StreamResult<ProtoUserInfo>;

    /// Load user info for all users (streaming) - requires admin
    #[instrument(skip(self, request), fields(user_id))]
    async fn load_users_info(
        &self,
        request: Request<()>,
    ) -> Result<Response<Self::LoadUsersInfoStream>, Status> {
        let admin_info = require_admin(&request)?;
        tracing::Span::current().record("user_id", admin_info.user_info.id.to_string());

        debug!(user_id = %admin_info.user_info.id, "Loading users info");

        let db = self.db.clone();

        let stream = try_stream! {
            let mut rows = db.users.stream_all_users();

            while let Some(result) = rows.next().await {
                let user = result.map_err(|e| {
                    let app_error: AppError = e.into();
                    error!(error = %app_error, "Failed to stream users");
                    Status::from(app_error)
                })?;

                yield ProtoUserInfo::from(user);
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type LoadUserAvatarStream = StreamResult<ProtoUserAvatar>;

    /// Load user avatars (streaming)
    #[instrument(skip(self, request), fields(user_id))]
    async fn load_user_avatar(
        &self,
        request: Request<LoadUserAvatarRequest>,
    ) -> Result<Response<Self::LoadUserAvatarStream>, Status> {
        let auth_info = require_auth(&request)?;
        tracing::Span::current().record("user_id", auth_info.user_info.id.to_string());

        let req = request.into_inner();
        let mut user_ids = Vec::with_capacity(req.user_id.len());

        for proto_id in &req.user_id {
            let id = Some(proto_id).parse_or_status()?;
            user_ids.push(id);
        }

        let is_admin = auth_info.user_info.role == DbUserRole::Administrator;
        if !is_admin {
            if user_ids.is_empty() {
                user_ids.push(auth_info.user_info.id);
            } else if user_ids.iter().any(|id| *id != auth_info.user_info.id) {
                warn!(
                    requestor = %auth_info.user_info.id,
                    "Attempt to load avatars for other users"
                );
                return Err(Status::permission_denied(
                    "Cannot load avatars for other users",
                ));
            }
        }

        debug!(
            user_id = %auth_info.user_info.id,
            count = user_ids.len(),
            "Loading user avatars"
        );

        let avatars = self
            .db
            .photos
            .load_user_avatars(&user_ids)
            .await
            .status("Failed to load avatars")?;

        let stream = try_stream! {
            for avatar in avatars {
                yield ProtoUserAvatar::from(avatar);
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type LoadUsersStream = StreamResult<ProtoUser>;

    /// Load all users (streaming)
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn load_users(
        &self,
        request: Request<UserId>,
    ) -> Result<Response<Self::LoadUsersStream>, Status> {
        let auth_info = require_auth(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let is_admin = auth_info.user_info.role == DbUserRole::Administrator;

        tracing::Span::current().record("user_id", auth_info.user_info.id.to_string());
        tracing::Span::current().record("target_user_id", target_user_id.to_string());

        if !is_admin && auth_info.user_info.id != target_user_id {
            warn!(
                user_id = %auth_info.user_info.id,
                target_user_id = %target_user_id,
                "Unauthorized user lookup"
            );
            return Err(Status::permission_denied("Cannot load other users"));
        }

        debug!(
            user_id = %auth_info.user_info.id,
            target_user_id = %target_user_id,
            "Loading user"
        );

        let user =
            self.db
                .users
                .get_user_info(target_user_id)
                .await
                .map_err(|error| match &error {
                    AppError::NotFound(_) => {
                        warn!(user_id = %target_user_id, "Requested user not found");
                        Status::not_found("User not found")
                    }
                    _ => {
                        error!(user_id = %target_user_id, error = %error, "Failed to load user");
                        Status::from(error)
                    }
                })?;

        let stream = try_stream! {
            yield ProtoUser::from(user);
        };

        Ok(Response::new(Box::pin(stream)))
    }

    /// Create a new user - requires admin
    #[instrument(skip(self, request), fields(admin_id, new_user_id))]
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_admin(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", auth_info.user_info.id.to_string());
        tracing::Span::current().record("new_user_id", user_id.to_string());
        info!(admin_id = %auth_info.user_info.id, new_user_id = %user_id, email = %email, "Creating user");

        let password_hash = Self::hash_password(&req.password)?;
        let role = DbUserRole::try_from(req.role)?;

        self.db
            .users
            .create_user(CreateUserParams {
                id: user_id,
                name: req.name,
                email,
                password: password_hash,
                role,
                deleted: req.deleted,
            })
            .await
            .status("Failed to create user")?;

        info!(
            user_id = %user_id,
            created_by = %auth_info.user_info.id,
            "User created"
        );

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Update an existing user - requires admin
    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_admin(&request)?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", auth_info.user_info.id.to_string());
        tracing::Span::current().record("target_user_id", user_id.to_string());
        info!(
            admin_id = %auth_info.user_info.id,
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

        info!(
            user_id = %user_id,
            updated_by = %auth_info.user_info.id,
            "User updated"
        );

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Save user photo - user can save own, admin can save any
    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn save_user_photo(
        &self,
        request: Request<UserPhoto>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth_info = require_auth(&request)?;

        let req = request.into_inner();

        // Schema-level validation (user_id required)
        req.validate_or_status()?;

        let target_user_id = req.user_id.as_ref().parse_or_status_with_field("user_id")?;

        tracing::Span::current().record("user_id", auth_info.user_info.id.to_string());
        tracing::Span::current().record("target_user_id", target_user_id.to_string());

        // Authorization: user can update own photo, admin can update any
        let is_self = auth_info.user_info.id == target_user_id;
        let is_admin = auth_info.user_info.role == DbUserRole::Administrator;

        if !is_self && !is_admin {
            warn!(
                user_id = %auth_info.user_info.id,
                target_user_id = %target_user_id,
                "Unauthorized photo update attempt"
            );
            return Err(Status::permission_denied("Can only update your own photo"));
        }

        let photo_data = req
            .photo
            .ok_or_else(|| Status::invalid_argument("Photo data is required"))?;

        if photo_data.len() > Self::MAX_PHOTO_BYTES {
            warn!(
                user_id = %target_user_id,
                size = photo_data.len(),
                "Photo exceeds maximum size"
            );
            return Err(Status::invalid_argument(
                "Photo exceeds maximum allowed size",
            ));
        }

        match image::guess_format(&photo_data) {
            Ok(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP) => {}
            Ok(_) | Err(_) => {
                warn!(user_id = %target_user_id, "Unsupported photo format");
                return Err(Status::invalid_argument("Unsupported image format"));
            }
        }

        debug!(
            user_id = %target_user_id,
            size = photo_data.len(),
            "Processing user photo"
        );

        // Process image to create avatar and blurhash
        let (avatar, blurhash) = to_avatar(&photo_data).map_err(|e| {
            error!(error = %e, "Failed to process photo");
            Status::invalid_argument("Invalid image data")
        })?;

        // Save photo
        self.db
            .photos
            .save_user_photo(
                SaveUserPhotoParams {
                    user_id: target_user_id,
                    avatar,
                    photo: photo_data,
                },
                &blurhash,
            )
            .await
            .status("Failed to save photo")?;

        info!(user_id = %target_user_id, "Photo saved");

        Ok(Response::new(ResultReply { result: true }))
    }
}
