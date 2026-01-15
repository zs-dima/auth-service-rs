//! Auth service gRPC implementation.

use std::net::IpAddr;
use std::sync::Arc;

use async_stream::try_stream;
use auth_core::{
    AppError, OptionStatusExt, OptionStrExt, RequestAuthExt, StatusExt, StrExt, ToProtoUuid,
    UuidExt, ValidateExt, json_to_proto_struct, proto_struct_to_json,
};
use auth_db::{
    CreateEmailVerificationTokenParams, CreatePasswordResetTokenParams, CreateSessionParams,
    CreateUserWithProfileParams, Database, UpdateUserParams, UpdateUserProfileParams, UserStatus,
    UserWithProfile, proto_to_role,
};
use auth_proto::auth::auth_service_server::AuthService;
use auth_proto::auth::{
    // Authentication
    AuthInfo,
    AuthResult,
    AuthStatus,
    AuthenticateRequest,
    // User management
    AvatarUploadUrl,
    ChangePasswordRequest,
    ConfirmAvatarUploadRequest,
    ConfirmMfaSetupRequest,
    ConfirmVerificationRequest,
    CreateUserRequest,
    DisableMfaRequest,
    ExchangeOAuthCodeRequest,
    GetAvatarUploadUrlRequest,
    GetOAuthUrlRequest,
    IdentifierType,
    LinkOAuthProviderRequest,
    LinkedProvidersReply,
    // Tokens & Sessions
    ListSessionsReply,
    LoadUsersInfoRequest,
    MfaSetupResult,
    MfaStatusReply,
    OAuthUrlReply,
    RecoveryConfirmRequest,
    RecoveryStartRequest,
    RefreshTokenReply,
    RefreshTokenRequest,
    RequestVerificationRequest,
    RevokeSessionRequest,
    RevokeSessionsReply,
    SessionInfo as ProtoSessionInfo,
    SetPasswordRequest,
    SetupMfaReply,
    SetupMfaRequest,
    SignUpRequest,
    UnlinkOAuthProviderRequest,
    UpdateUserRequest,
    User as ProtoUser,
    UserId,
    UserInfo as ProtoUserInfo,
    VerifyMfaRequest,
};
use auth_proto::core::ResultReply;
use auth_storage::S3Storage;
use chrono::Utc;
use futures::stream::BoxStream;
use ipnetwork::IpNetwork;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::core::{Encryptor, GeolocationService, JwtValidator, TokenGenerator, UrlBuilder};
use crate::middleware::ClientIp;
use crate::startup::EmailProvider;

/// Upload URL expiration (5 minutes).
const UPLOAD_URL_EXPIRES_SECS: u64 = 300;

/// Maximum length for user-agent string to prevent storage bloat.
const MAX_USER_AGENT_LEN: usize = 500;

/// Session tokens returned after successful authentication.
#[derive(Debug)]
struct SessionTokens {
    access_token: String,
    refresh_token: String,
}

/// Client context extracted from request for session creation.
#[derive(Debug, Default, Clone)]
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

impl ClientContext {
    fn with_ip(&mut self, ip: Option<IpAddr>) -> &mut Self {
        self.ip_address = ip;
        self
    }

    fn with_country(&mut self, country: Option<String>) -> &mut Self {
        self.ip_country = country;
        self
    }

    fn with_user_agent(&mut self, ua: Option<String>) -> &mut Self {
        self.user_agent = ua;
        self
    }

    fn with_device_id(&mut self, id: impl Into<String>) -> &mut Self {
        self.device_id = Some(id.into());
        self
    }

    fn with_device_name(&mut self, name: Option<String>) -> &mut Self {
        self.device_name = name;
        self
    }

    fn with_device_type(&mut self, dtype: Option<String>) -> &mut Self {
        self.device_type = dtype;
        self
    }

    fn with_client_version(&mut self, version: Option<String>) -> &mut Self {
        self.client_version = version;
        self
    }

    fn with_metadata(&mut self, metadata: Option<serde_json::Value>) -> &mut Self {
        self.metadata = metadata;
        self
    }

    /// Convert IP address to network for storage.
    fn ip_network(&self) -> Option<IpNetwork> {
        self.ip_address.map(IpNetwork::from)
    }

    /// Convert to `CreateSessionParams` for database insertion.
    fn to_session_params<'a>(
        &'a self,
        id_user: Uuid,
        refresh_token_hash: &'a [u8],
        expires_at: chrono::DateTime<Utc>,
        metadata: serde_json::Value,
    ) -> CreateSessionParams<'a> {
        CreateSessionParams {
            id_user,
            refresh_token_hash,
            expires_at,
            device_id: self.device_id.as_deref(),
            device_name: self.device_name.as_deref(),
            device_type: self.device_type.as_deref(),
            client_version: self.client_version.as_deref(),
            ip_address: self.ip_network(),
            ip_country: self.ip_country.as_deref(),
            metadata,
        }
    }
}

/// Configuration for auth service token TTLs and domain.
#[derive(Clone)]
pub struct AuthServiceConfig {
    /// JWT validator for token operations.
    pub jwt_validator: JwtValidator,
    /// Access token time-to-live in minutes.
    pub access_token_ttl_minutes: u64,
    /// Refresh token time-to-live in days.
    pub refresh_token_ttl_days: i64,
    /// Password reset token TTL in minutes.
    pub password_reset_ttl_minutes: u32,
    /// Email verification token TTL in hours.
    pub email_verification_ttl_hours: u32,
    /// URL builder for frontend links.
    pub urls: UrlBuilder,
}

/// Auth service implementation.
pub struct AuthServiceImpl {
    config: AuthServiceConfig,
    db: Database,
    s3: Option<Arc<S3Storage>>,
    email: Option<EmailProvider>,
    geolocation: GeolocationService,
}

impl AuthServiceImpl {
    /// Create a new auth service instance.
    #[must_use]
    pub fn new(
        config: AuthServiceConfig,
        db: Database,
        s3: Option<Arc<S3Storage>>,
        email: Option<EmailProvider>,
        geolocation: GeolocationService,
    ) -> Self {
        Self {
            config,
            db,
            s3,
            email,
            geolocation,
        }
    }

    /// Normalize email to lowercase for case-insensitive comparison.
    #[must_use]
    fn canonical_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Normalize phone number to E.164 format (if valid).
    ///
    /// E.164 format: +[country code][subscriber number], max 15 digits.
    /// Returns normalized phone or original if invalid.
    #[must_use]
    fn canonical_phone(phone: &str) -> String {
        let trimmed = phone.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        let has_plus = trimmed.starts_with('+');
        let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();

        // E.164: 7-15 digits (including country code)
        if digits.len() < 7 || digits.len() > 15 {
            // Return as-is if invalid length (validation should catch this)
            return trimmed.to_string();
        }

        if has_plus {
            format!("+{digits}")
        } else {
            digits
        }
    }

    /// Detect identifier type from format:
    /// - Starts with `+` → Phone (E.164)
    /// - Otherwise → Email (fallback)
    #[must_use]
    fn detect_identifier_type(identifier: &str) -> IdentifierType {
        let trimmed = identifier.trim_start();
        if trimmed.starts_with('+') {
            IdentifierType::Phone
        } else {
            // Default to email for legacy compatibility
            IdentifierType::Email
        }
    }

    /// Normalize identifier based on type.
    #[must_use]
    fn normalize_identifier(identifier: &str, id_type: IdentifierType) -> String {
        match id_type {
            IdentifierType::Phone => Self::canonical_phone(identifier),
            _ => Self::canonical_email(identifier),
        }
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
            .map(|s| s.chars().take(MAX_USER_AGENT_LEN).collect::<String>());

        let mut ctx = ClientContext::default();
        ctx.with_ip(ip_address)
            .with_country(ip_country)
            .with_user_agent(user_agent);
        ctx
    }

    /// Build full client context from request and client info.
    fn build_client_context<T>(
        &self,
        req: &Request<T>,
        client_info: Option<&auth_proto::auth::ClientInfo>,
    ) -> ClientContext {
        let mut ctx = self.extract_client_context(req);

        if let Some(info) = client_info {
            ctx.with_device_id(info.device_id.to_opt().unwrap_or_default())
                .with_device_name(info.device_name.to_opt())
                .with_device_type(info.device_type.to_opt())
                .with_client_version(info.client_version.to_opt())
                .with_metadata(info.metadata.as_ref().map(proto_struct_to_json));
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
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Missing device_id"))?;

        let access_token = self
            .config
            .jwt_validator
            .generate_access_token(
                user,
                device_id,
                installation_id,
                self.config.access_token_ttl_minutes,
            )
            .status("Failed to generate access token")?;

        let (refresh_token, expires_at) =
            TokenGenerator::generate_refresh_token(self.config.refresh_token_ttl_days)
                .status("Failed to generate refresh token")?;

        // Build metadata JSON with user_agent and any additional client metadata
        let metadata = {
            let mut map = ctx
                .metadata
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map_or_else(serde_json::Map::new, Clone::clone);

            if let Some(ua) = &ctx.user_agent {
                map.insert("user_agent".to_string(), ua.clone().into());
            }
            serde_json::Value::Object(map)
        };

        let refresh_token_hash = TokenGenerator::hash_token(&refresh_token);

        self.db
            .sessions
            .create_session(ctx.to_session_params(
                user.id,
                &refresh_token_hash,
                expires_at,
                metadata,
            ))
            .await
            .status("Failed to save session")?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
        })
    }

    #[inline]
    fn hash_password(password: &str) -> Result<String, Status> {
        Encryptor::hash(password).status("Failed to hash password")
    }

    #[inline]
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

    /// Create a standardized failed authentication response.
    /// Uses generic message to prevent user enumeration (OWASP).
    #[must_use]
    #[inline]
    fn failed_auth() -> AuthResult {
        AuthResult {
            status: AuthStatus::Failed.into(),
            auth_info: None,
            mfa_challenge: None,
            message: String::new(),
            lockout_info: None,
        }
    }

    /// Build successful authentication result with tokens.
    #[must_use]
    fn build_success_auth_result(user: &UserWithProfile, tokens: SessionTokens) -> AuthResult {
        AuthResult {
            status: AuthStatus::Success.into(),
            auth_info: Some(AuthInfo {
                user_id: Some(user.id.to_proto()),
                display_name: user.display_name.clone(),
                user_role: auth_db::role_to_proto(&user.role),
                refresh_token: tokens.refresh_token,
                access_token: tokens.access_token,
                email: user.email.clone().unwrap_or_default(),
                phone: user.phone.clone().unwrap_or_default(),
                email_verified: user.email_verified,
                phone_verified: user.phone_verified,
                mfa_enabled: false, // TODO: Check MFA status when implemented
                linked_providers: vec![], // TODO: Load from providers table
                status: auth_db::status_to_proto(user.status),
            }),
            mfa_challenge: None,
            message: String::new(),
            lockout_info: None,
        }
    }

    /// Spawn async task to send welcome email with verification link.
    ///
    /// Fire-and-forget: errors are logged but don't fail the parent operation.
    fn spawn_welcome_email(
        &self,
        user_id: Uuid,
        email: String,
        display_name: String,
        temp_password: Option<String>,
    ) {
        let Some(email_service) = self.email.clone() else {
            return;
        };

        let db = self.db.clone();
        let urls = self.config.urls.clone();
        let ttl_hours = self.config.email_verification_ttl_hours;

        tokio::spawn(async move {
            // Generate verification token
            let token = TokenGenerator::generate_secure_token();
            let token_hash = TokenGenerator::hash_token(&token);
            let expires_at = Utc::now() + chrono::Duration::hours(i64::from(ttl_hours));

            // Store token hash in database
            if let Err(e) = db
                .email_verifications
                .create_token(CreateEmailVerificationTokenParams {
                    id_user: user_id,
                    token_hash: &token_hash,
                    expires_at,
                })
                .await
            {
                error!(user_id = %user_id, error = %e, "Failed to create email verification token");
                return;
            }

            // Build URLs
            let verification_url = urls.verify_email(&token);
            let login_url = urls.sign_in();

            // Send welcome email
            if let Err(e) = email_service
                .send_welcome(
                    &email,
                    &display_name,
                    &login_url,
                    temp_password.as_deref(),
                    Some(&verification_url),
                )
                .await
            {
                error!(user_id = %user_id, error = %e, "Failed to send welcome email");
                return;
            }

            info!(user_id = %user_id, "Welcome email sent with verification link");
        });
    }
}

/// Streaming result type for gRPC responses.
type StreamResult<T> = BoxStream<'static, Result<T, Status>>;

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    /// Authenticate with identifier (email or phone) and password.
    /// Returns `AuthResult` with tokens on success, or error status.
    #[instrument(skip(self, request), fields(identifier))]
    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        // Extract client context before consuming request
        let client_ctx =
            self.build_client_context(&request, request.get_ref().client_info.as_ref());

        let req = request.into_inner();
        req.validate_or_status()?;

        // Detect identifier type if not specified
        let id_type = if req.identifier_type == IdentifierType::Unspecified as i32 {
            Self::detect_identifier_type(&req.identifier)
        } else {
            IdentifierType::try_from(req.identifier_type).unwrap_or(IdentifierType::Email)
        };

        let identifier = Self::normalize_identifier(&req.identifier, id_type);
        tracing::Span::current().record("identifier", &identifier);
        info!(identifier = %identifier, id_type = ?id_type, "Authentication attempt");

        let installation_id = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        // Lookup user by identifier type
        let user_result = match id_type {
            IdentifierType::Phone => self.db.users.get_active_user_by_phone(&identifier).await,
            _ => self.db.users.get_active_user_by_email(&identifier).await,
        };

        let Ok(user) = user_result else {
            warn!(identifier = %identifier, "User not found");
            // Generic error to prevent enumeration (OWASP)
            return Ok(Response::new(Self::failed_auth()));
        };

        // Check for account lockout (future: implement via failed_attempts tracking)
        // TODO: Add lockout_info when DB supports failed_attempts column

        let Some(password) = user.password.as_deref() else {
            warn!(identifier = %identifier, "User has no password (OAuth-only account)");
            return Ok(Response::new(Self::failed_auth()));
        };

        if !Encryptor::verify(&req.password, password) {
            warn!(identifier = %identifier, "Invalid password");
            // TODO: Track failed attempts for lockout
            return Ok(Response::new(Self::failed_auth()));
        }

        // TODO: Check if MFA is enabled and return MFA_REQUIRED status
        // For now, proceed directly to token creation

        let tokens = self
            .create_session(&user, &installation_id, &client_ctx)
            .await?;

        info!(
            user_id = %user.id,
            ip = ?client_ctx.ip_address,
            country = ?client_ctx.ip_country,
            device_type = ?client_ctx.device_type,
            "Authentication successful"
        );

        Ok(Response::new(Self::build_success_auth_result(
            &user, tokens,
        )))
    }

    /// Register a new user account.
    /// Returns `AuthResult` with tokens on success, or `PENDING` status if verification required.
    #[instrument(skip(self, request), fields(identifier))]
    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        // Extract client context before consuming request
        let client_ctx =
            self.build_client_context(&request, request.get_ref().client_info.as_ref());

        let req = request.into_inner();
        req.validate_or_status()?;

        // Detect identifier type if not specified
        let id_type = if req.identifier_type == IdentifierType::Unspecified as i32 {
            Self::detect_identifier_type(&req.identifier)
        } else {
            IdentifierType::try_from(req.identifier_type).unwrap_or(IdentifierType::Email)
        };

        let identifier = Self::normalize_identifier(&req.identifier, id_type);
        tracing::Span::current().record("identifier", &identifier);
        info!(identifier = %identifier, id_type = ?id_type, "Sign up attempt");

        let installation_id = req
            .installation_id
            .as_ref()
            .parse_or_status_with_field("installation_id")?;

        // Hash password
        let password_hash = Self::hash_password(&req.password)?;

        // Check if user already exists (prevent duplicate registration)
        let user_exists = match id_type {
            IdentifierType::Phone => self.db.users.get_user_by_phone(&identifier).await.is_ok(),
            _ => self.db.users.get_user_by_email(&identifier).await.is_ok(),
        };
        if user_exists {
            warn!(identifier = %identifier, "Registration attempted with existing identifier");
            // Generic error to prevent enumeration (OWASP)
            return Err(Status::already_exists("Registration failed"));
        }

        // Build create params based on identifier type (use references, avoid clone)
        let (email, phone) = match id_type {
            IdentifierType::Phone => (None, Some(identifier.as_str())),
            _ => (Some(identifier.as_str()), None),
        };

        // Create user with profile
        let user_id = self
            .db
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

        // Load created user for session creation
        let user = self
            .db
            .users
            .get_user_by_id(user_id)
            .await
            .status("Failed to load created user")?;

        let tokens = self
            .create_session(&user, &installation_id, &client_ctx)
            .await?;

        // Send welcome email with verification link (async, fire and forget)
        if let Some(email) = &user.email {
            self.spawn_welcome_email(user_id, email.clone(), user.display_name.clone(), None);
        }
        // TODO: Send phone verification SMS when phone-based sign up
        // This requires an SMS provider integration (e.g., Twilio, AWS SNS)

        info!(
            user_id = %user_id,
            ip = ?client_ctx.ip_address,
            country = ?client_ctx.ip_country,
            "Sign up successful"
        );

        Ok(Response::new(Self::build_success_auth_result(
            &user, tokens,
        )))
    }

    /// Verify MFA code to complete authentication.
    /// Currently returns unimplemented - MFA tables need to be added first.
    #[instrument(skip(self, _request))]
    async fn verify_mfa(
        &self,
        _request: Request<VerifyMfaRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        // TODO: Implement when MFA tables are added to database
        Err(Status::unimplemented("MFA not yet supported"))
    }

    /// Sign out the current user.
    #[instrument(skip(self, request), fields(user_id))]
    async fn sign_out(&self, request: Request<()>) -> Result<Response<ResultReply>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

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
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        // Extract client context for session update
        let client_ctx = self.extract_client_context(&request);

        let req = request.into_inner();
        req.validate_or_status()?;

        debug!(user_id = %auth.user_id, "Refresh token request");

        // Hash the provided refresh token to compare with stored hash
        let token_hash = TokenGenerator::hash_token(&req.refresh_token);

        // Touch session validates and extends it, updates IP/country
        let _session = self
            .db
            .sessions
            .touch_session(
                token_hash.as_slice(),
                client_ctx.ip_network(),
                client_ctx.ip_country.as_deref(),
            )
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, error = %e, "Session not found or expired");
                Status::unauthenticated("Session expired")
            })?;

        // Lookup user by ID
        let user = self
            .db
            .users
            .get_user_by_id(auth.user_id)
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, error = %e, "User not found during token refresh");
                Status::unauthenticated("User not found")
            })?;

        // Verify user is still active
        if user.status != UserStatus::Active {
            warn!(user_id = %auth.user_id, status = ?user.status, "Inactive user attempted token refresh");
            return Err(Status::permission_denied("Account is not active"));
        }

        // Build context with existing device info from JWT
        let mut ctx = ClientContext::default();
        ctx.with_ip(client_ctx.ip_address)
            .with_country(client_ctx.ip_country)
            .with_device_id(&auth.device_id);

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
        let auth = request.auth()?;

        debug!(user_id = %auth.user_id, "Validating credentials");

        // Lookup user by ID
        let user = self
            .db
            .users
            .get_user_by_id(auth.user_id)
            .await
            .map_err(|e| {
                warn!(user_id = %auth.user_id, error = %e, "User validation failed");
                Status::unauthenticated("User not found")
            })?;

        // Verify user is still active
        if user.status != UserStatus::Active {
            warn!(user_id = %auth.user_id, status = ?user.status, "Inactive user attempted validation");
            return Err(Status::permission_denied("Account is not active"));
        }

        Ok(Response::new(ResultReply { result: true }))
    }

    /// Start password recovery process.
    ///
    /// Always returns success to prevent user enumeration attacks.
    /// Sends password reset email/SMS asynchronously if user exists.
    /// Also used by OAuth-only users to add a password to their account.
    #[instrument(skip(self, request), fields(identifier))]
    async fn recovery_start(
        &self,
        request: Request<RecoveryStartRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let req = request.into_inner();
        req.validate_or_status()?;

        // Detect identifier type if not specified
        let id_type = if req.identifier_type == IdentifierType::Unspecified as i32 {
            Self::detect_identifier_type(&req.identifier)
        } else {
            IdentifierType::try_from(req.identifier_type).unwrap_or(IdentifierType::Email)
        };

        let identifier = Self::normalize_identifier(&req.identifier, id_type);
        tracing::Span::current().record("identifier", &identifier);
        debug!(identifier = %identifier, id_type = ?id_type, "Password reset requested");

        // Check if email service is configured (only email recovery supported for now)
        let Some(email_service) = self.email.clone() else {
            warn!("Password reset requested but email service not configured");
            // Still return success to prevent enumeration
            return Ok(Response::new(ResultReply { result: true }));
        };

        // Phone recovery would require SMS provider (future enhancement)
        if id_type == IdentifierType::Phone {
            warn!("Phone-based recovery not yet implemented, falling back to success response");
            return Ok(Response::new(ResultReply { result: true }));
        }

        let db = self.db.clone();
        let password_reset_ttl_minutes = self.config.password_reset_ttl_minutes;
        let urls = self.config.urls.clone();

        // Process asynchronously to prevent timing attacks.
        // Note: There's an inherent race between user lookup and token creation
        // (user could be deleted/suspended). This is acceptable for fire-and-forget
        // since the worst case is a token created for a non-existent user.
        tokio::spawn(async move {
            // Look up user by identifier
            let Ok(user) = db.users.get_active_user_by_email(&identifier).await else {
                debug!(identifier = %identifier, "User not found for password reset");
                return;
            };

            // Generate secure token (URL-safe base64, 32 bytes of entropy)
            let token = TokenGenerator::generate_secure_token();
            let token_hash = TokenGenerator::hash_token(&token);

            // Calculate expiration
            let expires_at =
                Utc::now() + chrono::Duration::minutes(i64::from(password_reset_ttl_minutes));

            // Store token hash in database
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

            // Build reset link
            let reset_link = urls.password_reset(&token);

            // Send email
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

        // Always return success to prevent user enumeration
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Confirm password recovery and set new password.
    #[instrument(skip(self, request), fields(token_len))]
    async fn recovery_confirm(
        &self,
        request: Request<RecoveryConfirmRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let req = request.into_inner();
        req.validate_or_status()?;

        tracing::Span::current().record("token_len", req.token.len());
        debug!("Password recovery confirmation attempt");

        // Hash the token to look up in database
        let token_hash = TokenGenerator::hash_token(&req.token);

        // Consume the token (validates and marks as used atomically)
        let user_id = self
            .db
            .password_resets
            .consume_token(&token_hash)
            .await
            .map_err(|e| {
                warn!(error = %e, "Invalid or expired password reset token");
                Status::invalid_argument("Invalid or expired reset token")
            })?;

        // Verify user is still active (prevent reset for suspended/deleted accounts)
        let user = self.db.users.get_user_by_id(user_id).await.map_err(|_| {
            warn!(user_id = %user_id, "User not found or inactive during password reset");
            Status::invalid_argument("Invalid or expired reset token")
        })?;

        if user.status != UserStatus::Active {
            warn!(user_id = %user_id, status = ?user.status, "Password reset attempted for non-active user");
            return Err(Status::permission_denied("Account is not active"));
        }

        // Hash the new password
        let password_hash = Self::hash_password(&req.new_password)?;

        // Update user password
        self.db
            .users
            .update_user_password(user_id, &password_hash)
            .await
            .status("Failed to update password")?;

        // Revoke all existing sessions for security
        if let Err(e) = self.db.sessions.revoke_all_user_sessions(user_id).await {
            warn!(user_id = %user_id, error = %e, "Failed to revoke sessions after password reset");
            // Don't fail the request, password was already changed
        }

        info!(user_id = %user_id, "Password reset completed successfully");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Change password (requires current password verification - OWASP).
    /// For users who forgot password or have OAuth-only accounts, use `recovery_start`/`recovery_confirm`.
    #[instrument(skip(self, request), fields(user_id))]
    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let req = request.into_inner();
        req.validate_or_status()?;

        debug!(user_id = %auth.user_id, "Password change requested");

        // Get user with current password
        let user = self
            .db
            .users
            .get_user_by_id(auth.user_id)
            .await
            .status("User not found")?;

        // Verify current password
        let current_password = user.password.as_deref().ok_or_else(|| {
            warn!(user_id = %auth.user_id, "User has no password (OAuth-only) - use recovery instead");
            Status::failed_precondition(
                "No password set. Use password recovery to create a password.",
            )
        })?;

        if !Encryptor::verify(&req.current_password, current_password) {
            warn!(user_id = %auth.user_id, "Invalid current password during change");
            return Err(Status::unauthenticated("Current password is incorrect"));
        }

        // Hash and save new password
        let password_hash = Self::hash_password(&req.new_password)?;

        self.db
            .users
            .update_user_password(auth.user_id, &password_hash)
            .await
            .status("Failed to update password")?;

        // Optionally revoke other sessions (keep current session active)
        if let Err(e) = self
            .db
            .sessions
            .revoke_sessions_except_device(auth.user_id, &auth.device_id)
            .await
        {
            warn!(user_id = %auth.user_id, error = %e, "Failed to revoke other sessions");
        }

        info!(user_id = %auth.user_id, "Password changed successfully");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Set password (admin only - bypasses current password requirement).
    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn set_password(
        &self,
        request: Request<SetPasswordRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let admin = request.auth_admin()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("admin_id", admin.user_id.to_string());
        tracing::Span::current().record("target_user_id", target_id.to_string());

        info!(admin_id = %admin.user_id, target_user_id = %target_id, "Admin setting password");

        // Verify target user exists
        self.db.users.get_user_by_id(target_id).await.map_err(|e| {
            warn!(target_user_id = %target_id, error = %e, "User not found for password set");
            Status::not_found("User not found")
        })?;

        let hash = Self::hash_password(&req.password)?;
        self.db
            .users
            .update_user_password(target_id, &hash)
            .await
            .status("Failed to update password")?;

        // Revoke all sessions for security
        if let Err(e) = self.db.sessions.revoke_all_user_sessions(target_id).await {
            warn!(target_user_id = %target_id, error = %e, "Failed to revoke sessions after admin password set");
        }

        info!(target_user_id = %target_id, set_by = %admin.user_id, "Password set by admin");
        Ok(Response::new(ResultReply { result: true }))
    }

    type LoadUsersInfoStream = StreamResult<ProtoUserInfo>;

    /// Load user info (streaming) - requires admin.
    #[instrument(skip(self, request), fields(user_id))]
    async fn load_users_info(
        &self,
        request: Request<LoadUsersInfoRequest>,
    ) -> Result<Response<Self::LoadUsersInfoStream>, Status> {
        let admin = request.auth_admin()?;
        tracing::Span::current().record("user_id", admin.user_id.to_string());

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

        // Clone is cheap: Database wraps Arc<PgPool>
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
        let auth = request.auth()?;
        let req = request.into_inner();
        req.validate_or_status()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        // Clone is cheap: Database wraps Arc<PgPool>
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
        let admin = request.auth_admin()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        // Normalize identifiers - compute as owned strings only when needed for email sending
        let email_normalized = (!req.email.is_empty()).then(|| Self::canonical_email(&req.email));
        let phone_normalized = (!req.phone.is_empty()).then(|| Self::canonical_phone(&req.phone));

        // At least one identifier required
        if email_normalized.is_none() && phone_normalized.is_none() {
            return Err(Status::invalid_argument(
                "Either email or phone must be provided",
            ));
        }

        tracing::Span::current().record("admin_id", admin.user_id.to_string());
        info!(admin_id = %admin.user_id, email = ?email_normalized, phone = ?phone_normalized, "Creating user");

        let password_hash = (!req.password.is_empty())
            .then(|| Self::hash_password(&req.password))
            .transpose()?;
        let role = proto_to_role(req.role).map_err(Status::invalid_argument)?;

        let user_id = self
            .db
            .users
            .create_user_with_profile(CreateUserWithProfileParams {
                email: email_normalized.as_deref(),
                phone: phone_normalized.as_deref(),
                password_hash: password_hash.as_deref(),
                role,
                display_name: Some(&req.name),
                locale: &req.locale,
                timezone: &req.timezone,
            })
            .await
            .status("Failed to create user")?;

        // Send welcome email with verification link (async, fire and forget)
        if let Some(email) = email_normalized {
            let temp_password = (!req.password.is_empty()).then(|| req.password.clone());
            self.spawn_welcome_email(user_id, email, req.name, temp_password);
        }

        info!(user_id = %user_id, created_by = %admin.user_id, "User created");
        Ok(Response::new(ResultReply { result: true }))
    }

    /// Update an existing user - requires admin.
    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let admin = request.auth_admin()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let user_id = req.id.as_ref().parse_or_status_with_field("user_id")?;
        let email = Self::canonical_email(&req.email);

        tracing::Span::current().record("admin_id", admin.user_id.to_string());
        tracing::Span::current().record("target_user_id", user_id.to_string());
        info!(
            admin_id = %admin.user_id,
            target_user_id = %user_id,
            "Updating user"
        );

        let role = proto_to_role(req.role).map_err(Status::invalid_argument)?;
        let status = if req.deleted {
            UserStatus::Deleted
        } else {
            UserStatus::Active
        };

        // Fetch existing user to preserve profile settings not in request
        let existing_user = self
            .db
            .users
            .get_user_by_id(user_id)
            .await
            .map_err(|_| Status::not_found("User not found"))?;

        self.db
            .users
            .update_user(UpdateUserParams {
                id: user_id,
                role,
                email: Some(&email),
                email_verified: true,
                phone: None,
                phone_verified: false,
                status,
            })
            .await
            .status("Failed to update user")?;

        // Update profile display name, preserving existing locale/timezone
        self.db
            .users
            .update_user_profile(UpdateUserProfileParams {
                id_user: user_id,
                display_name: &req.name,
                avatar_url: existing_user.avatar_url.as_deref(),
                locale: &existing_user.locale,
                timezone: &existing_user.timezone,
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
        let auth = request.auth()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", target_id.to_string());

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
        let auth = request.auth()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", target_id.to_string());

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
        let auth = request.auth()?;
        let req = request.into_inner();
        req.validate_or_status()?;

        let target_id: Uuid = req.id.as_ref().parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());
        tracing::Span::current().record("target_user_id", target_id.to_string());

        auth.require_access(target_id, "delete avatar")?;
        self.delete_avatar(&target_id).await?;

        info!(user_id = %target_id, "Avatar deleted");
        Ok(Response::new(ResultReply { result: true }))
    }

    // =========================================================================
    // Session Management
    // =========================================================================

    /// List all active sessions for the current user.
    ///
    /// Note: Sessions are identified by `device_id` rather than token hash.
    /// The current session is determined by matching the JWT's device_id claim.
    #[instrument(skip(self, request), fields(user_id))]
    async fn list_sessions(
        &self,
        request: Request<()>,
    ) -> Result<Response<ListSessionsReply>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        debug!(user_id = %auth.user_id, "Listing sessions");

        // Sessions are identified by device_id; empty token hash means
        // is_current will be false for all rows (we handle it client-side)
        let sessions = self
            .db
            .sessions
            .list_user_sessions(auth.user_id, &[])
            .await
            .status("Failed to list sessions")?;

        let proto_sessions: Vec<ProtoSessionInfo> = sessions
            .into_iter()
            .map(|s| ProtoSessionInfo {
                is_current: s.device_id.as_deref() == Some(auth.device_id.as_str()),
                device_id: s.device_id.unwrap_or_default(),
                device_name: s.device_name.unwrap_or_default(),
                device_type: s.device_type.or_str("unknown"),
                client_version: s.client_version.unwrap_or_default(),
                ip_address: s
                    .ip_address
                    .map_or_else(String::new, |ip| ip.ip().to_string()),
                ip_country: s.ip_country.unwrap_or_default(),
                created_at: s.created_at.timestamp_millis(),
                last_seen_at: s.last_seen_at.timestamp_millis(),
                expires_at: s.expires_at.timestamp_millis(),
                ip_created_by: s
                    .ip_created_by
                    .map_or_else(String::new, |ip| ip.ip().to_string()),
                activity_count: s.activity_count,
                metadata: json_to_proto_struct(s.metadata),
            })
            .collect();

        info!(user_id = %auth.user_id, count = proto_sessions.len(), "Sessions listed");

        Ok(Response::new(ListSessionsReply {
            sessions: proto_sessions,
        }))
    }

    /// Revoke a specific session by `device_id`.
    #[instrument(skip(self, request), fields(user_id))]
    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

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
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        debug!(user_id = %auth.user_id, "Revoking other sessions");

        // Revoke all sessions except current device
        let count = self
            .db
            .sessions
            .revoke_sessions_except_device(auth.user_id, &auth.device_id)
            .await
            .status("Failed to revoke sessions")?;

        info!(user_id = %auth.user_id, count, "Other sessions revoked");

        Ok(Response::new(RevokeSessionsReply {
            revoked_count: i32::try_from(count).unwrap_or(i32::MAX),
        }))
    }

    // =========================================================================
    // OAuth 2.0 / OpenID Connect (Stubs)
    // =========================================================================
    // TODO: Implement OAuth flows using oauth_states and providers tables

    /// Get OAuth authorization URL with PKCE state.
    #[instrument(skip(self, _request))]
    async fn get_o_auth_url(
        &self,
        _request: Request<GetOAuthUrlRequest>,
    ) -> Result<Response<OAuthUrlReply>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    /// Exchange OAuth callback code for tokens.
    #[instrument(skip(self, _request))]
    async fn exchange_o_auth_code(
        &self,
        _request: Request<ExchangeOAuthCodeRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    /// Link OAuth provider to existing account.
    #[instrument(skip(self, _request))]
    async fn link_o_auth_provider(
        &self,
        _request: Request<LinkOAuthProviderRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    /// Unlink OAuth provider from account.
    #[instrument(skip(self, _request))]
    async fn unlink_o_auth_provider(
        &self,
        _request: Request<UnlinkOAuthProviderRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    /// List linked OAuth providers for current user.
    #[instrument(skip(self, _request))]
    async fn list_linked_providers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<LinkedProvidersReply>, Status> {
        Err(Status::unimplemented("OAuth not yet implemented"))
    }

    // =========================================================================
    // Email/Phone Verification (Stubs)
    // =========================================================================
    // TODO: Implement verification_tokens table first

    /// Request verification code for email or phone.
    #[instrument(skip(self, _request))]
    async fn request_verification(
        &self,
        _request: Request<RequestVerificationRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        Err(Status::unimplemented("Verification not yet implemented"))
    }

    /// Confirm verification with code.
    #[instrument(skip(self, _request))]
    async fn confirm_verification(
        &self,
        _request: Request<ConfirmVerificationRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        Err(Status::unimplemented("Verification not yet implemented"))
    }

    // =========================================================================
    // MFA Management (Stubs)
    // =========================================================================
    // TODO: Implement MFA tables first (mfa_methods, mfa_recovery_codes)

    /// Get current MFA status for user.
    #[instrument(skip(self, _request))]
    async fn get_mfa_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MfaStatusReply>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    /// Begin MFA setup.
    #[instrument(skip(self, _request))]
    async fn setup_mfa(
        &self,
        _request: Request<SetupMfaRequest>,
    ) -> Result<Response<SetupMfaReply>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    /// Confirm MFA setup with verification code.
    #[instrument(skip(self, _request))]
    async fn confirm_mfa_setup(
        &self,
        _request: Request<ConfirmMfaSetupRequest>,
    ) -> Result<Response<MfaSetupResult>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }

    /// Disable MFA (requires password verification).
    #[instrument(skip(self, _request))]
    async fn disable_mfa(
        &self,
        _request: Request<DisableMfaRequest>,
    ) -> Result<Response<ResultReply>, Status> {
        Err(Status::unimplemented("MFA not yet implemented"))
    }
}
