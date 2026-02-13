//! Auth service gRPC implementation.
//!
//! Organized by domain:
//! - `mod.rs` — Core types, helpers, `AuthServer`
//! - `handlers.rs` — Thin gRPC trait implementation
//! - `authentication.rs` — Sign-in, sign-up, sign-out
//! - `tokens.rs` — Token refresh and validation
//! - `password.rs` — Recovery, change
//! - `sessions.rs` — List and revoke sessions

mod authentication;
mod handlers;
mod password;
mod sessions;
mod tokens;
mod verification;

use std::sync::Arc;

use auth_core::{
    SessionTokens, StatusExt, StrExt, ToProtoDuration, ToProtoTimestamp, TokenGenerator,
};
use auth_db::{UserWithProfile, role_to_proto, status_to_proto};
use auth_proto::auth::{
    AuthResponse, AuthStatus, ClientInfo, IdentifierType, LockoutInfo, TokenPair, UserSnapshot,
};
use tonic::{Request, Status};
use uuid::Uuid;

use crate::config::AuthServiceConfig;
use crate::core::{
    ClientContext, GeolocationService, ServiceContext, canonical_email, canonical_phone,
};
use crate::middleware::ClientIp;

/// Maximum length for user-agent string to prevent storage bloat.
const MAX_USER_AGENT_LEN: usize = 500;

// ============================================================================
// AuthService
// ============================================================================

/// Auth service gRPC implementation.
pub struct AuthService {
    config: AuthServiceConfig,
    ctx: Arc<ServiceContext>,
    geolocation: GeolocationService,
}

impl AuthService {
    /// Creates a new auth service instance.
    #[must_use]
    pub fn new(
        config: AuthServiceConfig,
        ctx: Arc<ServiceContext>,
        geolocation: GeolocationService,
    ) -> Self {
        Self {
            config,
            ctx,
            geolocation,
        }
    }
}

// ============================================================================
// Identifier Handling
// ============================================================================

impl AuthService {
    /// Detects identifier type from format (+ prefix → phone, else email).
    #[inline]
    fn detect_identifier_type(identifier: &str) -> IdentifierType {
        if identifier.trim_start().starts_with('+') {
            IdentifierType::Phone
        } else {
            IdentifierType::Email
        }
    }

    /// Resolves identifier type from proto enum or auto-detects.
    #[inline]
    fn resolve_identifier_type(proto_type: i32, identifier: &str) -> IdentifierType {
        if proto_type == IdentifierType::Unspecified as i32 {
            Self::detect_identifier_type(identifier)
        } else {
            IdentifierType::try_from(proto_type).unwrap_or(IdentifierType::Email)
        }
    }

    /// Normalizes identifier based on type.
    #[inline]
    fn normalize_identifier(identifier: &str, id_type: IdentifierType) -> String {
        match id_type {
            IdentifierType::Phone => canonical_phone(identifier),
            _ => canonical_email(identifier),
        }
    }
}

// ============================================================================
// Client Context
// ============================================================================

impl AuthService {
    /// Extracts client context from gRPC request metadata.
    fn extract_client_context<T>(&self, req: &Request<T>) -> ClientContext {
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

        ClientContext::default()
            .with_ip(ip_address)
            .with_country(ip_country)
            .with_user_agent(user_agent)
    }

    /// Builds full client context from request and optional client info.
    fn build_client_context<T>(
        &self,
        req: &Request<T>,
        client_info: Option<&ClientInfo>,
    ) -> ClientContext {
        let ctx = self.extract_client_context(req);

        if let Some(info) = client_info {
            ctx.with_device_id(info.device_id.to_opt())
                .with_device_name(info.device_name.to_opt())
                .with_device_type(info.device_type.to_opt())
                .with_client_version(info.client_version.to_opt())
                .with_metadata(Self::metadata_to_json(&info.metadata))
        } else {
            ctx
        }
    }

    /// Converts proto metadata map to JSON value.
    fn metadata_to_json(
        metadata: &std::collections::HashMap<String, String>,
    ) -> Option<serde_json::Value> {
        if metadata.is_empty() {
            return None;
        }
        let map: serde_json::Map<String, serde_json::Value> = metadata
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        Some(serde_json::Value::Object(map))
    }
}

// ============================================================================
// Session Management
// ============================================================================

impl AuthService {
    /// Creates session and returns tokens with expiration.
    #[allow(clippy::cast_possible_wrap)] // Safe: TTL in minutes is bounded config value
    async fn create_session(
        &self,
        user: &UserWithProfile,
        installation_id: &Uuid,
        ctx: &ClientContext,
    ) -> Result<SessionTokens, Status> {
        let device_id = ctx
            .device_id()
            .ok_or_else(|| Status::invalid_argument("Missing device_id"))?;

        // Calculate access token expiration
        let access_token_expires_at = chrono::Utc::now()
            + chrono::Duration::minutes(self.config.access_token_ttl_minutes as i64);

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

        let (refresh_token, session_expires_at) =
            TokenGenerator::generate_refresh_token(self.config.refresh_token_ttl_days)
                .status("Failed to generate refresh token")?;

        let metadata = Self::build_session_metadata(ctx);
        let refresh_token_hash = TokenGenerator::hash_token(&refresh_token);

        self.ctx
            .db()
            .sessions
            .create_session(ctx.to_session_params(
                user.id,
                &refresh_token_hash,
                session_expires_at,
                metadata,
            ))
            .await
            .status("Failed to save session")?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
            access_token_expires_at,
        })
    }

    /// Builds session metadata JSON from client context.
    fn build_session_metadata(ctx: &ClientContext) -> serde_json::Value {
        let mut map = ctx
            .metadata()
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();

        if let Some(ua) = ctx.user_agent() {
            map.insert(
                "user_agent".to_string(),
                serde_json::Value::String(ua.to_string()),
            );
        }

        serde_json::Value::Object(map)
    }
}

// ============================================================================
// Auth Response Builders
// ============================================================================

impl AuthService {
    /// Creates failed auth response (OWASP: generic message).
    fn failed_auth() -> AuthResponse {
        AuthResponse {
            status: AuthStatus::Failed.into(),
            tokens: None,
            user: None,
            mfa_challenge: None,
            lockout_info: None,
            message: String::new(),
        }
    }

    /// Creates locked account response with lockout info.
    fn locked_auth(
        locked_until: chrono::DateTime<chrono::Utc>,
        failed_attempts: i16,
        max_attempts: i32,
    ) -> AuthResponse {
        let retry_after_secs = (locked_until - chrono::Utc::now()).num_seconds().max(0);
        AuthResponse {
            status: AuthStatus::Locked.into(),
            tokens: None,
            user: None,
            mfa_challenge: None,
            lockout_info: Some(LockoutInfo {
                retry_after: Some(retry_after_secs.to_proto_duration()),
                failed_attempts: failed_attempts.into(),
                max_attempts,
                locked_until: Some(locked_until.to_proto_timestamp()),
            }),
            message: String::new(),
        }
    }

    /// Creates successful auth response with tokens.
    fn success_auth(user: &UserWithProfile, tokens: SessionTokens) -> AuthResponse {
        AuthResponse {
            status: AuthStatus::Success.into(),
            tokens: Some(TokenPair {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: Some(tokens.access_token_expires_at.to_proto_timestamp()),
            }),
            user: Some(UserSnapshot {
                user_id: Some(auth_core::ToProtoUuid::to_proto(&user.id)),
                display_name: user.display_name.clone(),
                email: user.email.clone().unwrap_or_default(),
                phone: user.phone.clone().unwrap_or_default(),
                role: role_to_proto(&user.role),
                status: status_to_proto(user.status),
                email_verified: user.email_verified,
                phone_verified: user.phone_verified,
                mfa_enabled: false,
                linked_providers: vec![],
                avatar_url: user.avatar_url.clone().unwrap_or_default(),
                has_password: user.password.is_some(),
            }),
            mfa_challenge: None,
            lockout_info: None,
            message: String::new(),
        }
    }
}
