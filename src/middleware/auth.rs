//! JWT authentication middleware for gRPC and REST endpoints.
//!
//! Validates Bearer tokens and injects `AuthInfo` into request extensions.
//! Uses a pre-compiled JWT validator for optimal performance.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use tower::{Layer, Service};
use tracing::{Span, debug, warn};
use uuid::Uuid;

use crate::db::UserRole;

/// Public routes/methods that bypass authentication (O(1) lookup).
static PUBLIC_ROUTES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // gRPC public methods
        "SignIn",
        "ResetPassword",
        "SetPassword",
        // gRPC health checks
        "Check",
        "Watch",
        // REST endpoints
        "/health",
        "/health/live",
        "/health/ready",
        "/ready",
        "/metrics",
        "/",
    ])
});

/// Authenticated user information extracted from JWT.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API - all fields may be used by consumers
pub struct AuthInfo {
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub device_id: Uuid,
    pub installation_id: Uuid,
}

impl AuthInfo {
    /// Check if user has admin role.
    #[inline]
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.role == UserRole::Administrator
    }

    /// Check if user can access the target user's resource.
    #[inline]
    #[must_use]
    pub fn can_access_user(&self, target_user_id: Uuid) -> bool {
        self.user_id == target_user_id || self.is_admin()
    }
}

/// Pre-compiled JWT validator with cached decoding key.
///
/// Creating `DecodingKey` and `Validation` is expensive; this caches them.
#[derive(Clone)]
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    /// JWT issuer/audience (must match token generation).
    const ISSUER: &str = "auth-service";
    const AUDIENCE: &str = "auth-service";

    /// Create a new validator with the given secret.
    #[must_use]
    pub fn new(secret: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[Self::AUDIENCE]);
        validation.set_issuer(&[Self::ISSUER]);
        // Explicitly validate exp and nbf claims
        validation.validate_exp = true;
        validation.validate_nbf = true;

        Self {
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        }
    }

    /// Validate a JWT and extract claims.
    fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| {
                debug!(error = %e, "JWT validation failed");
                AuthError::InvalidToken
            })
    }
}

/// Tower layer for JWT authentication.
#[derive(Clone)]
pub struct AuthLayer {
    validator: Arc<JwtValidator>,
}

impl AuthLayer {
    #[must_use]
    pub fn new(jwt_secret: &str) -> Self {
        Self {
            validator: Arc::new(JwtValidator::new(jwt_secret)),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            validator: Arc::clone(&self.validator),
        }
    }
}

/// Authentication middleware service.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    validator: Arc<JwtValidator>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for AuthMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Allow CORS preflight
        if req.method() == http::Method::OPTIONS {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        let path = req.uri().path();

        // Public routes bypass auth (O(1) lookup)
        if is_public_route(path) {
            debug!(path, "Public route - skipping auth");
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        // Authenticate
        match self.authenticate(&req) {
            Ok(auth_info) => {
                // Record user_id in current span for distributed tracing
                Span::current().record("user_id", auth_info.user_id.to_string());
                debug!(user_id = %auth_info.user_id, role = ?auth_info.role, "Authenticated");
                req.extensions_mut().insert(auth_info);
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(req).await })
            }
            Err(err) => {
                warn!(path, error = %err, "Authentication failed");
                let is_grpc = is_grpc_request(&req);
                Box::pin(async move { Ok(build_error_response(&err, is_grpc)) })
            }
        }
    }
}

impl<S> AuthMiddleware<S> {
    /// Bearer token prefix.
    const BEARER_PREFIX: &str = "Bearer ";

    /// Extract and validate JWT from request.
    fn authenticate<T>(&self, req: &Request<T>) -> Result<AuthInfo, AuthError> {
        let header = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingHeader)?;

        let token = header
            .strip_prefix(Self::BEARER_PREFIX)
            .or_else(|| header.strip_prefix("bearer "))
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::InvalidFormat)?;

        let claims = self.validator.validate(token)?;
        claims.try_into()
    }
}

/// Authentication error with appropriate HTTP/gRPC status mapping.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingHeader,
    #[error("invalid authorization format")]
    InvalidFormat,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("invalid claim: {0}")]
    InvalidClaim(&'static str),
}

/// JWT claims structure (matches token generation in jwt.rs).
#[derive(Debug, serde::Deserialize)]
struct Claims {
    sub: String,
    email: String,
    name: String,
    role: String,
    device_id: String,
    installation_id: String,
}

impl TryFrom<Claims> for AuthInfo {
    type Error = AuthError;

    fn try_from(claims: Claims) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: Uuid::parse_str(&claims.sub)
                .map_err(|_| AuthError::InvalidClaim("sub"))?,
            device_id: Uuid::parse_str(&claims.device_id)
                .map_err(|_| AuthError::InvalidClaim("device_id"))?,
            installation_id: Uuid::parse_str(&claims.installation_id)
                .map_err(|_| AuthError::InvalidClaim("installation_id"))?,
            role: claims
                .role
                .parse()
                .map_err(|_| AuthError::InvalidClaim("role"))?,
            email: claims.email,
            name: claims.name,
        })
    }
}

/// Check if path or gRPC method is public (`HashSet` O(1) lookup).
fn is_public_route(path: &str) -> bool {
    // Check full path first (REST endpoints)
    if PUBLIC_ROUTES.contains(path) {
        return true;
    }
    // Extract gRPC method name (last segment after /)
    path.rsplit('/')
        .next()
        .is_some_and(|method| !method.is_empty() && PUBLIC_ROUTES.contains(method))
}

/// Check if request is gRPC (by content-type header).
fn is_grpc_request<T>(req: &Request<T>) -> bool {
    req.headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}

/// Build appropriate error response for gRPC or REST.
fn build_error_response(err: &AuthError, is_grpc: bool) -> Response<Body> {
    if is_grpc {
        Response::builder()
            .status(StatusCode::OK) // gRPC uses trailers for status
            .header("content-type", "application/grpc")
            .header("grpc-status", "16") // UNAUTHENTICATED
            .header("grpc-message", err.to_string())
            .body(Body::empty())
            .expect("valid response")
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .header("www-authenticate", "Bearer")
            .body(Body::from(format!(r#"{{"error":"{err}"}}"#)))
            .expect("valid response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_routes_identified_correctly() {
        // gRPC paths with method extraction
        assert!(is_public_route("/auth.AuthService/SignIn"));
        assert!(is_public_route("/grpc.health.v1.Health/Check"));
        // REST paths
        assert!(is_public_route("/health"));
        assert!(is_public_route("/health/ready"));
        assert!(is_public_route("/"));
        // Protected routes
        assert!(!is_public_route("/auth.AuthService/CreateUser"));
        assert!(!is_public_route("/api/users"));
    }

    #[test]
    fn jwt_validator_rejects_invalid_token() {
        let validator = JwtValidator::new("test_secret_32_chars_minimum!!");
        assert!(validator.validate("invalid.token.here").is_err());
    }

    #[test]
    fn bearer_extraction_works() {
        let req = Request::builder()
            .header("authorization", "Bearer token123")
            .body(())
            .unwrap();

        let header = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(header.strip_prefix("Bearer "), Some("token123"));
    }

    #[test]
    fn grpc_request_detection() {
        let grpc_req = Request::builder()
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        assert!(is_grpc_request(&grpc_req));

        let rest_req = Request::builder()
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        assert!(!is_grpc_request(&rest_req));
    }
}
