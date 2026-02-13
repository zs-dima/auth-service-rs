//! JWT authentication middleware for gRPC and REST endpoints.
//!
//! Validates Bearer tokens and injects `AuthInfo` into request extensions.
//! Uses the shared `JwtValidator` from `auth_core` for consistency.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use auth_core::{AuthInfo, JwtError, JwtValidator};
use axum::body::Body;
use http::{Request, Response, StatusCode};
use phf::phf_set;
use tower::{Layer, Service};
use tracing::{Span, debug};

use super::client_ip::ClientIp;

/// Public routes that bypass authentication.
/// Uses compile-time perfect hash function for O(1) lookup with zero runtime initialization.
static PUBLIC_ROUTES: phf::Set<&'static str> = phf_set! {
    // gRPC public methods (authentication)
    "Authenticate",
    "SignUp",
    "RecoveryStart",
    "RecoveryConfirm",
    "RefreshTokens",
    "ConfirmVerification",
    "VerifyMfa",
    // gRPC public methods (OAuth)
    "GetOAuthUrl",
    "ExchangeOAuthCode",
    // gRPC health checks
    "Check",
    "Watch",
    // REST infrastructure endpoints
    "/health",
    "/health/live",
    "/health/ready",
    "/ready",
    "/metrics",
    "/verify-email",
    "/v1/verify-email",
    "/",
};

/// Tower layer for JWT authentication.
#[derive(Clone)]
pub struct AuthLayer {
    validator: JwtValidator,
}

impl AuthLayer {
    #[must_use]
    pub const fn new(validator: JwtValidator) -> Self {
        Self { validator }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            validator: self.validator.clone(),
        }
    }
}

/// Authentication middleware service.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    validator: JwtValidator,
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
        // Extract and inject client IP into request extensions
        let client_ip = ClientIp::from_request(&req);
        req.extensions_mut().insert(client_ip);

        // Allow CORS preflight
        if req.method() == http::Method::OPTIONS {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        let path = req.uri().path();

        // Public routes bypass auth
        if is_public_route(path) {
            debug!(path, "Public route - skipping auth");
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        // Authenticate
        match self.authenticate(&req) {
            Ok(auth_info) => {
                Span::current().record("user_id", auth_info.user_id.to_string());
                debug!(user_id = %auth_info.user_id, role = ?auth_info.role, "Authenticated");
                req.extensions_mut().insert(auth_info);
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(req).await })
            }
            Err(err) => {
                let is_grpc = is_grpc_request(&req);
                Box::pin(async move { Ok(build_error_response(&err, is_grpc)) })
            }
        }
    }
}

impl<S> AuthMiddleware<S> {
    const BEARER_PREFIX: &str = "Bearer ";

    fn authenticate<T>(&self, req: &Request<T>) -> Result<AuthInfo, JwtError> {
        let header = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(JwtError::MissingHeader)?;

        let token = header
            .strip_prefix(Self::BEARER_PREFIX)
            .or_else(|| header.strip_prefix("bearer "))
            .filter(|t| !t.is_empty())
            .ok_or(JwtError::InvalidFormat)?;

        self.validator.validate(token)
    }
}

/// Check if path or gRPC method is public.
fn is_public_route(path: &str) -> bool {
    if PUBLIC_ROUTES.contains(path) {
        return true;
    }

    // Check proto-generated public REST paths (from google.api.http annotations).
    // These are generated at build time from the proto definitions, eliminating
    // manual duplication between proto files and auth middleware.
    if auth_proto::rest::PUBLIC_REST_PATHS.contains(&path) {
        return true;
    }

    // Swagger UI and OpenAPI spec are only served when the feature is enabled.
    // Prefix match is required because Swagger UI serves assets at sub-paths.
    #[cfg(feature = "swagger")]
    if path.starts_with("/swagger-ui") || path.starts_with("/api-docs/") {
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
fn build_error_response(err: &JwtError, is_grpc: bool) -> Response<Body> {
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
    use secrecy::SecretString;

    #[test]
    fn public_routes_identified_correctly() {
        // Versioned gRPC paths (auth.v1 package)
        assert!(is_public_route("/auth.v1.AuthService/Authenticate"));
        assert!(is_public_route("/auth.v1.AuthService/SignUp"));
        assert!(is_public_route("/auth.v1.AuthService/RecoveryStart"));
        assert!(is_public_route("/auth.v1.AuthService/RecoveryConfirm"));
        assert!(is_public_route("/auth.v1.AuthService/RefreshTokens"));
        assert!(is_public_route("/auth.v1.AuthService/ConfirmVerification"));
        assert!(is_public_route("/auth.v1.AuthService/VerifyMfa"));
        assert!(is_public_route("/auth.v1.AuthService/GetOAuthUrl"));
        assert!(is_public_route("/auth.v1.AuthService/ExchangeOAuthCode"));
        assert!(is_public_route("/grpc.health.v1.Health/Check"));
        assert!(is_public_route("/grpc.health.v1.Health/Watch"));
        // REST infrastructure endpoints
        assert!(is_public_route("/health"));
        assert!(is_public_route("/health/live"));
        assert!(is_public_route("/health/ready"));
        assert!(is_public_route("/verify-email"));
        assert!(is_public_route("/v1/verify-email"));
        assert!(is_public_route("/metrics"));
        assert!(is_public_route("/"));
        // REST public endpoints (from generated PUBLIC_REST_PATHS)
        assert!(is_public_route("/v1/auth/authenticate"));
        assert!(is_public_route("/v1/auth/signup"));
        assert!(is_public_route("/v1/auth/token/refresh"));
        assert!(is_public_route("/v1/auth/recovery/start"));
        assert!(is_public_route("/v1/auth/recovery/confirm"));
        assert!(is_public_route("/v1/auth/verification/confirm"));
        assert!(is_public_route("/v1/auth/mfa/verify"));
        assert!(is_public_route("/v1/auth/oauth/url"));
        assert!(is_public_route("/v1/auth/oauth/exchange"));
        // Protected routes
        assert!(!is_public_route("/auth.v1.AuthService/ChangePassword"));
        assert!(!is_public_route("/auth.v1.AuthService/SignOut"));
        assert!(!is_public_route("/users.v1.UserService/GetUser"));
        assert!(!is_public_route("/api/users"));
    }

    #[cfg(feature = "swagger")]
    #[test]
    fn swagger_routes_are_public() {
        assert!(is_public_route("/swagger-ui"));
        assert!(is_public_route("/swagger-ui/index.html"));
        assert!(is_public_route("/swagger-ui/swagger-ui.css"));
        assert!(is_public_route("/api-docs/openapi.json"));
    }

    #[test]
    fn jwt_validator_rejects_invalid_token() {
        let secret = SecretString::from("test_secret_32_chars_minimum!!");
        let validator = JwtValidator::new(&secret);
        assert!(validator.validate("invalid.token.here").is_err());
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
