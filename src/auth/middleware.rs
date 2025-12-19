use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Request as HttpRequest, Response as HttpResponse};
use tonic::{Request, Status};
use tower::{Layer, Service};

use super::jwt::{JwtAuthInfo, TokenGenerator};

/// Methods that don't require authentication.
const PUBLIC_METHODS: &[&str] = &["SignIn", "ResetPassword"];

/// Tower layer for JWT authentication middleware.
#[derive(Clone)]
pub struct JwtAuthLayer {
    jwt_secret_key: Arc<String>,
}

impl JwtAuthLayer {
    pub fn new(jwt_secret_key: impl Into<String>) -> Self {
        Self {
            jwt_secret_key: Arc::new(jwt_secret_key.into()),
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            jwt_secret_key: Arc::clone(&self.jwt_secret_key),
        }
    }
}

/// JWT authentication middleware for tonic/tower.
///
/// Validates Bearer tokens and injects `JwtAuthInfo` into request extensions.
/// Public methods (SignIn, ResetPassword) bypass authentication.
#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    inner: S,
    jwt_secret_key: Arc<String>,
}

impl<S> JwtAuthMiddleware<S> {
    /// Check if the request path is for a public method that doesn't require auth.
    fn is_public_path(path: &str) -> bool {
        path.rsplit('/')
            .next()
            .is_some_and(|method| PUBLIC_METHODS.contains(&method))
    }

    /// Extract and validate bearer token from authorization header.
    fn extract_bearer_token(header: &str) -> Option<&str> {
        header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .or_else(|| header.strip_prefix("BEARER "))
    }
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for JwtAuthMiddleware<S>
where
    S: Service<HttpRequest<ReqBody>, Response = HttpResponse<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: HttpRequest<ReqBody>) -> Self::Future {
        // Clone inner service for the async block (required by tower)
        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);

        // Skip auth for public methods
        if Self::is_public_path(req.uri().path()) {
            return Box::pin(async move { inner.call(req).await });
        }

        // Extract and validate authorization header
        let auth_result = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("Missing authorization"))
            .and_then(|header| {
                Self::extract_bearer_token(header)
                    .ok_or_else(|| Status::unauthenticated("Invalid authorization"))
            })
            .and_then(|token| {
                TokenGenerator::validate_token(token, &self.jwt_secret_key)
                    .map_err(|_| Status::unauthenticated("Invalid token"))
            })
            .and_then(|claims| {
                TokenGenerator::extract_auth_info(&claims)
                    .map_err(|_| Status::unauthenticated("Invalid token"))
            });

        match auth_result {
            Ok(auth_info) => {
                req.extensions_mut().insert(auth_info);
                Box::pin(async move { inner.call(req).await })
            }
            Err(status) => {
                let response = status.into_http::<ResBody>();
                Box::pin(async move { Ok(response) })
            }
        }
    }
}

/// Require authentication and return auth info or Status error.
pub fn require_auth<T>(request: &Request<T>) -> Result<JwtAuthInfo, Status> {
    request
        .extensions()
        .get::<JwtAuthInfo>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("Not authenticated"))
}

/// Require admin role.
pub fn require_admin<T>(request: &Request<T>) -> Result<JwtAuthInfo, Status> {
    let auth = require_auth(request)?;
    if auth.user_info.role != crate::db::UserRole::Administrator {
        return Err(Status::permission_denied("Admin access required"));
    }
    Ok(auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_methods() {
        assert!(PUBLIC_METHODS.contains(&"SignIn"));
        assert!(PUBLIC_METHODS.contains(&"ResetPassword"));
        assert!(!PUBLIC_METHODS.contains(&"SignOut"));
        assert!(!PUBLIC_METHODS.contains(&"CreateUser"));
    }

    #[test]
    fn test_is_public_path() {
        assert!(JwtAuthMiddleware::<()>::is_public_path(
            "/auth.AuthService/SignIn"
        ));
        assert!(JwtAuthMiddleware::<()>::is_public_path(
            "/auth.AuthService/ResetPassword"
        ));
        assert!(!JwtAuthMiddleware::<()>::is_public_path(
            "/auth.AuthService/CreateUser"
        ));
        assert!(!JwtAuthMiddleware::<()>::is_public_path(
            "/auth.AuthService/SignOut"
        ));
    }

    #[test]
    fn test_bearer_token_extraction() {
        // Valid formats
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("bearer abc123"),
            Some("abc123")
        );
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("BEARER abc123"),
            Some("abc123")
        );

        // Invalid formats
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("Basic abc123"),
            None
        );
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("BeArEr abc123"),
            None
        );
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("Bearerabc123"),
            None
        );
        assert_eq!(
            JwtAuthMiddleware::<()>::extract_bearer_token("abc123"),
            None
        );
    }
}
