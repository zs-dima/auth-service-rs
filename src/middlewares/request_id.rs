//! Request ID middleware for distributed tracing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderValue, Request, Response};
use tower::{Layer, Service};
use tracing::Span;
use uuid::Uuid;

/// Header name for request ID propagation.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum length for request IDs.
const MAX_REQUEST_ID_LENGTH: usize = 64;

/// Request ID for the current request.
#[derive(Debug, Clone)]
pub struct RequestId(pub Arc<str>);

impl RequestId {
    /// Generate a new random request ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string().into())
    }

    /// Create from an existing string.
    pub fn from_str(s: &str) -> Self {
        Self(s.into())
    }

    /// Get as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Tower layer for request ID propagation.
#[derive(Clone, Default)]
pub struct RequestIdLayer;

impl RequestIdLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdMiddleware { inner }
    }
}

/// Request ID middleware service.
#[derive(Clone)]
pub struct RequestIdMiddleware<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestIdMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let request_id = extract_or_generate(&req);
        Span::current().record("request_id", request_id.as_str());
        req.extensions_mut().insert(request_id.clone());

        let request_id_str = request_id.0.to_string();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut response = inner.call(req).await?;
            if let Ok(value) = HeaderValue::from_str(&request_id_str) {
                response.headers_mut().insert(REQUEST_ID_HEADER, value);
            }
            Ok(response)
        })
    }
}

fn extract_or_generate<T>(req: &Request<T>) -> RequestId {
    req.headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= MAX_REQUEST_ID_LENGTH)
        .map(RequestId::from_str)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_generates_unique_values() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn request_id_from_str_preserves_value() {
        let id = RequestId::from_str("custom-id");
        assert_eq!(id.as_str(), "custom-id");
    }
}
