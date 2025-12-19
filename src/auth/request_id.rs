//! Request ID middleware for distributed tracing.
//!
//! Extracts or generates a unique request ID for each request and propagates it
//! through the tracing context for correlation across services.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderValue, Request as HttpRequest, Response as HttpResponse};
use tower::{Layer, Service};
use tracing::Span;
use uuid::Uuid;

/// Header name for request ID propagation
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Request ID extracted from or generated for the current request
#[derive(Debug, Clone)]
pub struct RequestId(pub Arc<str>);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string().into())
    }

    pub fn from_str(s: &str) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

/// Tower layer for request ID propagation
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

/// Request ID middleware that extracts or generates request IDs
#[derive(Clone)]
pub struct RequestIdMiddleware<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for RequestIdMiddleware<S>
where
    S: Service<HttpRequest<ReqBody>, Response = HttpResponse<ResBody>> + Clone + Send + 'static,
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

    fn call(&mut self, mut req: HttpRequest<ReqBody>) -> Self::Future {
        // Extract existing request ID or generate new one
        let request_id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .map(RequestId::from_str)
            .unwrap_or_default();

        // Record in current span
        Span::current().record("request_id", request_id.as_str());

        // Insert into extensions for downstream access
        req.extensions_mut().insert(request_id.clone());

        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);

        let request_id_value = request_id.0.to_string();

        Box::pin(async move {
            let mut response = inner.call(req).await?;

            // Add request ID to response headers
            if let Ok(header_value) = HeaderValue::from_str(&request_id_value) {
                response
                    .headers_mut()
                    .insert(REQUEST_ID_HEADER, header_value);
            }

            Ok(response)
        })
    }
}

/// Extract request ID from tonic Request extensions
pub fn get_request_id<T>(request: &tonic::Request<T>) -> Option<&RequestId> {
    request.extensions().get::<RequestId>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_generation() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();

        // Should be valid UUIDs
        assert!(Uuid::parse_str(id1.as_str()).is_ok());
        assert!(Uuid::parse_str(id2.as_str()).is_ok());

        // Should be unique
        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_request_id_from_str() {
        let custom_id = "my-custom-request-id";
        let id = RequestId::from_str(custom_id);
        assert_eq!(id.as_str(), custom_id);
    }
}
