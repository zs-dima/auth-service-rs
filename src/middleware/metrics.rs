//! Request metrics middleware for unified gRPC and REST observability.
//!
//! Records request count and duration for both gRPC and REST endpoints
//! using the `metrics` crate (rendered by Prometheus exporter).
//!
//! # Metrics Emitted
//!
//! | Metric | Type | Labels | Description |
//! |--------|------|--------|-------------|
//! | `http_requests_total` | Counter | `method`, `path`, `status` | Total request count |
//! | `http_request_duration_seconds` | Histogram | `method`, `path`, `status` | Request latency |
//!
//! ## Label values
//!
//! - **gRPC**: `path` = full method (e.g., `/auth.v1.AuthService/Authenticate`),
//!   `status` = `grpc-status` header when present, otherwise HTTP status code.
//!   Note: `grpc-status` is only available in response *headers* (not HTTP/2
//!   trailers) for error responses and tonic-web. For successful gRPC calls
//!   where the status lives in trailers, the HTTP status (always `200`) is used.
//! - **REST**: `path` = normalized route (e.g., `/health/ready`), `status` = HTTP
//!   status code. Unrecognized paths are bucketed as `/*` to prevent label
//!   cardinality explosion.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use http::{Request, Response};
use tower::{Layer, Service};

/// Known REST paths for metric label normalization.
///
/// Using a static slice keeps cardinality bounded — any path not in this
/// list is reported as `/*`. This prevents unbounded time-series growth
/// from dynamic path segments (UUIDs, tokens, device IDs).
const KNOWN_REST_PATHS: &[&str] = &[
    "/",
    "/health",
    "/health/live",
    "/health/ready",
    "/metrics",
    "/verify-email",
    "/v1/verify-email",
    "/swagger-ui",
    "/api-docs/openapi.yaml",
];

/// Tower layer for request metrics collection.
///
/// Must be placed after `RequestIdLayer` and before `AuthLayer` in the
/// middleware stack so it captures the full request lifecycle.
#[derive(Clone, Copy, Default)]
pub struct MetricsLayer;

impl MetricsLayer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsMiddleware { inner }
    }
}

/// Metrics middleware service.
#[derive(Clone)]
pub struct MetricsMiddleware<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsMiddleware<S>
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

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let method = req.method().to_string();
        let is_grpc = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/grpc"));

        // gRPC paths are already bounded (finite set of service/method combos).
        // REST paths are normalized to a known set to prevent cardinality explosion.
        let path = if is_grpc {
            req.uri().path().to_string()
        } else {
            normalize_rest_path(req.uri().path())
        };

        let start = Instant::now();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let response = inner.call(req).await?;

            let duration = start.elapsed().as_secs_f64();

            // For gRPC: prefer grpc-status header when present (error responses,
            // tonic-web). For successful unary calls the status lives in HTTP/2
            // trailers which aren't accessible here — fall back to HTTP status.
            // For REST: use the HTTP status code directly.
            let status = if is_grpc {
                response
                    .headers()
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .map_or_else(
                        || response.status().as_u16().to_string(),
                        str::to_string,
                    )
            } else {
                response.status().as_u16().to_string()
            };

            let labels = [
                ("method", method),
                ("path", path),
                ("status", status),
            ];

            metrics::counter!("http_requests_total", &labels).increment(1);
            metrics::histogram!("http_request_duration_seconds", &labels).record(duration);

            Ok(response)
        })
    }
}

/// Normalize REST paths to a known set to prevent label cardinality explosion.
///
/// Returns the path verbatim if it matches a known route, otherwise `/*`.
fn normalize_rest_path(path: &str) -> String {
    if KNOWN_REST_PATHS.contains(&path) {
        return path.to_string();
    }

    // Swagger UI serves assets at sub-paths (e.g., /swagger-ui/index.html)
    if path.starts_with("/swagger-ui") {
        return "/swagger-ui".to_string();
    }

    "/*".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_rest_paths_pass_through() {
        assert_eq!(normalize_rest_path("/health/ready"), "/health/ready");
        assert_eq!(normalize_rest_path("/metrics"), "/metrics");
        assert_eq!(normalize_rest_path("/v1/verify-email"), "/v1/verify-email");
    }

    #[test]
    fn unknown_rest_paths_bucketed() {
        assert_eq!(normalize_rest_path("/v1/auth/sessions/device-abc-123"), "/*");
        assert_eq!(normalize_rest_path("/unknown/route"), "/*");
        assert_eq!(normalize_rest_path("/verify-email?token=abc"), "/*");
    }

    #[test]
    fn swagger_paths_normalized() {
        assert_eq!(normalize_rest_path("/swagger-ui"), "/swagger-ui");
        assert_eq!(normalize_rest_path("/swagger-ui/index.html"), "/swagger-ui");
        assert_eq!(normalize_rest_path("/swagger-ui/swagger-ui.css"), "/swagger-ui");
    }
}
