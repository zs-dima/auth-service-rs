//! REST routes and health check handlers.
//!
//! This module provides REST endpoints for the auth service. While the primary API
//! is gRPC, these REST endpoints serve specific purposes:
//!
//! # Endpoints
//!
//! ## Health Checks (Kubernetes probes)
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/` | GET | Service identity - returns `"auth-service"` |
//! | `/health` | GET | Simple liveness - returns `"OK"` |
//! | `/health/live` | GET | Kubernetes liveness probe - returns `"OK"` |
//! | `/health/ready` | GET | Kubernetes readiness probe with dependency checks |
//!
//! ## Email Verification
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/v1/verify-email?token=xxx` | GET | Email verification link handler (302 redirect) |
//! | `/verify-email?token=xxx` | GET | **Deprecated** — backward compat, use `/v1/` path |
//!
//! ## Metrics (optional)
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/metrics` | GET | Prometheus metrics (when enabled) |
//!
//! # Health Check Response
//!
//! The `/health/ready` endpoint returns a JSON response with component health:
//!
//! ```json
//! {
//!   "status": "healthy",
//!   "version": "0.1.0",
//!   "checks": {
//!     "database": { "status": "healthy" },
//!     "storage": { "status": "healthy" }
//!   }
//! }
//! ```
//!
//! # Email Verification Flow
//!
//! 1. User clicks verification link in email: `https://domain/v1/verify-email?token=xxx`
//! 2. Backend validates token and marks email as verified
//! 3. User is redirected to frontend success/error page

use auth_core::TokenGenerator;
use auth_proto::operations::{CheckResult, HealthChecks, HealthResponse, HealthStatus};
use axum::{
    Json, Router,
    extract::{Query, State},
    response::Redirect,
    routing::get,
};
use http::StatusCode;
use serde::Deserialize;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};

use crate::core::error_codes;
use crate::startup::AppState;

/// Build version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Query parameters for email verification.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    /// The verification token from the email link.
    pub token: String,
}

/// Build REST routes with the given application state.
///
/// Infrastructure endpoints (health, metrics) live at the root.
/// API endpoints are nested under `/v1` for forward-compatible versioning.
pub fn rest_routes(state: AppState) -> Router {
    let v1 = Router::new().route("/verify-email", get(verify_email_handler));

    Router::new()
        .route("/", get(|| async { "auth-service" }))
        .route("/health", get(|| async { "OK" }))
        .route("/health/live", get(|| async { "OK" }))
        .route("/health/ready", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        // Versioned API routes
        .nest("/v1", v1)
        // Keep root-level verify-email for backward compatibility with
        // existing email links already sent to users.
        // Deprecated: clients should use /v1/verify-email going forward.
        .route(
            "/verify-email",
            get(verify_email_handler).layer(deprecated_layer()),
        )
        .with_state(state)
}

/// Prometheus metrics endpoint.
///
/// Returns Prometheus-formatted metrics when metrics collection is enabled.
/// Returns an empty string when metrics are disabled.
async fn metrics_handler(State(state): State<AppState>) -> String {
    state
        .metrics
        .as_ref()
        .map(auth_telemetry::PrometheusHandle::render)
        .unwrap_or_default()
}

/// Kubernetes readiness probe with dependency health checks.
///
/// Returns HTTP 200 with JSON body when all dependencies are healthy,
/// or HTTP 503 (Service Unavailable) when any dependency is unhealthy.
/// Kubernetes uses the status code to determine pod readiness.
async fn readiness_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<HealthResponse>) {
    let db_check = if state.ctx.db().health_check().await {
        CheckResult {
            status: HealthStatus::Healthy.into(),
            message: None,
        }
    } else {
        CheckResult {
            status: HealthStatus::Unhealthy.into(),
            message: Some("Database connection failed".to_string()),
        }
    };

    let storage_check = match state.ctx.s3() {
        Some(s3) => Some(if s3.health_check().await {
            CheckResult {
                status: HealthStatus::Healthy.into(),
                message: None,
            }
        } else {
            CheckResult {
                status: HealthStatus::Unhealthy.into(),
                message: Some("S3 connection failed".to_string()),
            }
        }),
        None => None,
    };

    let all_healthy = HealthStatus::try_from(db_check.status) == Ok(HealthStatus::Healthy)
        && storage_check
            .as_ref()
            .is_none_or(|s| HealthStatus::try_from(s.status) == Ok(HealthStatus::Healthy));

    let overall = if all_healthy {
        HealthStatus::Healthy
    } else {
        HealthStatus::Unhealthy
    };

    let http_status = if all_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(HealthResponse {
            status: overall.into(),
            version: VERSION.to_string(),
            checks: Some(HealthChecks {
                database: Some(db_check),
                storage: storage_check,
            }),
        }),
    )
}

/// Handle email verification link clicks.
///
/// Flow: Email link → Backend /verify-email?token=xxx → 302 redirect → Frontend success page.
///
/// - On success: Marks email as verified, redirects to success page
/// - On failure: Redirects to error page with error code
///
/// Uses atomic DB function that validates token, checks user status,
/// consumes token, and marks email verified in a single transaction.
async fn verify_email_handler(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Redirect {
    let urls = state.ctx.urls();

    // Decode the URL-encoded token
    let token = match urlencoding::decode(&query.token) {
        Ok(t) => t.into_owned(),
        Err(e) => {
            warn!(error = %e, "Invalid token encoding");
            return Redirect::to(&urls.email_verified_error(error_codes::INVALID_TOKEN));
        }
    };

    // Hash the token to look up in database
    let token_hash = TokenGenerator::hash_token(&token);

    // Atomic: validate → check status → consume → verify → activate
    match state
        .ctx
        .db()
        .email_verifications
        .verify_email(&token_hash)
        .await
    {
        Ok(user) => {
            info!(user_id = %user.id, "Email verified successfully");
            Redirect::to(&urls.email_verified_success())
        }
        Err(e) => {
            warn!(error = %e, "Email verification failed");
            let error_code = match e {
                auth_core::AppError::PermissionDenied(_) => error_codes::ACCOUNT_SUSPENDED,
                _ => error_codes::EXPIRED_TOKEN,
            };
            Redirect::to(&urls.email_verified_error(error_code))
        }
    }
}

/// Create a layer that adds the RFC 8594 `Deprecation` response header
/// to signal that an endpoint is deprecated and clients should migrate.
///
/// When a removal date is determined, add a `Sunset` header alongside
/// this with the retirement timestamp (RFC 7231 date format).
fn deprecated_layer() -> SetResponseHeaderLayer<http::HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        http::HeaderName::from_static("deprecation"),
        http::HeaderValue::from_static("true"),
    )
}
