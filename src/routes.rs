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
//! | `/verify-email?token=xxx` | GET | Email verification link handler (302 redirect) |
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
//! 1. User clicks verification link in email: `https://domain/verify-email?token=xxx`
//! 2. Backend validates token and marks email as verified
//! 3. User is redirected to frontend success/error page

use auth_core::TokenGenerator;
use auth_telemetry::PrometheusHandle;
use axum::{
    Json, Router,
    extract::{Query, State},
    response::Redirect,
    routing::get,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::core::error_codes;
use crate::startup::AppState;

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<HealthChecks>,
}

#[derive(Serialize)]
pub struct HealthChecks {
    database: CheckResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage: Option<CheckResult>,
}

#[derive(Serialize)]
pub struct CheckResult {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl CheckResult {
    const fn healthy() -> Self {
        Self {
            status: "healthy",
            message: None,
        }
    }

    fn unhealthy(message: &str) -> Self {
        Self {
            status: "unhealthy",
            message: Some(message.to_string()),
        }
    }
}

/// Build version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Query parameters for email verification.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    /// The verification token from the email link.
    pub token: String,
}

/// Build REST routes with the given application state.
pub fn rest_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "auth-service" }))
        .route("/health", get(|| async { "OK" }))
        .route("/health/live", get(|| async { "OK" }))
        .route("/health/ready", get(readiness_handler))
        .route("/verify-email", get(verify_email_handler))
        .with_state(state)
}

/// Build REST routes with metrics endpoint.
#[allow(dead_code)] // Available for metrics endpoint integration
pub fn rest_routes_with_metrics(state: AppState, metrics_handle: PrometheusHandle) -> Router {
    rest_routes(state).route(
        "/metrics",
        get(move || {
            let handle = metrics_handle.clone();
            async move { handle.render() }
        }),
    )
}

async fn readiness_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let db_check = if state.db.health_check().await {
        CheckResult::healthy()
    } else {
        CheckResult::unhealthy("Database connection failed")
    };

    let storage_check = match &state.s3 {
        Some(s3) => Some(if s3.health_check().await {
            CheckResult::healthy()
        } else {
            CheckResult::unhealthy("S3 connection failed")
        }),
        None => None,
    };

    let healthy = db_check.status == "healthy"
        && storage_check.as_ref().is_none_or(|s| s.status == "healthy");

    Json(HealthResponse {
        status: if healthy { "healthy" } else { "unhealthy" },
        version: VERSION,
        checks: Some(HealthChecks {
            database: db_check,
            storage: storage_check,
        }),
    })
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
    let urls = &state.urls;

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
    match state.db.email_verifications.verify_email(&token_hash).await {
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
