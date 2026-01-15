//! REST routes and health check handlers.

use auth_core::TokenGenerator;
use auth_telemetry::PrometheusHandle;
use axum::{
    Json, Router,
    extract::{Query, State},
    response::Redirect,
    routing::get,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

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

    // Consume the token (validates and marks as used atomically)
    let user_id = match state
        .db
        .email_verifications
        .consume_token(&token_hash)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "Invalid or expired email verification token");
            return Redirect::to(&urls.email_verified_error(error_codes::EXPIRED_TOKEN));
        }
    };

    // Mark user email as verified
    if let Err(e) = state.db.users.set_email_verified(user_id).await {
        error!(user_id = %user_id, error = %e, "Failed to set email verified");
        return Redirect::to(&urls.email_verified_error(error_codes::INTERNAL_ERROR));
    }

    info!(user_id = %user_id, "Email verified successfully");

    // Redirect to frontend success page
    Redirect::to(&urls.email_verified_success())
}
