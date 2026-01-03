//! REST routes and health check handlers.

use auth_telemetry::PrometheusHandle;
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

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

    fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: "unhealthy",
            message: Some(message.into()),
        }
    }
}

/// Build version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build REST routes with the given application state.
pub fn rest_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "auth-service" }))
        .route("/health", get(|| async { "OK" }))
        .route("/health/live", get(|| async { "OK" }))
        .route("/health/ready", get(readiness_handler))
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
        && storage_check
            .as_ref()
            .map_or(true, |s| s.status == "healthy");

    Json(HealthResponse {
        status: if healthy { "healthy" } else { "unhealthy" },
        version: VERSION,
        checks: Some(HealthChecks {
            database: db_check,
            storage: storage_check,
        }),
    })
}
