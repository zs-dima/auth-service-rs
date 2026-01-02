//! Auth service: gRPC + REST authentication service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::{Json, Router, routing::get};
use http::Request;
use secrecy::ExposeSecret;
use serde::Serialize;
use tokio::signal;
use tonic::service::Routes;
use tonic_health::server::health_reporter;
use tonic_web::GrpcWebLayer;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{Level, info};

#[path = "_core/mod.rs"]
mod core;
mod auth;
mod db;
mod middleware;
mod proto;
mod service;
mod util;

use core::{
    config::Config,
    telemetry::{init_metrics, setup_telemetry, shutdown_telemetry},
};
use db::{Database, create_pool};
use middleware::{AuthLayer, RequestIdLayer};
use proto::auth::auth_service_server::AuthServiceServer;
use service::{AuthServiceConfig, AuthServiceImpl};
use util::{S3Config, S3Storage};

/// Build version (injected at compile time or default)
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum gRPC message size (32 MB)
const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<HealthChecks>,
}

#[derive(Serialize)]
struct HealthChecks {
    database: CheckResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage: Option<CheckResult>,
}

#[derive(Serialize)]
struct CheckResult {
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

/// Application state for health checks.
#[derive(Clone)]
struct AppState {
    db: Database,
    s3: Option<Arc<S3Storage>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::init()?;
    let otel_provider = setup_telemetry(&config);
    let metrics_handle = init_metrics();

    info!(
        version = VERSION,
        address = %config.grpc_address,
        grpc_web = config.grpc_web,
        otlp = config.otlp_endpoint.is_some(),
        pid = std::process::id(),
        "Starting auth-service"
    );

    // Database
    let pool = create_pool(&config).await?;
    info!("Connected to database");
    let database = Database::new(pool);

    // S3 storage
    let s3_storage = init_s3(&config).await;

    // Server address
    let addr: SocketAddr = config.grpc_address.parse()?;

    // Build services
    let auth_service_config = AuthServiceConfig {
        jwt_secret_key: config.jwt_secret_key.expose_secret().to_string(),
        access_token_ttl_minutes: config.access_token_ttl_minutes,
        refresh_token_ttl_days: config.refresh_token_ttl_days,
    };

    let auth_service =
        AuthServiceImpl::new(auth_service_config, database.clone(), s3_storage.clone());

    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    let auth_server = AuthServiceServer::new(auth_service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE);

    let mut grpc_routes = Routes::new(health_service).add_service(auth_server);

    if config.grpc_reflection {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/file_descriptor_set.bin"
            )))
            .build_v1()?;
        grpc_routes = grpc_routes.add_service(reflection);
        info!("gRPC reflection enabled");
    }

    // Application state for health checks
    let app_state = AppState {
        db: database,
        s3: s3_storage,
    };

    // Build REST routes
    let rest_routes = Router::new()
        .route("/", get(|| async { "auth-service" }))
        .route("/health", get(|| async { "OK" }))
        .route("/health/live", get(|| async { "OK" }))
        .route("/health/ready", get(readiness_handler))
        .route(
            "/metrics",
            get(move || async move { metrics_handle.render() }),
        )
        .with_state(app_state);

    // Combine gRPC and REST
    let grpc_router = if config.grpc_web {
        grpc_routes.into_axum_router().layer(GrpcWebLayer::new())
    } else {
        grpc_routes.into_axum_router()
    };

    let jwt_secret = config.jwt_secret_key.expose_secret();
    let cors = build_cors(config.cors_allow_origins.as_deref());
    let request_timeout = Duration::from_secs(30);

    // Build middleware stack with ServiceBuilder (executes top-to-bottom on request)
    let middleware = ServiceBuilder::new()
        // 1. Request ID - generate/propagate first
        .layer(RequestIdLayer::new())
        // 2. Tracing - create span with request details
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request<_>| {
                    tracing::info_span!(
                        "request",
                        method = %req.method(),
                        uri = %req.uri(),
                        request_id = tracing::field::Empty,
                        user_id = tracing::field::Empty,
                    )
                })
                .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::DEBUG)),
        )
        // 3. Timeout - prevent hung requests
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        // 4. CORS - handle preflight before auth
        .layer(cors)
        // 5. Auth - JWT validation (skips public routes)
        .layer(AuthLayer::new(jwt_secret));

    let app = rest_routes.merge(grpc_router).layer(middleware);

    info!(address = %addr, "Server listening");

    // Run server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    shutdown_telemetry(otel_provider);
    info!("Shutdown complete");
    Ok(())
}

async fn init_s3(config: &Config) -> Option<Arc<S3Storage>> {
    match (
        &config.s3_url,
        &config.s3_access_key_id,
        &config.s3_secret_access_key,
    ) {
        (Some(url), Some(key), Some(secret)) => {
            let s3_config =
                S3Config::from_url(url, key.clone(), secret.clone()).expect("Invalid S3 URL");
            let storage = S3Storage::new(s3_config).await.expect("Failed to init S3");
            Some(Arc::new(storage))
        }
        _ => {
            info!("S3 not configured");
            None
        }
    }
}

fn build_cors(origins: Option<&str>) -> CorsLayer {
    let cors = match origins {
        Some(o) if o.trim() == "*" => CorsLayer::permissive(),
        Some(o) => {
            let origins: Vec<_> = o.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            CorsLayer::new().allow_origin(origins)
        }
        None => CorsLayer::permissive(),
    };

    cors.allow_headers(Any)
        .expose_headers([
            "grpc-status".parse().unwrap(),
            "grpc-message".parse().unwrap(),
            "x-request-id".parse().unwrap(),
        ])
        .allow_methods(Any)
        .max_age(Duration::from_secs(3600))
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

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
    }
}
