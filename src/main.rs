use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::State;
use axum::{Json, Router, routing::get};
use http::{Method, header};
use metrics_exporter_prometheus::PrometheusHandle;
use secrecy::ExposeSecret;
use serde::Serialize;
use tokio::signal;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tonic_web::GrpcWebLayer;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

mod auth;
mod config;
mod db;
mod error;
mod extensions;
mod proto;
mod service;
mod telemetry;
mod util;
mod validation;

use auth::{JwtAuthLayer, RequestIdLayer};
use config::Config;
use db::{Database, create_pool};
use proto::auth::auth_service_server::AuthServiceServer;
use service::{AuthServiceConfig, AuthServiceImpl};
use telemetry::{init_metrics, setup_telemetry, shutdown_telemetry};

/// Build version (injected at compile time or default)
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    database: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load and validate configuration
    let config = Config::init()?;

    // Setup telemetry (logging + OpenTelemetry)
    let otel_provider = setup_telemetry(&config);

    // Initialize Prometheus metrics
    let metrics_handle = init_metrics();

    info!(
        version = VERSION,
        grpc_address = %config.grpc_address,
        http_address = ?config.http_address,
        grpc_web = config.grpc_web,
        otlp_enabled = config.otlp_endpoint.is_some(),
        pid = std::process::id(),
        "Starting auth-service"
    );

    // Connect to database
    let pool = create_pool(&config).await?;
    info!("Connected to database");

    let database = Database::new(pool);

    // Parse gRPC address
    let grpc_addr: SocketAddr = config.grpc_address.parse()?;

    // Build CORS layer if configured
    let cors_layer = build_cors_layer(config.cors_allow_origins.as_deref());

    // Create auth service config (only what the service needs)
    let auth_service_config = AuthServiceConfig {
        jwt_secret_key: config.jwt_secret_key.expose_secret().to_string(),
        access_token_ttl_minutes: config.access_token_ttl_minutes,
        refresh_token_ttl_days: config.refresh_token_ttl_days,
        max_photo_bytes: config.max_photo_bytes,
    };

    let auth_service = AuthServiceImpl::new(auth_service_config, database.clone());
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    // Compose middleware layers (order matters: first added = outermost)
    let server_layers = ServiceBuilder::new()
        // Request ID propagation (outermost for tracing)
        .layer(RequestIdLayer::new())
        // CORS must be early to handle OPTIONS preflight
        .option_layer(cors_layer.clone())
        // gRPC-Web support for browser clients
        .option_layer(config.grpc_web.then_some(GrpcWebLayer::new()))
        // Concurrency limiting
        .layer(ConcurrencyLimitLayer::new(config.rate_limit_rps as usize))
        // JWT authentication
        .layer(JwtAuthLayer::new(config.jwt_secret_key.expose_secret()))
        // Request timeout
        .timeout(Duration::from_secs(30))
        .into_inner();

    let auth_grpc_service = AuthServiceServer::new(auth_service);

    let mut router = Server::builder()
        .accept_http1(config.grpc_web)
        .layer(server_layers)
        .add_service(health_service)
        .add_service(auth_grpc_service);

    if config.grpc_reflection {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/file_descriptor_set.bin"
            )))
            .build_v1()?;
        router = router.add_service(reflection_service);
        info!("gRPC reflection enabled");
    }

    info!(address = %grpc_addr, "gRPC server listening");

    // Start HTTP server for health/metrics if configured
    if let Some(http_addr) = &config.http_address {
        let http_addr: SocketAddr = http_addr.parse()?;
        let http_router = build_http_router(database.clone(), cors_layer, metrics_handle);

        info!(address = %http_addr, "HTTP server listening");

        // Run both servers concurrently
        tokio::select! {
            result = router.serve_with_shutdown(grpc_addr, shutdown_signal()) => {
                result?;
            }
            result = axum::serve(
                tokio::net::TcpListener::bind(http_addr).await?,
                http_router
            ) => {
                result?;
            }
        }
    } else {
        router
            .serve_with_shutdown(grpc_addr, shutdown_signal())
            .await?;
    }

    // Gracefully shutdown OpenTelemetry
    shutdown_telemetry(otel_provider);

    info!("Server shut down gracefully");
    Ok(())
}

/// Build CORS layer from configuration
fn build_cors_layer(origins: Option<&str>) -> Option<CorsLayer> {
    let origins = origins?;

    let cors = if origins.trim() == "*" {
        CorsLayer::new().allow_origin(Any)
    } else {
        let origins: Vec<_> = origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new().allow_origin(origins)
    };

    Some(
        cors.allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            "x-grpc-web".parse().unwrap(),
            "x-user-agent".parse().unwrap(),
            "x-request-id".parse().unwrap(),
        ])
        .expose_headers([
            "grpc-status".parse().unwrap(),
            "grpc-message".parse().unwrap(),
            "x-request-id".parse().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .max_age(Duration::from_secs(3600)),
    )
}

/// Build HTTP router for health, metrics, and file operations
fn build_http_router(db: Database, cors: Option<CorsLayer>, metrics: PrometheusHandle) -> Router {
    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
        .route("/metrics", get(move || async move { metrics.render() }))
        .with_state(db);

    if let Some(cors) = cors {
        router.layer(cors)
    } else {
        router
    }
}

/// Liveness probe - always returns OK if server is running
async fn health_handler() -> &'static str {
    "OK"
}

/// Readiness probe - checks database connectivity
async fn readiness_handler(State(db): State<Database>) -> Json<HealthResponse> {
    let db_healthy = db.health_check().await;

    Json(HealthResponse {
        status: if db_healthy { "ready" } else { "degraded" },
        version: VERSION,
        database: db_healthy,
    })
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, starting graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown");
        }
    }
}
