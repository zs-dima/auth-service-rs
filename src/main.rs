//! Auth service: gRPC + REST authentication service.

use auth_telemetry::{TelemetryConfig, init_metrics, setup_telemetry};
use tokio::signal;
use tracing::info;

mod config;
mod core;
mod middleware;
mod routes;
mod services;
mod startup;

use config::Config;

/// Build version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::init()?;

    // Setup telemetry (tracing, metrics, Sentry)
    let telemetry_config = TelemetryConfig {
        log_level: config.log_level.clone(),
        json_logs: config.json_logs,
        otlp_endpoint: config.otlp_endpoint.clone(),
        sentry_dsn: config.sentry_dsn.clone(),
        environment: config.environment.clone(),
        version: Some(VERSION.to_string()),
    };
    let telemetry_guard = setup_telemetry(&telemetry_config);
    let _metrics_handle = init_metrics();

    info!(
        version = VERSION,
        address = %config.grpc_address,
        grpc_web = config.grpc_web,
        otlp = config.otlp_endpoint.is_some(),
        sentry = config.sentry_dsn.is_some(),
        pid = std::process::id(),
        "Starting auth-service"
    );

    let (app, addr) = startup::build_app(&config).await?;

    info!(address = %addr, "Server listening");

    // Run server with ConnectInfo to capture client socket addresses
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    telemetry_guard.shutdown();
    info!("Shutdown complete");
    Ok(())
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
