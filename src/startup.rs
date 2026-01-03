//! Server startup and wiring.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use auth_db::{Database, DbConfig, create_pool};
use auth_proto::auth::auth_service_server::AuthServiceServer;
use auth_storage::{S3Config, S3Storage};
use axum::Router;
use http::Request;
use tonic::service::Routes;
use tonic_health::server::health_reporter;
use tonic_web::GrpcWebLayer;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{Level, info};

use crate::config::Config;
use crate::core::JwtValidator;
use crate::middleware::{AuthLayer, RequestIdLayer};
use crate::routes::rest_routes;
use crate::services::AuthServiceImpl;

/// Maximum gRPC message size (32 MB).
const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Request timeout duration.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub s3: Option<Arc<S3Storage>>,
}

/// Build and configure the complete application.
pub async fn build_app(config: &Config) -> anyhow::Result<(Router, SocketAddr)> {
    // Create shared JWT validator once
    let jwt_validator = JwtValidator::new(&config.jwt_secret_key);

    // Database
    let db_config = DbConfig {
        url: config.database_url(),
        pool_min: config.db_pool_min,
        pool_max: config.db_pool_max,
        connect_timeout: config.db_connect_timeout(),
    };
    let pool = create_pool(&db_config).await?;
    info!("Connected to database");
    let database = Database::new(pool);

    // S3 storage
    let s3_storage = init_s3(config).await;

    // Server address
    let addr: SocketAddr = config.grpc_address.parse()?;

    // Build auth service with shared validator
    let auth_service = AuthServiceImpl::new(
        jwt_validator.clone(),
        config.access_token_ttl_minutes,
        config.refresh_token_ttl_days,
        database.clone(),
        s3_storage.clone(),
    );

    // Health reporter
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    // Auth server
    let auth_server = AuthServiceServer::new(auth_service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE);

    // gRPC routes
    let mut grpc_routes = Routes::new(health_service).add_service(auth_server);

    if config.grpc_reflection {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(auth_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        grpc_routes = grpc_routes.add_service(reflection);
        info!("gRPC reflection enabled");
    }

    // Application state
    let app_state = AppState {
        db: database,
        s3: s3_storage,
    };

    // Build REST routes
    let rest_router = rest_routes(app_state);

    // Combine gRPC and REST
    let grpc_router = if config.grpc_web {
        grpc_routes.into_axum_router().layer(GrpcWebLayer::new())
    } else {
        grpc_routes.into_axum_router()
    };

    // Build middleware stack
    let cors = build_cors(config.cors_allow_origins.as_deref());

    let middleware = ServiceBuilder::new()
        .layer(RequestIdLayer::new())
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
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ))
        .layer(cors)
        .layer(AuthLayer::new(jwt_validator));

    let app = rest_router.merge(grpc_router).layer(middleware);

    Ok((app, addr))
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
