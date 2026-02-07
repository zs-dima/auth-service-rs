//! Server startup and wiring.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use auth_core::{JwtValidator, OptionStrExt};
use auth_db::{Database, DbConfig, create_pool};
use auth_email::{EmailConfig, EmailService};
use auth_mailjet::{MailjetConfig, MailjetService};
use auth_proto::auth::auth_service_server::AuthServiceServer;
use auth_proto::users::user_service_server::UserServiceServer;
use auth_storage::{S3Config, S3Storage};
use auth_telemetry::PrometheusHandle;
use axum::Router;
use http::Request;
use secrecy::SecretString;
use tonic::service::Routes;
use tonic_health::server::health_reporter;
use tonic_web::GrpcWebLayer;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{Level, info, warn};

#[cfg(feature = "swagger")]
use utoipa_swagger_ui::{Config as SwaggerConfig, SwaggerUi};

use crate::config::{AuthServiceConfig, Config, UserServiceConfig};
use crate::core::{EmailProvider, GeolocationService, ServiceContext, UrlBuilder};
use crate::middleware::{AuthLayer, MetricsLayer, RequestIdLayer};
use crate::routes::{VERSION, rest_routes};
use crate::services::{AuthService, UserService};

/// Maximum gRPC message size (32 MB).
const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Request timeout duration.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Application state shared across handlers.
///
/// Wraps `ServiceContext` (database, email, S3, URLs) and adds REST-specific
/// concerns like metrics. gRPC services use `Arc<ServiceContext>` directly.
#[derive(Clone)]
pub struct AppState {
    /// Shared infrastructure context (database, email, S3, URLs).
    pub ctx: Arc<ServiceContext>,
    /// Prometheus metrics handle (None if metrics disabled).
    pub metrics: Option<PrometheusHandle>,
}

/// Build and configure the complete application.
///
/// # Errors
/// Returns an error if database connection, S3, or server configuration fails.
///
/// # Panics
/// Panics if JWT secret is not configured (validated in `Config::init`).
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub async fn build_app(
    config: &Config,
    metrics_handle: Option<auth_telemetry::PrometheusHandle>,
) -> anyhow::Result<(Router, SocketAddr)> {
    // Create shared JWT validator once
    let jwt_secret = config
        .jwt_secret_key()
        .expect("JWT secret is required (validated in Config::init)");
    let jwt_validator = JwtValidator::new(&jwt_secret);

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
    let s3_storage = init_s3(config);

    // Email service
    let email_service = init_email(config);

    // GeoIP service
    let geolocation = GeolocationService::new(config.geoip_db_path.clone());
    if geolocation.is_available() {
        info!("GeoIP service initialized");
    } else {
        info!("GeoIP service disabled (no database configured)");
    }

    // Server address (PORT env var for Cloud Run, or GRPC_ADDRESS)
    let addr: SocketAddr = config.server_address().parse()?;

    // Get domain for email links (defaults to "localhost" if not configured)
    let domain = config.domain.clone().or_str("localhost");

    // Build URL builder for frontend links
    let urls = UrlBuilder::new(&domain);

    // Build shared service context (infrastructure only)
    let service_ctx = Arc::new(ServiceContext::new(
        database.clone(),
        email_service.clone(),
        s3_storage.clone(),
        urls.clone(),
    ));

    // Build auth service config (auth-specific settings)
    let auth_config = AuthServiceConfig {
        jwt_validator: jwt_validator.clone(),
        access_token_ttl_minutes: config.access_token_ttl_minutes,
        refresh_token_ttl_days: config.refresh_token_ttl_days,
        password_reset_ttl_minutes: config.password_reset_ttl_minutes,
        email_verification_ttl_hours: config.email_verification_ttl_hours,
        max_failed_login_attempts: config.max_failed_login_attempts,
        lockout_duration_minutes: config.lockout_duration_minutes,
    };

    // Build user service config
    let user_config = UserServiceConfig {
        email_verification_ttl_hours: config.email_verification_ttl_hours,
    };

    // Build auth service with shared context
    let auth_service = AuthService::new(auth_config, service_ctx.clone(), geolocation.clone());

    // Build user service with shared context
    let user_service = UserService::new(user_config, service_ctx.clone());

    // Health reporter
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthService>>()
        .await;
    health_reporter
        .set_serving::<UserServiceServer<UserService>>()
        .await;

    // Auth server
    let auth_server = AuthServiceServer::new(auth_service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE);

    // User server
    let user_server = UserServiceServer::new(user_service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE);

    // gRPC routes
    let mut grpc_routes = Routes::new(health_service)
        .add_service(auth_server)
        .add_service(user_server);

    if config.grpc_reflection {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(auth_proto::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        grpc_routes = grpc_routes.add_service(reflection);
        info!("gRPC reflection enabled");
    }

    // Application state (shares ServiceContext with gRPC services)
    let app_state = AppState {
        ctx: service_ctx,
        metrics: metrics_handle,
    };

    // Build REST routes with request timeout
    // REST gets HTTP 408 on timeout. gRPC relies on Tonic's built-in deadline
    // propagation via the `grpc-timeout` header, so no separate timeout layer is needed.
    let rest_router = rest_routes(app_state).layer(TimeoutLayer::with_status_code(
        http::StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    ));

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
        .layer(MetricsLayer::new())
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
        .layer(cors)
        .layer(AuthLayer::new(jwt_validator));

    let app = rest_router.merge(grpc_router);

    // Serve the proto-generated OpenAPI 3.1 spec and Swagger UI.
    // The spec is read from disk at startup (`api/openapi/v1/openapi.yaml`,
    // generated by `make openapi` from proto definitions). This avoids
    // `include_str!` which fails when the file hasn't been generated yet.
    #[cfg(feature = "swagger")]
    let app = {
        let spec_path = std::env::var("OPENAPI_SPEC_PATH")
            .unwrap_or_else(|_| "api/openapi/v1/openapi.yaml".to_string());
        let spec_yaml: Arc<str> = std::fs::read_to_string(&spec_path)
            .unwrap_or_else(|_| {
                warn!("OpenAPI spec not found at {spec_path} — run `make openapi` to generate");
                "openapi: \"3.1.0\"\ninfo:\n  title: Auth Service API\n  version: \"0.0.0\"\npaths: {}".to_string()
            })
            .into();

        let etag: Arc<str> = format!("\"{VERSION}\"").into();

        app.route(
            "/api-docs/openapi.yaml",
            axum::routing::get({
                let yaml = spec_yaml;
                move || {
                    let yaml = Arc::clone(&yaml);
                    let etag = Arc::clone(&etag);
                    async move {
                        let mut headers = http::HeaderMap::new();
                        headers.insert(
                            http::header::CONTENT_TYPE,
                            "text/yaml; charset=utf-8".parse().unwrap(),
                        );
                        headers.insert(
                            http::header::CACHE_CONTROL,
                            "public, max-age=3600".parse().unwrap(),
                        );
                        headers.insert(
                            http::header::ETAG,
                            etag.parse().expect("VERSION is valid ASCII"),
                        );
                        (headers, yaml.to_string())
                    }
                }
            }),
        )
        .merge(SwaggerUi::new("/swagger-ui").config(SwaggerConfig::new(["/api-docs/openapi.yaml"])))
    };

    let app = app.layer(middleware);

    Ok((app, addr))
}

fn init_s3(config: &Config) -> Option<Arc<S3Storage>> {
    let secret = config.s3_secret_access_key();
    if let (Some(url), Some(key), Some(secret)) = (&config.s3_url, &config.s3_access_key_id, secret)
    {
        let s3_config = S3Config::from_url(url, key.clone(), secret).expect("Invalid S3 URL");
        Some(Arc::new(S3Storage::new(s3_config)))
    } else {
        info!("S3 not configured");
        None
    }
}

fn init_email(config: &Config) -> Option<EmailProvider> {
    let domain = config.domain.as_ref()?;

    // Check provider preference
    let provider = config.email_provider.to_lowercase();

    if provider == "mailjet" {
        return init_mailjet(config);
    }

    // Default to SMTP, fallback to Mailjet if SMTP not configured
    if config.smtp_enabled() {
        init_smtp(config, domain)
    } else if config.mailjet_enabled() {
        info!("SMTP not configured, falling back to Mailjet");
        init_mailjet(config)
    } else {
        info!("Email not configured (SMTP_URL/SMTP_SENDER or MAILJET_* required)");
        None
    }
}

fn init_smtp(config: &Config, domain: &str) -> Option<EmailProvider> {
    let smtp_url = config.smtp_url_with_password()?;
    let sender = config.email_sender.as_ref()?;

    match EmailConfig::from_url(&smtp_url, sender, domain) {
        Ok(email_config) => match EmailService::new(email_config) {
            Ok(service) => {
                info!("Email service initialized (SMTP with code templates)");
                Some(EmailProvider::Smtp(Arc::new(service)))
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize SMTP email service");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "Invalid SMTP configuration");
            None
        }
    }
}

fn init_mailjet(config: &Config) -> Option<EmailProvider> {
    let api_key = config.mailjet_api_key.as_ref()?;
    let api_secret = config.mailjet_api_secret()?;
    let (sender_name, sender_email) = config.parse_email_sender()?;
    let password_reset_template_id = config.mailjet_password_recovery_start_template_id?;
    let welcome_template_id = config.mailjet_welcome_template_id.unwrap_or(0);
    let email_verification_template_id = config.mailjet_email_verification_template_id.unwrap_or(0);
    let password_changed_template_id = config.mailjet_password_changed_template_id.unwrap_or(0);

    let mailjet_config = MailjetConfig {
        api_key: api_key.clone(),
        api_secret: SecretString::from(api_secret),
        sender_name,
        sender_email,
        password_reset_template_id,
        welcome_template_id,
        email_verification_template_id,
        password_changed_template_id,
    };

    let service = MailjetService::new(mailjet_config);
    info!("Email service initialized (Mailjet with platform templates)");
    Some(EmailProvider::Mailjet(Arc::new(service)))
}

fn build_cors(origins: Option<&str>) -> CorsLayer {
    let cors = match origins {
        Some(o) if o.trim() == "*" => CorsLayer::permissive(),
        Some(o) => {
            let origins: Vec<_> = o.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            CorsLayer::new().allow_origin(origins)
        }
        None => {
            warn!("CORS_ALLOW_ORIGINS not set — defaulting to restrictive (no cross-origin)");
            CorsLayer::new()
        }
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
