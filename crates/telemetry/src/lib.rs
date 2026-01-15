//! Telemetry setup for OpenTelemetry tracing, Prometheus metrics, and Sentry error tracking.
//!
//! This crate provides a unified observability stack for gRPC services:
//! - **Tracing**: Structured logging with optional OpenTelemetry export
//! - **Metrics**: Prometheus metrics endpoint
//! - **Error tracking**: Sentry integration for error reporting
//!
//! # Features
//! - `otlp` (default): OpenTelemetry OTLP exporter
//! - `prometheus` (default): Prometheus metrics exporter
//! - `sentry` (default): Sentry error tracking

use std::time::Duration;

use tracing::Level;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "prometheus")]
pub use metrics_exporter_prometheus::PrometheusHandle;

#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
#[cfg(feature = "otlp")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "otlp")]
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};

#[cfg(feature = "sentry")]
pub use sentry;

/// Service name constant.
const SERVICE_NAME: &str = "auth-service";

/// Telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    pub log_level: String,
    /// Use JSON log format
    pub json_logs: bool,
    /// OpenTelemetry OTLP endpoint (optional)
    pub otlp_endpoint: Option<String>,
    /// Sentry DSN (optional)
    pub sentry_dsn: Option<String>,
    /// Environment name (e.g., "production", "development")
    pub environment: Option<String>,
    /// Application version
    pub version: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: "INFO".to_string(),
            json_logs: true,
            otlp_endpoint: None,
            sentry_dsn: None,
            environment: None,
            version: None,
        }
    }
}

/// Active telemetry handles that need graceful shutdown.
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    otel_provider: Option<SdkTracerProvider>,
    #[cfg(feature = "sentry")]
    _sentry_guard: Option<sentry::ClientInitGuard>,
}

impl TelemetryGuard {
    /// Shutdown telemetry providers gracefully.
    pub fn shutdown(self) {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.otel_provider
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Failed to shutdown OpenTelemetry provider: {e}");
        }
        // Sentry guard is dropped automatically
    }
}

/// Initialize Prometheus metrics exporter and return the handle for the /metrics endpoint.
///
/// # Panics
/// Panics if the Prometheus recorder fails to install.
#[cfg(feature = "prometheus")]
#[must_use]
pub fn init_metrics() -> PrometheusHandle {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder")
}

/// Initialize OpenTelemetry tracing with OTLP exporter.
///
/// Returns `None` if OTLP endpoint is not configured.
#[cfg(feature = "otlp")]
fn init_opentelemetry(otlp_endpoint: Option<&str>) -> Option<SdkTracerProvider> {
    let endpoint = otlp_endpoint?;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to create OTLP exporter");

    let resource = Resource::builder()
        .with_attributes([KeyValue::new("service.name", SERVICE_NAME)])
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());

    Some(provider)
}

/// Initialize Sentry error tracking.
///
/// Returns `None` if Sentry DSN is not configured.
#[cfg(feature = "sentry")]
fn init_sentry(config: &TelemetryConfig) -> Option<sentry::ClientInitGuard> {
    let dsn = config.sentry_dsn.as_ref()?;

    let guard = sentry::init((
        dsn.as_str(),
        sentry::ClientOptions {
            release: config.version.clone().map(Into::into),
            environment: config.environment.clone().map(Into::into),
            // Capture 100% of transactions for performance monitoring
            traces_sample_rate: 1.0,
            // Attach stacktraces to messages
            attach_stacktrace: true,
            // Send default PII (request data, user info)
            send_default_pii: false,
            ..Default::default()
        },
    ));

    if guard.is_enabled() {
        tracing::info!("Sentry initialized");
        Some(guard)
    } else {
        tracing::warn!("Sentry DSN provided but client not enabled");
        None
    }
}

/// Setup complete logging/tracing stack.
///
/// - Console logging (JSON or human-readable)
/// - `OpenTelemetry` tracing (if OTLP endpoint configured)
/// - Sentry error tracking (if DSN configured)
///
/// Returns a guard that should be kept alive for the application lifetime.
/// Call `shutdown()` on the guard for graceful shutdown.
///
/// # Panics
/// Panics if the tracing subscriber cannot be initialized.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn setup_telemetry(config: &TelemetryConfig) -> TelemetryGuard {
    let level = match config.log_level.to_uppercase().as_str() {
        "TRACE" => Level::TRACE,
        "DEBUG" => Level::DEBUG,
        "WARN" => Level::WARN,
        "ERROR" => Level::ERROR,
        _ => Level::INFO,
    };

    let env_filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("sqlx::query=warn".parse().unwrap())
        .add_directive("tower=info".parse().unwrap())
        .add_directive("h2=info".parse().unwrap())
        .add_directive("hyper=info".parse().unwrap())
        .add_directive("sentry=warn".parse().unwrap())
        .add_directive("maxminddb=info".parse().unwrap());

    // Initialize Sentry first (before tracing subscriber)
    #[cfg(feature = "sentry")]
    let sentry_guard = init_sentry(config);

    // Initialize OpenTelemetry if endpoint is configured
    #[cfg(feature = "otlp")]
    let otel_provider = init_opentelemetry(config.otlp_endpoint.as_deref());

    // Build fmt layer based on config
    let fmt_layer = if config.json_logs {
        fmt::layer().json().with_target(true).boxed()
    } else {
        fmt::layer()
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_timer(ChronoLocal::new("%H:%M:%S%.3f".to_string()))
            .compact()
            .boxed()
    };

    // Build and initialize the subscriber
    #[cfg(all(feature = "otlp", feature = "sentry"))]
    {
        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        if otel_provider.is_some() {
            let tracer = opentelemetry::global::tracer(SERVICE_NAME);
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let sentry_layer = sentry_tracing::layer();
            registry.with(otel_layer).with(sentry_layer).init();
        } else {
            let sentry_layer = sentry_tracing::layer();
            registry.with(sentry_layer).init();
        }
    }

    #[cfg(all(feature = "otlp", not(feature = "sentry")))]
    {
        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        if otel_provider.is_some() {
            let tracer = opentelemetry::global::tracer(SERVICE_NAME);
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            registry.with(otel_layer).init();
        } else {
            registry.init();
        }
    }

    #[cfg(all(not(feature = "otlp"), feature = "sentry"))]
    {
        let sentry_layer = sentry_tracing::layer();
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(sentry_layer)
            .init();
    }

    #[cfg(all(not(feature = "otlp"), not(feature = "sentry")))]
    {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    TelemetryGuard {
        #[cfg(feature = "otlp")]
        otel_provider,
        #[cfg(feature = "sentry")]
        _sentry_guard: sentry_guard,
    }
}

/// Capture an error to Sentry (if enabled).
#[cfg(feature = "sentry")]
pub fn capture_error<E: std::fmt::Display>(error: &E) {
    sentry::capture_message(&error.to_string(), sentry::Level::Error);
}

/// Capture an error to Sentry (no-op if Sentry feature is disabled).
#[cfg(not(feature = "sentry"))]
pub fn capture_error<E: std::fmt::Display>(_error: &E) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_defaults() {
        let config = TelemetryConfig::default();
        assert_eq!(config.log_level, "INFO");
        assert!(config.json_logs);
        assert!(config.otlp_endpoint.is_none());
        assert!(config.sentry_dsn.is_none());
    }
}
