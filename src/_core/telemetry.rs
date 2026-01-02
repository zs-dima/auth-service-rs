//! Telemetry setup for OpenTelemetry tracing and Prometheus metrics.

use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use tracing::Level;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use super::config::Config;

/// Service name constant
const SERVICE_NAME: &str = "auth-service";

/// Initialize Prometheus metrics exporter and return the handle for the /metrics endpoint.
pub fn init_metrics() -> PrometheusHandle {
    PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder")
}

/// Initialize OpenTelemetry tracing with OTLP exporter.
///
/// Returns `None` if OTLP endpoint is not configured.
pub fn init_opentelemetry(otlp_endpoint: Option<&str>) -> Option<SdkTracerProvider> {
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

/// Setup complete logging/tracing stack.
///
/// - Console logging (JSON or human-readable)
/// - OpenTelemetry tracing (if OTLP endpoint configured)
pub fn setup_telemetry(config: &Config) -> Option<SdkTracerProvider> {
    let level = match config.log_level.to_uppercase().as_str() {
        "TRACE" => Level::TRACE,
        "DEBUG" => Level::DEBUG,
        "INFO" => Level::INFO,
        "WARN" => Level::WARN,
        "ERROR" => Level::ERROR,
        _ => Level::INFO,
    };

    let env_filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("sqlx::query=warn".parse().unwrap())
        .add_directive("tower=info".parse().unwrap())
        .add_directive("h2=info".parse().unwrap())
        .add_directive("hyper=info".parse().unwrap());

    // Initialize OpenTelemetry if endpoint is configured
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

    // Initialize subscriber
    if otel_provider.is_some() {
        let tracer = opentelemetry::global::tracer(SERVICE_NAME);
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    otel_provider
}

/// Shutdown OpenTelemetry provider gracefully.
pub fn shutdown_telemetry(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider {
        if let Err(e) = provider.shutdown() {
            eprintln!("Failed to shutdown OpenTelemetry provider: {e}");
        }
    }
}
