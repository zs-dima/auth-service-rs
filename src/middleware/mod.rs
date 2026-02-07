//! Unified middleware pipeline for gRPC and REST endpoints.
//!
//! This module provides tower-based middleware that works consistently for both
//! gRPC and REST endpoints.
//!
//! # Middleware Order
//! Middleware is applied in layers. When using `.layer()` on a router:
//! - Outermost layer is added last
//! - Request flows: outermost → innermost → handler
//! - Response flows: handler → innermost → outermost
//!
//! Unified middleware stack (applied in reverse via `ServiceBuilder`):
//! 1. `RequestIdLayer` - Extract/generate request ID first
//! 2. `MetricsLayer` - Record request count and duration
//! 3. `TraceLayer` - Request tracing with spans
//! 4. `CorsLayer` - CORS handling
//! 5. `AuthLayer` - JWT authentication (skips public routes)
//!
//! REST-only (applied to REST router before merge):
//! - `TimeoutLayer` - Request timeout (gRPC uses `grpc-timeout` header instead)

pub mod auth;
pub mod client_ip;
pub mod metrics;
pub mod request_id;

pub use auth::AuthLayer;
pub use client_ip::ClientIp;
pub use metrics::MetricsLayer;
pub use request_id::RequestIdLayer;
