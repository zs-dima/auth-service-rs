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
//! Recommended order (applied in reverse):
//! 1. RequestIdLayer - Extract/generate request ID first
//! 2. TraceLayer - Request tracing with spans
//! 3. TimeoutLayer - Request timeout
//! 4. ConcurrencyLimitLayer - Backpressure control
//! 5. CorsLayer - CORS handling
//! 6. AuthLayer - JWT authentication (skips public routes)

pub mod auth;
pub mod request_id;

pub use auth::{AuthInfo, AuthLayer};
pub use request_id::RequestIdLayer;
