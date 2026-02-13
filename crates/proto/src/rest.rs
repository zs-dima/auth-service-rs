//! REST route support — utilities and generated route handlers.
//!
//! This module combines:
//! - **Re-exported** runtime types from [`tonic_rest`]
//! - **Generated** route handlers: produced by `build.rs` from `google.api.http` proto annotations
//!
//! The generated handlers are thin wrappers that transcode HTTP/JSON ↔ proto and
//! call through the Tonic service traits, sharing all auth, validation, and
//! business logic with gRPC handlers.

// Re-export runtime types so existing consumers (`auth-service` middleware, etc.)
// can continue using `auth_proto::rest::RestError` and friends.
pub use tonic_rest::{
    CLOUDFLARE_HEADERS, FORWARDED_HEADERS, RestError, build_tonic_request,
    build_tonic_request_with_headers, grpc_code_name, grpc_to_http_status, sse_error_event,
};

// Include auto-generated route handlers from build.rs.
// The generated code is fully self-contained — all imports are included.
include!(concat!(env!("OUT_DIR"), "/rest_routes.rs"));
