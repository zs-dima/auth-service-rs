//! Core library with shared types, traits, and error handling.
//!
//! This crate provides reusable components for gRPC services:
//! - Error types with automatic Status conversion
//! - Proto extension traits for UUID handling
//! - Validation helpers
//! - JWT token generation and validation (with `jwt` feature)

pub mod error;
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod proto_ext;
pub mod validation;

pub use error::{AppError, OptionStatusExt, StatusExt};
#[cfg(feature = "jwt")]
pub use jwt::{AuthInfo, JwtError, JwtSubject, JwtValidator, TokenGenerator, UserRole};
pub use proto_ext::{ToProtoUuid, UuidExt};
pub use validation::ValidateExt;
