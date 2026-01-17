//! Structured error handling for gRPC services.
//!
//! Provides type-safe error handling with automatic conversion to gRPC Status codes.
//! Internal details are logged but never exposed to clients.

use std::fmt::Display;

use thiserror::Error;
use tonic::Status;
use tracing::error;

/// Application error type with automatic Status conversion.
///
/// Internal details are logged but sanitized messages are sent to clients.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthenticated: {0}")]
    Unauthenticated(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Unavailable: {0}")]
    Unavailable(String),

    #[error("Internal: {0}")]
    Internal(String),
}

impl AppError {
    /// Create a not found error for an entity.
    pub fn not_found(entity: &str, id: impl Display) -> Self {
        Self::NotFound(format!("{entity} not found: {id}"))
    }

    /// Create an error for invalid or expired tokens.
    #[must_use]
    pub fn token_invalid(token_type: &str) -> Self {
        Self::NotFound(format!("Invalid or expired {token_type}"))
    }

    /// Create a conflict error for duplicate data.
    #[must_use]
    pub fn conflict(entity: &str, field: &str) -> Self {
        Self::Conflict(format!("{entity} with this {field} already exists"))
    }
}

impl From<AppError> for Status {
    fn from(error: AppError) -> Self {
        match &error {
            AppError::NotFound(msg) => Status::not_found(msg),
            AppError::Unauthenticated(msg) => Status::unauthenticated(msg),
            AppError::PermissionDenied(msg) => Status::permission_denied(msg),
            AppError::InvalidArgument(msg) => Status::invalid_argument(msg),
            AppError::Conflict(msg) | AppError::AlreadyExists(msg) => Status::already_exists(msg),
            AppError::Unavailable(msg) => Status::unavailable(msg),
            AppError::Internal(msg) => {
                error!(error = %msg, "Internal error");
                Status::internal("Internal server error")
            }
        }
    }
}

/// Extension trait for converting errors to Status with logging.
pub trait StatusExt<T> {
    /// Convert error to internal Status with logging.
    ///
    /// # Errors
    /// Returns `Status::internal` with the provided message.
    fn status(self, msg: &'static str) -> Result<T, Status>;
}

impl<T, E: Display> StatusExt<T> for Result<T, E> {
    fn status(self, msg: &'static str) -> Result<T, Status> {
        self.map_err(|e| {
            error!(error = %e, "{msg}");
            Status::internal(msg)
        })
    }
}

/// Extension trait for Option types.
pub trait OptionStatusExt<T> {
    /// Convert `None` to `not_found` Status.
    ///
    /// # Errors
    /// Returns `Status::not_found` if the option is `None`.
    fn ok_or_not_found(self, msg: &'static str) -> Result<T, Status>;
}

impl<T> OptionStatusExt<T> for Option<T> {
    fn ok_or_not_found(self, msg: &'static str) -> Result<T, Status> {
        self.ok_or_else(|| Status::not_found(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_helper_formats_correctly() {
        let err = AppError::not_found("User", "abc-123");
        assert!(err.to_string().contains("User"));
        assert!(err.to_string().contains("abc-123"));
    }

    #[test]
    fn conflict_helper_formats_correctly() {
        let err = AppError::conflict("User", "email");
        assert!(err.to_string().contains("User"));
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn status_conversion_maps_correctly() {
        assert_eq!(
            Status::from(AppError::NotFound("test".to_string())).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            Status::from(AppError::Unauthenticated("test".to_string())).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Status::from(AppError::Conflict("test".to_string())).code(),
            tonic::Code::AlreadyExists
        );
    }
}
