//! Structured error handling for gRPC services.
//!
//! Provides type-safe error handling with automatic conversion to gRPC Status codes.
//! Uses the Google `google.rpc.Status` rich error model via `tonic-types` to provide
//! machine-readable error details alongside human-readable messages.
//!
//! Internal details are logged but never exposed to clients.

use std::fmt::Display;

use thiserror::Error;
use tonic::Status;
use tonic_types::{ErrorDetails, StatusExt as TonicStatusExt};
use tracing::error;

/// Error domain for `ErrorInfo` details.
const ERROR_DOMAIN: &str = "auth-service";

/// Application error type with automatic Status conversion.
///
/// Internal details are logged but sanitized messages are sent to clients.
/// Each variant maps to a gRPC status code and includes rich error details
/// following the `google.rpc` error model.
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
            AppError::NotFound(msg) => {
                let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "NOT_FOUND", []);
                tonic::Status::with_error_details(tonic::Code::NotFound, msg, details)
            }
            AppError::Unauthenticated(msg) => {
                let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "UNAUTHENTICATED", []);
                tonic::Status::with_error_details(tonic::Code::Unauthenticated, msg, details)
            }
            AppError::PermissionDenied(msg) => {
                let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "PERMISSION_DENIED", []);
                tonic::Status::with_error_details(tonic::Code::PermissionDenied, msg, details)
            }
            AppError::InvalidArgument(msg) => {
                let mut details = ErrorDetails::new();
                details.add_bad_request_violation("", msg);
                tonic::Status::with_error_details(tonic::Code::InvalidArgument, msg, details)
            }
            AppError::Conflict(msg) | AppError::AlreadyExists(msg) => {
                let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "ALREADY_EXISTS", []);
                tonic::Status::with_error_details(tonic::Code::AlreadyExists, msg, details)
            }
            AppError::Unavailable(msg) => {
                let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "UNAVAILABLE", []);
                tonic::Status::with_error_details(tonic::Code::Unavailable, msg, details)
            }
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
    /// Convert `None` to `not_found` Status with rich error details.
    ///
    /// # Errors
    /// Returns `Status::not_found` with `ErrorInfo` if the option is `None`.
    fn ok_or_not_found(self, msg: &'static str) -> Result<T, Status>;
}

impl<T> OptionStatusExt<T> for Option<T> {
    fn ok_or_not_found(self, msg: &'static str) -> Result<T, Status> {
        self.ok_or_else(|| {
            let details = ErrorDetails::with_error_info(ERROR_DOMAIN, "NOT_FOUND", []);
            tonic::Status::with_error_details(tonic::Code::NotFound, msg, details)
        })
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
