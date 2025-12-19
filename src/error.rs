use std::fmt::Display;

use thiserror::Error;
use tonic::Status;
use tracing::error;

/// Application error type
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

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<AppError> for Status {
    fn from(error: AppError) -> Self {
        match error {
            AppError::NotFound(msg) => Status::not_found(msg),
            AppError::Unauthenticated(msg) => Status::unauthenticated(msg),
            AppError::PermissionDenied(msg) => Status::permission_denied(msg),
            AppError::InvalidArgument(msg) => Status::invalid_argument(msg),
            AppError::Internal(ref msg) => {
                error!(error = %msg, "Internal error");
                Status::internal("Internal error")
            }
            AppError::Database(ref e) => {
                error!(error = %e, "Database error");
                Status::internal("Internal error")
            }
        }
    }
}

/// Result type alias for the application
pub type AppResult<T> = Result<T, AppError>;

/// Extension trait for converting errors to Status with logging
pub trait StatusExt<T> {
    /// Map error to Status::internal with logging
    fn status(self, msg: &'static str) -> Result<T, Status>;

    /// Map error to Status::unauthenticated with logging
    fn status_unauthenticated(self, msg: &'static str) -> Result<T, Status>;

    /// Map error to Status::not_found with logging
    fn status_not_found(self, msg: &'static str) -> Result<T, Status>;
}

impl<T, E: Display> StatusExt<T> for Result<T, E> {
    fn status(self, msg: &'static str) -> Result<T, Status> {
        self.map_err(|e| {
            error!(error = %e, "{msg}");
            Status::internal(msg)
        })
    }

    fn status_unauthenticated(self, msg: &'static str) -> Result<T, Status> {
        self.map_err(|e| {
            error!(error = %e, "{msg}");
            Status::unauthenticated(msg)
        })
    }

    fn status_not_found(self, msg: &'static str) -> Result<T, Status> {
        self.map_err(|e| {
            error!(error = %e, "{msg}");
            Status::not_found(msg)
        })
    }
}
