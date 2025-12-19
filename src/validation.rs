//! Request validation helpers
//!
//! PGV (protoc-gen-validate) based validation utilities for gRPC requests.
//! Validation rules are defined in proto files using annotations like:
//! - [(validate.rules).string.email = true]
//! - [(validate.rules).string.min_len = 8]
//! - [(validate.rules).message.required = true]

use prost_validate::Validator;
use tonic::Status;

/// Extension trait for validating requests and converting errors to Status
pub trait ValidateExt {
    /// Validate the request and return Status error on failure
    fn validate_or_status(&self) -> Result<(), Status>;
}

impl<T: Validator> ValidateExt for T {
    fn validate_or_status(&self) -> Result<(), Status> {
        self.validate()
            .map_err(|e| Status::invalid_argument(e.to_string()))
    }
}
