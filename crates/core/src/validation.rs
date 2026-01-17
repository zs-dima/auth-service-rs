//! Request validation helpers.
//!
//! PGV (protoc-gen-validate) based validation utilities for gRPC requests.
//! Validation rules are defined in proto files using annotations like:
//! - `[(validate.rules).string.email = true]`
//! - `[(validate.rules).string.min_len = 8]`
//! - `[(validate.rules).message.required = true]`

use prost_validate::Validator;
use tonic::Status;

/// Extension trait for validating requests and converting errors to Status.
pub trait ValidateExt {
    /// Validate the request and return Status error on failure.
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` if validation fails.
    fn validate_or_status(&self) -> Result<(), Status>;
}

impl<T: Validator> ValidateExt for T {
    fn validate_or_status(&self) -> Result<(), Status> {
        self.validate()
            .map_err(|e| Status::invalid_argument(e.to_string()))
    }
}

/// Domain-level validation helpers for business rules.
///
/// Use these for validation that can't be expressed in proto annotations.
pub mod domain {
    use tonic::Status;

    /// Minimum password length for security.
    pub const MIN_PASSWORD_LENGTH: usize = 8;
    /// Maximum email length.
    pub const MAX_EMAIL_LENGTH: usize = 255;
    /// Maximum name length.
    pub const MAX_NAME_LENGTH: usize = 255;

    /// Validate password strength beyond basic length.
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` if the password is too short or lacks required characters.
    pub fn validate_password(password: &str) -> Result<(), Status> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(Status::invalid_argument(format!(
                "Password must be at least {MIN_PASSWORD_LENGTH} characters"
            )));
        }

        let has_letter = password.chars().any(char::is_alphabetic);
        let has_digit = password.chars().any(|c| c.is_ascii_digit());

        if !has_letter || !has_digit {
            return Err(Status::invalid_argument(
                "Password must contain at least one letter and one number",
            ));
        }

        Ok(())
    }

    /// Validate email format (basic check beyond proto validation).
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` if the email format is invalid.
    pub fn validate_email(email: &str) -> Result<(), Status> {
        if email.len() > MAX_EMAIL_LENGTH {
            return Err(Status::invalid_argument(format!(
                "Email must not exceed {MAX_EMAIL_LENGTH} characters"
            )));
        }

        if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
            return Err(Status::invalid_argument("Invalid email format"));
        }

        Ok(())
    }

    /// Validate user name.
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` if the name is empty or too long.
    pub fn validate_name(name: &str) -> Result<(), Status> {
        let name = name.trim();

        if name.is_empty() {
            return Err(Status::invalid_argument("Name cannot be empty"));
        }

        if name.len() > MAX_NAME_LENGTH {
            return Err(Status::invalid_argument(format!(
                "Name must not exceed {MAX_NAME_LENGTH} characters"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::domain::*;

    #[test]
    fn test_password_validation() {
        assert!(validate_password("password1").is_ok());
        assert!(validate_password("MySecure123").is_ok());
        assert!(validate_password("short1").is_err());
        assert!(validate_password("onlyletters").is_err());
        assert!(validate_password("12345678").is_err());
    }

    #[test]
    fn test_email_validation() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@domain.org").is_ok());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("nodomain").is_err());
    }

    #[test]
    fn test_name_validation() {
        assert!(validate_name("John Doe").is_ok());
        assert!(validate_name("Alice").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
    }
}
