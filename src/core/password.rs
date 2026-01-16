//! Password encryption using Argon2id (OWASP recommended).

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use auth_core::AppError;

/// Hash a password using Argon2id.
///
/// # Errors
///
/// Returns `AppError::Internal` if password hashing fails.
pub fn hash(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))?;

    Ok(hash.to_string())
}

/// Verify a password against its hash.
#[must_use]
pub fn verify(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash(password).unwrap();

        assert!(verify(password, &hash));
        assert!(!verify("wrong_password", &hash));
    }

    #[test]
    fn test_hash_produces_different_results() {
        let password = "same_password";
        let hash1 = hash(password).unwrap();
        let hash2 = hash(password).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify(password, &hash1));
        assert!(verify(password, &hash2));
    }
}
