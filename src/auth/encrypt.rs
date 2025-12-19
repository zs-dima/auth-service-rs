use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::AppError;

/// Password hasher using Argon2id (OWASP recommended)
pub struct Encryptor;

impl Encryptor {
    /// Hash a password using Argon2id
    pub fn hash(password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hash error: {}", e)))?;

        Ok(hash.to_string())
    }

    /// Verify a password against its hash
    pub fn verify(password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_123";
        let hash = Encryptor::hash(password).unwrap();

        assert!(Encryptor::verify(password, &hash));
        assert!(!Encryptor::verify("wrong_password", &hash));
    }

    #[test]
    fn test_hash_produces_different_results() {
        let password = "same_password";
        let hash1 = Encryptor::hash(password).unwrap();
        let hash2 = Encryptor::hash(password).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(Encryptor::verify(password, &hash1));
        assert!(Encryptor::verify(password, &hash2));
    }
}
