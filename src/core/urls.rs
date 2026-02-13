//! Centralized URL builder for frontend redirects and email links.
//!
//! All frontend URL paths are defined here as constants to ensure consistency
//! and make maintenance easier. The domain is configured via environment variable.

/// Frontend URL path constants.
mod paths {
    pub const VERIFY_EMAIL: &str = "/verify-email";
    pub const EMAIL_VERIFIED: &str = "/email-verified";
    pub const PASSWORD_RESET: &str = "/auth-reset";
    pub const SIGN_IN: &str = "/signin";
}

/// Error codes for email verification redirects.
pub mod error_codes {
    pub const INVALID_TOKEN: &str = "invalid_token";
    pub const EXPIRED_TOKEN: &str = "expired_token";
    pub const ACCOUNT_SUSPENDED: &str = "account_suspended";
    pub const _INTERNAL_ERROR: &str = "internal_error";
}

/// Builder for constructing frontend URLs with the configured domain.
///
/// Centralizes all URL construction to ensure consistency across the codebase.
/// The domain is typically configured via the `DOMAIN` environment variable.
#[derive(Debug, Clone)]
pub struct UrlBuilder {
    base_url: String,
}

impl UrlBuilder {
    /// Create a new URL builder with the given domain.
    ///
    /// # Arguments
    /// * `domain` - The domain name (e.g., "example.com")
    #[must_use]
    pub fn new(domain: &str) -> Self {
        Self {
            base_url: format!("https://{domain}"),
        }
    }

    /// Build URL for email verification with token.
    ///
    /// Example: `https://example.com/verify-email?token=abc123`
    #[must_use]
    pub fn verify_email(&self, token: &str) -> String {
        let encoded = urlencoding::encode(token);
        format!("{}{}?token={encoded}", self.base_url, paths::VERIFY_EMAIL)
    }

    /// Build URL for successful email verification redirect.
    ///
    /// Example: `https://example.com/email-verified?status=success`
    #[must_use]
    pub fn email_verified_success(&self) -> String {
        format!("{}{}?status=success", self.base_url, paths::EMAIL_VERIFIED)
    }

    /// Build URL for failed email verification redirect with error code.
    ///
    /// Example: `https://example.com/email-verified?status=error&code=expired_token`
    #[must_use]
    pub fn email_verified_error(&self, code: &str) -> String {
        format!(
            "{}{}?status=error&code={code}",
            self.base_url,
            paths::EMAIL_VERIFIED
        )
    }

    /// Build URL for password reset with token.
    ///
    /// Example: `https://example.com/auth-reset?token=abc123`
    #[must_use]
    pub fn password_reset(&self, token: &str) -> String {
        let encoded = urlencoding::encode(token);
        format!("{}{}?token={encoded}", self.base_url, paths::PASSWORD_RESET)
    }

    /// Build URL for sign-in page.
    ///
    /// Example: `https://example.com/signin`
    #[must_use]
    pub fn sign_in(&self) -> String {
        format!("{}{}", self.base_url, paths::SIGN_IN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_email_url() {
        let builder = UrlBuilder::new("example.com");
        assert_eq!(
            builder.verify_email("token123"),
            "https://example.com/verify-email?token=token123"
        );
    }

    #[test]
    fn verify_email_url_encodes_special_chars() {
        let builder = UrlBuilder::new("example.com");
        let url = builder.verify_email("a+b=c&d");
        assert!(url.contains("a%2Bb%3Dc%26d"));
    }

    #[test]
    fn email_verified_success_url() {
        let builder = UrlBuilder::new("example.com");
        assert_eq!(
            builder.email_verified_success(),
            "https://example.com/email-verified?status=success"
        );
    }

    #[test]
    fn email_verified_error_url() {
        let builder = UrlBuilder::new("example.com");
        assert_eq!(
            builder.email_verified_error(error_codes::EXPIRED_TOKEN),
            "https://example.com/email-verified?status=error&code=expired_token"
        );
    }

    #[test]
    fn password_reset_url() {
        let builder = UrlBuilder::new("example.com");
        assert_eq!(
            builder.password_reset("reset_token"),
            "https://example.com/auth-reset?token=reset_token"
        );
    }

    #[test]
    fn sign_in_url() {
        let builder = UrlBuilder::new("example.com");
        assert_eq!(builder.sign_in(), "https://example.com/signin");
    }
}
