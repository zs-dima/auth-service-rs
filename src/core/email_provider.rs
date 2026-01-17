//! Email provider abstraction for SMTP and Mailjet backends.
//!
//! Uses enum dispatch for simplicity since we have a small, fixed set of providers.
//! For a large number of providers, consider trait objects with `async_trait`.

use std::sync::Arc;

use auth_email::EmailService;
use auth_mailjet::MailjetService;

/// Boxed async error type for email operations.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Email provider supporting SMTP and Mailjet backends.
///
/// Enum dispatch is preferred here for:
/// - Zero runtime overhead (no vtable indirection)
/// - Simple cloning without `Arc<dyn Trait>`
/// - Exhaustive match ensures all providers handle all methods
#[derive(Clone)]
pub enum EmailProvider {
    /// SMTP with code-based templates.
    Smtp(Arc<EmailService>),
    /// Mailjet with platform-hosted templates.
    Mailjet(Arc<MailjetService>),
}

impl EmailProvider {
    /// Send a password reset email using the configured provider.
    ///
    /// # Errors
    /// Returns an error if the email fails to send.
    pub async fn send_password_reset(
        &self,
        to_email: &str,
        to_name: &str,
        reset_url: &str,
        expires_minutes: u32,
    ) -> Result<(), BoxError> {
        match self {
            Self::Smtp(service) => {
                // SMTP uses code templates with expires_minutes
                service
                    .send_password_reset(to_email, to_name, reset_url, expires_minutes)
                    .await
                    .map_err(Into::into)
            }
            Self::Mailjet(service) => {
                // Mailjet uses platform templates (expires_minutes in template)
                service
                    .send_password_reset(to_email, to_name, reset_url)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    /// Send a welcome email to a new user.
    ///
    /// # Errors
    /// Returns an error if the email fails to send.
    pub async fn send_welcome(
        &self,
        to_email: &str,
        to_name: &str,
        login_url: &str,
        temp_password: Option<&str>,
        verification_url: Option<&str>,
    ) -> Result<(), BoxError> {
        match self {
            Self::Smtp(_service) => {
                // TODO: Implement SMTP welcome email template
                Ok(())
            }
            Self::Mailjet(service) => service
                .send_welcome(
                    to_email,
                    to_name,
                    login_url,
                    temp_password,
                    verification_url,
                )
                .await
                .map_err(Into::into),
        }
    }

    /// Send a password changed confirmation email.
    ///
    /// # Errors
    /// Returns an error if the email fails to send.
    #[allow(dead_code)]
    pub async fn send_password_changed(
        &self,
        to_email: &str,
        to_name: &str,
    ) -> Result<(), BoxError> {
        match self {
            Self::Smtp(_service) => {
                // TODO: Implement SMTP password changed email template
                Ok(())
            }
            Self::Mailjet(service) => service
                .send_password_changed(to_email, to_name)
                .await
                .map_err(Into::into),
        }
    }
}
