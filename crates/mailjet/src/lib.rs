//! Mailjet email service using the Send API v3.1 with Mailjet templates.
//!
//! Templates are stored in Mailjet's platform and referenced by ID.
//! Create templates at: <https://app.mailjet.com/templates>
//!
//! # Configuration
//!
//! Environment variables:
//! - `EMAIL_SENDER` - Sender in format "Name <email@example.com>"
//! - `MAILJET_API_KEY` - Public API key
//! - `MAILJET_API_SECRET` - Private API key
//! - `MAILJET_PASSWORD_RECOVERY_START_TEMPLATE_ID` - Template ID for password reset
//!
//! # Example
//!
//! ```ignore
//! let service = MailjetService::new(config);
//! service.send_password_reset("user@example.com", "John", "https://app.example.com/#/reset?token=abc").await?;
//! ```

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{Map, Value};
use tracing::{debug, error, info, instrument};

/// Mailjet API endpoint for sending emails.
const MAILJET_API_URL: &str = "https://api.mailjet.com/v3.1/send";

/// Email service errors.
#[derive(Debug, thiserror::Error)]
pub enum MailjetError {
    #[error("Failed to send email: {0}")]
    SendError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Mailjet service configuration.
#[derive(Debug, Clone)]
pub struct MailjetConfig {
    /// Mailjet API key (public).
    pub api_key: String,
    /// Mailjet API secret (private).
    pub api_secret: SecretString,
    /// Sender name.
    pub sender_name: String,
    /// Sender email address (must be verified in Mailjet).
    pub sender_email: String,
    /// Template ID for password reset emails.
    pub password_reset_template_id: u64,
    /// Template ID for welcome emails.
    pub welcome_template_id: u64,
    /// Template ID for email verification emails.
    pub email_verification_template_id: u64,
    /// Template ID for password changed confirmation.
    pub password_changed_template_id: u64,
}

/// Mailjet email service using Mailjet-hosted templates.
#[derive(Clone)]
pub struct MailjetService {
    client: Client,
    config: MailjetConfig,
}

impl std::fmt::Debug for MailjetService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailjetService")
            .field("sender_email", &self.config.sender_email)
            .field("sender_name", &self.config.sender_name)
            .field(
                "password_reset_template_id",
                &self.config.password_reset_template_id,
            )
            .finish_non_exhaustive()
    }
}

// Mailjet API v3.1 request structures
#[derive(Serialize)]
struct SendRequest<'a> {
    #[serde(rename = "Messages")]
    messages: [Message<'a>; 1],
}

#[derive(Serialize)]
struct Message<'a> {
    #[serde(rename = "From")]
    from: EmailAddress<'a>,
    #[serde(rename = "To")]
    to: [EmailAddress<'a>; 1],
    #[serde(rename = "TemplateID")]
    template_id: u64,
    #[serde(rename = "TemplateLanguage")]
    template_language: bool,
    #[serde(rename = "Variables")]
    variables: Map<String, Value>,
}

#[derive(Serialize)]
struct EmailAddress<'a> {
    #[serde(rename = "Email")]
    email: &'a str,
    #[serde(rename = "Name")]
    name: &'a str,
}

impl MailjetService {
    /// Create a new Mailjet service.
    ///
    /// # Panics
    /// Panics if the HTTP client fails to create.
    #[must_use]
    pub fn new(config: MailjetConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        info!(
            sender = %config.sender_email,
            password_reset_template = config.password_reset_template_id,
            "Mailjet service initialized"
        );

        Self { client, config }
    }

    /// Send a password reset email using Mailjet template.
    ///
    /// Template variables: `name`, `email`, `url`
    ///
    /// # Errors
    /// Returns `MailjetError::SendError` if the email fails to send.
    #[instrument(skip(self, reset_url), fields(email = %to_email))]
    pub async fn send_password_reset(
        &self,
        to_email: &str,
        to_name: &str,
        reset_url: &str,
    ) -> Result<(), MailjetError> {
        self.send(
            to_email,
            to_name,
            self.config.password_reset_template_id,
            serde_json::json!({
                "name": to_name,
                "email": to_email,
                "url": reset_url
            }),
        )
        .await
    }

    /// Send a welcome email using Mailjet template.
    ///
    /// Template variables: `name`, `email`, `url`, `password` (optional), `verification_url` (optional)
    ///
    /// # Errors
    /// Returns `MailjetError::ConfigError` if the welcome template is not configured.
    /// Returns `MailjetError::SendError` if the email fails to send.
    #[instrument(skip(self, temp_password, verification_url), fields(email = %to_email))]
    pub async fn send_welcome(
        &self,
        to_email: &str,
        to_name: &str,
        login_url: &str,
        temp_password: Option<&str>,
        verification_url: Option<&str>,
    ) -> Result<(), MailjetError> {
        if self.config.welcome_template_id == 0 {
            return Err(MailjetError::ConfigError(
                "Welcome template ID not configured".to_string(),
            ));
        }

        let mut vars = serde_json::json!({
            "name": to_name,
            "email": to_email,
            "url": login_url
        });

        if let Some(pwd) = temp_password {
            vars["password"] = serde_json::Value::String(pwd.to_string());
        }

        if let Some(verify_url) = verification_url {
            vars["verification_url"] = serde_json::Value::String(verify_url.to_string());
        }

        self.send(to_email, to_name, self.config.welcome_template_id, vars)
            .await
    }

    /// Send an email verification email using Mailjet template.
    ///
    /// Template variables: `name`, `email`, `url`
    ///
    /// # Errors
    /// Returns `MailjetError::ConfigError` if the email verification template is not configured.
    /// Returns `MailjetError::SendError` if the email fails to send.
    #[instrument(skip(self, verification_url), fields(email = %to_email))]
    pub async fn send_email_verification(
        &self,
        to_email: &str,
        to_name: &str,
        verification_url: &str,
    ) -> Result<(), MailjetError> {
        if self.config.email_verification_template_id == 0 {
            return Err(MailjetError::ConfigError(
                "Email verification template ID not configured".to_string(),
            ));
        }

        self.send(
            to_email,
            to_name,
            self.config.email_verification_template_id,
            serde_json::json!({
                "name": to_name,
                "email": to_email,
                "url": verification_url
            }),
        )
        .await
    }

    /// Send a password changed confirmation using Mailjet template.
    ///
    /// Template variables: `name`, `email`
    ///
    /// # Errors
    /// Returns `MailjetError::ConfigError` if the password changed template is not configured.
    /// Returns `MailjetError::SendError` if the email fails to send.
    #[instrument(skip(self), fields(email = %to_email))]
    pub async fn send_password_changed(
        &self,
        to_email: &str,
        to_name: &str,
    ) -> Result<(), MailjetError> {
        if self.config.password_changed_template_id == 0 {
            return Err(MailjetError::ConfigError(
                "Password changed template ID not configured".to_string(),
            ));
        }

        self.send(
            to_email,
            to_name,
            self.config.password_changed_template_id,
            serde_json::json!({ "name": to_name, "email": to_email }),
        )
        .await
    }

    /// Send an email using a Mailjet template.
    async fn send(
        &self,
        to_email: &str,
        to_name: &str,
        template_id: u64,
        variables: Value,
    ) -> Result<(), MailjetError> {
        let variables = variables.as_object().cloned().unwrap_or_default();

        let request = SendRequest {
            messages: [Message {
                from: EmailAddress {
                    email: &self.config.sender_email,
                    name: &self.config.sender_name,
                },
                to: [EmailAddress {
                    email: to_email,
                    name: to_name,
                }],
                template_id,
                template_language: true,
                variables,
            }],
        };

        debug!(to = %to_email, template_id, "Sending email via Mailjet");

        let response = self
            .client
            .post(MAILJET_API_URL)
            .basic_auth(
                &self.config.api_key,
                Some(self.config.api_secret.expose_secret()),
            )
            .json(&request)
            .send()
            .await
            .map_err(|e| MailjetError::SendError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(%status, %body, "Mailjet API error");
            return Err(MailjetError::SendError(format!("{status}: {body}")));
        }

        info!(to = %to_email, template_id, "Email sent");
        Ok(())
    }

    /// Validate configuration (does not make network calls).
    ///
    /// # Errors
    /// Returns `MailjetError::ConfigError` if any required configuration is missing.
    pub fn validate_config(&self) -> Result<(), MailjetError> {
        if self.config.api_key.is_empty() {
            return Err(MailjetError::ConfigError("API key is empty".to_string()));
        }
        if self.config.api_secret.expose_secret().is_empty() {
            return Err(MailjetError::ConfigError("API secret is empty".to_string()));
        }
        if self.config.password_reset_template_id == 0 {
            return Err(MailjetError::ConfigError(
                "Password reset template ID not configured".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MailjetConfig {
        MailjetConfig {
            api_key: "test_api_key".to_string(),
            api_secret: SecretString::from("test_api_secret"),
            sender_name: "Test App".to_string(),
            sender_email: "noreply@example.com".to_string(),
            password_reset_template_id: 12345,
            welcome_template_id: 12346,
            email_verification_template_id: 12348,
            password_changed_template_id: 12347,
        }
    }

    #[test]
    fn creates_service() {
        let service = MailjetService::new(test_config());
        assert_eq!(service.config.sender_email, "noreply@example.com");
    }

    #[test]
    fn validate_config_passes() {
        let service = MailjetService::new(test_config());
        assert!(service.validate_config().is_ok());
    }

    #[test]
    fn validate_config_fails_with_empty_key() {
        let mut config = test_config();
        config.api_key = String::new();
        let service = MailjetService::new(config);
        assert!(service.validate_config().is_err());
    }

    #[test]
    fn validate_config_fails_with_zero_template_id() {
        let mut config = test_config();
        config.password_reset_template_id = 0;
        let service = MailjetService::new(config);
        assert!(service.validate_config().is_err());
    }
}
