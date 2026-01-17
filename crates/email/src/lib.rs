//! Email service using SMTP with lettre.
//!
//! Provides type-safe email sending with compile-time template verification.
//!
//! # Configuration
//!
//! Uses a single `SMTP_URL` for simplified configuration:
//! ```text
//! smtp://user:password@smtp.example.com:587?tls=starttls
//! smtps://user:password@smtp.example.com:465
//! ```
//!
//! Query parameters:
//! - `tls=starttls` - Use STARTTLS (default for port 587)
//! - `tls=implicit` - Use implicit TLS (default for port 465)
//! - `tls=none` - No TLS (not recommended)

mod templates;

use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MessageBuilder};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, error, info, instrument};
use url::Url;

pub use templates::PasswordResetEmail;

/// Email service errors.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Invalid SMTP URL: {0}")]
    InvalidUrl(String),
    #[error("Missing SMTP host")]
    MissingHost,
    #[error("Invalid sender address: {0}")]
    InvalidSender(String),
    #[error("Invalid recipient address: {0}")]
    InvalidRecipient(String),
    #[error("Failed to build email: {0}")]
    BuildError(String),
    #[error("Failed to send email: {0}")]
    SendError(String),
    #[error("Template rendering error: {0}")]
    TemplateError(String),
}

/// SMTP TLS mode.
#[derive(Debug, Clone, Copy, Default)]
pub enum TlsMode {
    /// No TLS (insecure, not recommended).
    None,
    /// STARTTLS upgrade after connecting.
    #[default]
    StartTls,
    /// Implicit TLS (connect directly with TLS).
    Implicit,
}

/// Email service configuration.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 465 for implicit TLS).
    pub port: u16,
    /// TLS mode.
    pub tls_mode: TlsMode,
    /// SMTP username (optional).
    pub username: Option<String>,
    /// SMTP password (optional).
    pub password: Option<SecretString>,
    /// Sender email address with name: "Name <email@example.com>".
    pub sender: String,
    /// Application domain (for generating links).
    pub domain: String,
    /// Connection timeout.
    pub timeout: Duration,
}

impl EmailConfig {
    /// Parse configuration from SMTP URL.
    ///
    /// Format: `smtp://user:pass@host:port?tls=starttls`
    ///
    /// # Errors
    ///
    /// Returns `EmailError::InvalidUrl` if the URL is malformed.
    /// Returns `EmailError::MissingHost` if no host is specified.
    ///
    /// # Examples
    /// ```ignore
    /// // STARTTLS (most common)
    /// let config = EmailConfig::from_url(
    ///     "smtp://user:pass@smtp.example.com:587?tls=starttls",
    ///     "App <noreply@example.com>",
    ///     "example.com"
    /// )?;
    ///
    /// // Implicit TLS
    /// let config = EmailConfig::from_url(
    ///     "smtps://user:pass@smtp.example.com:465",
    ///     "App <noreply@example.com>",
    ///     "example.com"
    /// )?;
    /// ```
    pub fn from_url(smtp_url: &str, sender: &str, domain: &str) -> Result<Self, EmailError> {
        let url = Url::parse(smtp_url).map_err(|e| EmailError::InvalidUrl(e.to_string()))?;

        let host = url.host_str().ok_or(EmailError::MissingHost)?.to_string();

        // Default port based on scheme
        let default_port = match url.scheme() {
            "smtps" => 465,
            _ => 587,
        };
        let port = url.port().unwrap_or(default_port);

        // TLS mode from query param or scheme
        let tls_mode = url.query_pairs().find(|(k, _)| k == "tls").map_or_else(
            || {
                if url.scheme() == "smtps" || port == 465 {
                    TlsMode::Implicit
                } else {
                    TlsMode::StartTls
                }
            },
            |(_, v)| match v.as_ref() {
                "none" => TlsMode::None,
                "implicit" | "smtps" => TlsMode::Implicit,
                _ => TlsMode::StartTls,
            },
        );

        let username = if url.username().is_empty() {
            None
        } else {
            Some(
                urlencoding::decode(url.username())
                    .map_err(|e| EmailError::InvalidUrl(e.to_string()))?
                    .into_owned(),
            )
        };

        let password = url.password().map(|p| {
            SecretString::from(
                urlencoding::decode(p)
                    .unwrap_or_else(|_| p.into())
                    .into_owned(),
            )
        });

        Ok(Self {
            host,
            port,
            tls_mode,
            username,
            password,
            sender: sender.to_string(),
            domain: domain.to_string(),
            timeout: Duration::from_secs(30),
        })
    }
}

/// Async email service using lettre SMTP transport.
#[derive(Clone)]
pub struct EmailService {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    sender: Mailbox,
    domain: String,
}

impl std::fmt::Debug for EmailService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailService")
            .field("sender", &self.sender)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl EmailService {
    /// Create a new email service from configuration.
    ///
    /// # Errors
    ///
    /// Returns `EmailError::InvalidSender` if the sender address is invalid.
    /// Returns `EmailError::InvalidUrl` if TLS configuration fails.
    pub fn new(config: EmailConfig) -> Result<Self, EmailError> {
        let sender: Mailbox = config
            .sender
            .parse()
            .map_err(|e| EmailError::InvalidSender(format!("{e}")))?;

        // Build TLS parameters
        let tls_params = TlsParameters::builder(config.host.clone())
            .build_rustls()
            .map_err(|e| EmailError::InvalidUrl(format!("TLS config error: {e}")))?;

        // Build transport
        let mut builder = match config.tls_mode {
            TlsMode::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .tls(Tls::None),
            TlsMode::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .port(config.port)
                    .tls(Tls::Required(tls_params))
            }
            TlsMode::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| EmailError::InvalidUrl(e.to_string()))?
                .port(config.port),
        };

        // Add credentials if provided
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            builder = builder.credentials(Credentials::new(
                username.clone(),
                password.expose_secret().to_string(),
            ));
        }

        let transport = builder.timeout(Some(config.timeout)).build();

        info!(
            host = %config.host,
            port = config.port,
            tls = ?config.tls_mode,
            "Email service initialized"
        );

        Ok(Self {
            transport,
            sender,
            domain: config.domain,
        })
    }

    /// Get the application domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Send a password reset email.
    ///
    /// # Errors
    ///
    /// Returns `EmailError` if template rendering or email sending fails.
    #[instrument(skip(self, token), fields(email = %to_email))]
    pub async fn send_password_reset(
        &self,
        to_email: &str,
        to_name: &str,
        token: &str,
        expires_minutes: u32,
    ) -> Result<(), EmailError> {
        let reset_link = format!(
            "https://{}/auth/reset-password?token={}",
            self.domain, token
        );

        let email_data = PasswordResetEmail {
            user_name: to_name,
            reset_link: &reset_link,
            expires_minutes,
            domain: &self.domain,
        };

        let html_body = email_data.render_html()?;
        let text_body = email_data.render_text()?;

        self.send_email(
            to_email,
            to_name,
            "Reset your password",
            &html_body,
            &text_body,
        )
        .await
    }

    /// Send an email with HTML and plain text body.
    #[instrument(skip(self, html_body, text_body), fields(to = %to_email, subject))]
    async fn send_email(
        &self,
        to_email: &str,
        to_name: &str,
        subject: &str,
        html_body: &str,
        text_body: &str,
    ) -> Result<(), EmailError> {
        let to: Mailbox = format!("{to_name} <{to_email}>")
            .parse()
            .or_else(|_| to_email.parse())
            .map_err(|e| EmailError::InvalidRecipient(format!("{e}")))?;

        // Build multipart message with both HTML and plain text
        let message = Message::builder()
            .from(self.sender.clone())
            .to(to)
            .subject(subject)
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body.to_string()),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )
            .map_err(|e| EmailError::BuildError(e.to_string()))?;

        debug!(to = %to_email, subject, "Sending email");

        self.transport.send(message).await.map_err(|e| {
            error!(error = %e, to = %to_email, "Failed to send email");
            EmailError::SendError(e.to_string())
        })?;

        info!(to = %to_email, subject, "Email sent successfully");
        Ok(())
    }

    /// Test the SMTP connection.
    ///
    /// # Errors
    ///
    /// Returns `EmailError::SendError` if the connection test fails.
    pub async fn test_connection(&self) -> Result<(), EmailError> {
        self.transport
            .test_connection()
            .await
            .map_err(|e| EmailError::SendError(format!("Connection test failed: {e}")))?;
        info!("SMTP connection test successful");
        Ok(())
    }
}

/// Builder for creating email messages with common patterns.
#[must_use]
pub struct EmailBuilder {
    builder: MessageBuilder,
}

impl EmailBuilder {
    /// Create a new email builder with sender.
    pub fn new(from: Mailbox) -> Self {
        Self {
            builder: Message::builder().from(from),
        }
    }

    /// Set the recipient.
    pub fn to(mut self, to: Mailbox) -> Self {
        self.builder = self.builder.to(to);
        self
    }

    /// Set the subject.
    pub fn subject(mut self, subject: &str) -> Self {
        self.builder = self.builder.subject(subject);
        self
    }

    /// Build with HTML and text body.
    ///
    /// # Errors
    ///
    /// Returns `EmailError::BuildError` if the message cannot be built.
    pub fn build(self, html: &str, text: &str) -> Result<Message, EmailError> {
        self.builder
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text.to_string()),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html.to_string()),
                    ),
            )
            .map_err(|e| EmailError::BuildError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_smtp_url_starttls() {
        let config = EmailConfig::from_url(
            "smtp://user:pass@smtp.example.com:587?tls=starttls",
            "Test <test@example.com>",
            "example.com",
        )
        .unwrap();

        assert_eq!(config.host, "smtp.example.com");
        assert_eq!(config.port, 587);
        assert!(matches!(config.tls_mode, TlsMode::StartTls));
        assert_eq!(config.username, Some("user".to_string()));
    }

    #[test]
    fn parse_smtp_url_implicit_tls() {
        let config = EmailConfig::from_url(
            "smtps://user:pass@smtp.example.com",
            "Test <test@example.com>",
            "example.com",
        )
        .unwrap();

        assert_eq!(config.port, 465);
        assert!(matches!(config.tls_mode, TlsMode::Implicit));
    }

    #[test]
    fn parse_smtp_url_no_auth() {
        let config = EmailConfig::from_url(
            "smtp://localhost:25?tls=none",
            "Test <test@example.com>",
            "example.com",
        )
        .unwrap();

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 25);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn parse_smtp_url_encoded_password() {
        let config = EmailConfig::from_url(
            "smtp://user:pass%40word@smtp.example.com:587",
            "Test <test@example.com>",
            "example.com",
        )
        .unwrap();

        assert_eq!(config.password.unwrap().expose_secret(), "pass@word");
    }
}
