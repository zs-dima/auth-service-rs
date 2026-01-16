//! Shared service context for all gRPC services.
//!
//! Provides common infrastructure (database, email, S3, URLs) used by multiple services.

use std::sync::Arc;

use auth_core::TokenGenerator;
use auth_db::Database;
use auth_storage::S3Storage;
use chrono::Utc;
use tracing::{error, info};
use uuid::Uuid;

use super::{EmailProvider, UrlBuilder};

/// Shared infrastructure context for all services.
///
/// Holds common dependencies that multiple gRPC services need.
/// Services hold `Arc<ServiceContext>` to share this efficiently.
#[derive(Clone)]
pub struct ServiceContext {
    db: Database,
    email: Option<EmailProvider>,
    s3: Option<Arc<S3Storage>>,
    urls: UrlBuilder,
}

impl ServiceContext {
    /// Creates a new service context.
    #[must_use]
    pub fn new(
        db: Database,
        email: Option<EmailProvider>,
        s3: Option<Arc<S3Storage>>,
        urls: UrlBuilder,
    ) -> Self {
        Self {
            db,
            email,
            s3,
            urls,
        }
    }

    /// Database connection pool.
    #[inline]
    #[must_use]
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Email provider (SMTP or Mailjet), if configured.
    #[inline]
    #[must_use]
    pub fn email(&self) -> Option<&EmailProvider> {
        self.email.as_ref()
    }

    /// S3 storage for avatars, if configured.
    #[inline]
    #[must_use]
    pub fn s3(&self) -> Option<&Arc<S3Storage>> {
        self.s3.as_ref()
    }

    /// URL builder for frontend links.
    #[inline]
    #[must_use]
    pub fn urls(&self) -> &UrlBuilder {
        &self.urls
    }

    /// Sends welcome email with verification link (fire-and-forget).
    ///
    /// Spawns an async task to create a verification token and send the email.
    /// Does nothing if email service is not configured.
    pub fn send_welcome_email(
        &self,
        ttl_hours: u32,
        user_id: Uuid,
        email: String,
        display_name: String,
        temp_password: Option<String>,
    ) {
        let Some(email_provider) = self.email.clone() else {
            return;
        };

        let db = self.db.clone();
        let urls = self.urls.clone();

        tokio::spawn(async move {
            let token = TokenGenerator::generate_secure_token();
            let token_hash = TokenGenerator::hash_token(&token);
            let expires_at = Utc::now() + chrono::Duration::hours(i64::from(ttl_hours));

            if let Err(e) = db
                .email_verifications
                .create_token(auth_db::CreateEmailVerificationTokenParams {
                    id_user: user_id,
                    token_hash: &token_hash,
                    expires_at,
                })
                .await
            {
                error!(user_id = %user_id, error = %e, "Failed to create email verification token");
                return;
            }

            let verification_url = urls.verify_email(&token);
            let login_url = urls.sign_in();

            if let Err(e) = email_provider
                .send_welcome(
                    &email,
                    &display_name,
                    &login_url,
                    temp_password.as_deref(),
                    Some(&verification_url),
                )
                .await
            {
                error!(user_id = %user_id, error = %e, "Failed to send welcome email");
                return;
            }

            info!(user_id = %user_id, "Welcome email sent with verification link");
        });
    }
}
