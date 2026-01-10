//! S3 storage client implementation.
//!
//! Uses path-style addressing for compatibility with `MinIO` and S3-compatible services.
//! Configured with timeouts and retries for production reliability.

use std::time::Duration;

use auth_core::AppError;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::SdkError,
    operation::head_object::HeadObjectError,
    presigning::PresigningConfig,
};
use aws_smithy_types::retry::RetryMode;
use tracing::{debug, info};
use uuid::Uuid;

/// S3 storage configuration.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl S3Config {
    /// Parse S3 URL: `http://host:port/bucket-name/`
    ///
    /// # Errors
    /// Returns error if URL format is invalid or bucket name is empty.
    pub fn from_url(
        url: &str,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<Self, AppError> {
        let url = url.trim_end_matches('/');
        let last_slash = url
            .rfind('/')
            .ok_or_else(|| AppError::InvalidArgument("Invalid S3 URL format".to_string()))?;

        let (endpoint, bucket) = url.split_at(last_slash);
        let bucket = &bucket[1..]; // Skip the slash

        if bucket.is_empty() {
            return Err(AppError::InvalidArgument(
                "S3 URL must contain bucket name".to_string(),
            ));
        }

        Ok(Self {
            endpoint: endpoint.to_string(),
            bucket: bucket.to_string(),
            access_key_id,
            secret_access_key,
        })
    }
}

/// Check if error indicates object not found.
///
/// Returns true for:
/// - 404 Not Found (standard S3 response)
/// - 403 Forbidden (`MinIO` behind Cloudflare may return this for missing objects)
fn is_not_found(err: &SdkError<HeadObjectError>) -> bool {
    match err {
        SdkError::ServiceError(e) => {
            // Standard "not found" check
            if e.err().is_not_found() {
                return true;
            }
            // Some S3-compatible services return 403 for missing objects
            e.raw().status().as_u16() == 403 || e.raw().status().as_u16() == 404
        }
        _ => false,
    }
}

/// S3 storage client for avatar and file operations.
#[derive(Clone)]
pub struct S3Storage {
    client: Client,
    bucket: String,
}

/// Presigned URL response.
pub struct PresignedUpload {
    pub url: String,
    pub expires_in_secs: u64,
}

/// Default operation timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Maximum retry attempts for transient failures.
const MAX_RETRIES: u32 = 3;

impl S3Storage {
    /// Create a new S3 storage client with production-ready defaults.
    ///
    /// Configures:
    /// - Path-style addressing (required for `MinIO`)
    /// - Timeouts (30s connect, 30s operation)
    /// - Retries (3 attempts with exponential backoff)
    #[must_use]
    pub fn new(config: S3Config) -> Self {
        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "auth-service",
        );

        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .operation_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build();

        let retry_config = RetryConfig::standard()
            .with_retry_mode(RetryMode::Standard)
            .with_max_attempts(MAX_RETRIES);

        let s3_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&config.endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(credentials)
            .force_path_style(true)
            .timeout_config(timeout_config)
            .retry_config(retry_config)
            .build();

        info!(bucket = %config.bucket, endpoint = %config.endpoint, "S3 storage initialized");

        Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket,
        }
    }

    /// Check if S3 bucket is accessible.
    pub async fn health_check(&self) -> bool {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .is_ok()
    }

    fn avatar_key(user_id: &Uuid) -> String {
        format!("users/{user_id}/avatar.webp")
    }

    /// Check if avatar exists for a user.
    ///
    /// Uses `HeadObject` which is the standard S3 existence check.
    /// Returns `false` for both 404 (not found) and 403 (access denied on missing object).
    ///
    /// # Errors
    /// Returns error only for actual failures (network, timeout, server errors).
    pub async fn avatar_exists(&self, user_id: &Uuid) -> Result<bool, AppError> {
        let key = Self::avatar_key(user_id);
        debug!(user_id = %user_id, key = %key, "Checking avatar exists");

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => {
                debug!(user_id = %user_id, "Avatar exists");
                Ok(true)
            }
            Err(err) => {
                if is_not_found(&err) {
                    debug!(user_id = %user_id, "Avatar not found");
                    Ok(false)
                } else {
                    tracing::error!(user_id = %user_id, error = ?err, "S3 HeadObject failed");
                    Err(AppError::Internal(format!("Failed to check avatar: {err}")))
                }
            }
        }
    }

    /// Delete avatar for a user.
    ///
    /// # Errors
    /// Returns error if S3 delete operation fails.
    pub async fn delete_avatar(&self, user_id: &Uuid) -> Result<(), AppError> {
        let key = Self::avatar_key(user_id);
        debug!(user_id = %user_id, key = %key, "Deleting avatar");

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(user_id = %user_id, key = %key, error = ?e, "S3 delete failed");
                AppError::Internal(format!("Failed to delete avatar: {e}"))
            })?;

        info!(user_id = %user_id, key = %key, "Avatar deleted");
        Ok(())
    }

    /// Generate a presigned URL for uploading an avatar.
    ///
    /// # Errors
    /// Returns error if presigning configuration is invalid or URL generation fails.
    #[allow(clippy::cast_possible_wrap)]
    pub async fn presign_avatar_upload(
        &self,
        user_id: &Uuid,
        content_type: &str,
        content_length: u64,
        expires_in_secs: u64,
    ) -> Result<PresignedUpload, AppError> {
        let key = Self::avatar_key(user_id);
        debug!(user_id = %user_id, key = %key, "Generating presigned upload URL");

        let presigning_config = PresigningConfig::expires_in(Duration::from_secs(expires_in_secs))
            .map_err(|e| AppError::Internal(format!("Invalid presign duration: {e}")))?;

        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type(content_type)
            .content_length(content_length as i64)
            .presigned(presigning_config)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to generate presigned URL: {e}")))?;

        info!(user_id = %user_id, key = %key, expires_in = expires_in_secs, "Presigned URL generated");

        Ok(PresignedUpload {
            url: presigned.uri().to_string(),
            expires_in_secs,
        })
    }
}
