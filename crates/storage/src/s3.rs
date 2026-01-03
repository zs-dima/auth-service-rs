//! S3 storage client implementation.

use std::time::Duration;

use auth_core::AppError;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region},
    presigning::PresigningConfig,
};
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

impl S3Storage {
    /// Create a new S3 storage client.
    pub async fn new(config: S3Config) -> Result<Self, AppError> {
        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "auth-service",
        );

        let s3_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&config.endpoint)
            .region(Region::new("us-east-1")) // MinIO doesn't care about region
            .credentials_provider(credentials)
            .force_path_style(true) // Required for MinIO
            .build();

        info!(bucket = %config.bucket, endpoint = %config.endpoint, "S3 storage initialized");

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: config.bucket,
        })
    }

    /// Check if S3 is accessible.
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
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_not_found() {
                    debug!(user_id = %user_id, "Avatar not found");
                    Ok(false)
                } else {
                    Err(AppError::Internal(format!(
                        "Failed to check avatar: {service_err}"
                    )))
                }
            }
        }
    }

    /// Delete avatar for a user.
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
