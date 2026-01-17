//! User service gRPC implementation.
//!
//! Organized by domain:
//! - `mod.rs` — Core types, helpers, `UserServer`
//! - `handlers.rs` — Thin gRPC trait implementation
//! - `management.rs` — User CRUD operations
//! - `avatars.rs` — S3 avatar operations

mod avatars;
mod handlers;
mod management;

use std::sync::Arc;

use auth_core::StatusExt;
use auth_storage::S3Storage;
use futures::stream::BoxStream;
use tonic::Status;
use tracing::error;
use uuid::Uuid;

use crate::config::UserServiceConfig;
use crate::core::ServiceContext;

/// Upload URL expiration (5 minutes).
const UPLOAD_URL_EXPIRES_SECS: u64 = 300;

/// Streaming result type for gRPC responses.
type StreamResult<T> = BoxStream<'static, Result<T, Status>>;

// ============================================================================
// UserService
// ============================================================================

/// User service gRPC implementation for user management and avatars.
pub struct UserService {
    config: UserServiceConfig,
    ctx: Arc<ServiceContext>,
}

impl UserService {
    /// Creates a new user service instance.
    #[must_use]
    pub fn new(config: UserServiceConfig, ctx: Arc<ServiceContext>) -> Self {
        Self { config, ctx }
    }
}

// ============================================================================
// S3 Storage
// ============================================================================

impl UserService {
    /// Returns S3 storage or error if not configured.
    #[inline]
    fn require_s3(&self) -> Result<&Arc<S3Storage>, Status> {
        self.ctx.s3().ok_or_else(|| {
            error!("S3 storage not configured");
            Status::internal("Storage not configured")
        })
    }

    /// Deletes avatar from S3.
    async fn delete_avatar(&self, user_id: &Uuid) -> Result<(), Status> {
        if let Some(s3) = self.ctx.s3() {
            s3.delete_avatar(user_id)
                .await
                .status("Failed to delete avatar")?;
            tracing::debug!(user_id = %user_id, "Avatar deleted from S3");
        }
        Ok(())
    }
}
