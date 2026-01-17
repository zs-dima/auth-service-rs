//! S3/object storage abstraction.
//!
//! Provides a clean interface for S3-compatible storage operations
//! with support for presigned URLs and health checks.

mod s3;

pub use s3::{PresignedUpload, S3Config, S3Storage};
