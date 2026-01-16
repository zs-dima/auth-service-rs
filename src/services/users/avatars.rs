//! Avatar management: upload URL, confirm, delete.

use auth_core::{OptionStatusExt, StatusExt, ToProtoDuration, UuidExt, ValidateExt};
use auth_proto::users::{
    ConfirmAvatarUploadRequest, DeleteAvatarRequest, GetAvatarUploadUrlRequest,
    GetAvatarUploadUrlResponse,
};
use tonic::Status;
use tracing::info;
use uuid::Uuid;

use super::{UPLOAD_URL_EXPIRES_SECS, UserService};

impl UserService {
    /// Generates presigned URL for avatar upload.
    pub(super) async fn get_avatar_upload_url(
        &self,
        req: GetAvatarUploadUrlRequest,
        target_id: Uuid,
    ) -> Result<GetAvatarUploadUrlResponse, Status> {
        req.validate_or_status()?;

        self.ctx
            .db()
            .users
            .get_user_by_id(target_id)
            .await
            .map_err(|_| Status::not_found("User not found"))?;

        let s3 = self.require_s3()?;
        let presigned = s3
            .presign_avatar_upload(
                &target_id,
                &req.content_type,
                req.content_size,
                UPLOAD_URL_EXPIRES_SECS,
            )
            .await
            .status("Failed to generate S3 upload URL")?;

        info!(user_id = %target_id, "Upload URL generated");

        Ok(GetAvatarUploadUrlResponse {
            upload_url: presigned.url,
            expires_in: Some(presigned.expires_in_secs.to_proto_duration()),
        })
    }

    /// Confirms avatar was uploaded to S3.
    pub(super) async fn confirm_avatar_upload(
        &self,
        req: ConfirmAvatarUploadRequest,
        target_id: Uuid,
    ) -> Result<(), Status> {
        req.validate_or_status()?;

        let s3 = self.require_s3()?;

        s3.avatar_exists(&target_id)
            .await
            .status("Failed to check avatar")?
            .then_some(())
            .ok_or_not_found("Avatar not uploaded")?;

        info!(user_id = %target_id, "Avatar upload confirmed");
        Ok(())
    }

    /// Deletes user avatar from S3.
    pub(super) async fn delete_user_avatar(&self, req: DeleteAvatarRequest) -> Result<(), Status> {
        req.validate_or_status()?;

        let target_id: Uuid = req.user_id.as_ref().parse_or_status_with_field("user_id")?;
        self.delete_avatar(&target_id).await?;

        info!(user_id = %target_id, "Avatar deleted");
        Ok(())
    }
}
