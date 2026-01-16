//! gRPC `UserService` trait implementation.
//!
//! Thin handlers that extract auth/context and delegate to domain methods.

use auth_core::{RequestAuthExt, UuidExt, ValidateExt};
use auth_proto::users::user_service_server::UserService as UserServiceTrait;
use auth_proto::users::{
    ConfirmAvatarUploadRequest, CreateUserRequest, DeleteAvatarRequest, GetAvatarUploadUrlRequest,
    GetAvatarUploadUrlResponse, ListUsersRequest, SetPasswordRequest, UpdateUserRequest,
    User as ProtoUser, UserInfo as ProtoUserInfo,
};
use tonic::{Request, Response, Status};
use tracing::instrument;

use super::{StreamResult, UserService};

#[tonic::async_trait]
impl UserServiceTrait for UserService {
    // ========================================================================
    // User Management
    // ========================================================================

    type ListUsersInfoStream = StreamResult<ProtoUserInfo>;

    #[instrument(skip(self, request), fields(user_id))]
    async fn list_users_info(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<Self::ListUsersInfoStream>, Status> {
        let admin = request.auth_admin()?;
        tracing::Span::current().record("user_id", admin.user_id.to_string());

        let req = request.into_inner();
        req.validate_or_status()?;

        let stream = self.list_users_info(req);
        Ok(Response::new(stream))
    }

    type ListUsersStream = StreamResult<ProtoUser>;

    #[instrument(skip(self, request), fields(user_id))]
    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<Self::ListUsersStream>, Status> {
        let auth = request.auth()?;
        let req = request.into_inner();
        req.validate_or_status()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let stream = self.list_users(req, auth.user_id, auth.is_admin());
        Ok(Response::new(stream))
    }

    #[instrument(skip(self, request), fields(admin_id))]
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<ProtoUser>, Status> {
        let admin = request.auth_admin()?;
        tracing::Span::current().record("admin_id", admin.user_id.to_string());

        let user = self
            .create_user(request.into_inner(), admin.user_id)
            .await?;
        Ok(Response::new(user))
    }

    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<ProtoUser>, Status> {
        let admin = request.auth_admin()?;
        tracing::Span::current().record("admin_id", admin.user_id.to_string());

        let user = self
            .update_user(request.into_inner(), admin.user_id)
            .await?;
        Ok(Response::new(user))
    }

    #[instrument(skip(self, request), fields(admin_id, target_user_id))]
    async fn set_password(
        &self,
        request: Request<SetPasswordRequest>,
    ) -> Result<Response<()>, Status> {
        let admin = request.auth_admin()?;
        tracing::Span::current().record("admin_id", admin.user_id.to_string());

        self.set_password(request.into_inner(), admin.user_id)
            .await?;
        Ok(Response::new(()))
    }

    // ========================================================================
    // Avatar Management
    // ========================================================================

    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn get_avatar_upload_url(
        &self,
        request: Request<GetAvatarUploadUrlRequest>,
    ) -> Result<Response<GetAvatarUploadUrlResponse>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let target_id = request
            .get_ref()
            .user_id
            .as_ref()
            .parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("target_user_id", target_id.to_string());

        auth.require_access(target_id, "upload avatar")?;
        let result = self
            .get_avatar_upload_url(request.into_inner(), target_id)
            .await?;
        Ok(Response::new(result))
    }

    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn confirm_avatar_upload(
        &self,
        request: Request<ConfirmAvatarUploadRequest>,
    ) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let target_id = request
            .get_ref()
            .user_id
            .as_ref()
            .parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("target_user_id", target_id.to_string());

        auth.require_access(target_id, "confirm avatar upload")?;
        self.confirm_avatar_upload(request.into_inner(), target_id)
            .await?;
        Ok(Response::new(()))
    }

    #[instrument(skip(self, request), fields(user_id, target_user_id))]
    async fn delete_avatar(
        &self,
        request: Request<DeleteAvatarRequest>,
    ) -> Result<Response<()>, Status> {
        let auth = request.auth()?;
        tracing::Span::current().record("user_id", auth.user_id.to_string());

        let target_id = request
            .get_ref()
            .user_id
            .as_ref()
            .parse_or_status_with_field("user_id")?;
        tracing::Span::current().record("target_user_id", target_id.to_string());

        auth.require_access(target_id, "delete avatar")?;
        self.delete_user_avatar(request.into_inner()).await?;
        Ok(Response::new(()))
    }
}
