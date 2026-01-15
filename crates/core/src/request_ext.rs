//! Extension traits for `tonic::Request`.
//!
//! Provides ergonomic methods for extracting authentication context
//! from gRPC requests in service implementations.

use tonic::{Request, Status};

use crate::jwt::{AuthInfo, UserRole};

/// Extension trait for extracting authentication from gRPC requests.
///
/// Provides fluent API for common auth patterns in service implementations:
///
/// ```ignore
/// use auth_core::RequestAuthExt;
///
/// async fn some_rpc(&self, request: Request<Req>) -> Result<Response<Resp>, Status> {
///     let auth = request.auth()?;           // Require authentication
///     let admin = request.auth_admin()?;    // Require admin role
///     let auth = request.auth_for(user_id)?; // Require access to specific user
///     // ...
/// }
/// ```
pub trait RequestAuthExt<T> {
    /// Extract authentication info from request extensions.
    ///
    /// The `AuthInfo` is injected by the auth middleware for authenticated routes.
    ///
    /// # Errors
    /// Returns `Status::unauthenticated` if auth info is not present.
    fn auth(&self) -> Result<AuthInfo, Status>;

    /// Extract authentication and verify admin role.
    ///
    /// # Errors
    /// - `Status::unauthenticated` if not authenticated
    /// - `Status::permission_denied` if not an admin
    fn auth_admin(&self) -> Result<AuthInfo, Status>;

    /// Extract authentication and verify access to a specific user.
    ///
    /// Access is granted if the authenticated user matches `target_user_id`
    /// or has admin role.
    ///
    /// # Errors
    /// - `Status::unauthenticated` if not authenticated
    /// - `Status::permission_denied` if access denied
    fn auth_for(&self, target_user_id: uuid::Uuid) -> Result<AuthInfo, Status>;

    /// Extract authentication and verify one of the specified roles.
    ///
    /// # Errors
    /// - `Status::unauthenticated` if not authenticated
    /// - `Status::permission_denied` if role not in allowed list
    fn auth_with_roles(&self, allowed_roles: &[UserRole]) -> Result<AuthInfo, Status>;

    /// Try to extract authentication info without failing.
    ///
    /// Returns `None` if not authenticated. Useful for endpoints that
    /// behave differently for authenticated vs anonymous users.
    fn try_auth(&self) -> Option<AuthInfo>;
}

impl<T> RequestAuthExt<T> for Request<T> {
    fn auth(&self) -> Result<AuthInfo, Status> {
        self.extensions()
            .get::<AuthInfo>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("Authentication required"))
    }

    fn auth_admin(&self) -> Result<AuthInfo, Status> {
        let auth = self.auth()?;
        if !auth.is_admin() {
            return Err(Status::permission_denied("Admin access required"));
        }
        Ok(auth)
    }

    fn auth_for(&self, target_user_id: uuid::Uuid) -> Result<AuthInfo, Status> {
        let auth = self.auth()?;
        if !auth.can_access(target_user_id) {
            return Err(Status::permission_denied(
                "Cannot access another user's resources",
            ));
        }
        Ok(auth)
    }

    fn auth_with_roles(&self, allowed_roles: &[UserRole]) -> Result<AuthInfo, Status> {
        let auth = self.auth()?;
        if !allowed_roles.contains(&auth.role) {
            return Err(Status::permission_denied("Insufficient permissions"));
        }
        Ok(auth)
    }

    fn try_auth(&self) -> Option<AuthInfo> {
        self.extensions().get::<AuthInfo>().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_request_with_auth(role: UserRole) -> Request<()> {
        let mut req = Request::new(());
        req.extensions_mut().insert(AuthInfo {
            user_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            name: "Test".to_string(),
            role,
            device_id: "device-123".to_string(),
            installation_id: Uuid::new_v4(),
        });
        req
    }

    fn make_request_without_auth() -> Request<()> {
        Request::new(())
    }

    #[test]
    fn auth_succeeds_when_authenticated() {
        let req = make_request_with_auth(UserRole::User);
        assert!(req.auth().is_ok());
    }

    #[test]
    fn auth_fails_when_not_authenticated() {
        let req = make_request_without_auth();
        let err = req.auth().unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn auth_admin_succeeds_for_admin() {
        let req = make_request_with_auth(UserRole::Administrator);
        assert!(req.auth_admin().is_ok());
    }

    #[test]
    fn auth_admin_fails_for_regular_user() {
        let req = make_request_with_auth(UserRole::User);
        let err = req.auth_admin().unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn auth_for_succeeds_for_own_resource() {
        let mut req = Request::new(());
        let user_id = Uuid::new_v4();
        req.extensions_mut().insert(AuthInfo {
            user_id,
            email: "test@example.com".to_string(),
            name: "Test".to_string(),
            role: UserRole::User,
            device_id: "device-123".to_string(),
            installation_id: Uuid::new_v4(),
        });

        assert!(req.auth_for(user_id).is_ok());
    }

    #[test]
    fn auth_for_fails_for_other_user() {
        let req = make_request_with_auth(UserRole::User);
        let other_user_id = Uuid::new_v4();
        let err = req.auth_for(other_user_id).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn auth_for_succeeds_for_admin_accessing_any_user() {
        let req = make_request_with_auth(UserRole::Administrator);
        let other_user_id = Uuid::new_v4();
        assert!(req.auth_for(other_user_id).is_ok());
    }

    #[test]
    fn auth_with_roles_succeeds_for_matching_role() {
        let req = make_request_with_auth(UserRole::User);
        assert!(
            req.auth_with_roles(&[UserRole::User, UserRole::Guest])
                .is_ok()
        );
    }

    #[test]
    fn auth_with_roles_fails_for_non_matching_role() {
        let req = make_request_with_auth(UserRole::Guest);
        let err = req
            .auth_with_roles(&[UserRole::Administrator, UserRole::User])
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn try_auth_returns_some_when_authenticated() {
        let req = make_request_with_auth(UserRole::User);
        assert!(req.try_auth().is_some());
    }

    #[test]
    fn try_auth_returns_none_when_not_authenticated() {
        let req = make_request_without_auth();
        assert!(req.try_auth().is_none());
    }
}
