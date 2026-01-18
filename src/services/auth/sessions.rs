//! Session management: list and revoke.

use auth_core::{OptionStrExt, StatusExt, ToProtoTimestamp, ValidateExt};
use auth_proto::auth::{ListSessionsResponse, RevokeSessionRequest, SessionInfo};
use tonic::Status;
use tracing::{debug, info};
use uuid::Uuid;

use super::AuthService;

impl AuthService {
    /// Lists all active sessions for a user.
    ///
    /// Uses the refresh token hash to accurately identify the current session.
    pub(super) async fn list_sessions(
        &self,
        user_id: Uuid,
        current_token_hash: &[u8],
    ) -> Result<ListSessionsResponse, Status> {
        debug!(user_id = %user_id, "Listing sessions");

        let sessions = self
            .ctx
            .db()
            .sessions
            .list_user_sessions(user_id, current_token_hash)
            .await
            .status("Failed to list sessions")?;

        let sessions: Vec<SessionInfo> = sessions
            .into_iter()
            .map(|s| SessionInfo {
                is_current: s.is_current,
                device_id: s.device_id.unwrap_or_default(),
                device_name: s.device_name.unwrap_or_default(),
                device_type: s.device_type.or_str("unknown"),
                client_version: s.client_version.unwrap_or_default(),
                ip_address: s
                    .ip_address
                    .map_or_else(String::new, |ip| ip.ip().to_string()),
                ip_country: s.ip_country.unwrap_or_default(),
                created_at: Some(s.created_at.to_proto_timestamp()),
                last_seen_at: Some(s.last_seen_at.to_proto_timestamp()),
                expires_at: Some(s.expires_at.to_proto_timestamp()),
                ip_created_by: s
                    .ip_created_by
                    .map_or_else(String::new, |ip| ip.ip().to_string()),
                activity_count: s.activity_count,
                metadata: Self::json_to_string_map(s.metadata),
            })
            .collect();

        info!(user_id = %user_id, count = sessions.len(), "Sessions listed");

        Ok(ListSessionsResponse { sessions })
    }

    /// Converts JSON value to `HashMap<String, String>` for proto metadata.
    fn json_to_string_map(value: serde_json::Value) -> std::collections::HashMap<String, String> {
        match value {
            serde_json::Value::Object(map) => map
                .into_iter()
                .map(|(k, v)| {
                    let s = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, s)
                })
                .collect(),
            _ => std::collections::HashMap::new(),
        }
    }

    /// Revokes a specific session by device ID.
    pub(super) async fn revoke_session(
        &self,
        req: RevokeSessionRequest,
        user_id: Uuid,
    ) -> Result<(), Status> {
        req.validate_or_status()?;

        debug!(user_id = %user_id, device_id = %req.device_id, "Revoking session");

        let revoked = self
            .ctx
            .db()
            .sessions
            .revoke_session_by_device_id(user_id, &req.device_id)
            .await
            .status("Failed to revoke session")?;

        if revoked {
            info!(user_id = %user_id, device_id = %req.device_id, "Session revoked");
        } else {
            debug!(user_id = %user_id, device_id = %req.device_id, "Session not found");
        }

        Ok(())
    }

    /// Revokes all sessions except the current device.
    pub(super) async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        current_device_id: &str,
    ) -> Result<i32, Status> {
        debug!(user_id = %user_id, "Revoking other sessions");

        let count = self
            .ctx
            .db()
            .sessions
            .revoke_sessions_except_device(user_id, current_device_id)
            .await
            .status("Failed to revoke sessions")?;

        info!(user_id = %user_id, count, "Other sessions revoked");

        Ok(i32::try_from(count).unwrap_or(i32::MAX))
    }
}
