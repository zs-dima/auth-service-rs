//! Client context extraction from gRPC requests.
//!
//! Captures client metadata (IP, geolocation, device info) for session tracking,
//! audit logging, and security analysis.

use std::net::IpAddr;

use auth_db::CreateSessionParams;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use uuid::Uuid;

/// Client context extracted from request for session creation and audit logging.
///
/// Contains device information, IP address, and geolocation data.
/// Built progressively using builder methods.
#[derive(Debug, Default, Clone)]
pub struct ClientContext {
    ip_address: Option<IpAddr>,
    ip_country: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    device_type: Option<String>,
    client_version: Option<String>,
    user_agent: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl ClientContext {
    /// Set the client IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.ip_address = ip;
        self
    }

    /// Set the country code derived from IP geolocation.
    #[must_use]
    pub fn with_country(mut self, country: Option<String>) -> Self {
        self.ip_country = country;
        self
    }

    /// Set the user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, ua: Option<String>) -> Self {
        self.user_agent = ua;
        self
    }

    /// Set the unique device identifier.
    #[must_use]
    pub fn with_device_id(mut self, id: Option<String>) -> Self {
        self.device_id = id;
        self
    }

    /// Set the human-readable device name.
    #[must_use]
    pub fn with_device_name(mut self, name: Option<String>) -> Self {
        self.device_name = name;
        self
    }

    /// Set the device type (e.g., "mobile", "desktop", "tablet").
    #[must_use]
    pub fn with_device_type(mut self, dtype: Option<String>) -> Self {
        self.device_type = dtype;
        self
    }

    /// Set the client application version.
    #[must_use]
    pub fn with_client_version(mut self, version: Option<String>) -> Self {
        self.client_version = version;
        self
    }

    /// Set additional metadata as JSON.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Option<serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Get the device ID if set.
    #[must_use]
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Get the IP address if set.
    #[must_use]
    pub const fn ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    /// Get the IP country if set.
    #[must_use]
    pub fn ip_country(&self) -> Option<&str> {
        self.ip_country.as_deref()
    }

    /// Get the user agent if set.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Get the metadata if set.
    #[must_use]
    pub const fn metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }

    /// Convert IP address to network for database storage.
    #[must_use]
    pub fn ip_network(&self) -> Option<IpNetwork> {
        self.ip_address.map(IpNetwork::from)
    }

    /// Build `CreateSessionParams` from client context and session data.
    #[must_use]
    pub fn to_session_params<'a>(
        &'a self,
        id_user: Uuid,
        refresh_token_hash: &'a [u8],
        expires_at: DateTime<Utc>,
        metadata: serde_json::Value,
    ) -> CreateSessionParams<'a> {
        CreateSessionParams {
            id_user,
            refresh_token_hash,
            expires_at,
            device_id: self.device_id.as_deref(),
            device_name: self.device_name.as_deref(),
            device_type: self.device_type.as_deref(),
            client_version: self.client_version.as_deref(),
            ip_address: self.ip_network(),
            ip_country: self.ip_country.as_deref(),
            metadata,
        }
    }
}
