//! Serde adapters for prost types that lack native `Serialize`/`Deserialize`.
//!
//! ## Well-known types (`prost_types`)
//!
//! Re-exported from [`tonic_rest::serde`]:
//! - **Timestamp** → RFC 3339 string (`"2025-01-15T09:30:00Z"`)
//! - **Duration**  → seconds string with `s` suffix (`"300s"`)
//! - **`FieldMask`** → comma-separated camelCase paths (`"name,email,role"`)
//!
//! ## Proto enums (i32 fields)
//!
//! Proto3 enum fields are `i32` in prost. The [`tonic_rest::define_enum_serde`] macro
//! generates `#[serde(with)]` modules that serialize as proto enum name
//! strings (e.g., `"USER_ROLE_ADMIN"`) following Google's protobuf JSON mapping.
//!
//! Each invocation generates three sub-modules:
//! - `{name}`              — for `i32` fields
//! - `{name}::optional`    — for `Option<i32>` fields (`optional` in proto3)
//! - `{name}::repeated`    — for `Vec<i32>` fields (`repeated` in proto3)

// Re-export WKT adapters from the runtime crate
pub use tonic_rest::serde::{opt_duration, opt_field_mask, opt_timestamp};

// =============================================================================
// Proto enum serde adapters
// =============================================================================

// Operations enums — custom serde for REST JSON contract
// HealthStatus serializes as lowercase "healthy" / "unhealthy" (not "HEALTH_STATUS_HEALTHY").
tonic_rest::define_enum_serde!(
    health_status,
    crate::operations::HealthStatus,
    "HEALTH_STATUS_"
);

// Core enums
tonic_rest::define_enum_serde!(user_role, crate::core::UserRole);
tonic_rest::define_enum_serde!(user_status, crate::core::UserStatus);

// Auth enums
tonic_rest::define_enum_serde!(identifier_type, crate::auth::IdentifierType);
tonic_rest::define_enum_serde!(oauth_provider, crate::auth::OAuthProvider);
tonic_rest::define_enum_serde!(auth_status, crate::auth::AuthStatus);
tonic_rest::define_enum_serde!(verification_type, crate::auth::VerificationType);
tonic_rest::define_enum_serde!(mfa_method, crate::auth::MfaMethod);
