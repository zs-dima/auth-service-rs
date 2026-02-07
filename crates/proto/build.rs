use std::io::Result;

fn main() -> Result<()> {
    // operations.proto is compiled for its **message types** only (used by REST handlers).
    // Its `OperationsService` gRPC service is intentionally unimplemented — it exists
    // in proto solely to produce OpenAPI paths via gnostic. The generated server trait
    // is suppressed by `#[allow(dead_code)]` in lib.rs.
    let proto_files = &[
        "../../api/proto/auth.proto",
        "../../api/proto/users.proto",
        "../../api/proto/core.proto",
        "../../api/proto/operations.proto",
    ];
    let includes = &["../../api/proto"];

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let descriptor_path = format!("{out_dir}/file_descriptor_set.bin");

    // Create prost config
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor_path);

    // Add serde support for JSON serialization (REST/SSE endpoints)
    config.message_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"camelCase\")]",
    );
    config.enum_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    // Wire serde adapters for prost well-known types (Timestamp, Duration, FieldMask)
    // which don't implement Serialize/Deserialize natively.
    let ts = "#[serde(with = \"crate::serde_wkt::opt_timestamp\", default)]";
    let dur = "#[serde(with = \"crate::serde_wkt::opt_duration\", default)]";
    let fm = "#[serde(with = \"crate::serde_wkt::opt_field_mask\", default)]";

    // Timestamp fields
    for path in [
        ".auth.v1.TokenPair.expires_at",
        ".auth.v1.LockoutInfo.locked_until",
        ".auth.v1.MfaChallenge.expires_at",
        ".auth.v1.LinkedProvider.linked_at",
        ".auth.v1.MfaMethodStatus.configured_at",
        ".auth.v1.SetupMfaResponse.expires_at",
        ".auth.v1.SessionInfo.created_at",
        ".auth.v1.SessionInfo.last_seen_at",
        ".auth.v1.SessionInfo.expires_at",
        ".core.v1.DateRange.from_date",
        ".core.v1.DateRange.to_date",
        ".users.v1.User.created_at",
        ".users.v1.User.updated_at",
    ] {
        config.field_attribute(path, ts);
    }

    // Duration fields
    for path in [
        ".auth.v1.LockoutInfo.retry_after",
        ".users.v1.GetAvatarUploadUrlResponse.expires_in",
    ] {
        config.field_attribute(path, dur);
    }

    // FieldMask fields
    config.field_attribute(".users.v1.UpdateUserRequest.update_mask", fm);
    // Operations-specific: skip None fields to match REST JSON contract
    let skip_none = "#[serde(skip_serializing_if = \"Option::is_none\")]";
    config.field_attribute(".operations.v1.HealthChecks.storage", skip_none);
    config.field_attribute(".operations.v1.CheckResult.message", skip_none);
    config.field_attribute(".operations.v1.HealthResponse.checks", skip_none);
    // Wire serde adapters for proto enum fields (i32 in prost → string in JSON).
    // Serializes as proto enum name (e.g., "USER_ROLE_ADMIN") per protobuf JSON mapping.

    // Singular enum fields (i32)
    for (path, module) in [
        (".auth.v1.MfaMethodInfo.method", "mfa_method"),
        (
            ".auth.v1.AuthenticateRequest.identifier_type",
            "identifier_type",
        ),
        (".auth.v1.AuthResponse.status", "auth_status"),
        (".auth.v1.SignUpRequest.identifier_type", "identifier_type"),
        (".auth.v1.VerifyMfaRequest.method", "mfa_method"),
        (".auth.v1.GetOAuthUrlRequest.provider", "oauth_provider"),
        (
            ".auth.v1.UnlinkOAuthProviderRequest.provider",
            "oauth_provider",
        ),
        (".auth.v1.LinkedProvider.provider", "oauth_provider"),
        (
            ".auth.v1.RecoveryStartRequest.identifier_type",
            "identifier_type",
        ),
        (
            ".auth.v1.RequestVerificationRequest.type",
            "verification_type",
        ),
        (
            ".auth.v1.ConfirmVerificationRequest.type",
            "verification_type",
        ),
        (".auth.v1.MfaMethodStatus.method", "mfa_method"),
        (".auth.v1.SetupMfaRequest.method", "mfa_method"),
        (".auth.v1.DisableMfaRequest.method", "mfa_method"),
        (".auth.v1.UserSnapshot.role", "user_role"),
        (".auth.v1.UserSnapshot.status", "user_status"),
        (".users.v1.UserInfo.role", "user_role"),
        (".users.v1.UserInfo.status", "user_status"),
        (".users.v1.User.role", "user_role"),
        (".users.v1.User.status", "user_status"),
        (".users.v1.CreateUserRequest.role", "user_role"),
        (".operations.v1.HealthResponse.status", "health_status"),
        (".operations.v1.CheckResult.status", "health_status"),
    ] {
        config.field_attribute(
            path,
            format!("#[serde(with = \"crate::serde_wkt::{module}\")]"),
        );
    }

    // Optional enum fields (Option<i32>)
    for (path, module) in [
        (".users.v1.UpdateUserRequest.role", "user_role"),
        (".users.v1.UpdateUserRequest.status", "user_status"),
    ] {
        config.field_attribute(
            path,
            format!("#[serde(with = \"crate::serde_wkt::{module}::optional\", default)]"),
        );
    }

    // Repeated enum fields (Vec<i32>)
    for (path, module) in [
        (".auth.v1.UserSnapshot.linked_providers", "oauth_provider"),
        (".users.v1.ListUsersRequest.statuses", "user_status"),
        (".users.v1.ListUsersRequest.roles", "user_role"),
    ] {
        config.field_attribute(
            path,
            format!("#[serde(with = \"crate::serde_wkt::{module}::repeated\")]"),
        );
    }

    // Configure prost-validate to add Validator derive to all messages
    prost_validate_build::Builder::new()
        .configure(&mut config, proto_files, includes)
        .expect("Failed to configure prost-validate");

    // Add tonic service generator to the config
    config.service_generator(
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(false)
            .service_generator(),
    );

    // Compile protos with the configured prost config
    config
        .compile_protos(proto_files, includes)
        .expect("Failed to compile protos");

    // Recompile if proto files change
    println!("cargo:rerun-if-changed=../../api/proto/auth.proto");
    println!("cargo:rerun-if-changed=../../api/proto/users.proto");
    println!("cargo:rerun-if-changed=../../api/proto/core.proto");
    println!("cargo:rerun-if-changed=../../api/proto/operations.proto");
    println!("cargo:rerun-if-changed=../../api/proto/validate/validate.proto");
    println!("cargo:rerun-if-changed=../../api/proto/google/api/annotations.proto");
    println!("cargo:rerun-if-changed=../../api/proto/google/api/http.proto");

    Ok(())
}
