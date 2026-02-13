use tonic_rest_build::{
    RestCodegenConfig, configure_prost_serde, dump_file_descriptor_set, generate,
};

/// Proto source files to compile (derived from `PROTO_INCLUDES`).
const PROTO_FILES: &[&str] = &[
    "../../api/proto/auth.proto",
    "../../api/proto/users.proto",
    "../../api/proto/core.proto",
    "../../api/proto/operations.proto",
];
const PROTO_INCLUDES: &[&str] = &["../../api/proto"];

/// Additional proto files that are imported but not compiled directly.
/// Changes to these also trigger a rebuild.
const PROTO_DEPS: &[&str] = &[
    "../../api/proto/validate/validate.proto",
    "../../api/proto/google/api/annotations.proto",
    "../../api/proto/google/api/http.proto",
];

/// Maps proto enum FQN → `serde_wkt` module name for JSON string serialization.
///
/// When a proto field uses one of these enum types, the build script
/// automatically wires the corresponding `#[serde(with)]` adapter so the
/// field serializes as a human-readable string instead of a raw `i32`.
///
/// Adding a new enum type here is the **only** manual step required when
/// introducing new enums — all field discovery is automatic.
const ENUM_MODULE_MAP: &[(&str, &str)] = &[
    (".auth.v1.AuthStatus", "auth_status"),
    (".auth.v1.IdentifierType", "identifier_type"),
    (".auth.v1.MfaMethod", "mfa_method"),
    (".auth.v1.OAuthProvider", "oauth_provider"),
    (".auth.v1.VerificationType", "verification_type"),
    (".core.v1.UserRole", "user_role"),
    (".core.v1.UserStatus", "user_status"),
    (".operations.v1.HealthStatus", "health_status"),
];

/// Maps well-known protobuf type FQN → `serde_wkt` module name.
///
/// These types need custom serde adapters because `prost_types` doesn't
/// derive `Serialize`/`Deserialize`. Adding a new WKT adapter here
/// automatically wires it for all fields across all proto files.
const WKT_MODULE_MAP: &[(&str, &str)] = &[
    (".google.protobuf.Timestamp", "opt_timestamp"),
    (".google.protobuf.Duration", "opt_duration"),
    (".google.protobuf.FieldMask", "opt_field_mask"),
];

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let descriptor_path = format!("{out_dir}/file_descriptor_set.bin");

    // Phase 1: Parse protos into a FileDescriptorSet (descriptor-only, no codegen).
    let descriptor_bytes = dump_file_descriptor_set(PROTO_FILES, PROTO_INCLUDES, &descriptor_path);

    // Phase 2: Build prost config with auto-discovered serde attributes.
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor_path);

    configure_prost_serde(
        &mut config,
        &descriptor_bytes,
        PROTO_FILES,
        "crate::serde_wkt",
        WKT_MODULE_MAP,
        ENUM_MODULE_MAP,
    );

    // Operations-specific: HealthResponse.checks is a regular message field (not proto3 `optional`),
    // so configure_prost_serde won't auto-add skip_serializing_if. Add it manually to match
    // the REST JSON contract where `checks` is omitted when None.
    config.field_attribute(
        ".operations.v1.HealthResponse.checks",
        "#[serde(skip_serializing_if = \"Option::is_none\")]",
    );

    prost_validate_build::Builder::new()
        .configure(&mut config, PROTO_FILES, PROTO_INCLUDES)
        .expect("failed to configure prost-validate");

    config.service_generator(
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(false)
            .service_generator(),
    );

    config
        .compile_protos(PROTO_FILES, PROTO_INCLUDES)
        .expect("failed to compile protos");

    generate_rest_routes(&out_dir, &descriptor_bytes);

    for path in PROTO_FILES.iter().chain(PROTO_DEPS) {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// Generate REST route code from the file descriptor set.
///
/// Reads `google.api.http` annotations and generates Axum handlers
/// that call through the Tonic service traits.
fn generate_rest_routes(out_dir: &str, descriptor_bytes: &[u8]) {
    // **Cross-reference:** `api/openapi/config.yaml` → `public_methods` maintains
    // the same concept for OpenAPI spec `security: []`. That list is a superset —
    // it also includes OperationsService RPCs with hand-written Axum routes.
    let rest_config = RestCodegenConfig::new()
        .proto_root("crate")
        .runtime_crate("tonic_rest")
        .wrapper_type("crate::core::Uuid")
        .extension_type("auth_core::AuthInfo")
        .package("auth.v1", "auth")
        .package("users.v1", "users")
        .public_methods(&[
            "Authenticate",
            "SignUp",
            "RecoveryStart",
            "RecoveryConfirm",
            "RefreshTokens",
            "ConfirmVerification",
            "VerifyMfa",
            "GetOAuthUrl",
            "ExchangeOAuthCode",
        ])
        .extra_forwarded_headers(&["cf-connecting-ip"]);

    let rest_code = generate(descriptor_bytes, &rest_config)
        .expect("failed to generate REST routes from descriptor set");
    let rest_path = format!("{out_dir}/rest_routes.rs");
    std::fs::write(&rest_path, rest_code).expect("failed to write REST routes");
}
