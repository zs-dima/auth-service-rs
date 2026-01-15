# Copilot Instructions

Rust 1.92 gRPC authentication service using Tonic, SQLx, and Tokio.

## Code Style
- Prefer `.to_string()` over `.into()` or `.to_owned()`
- Use `thiserror` for error types, `anyhow` for ad-hoc errors
- Follow clippy pedantic lints
- No `unsafe` code allowed

## Error Handling
- Use `AppError` enum from `auth_core` for domain errors
- Use `StatusExt` trait for converting errors to gRPC Status
- Use `OptionStatusExt` for Option → Status::not_found

## Patterns
- gRPC services implement `*_server::*Service` traits from `auth_proto`
- Database operations via `auth_db::Database` with SQLx
- Validation via `ValidateExt` trait (protobuf-validator)
- JWT via `TokenGenerator` and `JwtValidator`

## Database Params vs Models
- **Param structs**: Borrow from caller with `&'a str`, derive `Copy` when all fields are references
- **DB models**: Own their data (`String`, `Vec<u8>`) since SQLx deserializes into them
- Use `StrExt` trait to handle protobuf empty-string → `Option` conversion
