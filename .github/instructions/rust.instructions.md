---
applyTo: "**/*.rs"
---

# Rust Guidelines

## Imports
- Group: std → external crates → workspace crates → local modules
- Use `auth_core` re-exports: `AppError`, `StatusExt`, `UuidExt`, `ValidateExt`

## Async
- All async code uses Tokio runtime
- Use `#[instrument]` from tracing for spans
- Streaming RPCs use `async_stream::try_stream!`

## Types
- UUIDs: `uuid::Uuid`, convert with `UuidExt` and `ToProtoUuid`
- Timestamps: `chrono::DateTime<Utc>`, store as Unix millis in proto
- Passwords: Hash with `argon2`, wrap secrets in `secrecy::SecretString`
- Prefer .to_string() over .into() or .to_owned() for conversions to String.

## Database Param Structs
- Param structs: `&'a str`, derive `Copy` when all fields are references
- DB models: own data (`String`) since SQLx deserializes into them
- Use `StrExt::none_if_empty()` for protobuf empty-string → `Option`

## Testing
- Unit tests in same file under `#[cfg(test)]` module
- Use `tokio::test` for async tests
