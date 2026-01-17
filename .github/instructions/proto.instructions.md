---
applyTo: "**/*.proto"
---

# Protobuf Guidelines

## Style
- Use proto3 syntax
- Package names: lowercase (e.g., `auth`, `core`)
- Enum values: SCREAMING_SNAKE_CASE with package prefix
- First enum value must be `*_UNSPECIFIED = 0`

## Validation
- Import `validate/validate.proto` for field validation
- Required fields: `[(validate.rules).message.required = true]`
- String constraints: `[(validate.rules).string = {min_len: 1, max_len: N}]`

## Conventions
- Timestamps: `int64` as Unix milliseconds
- UUIDs: Use `core.UUID` message type
- Results: Use `core.ResultReply` for simple success/fail responses
