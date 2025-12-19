# Auth Service (Rust)

A high-performance authentication gRPC service written in Rust.

## Features

- **gRPC API** with streaming support using Tonic
- **JWT Authentication** with access and refresh tokens
- **PostgreSQL Database** using SQLx with compile-time query verification
- **Password Hashing** using argon2
- **Image Processing** with blurhash generation for avatars
- **Health Checks** via gRPC health protocol
- **Graceful Shutdown** handling SIGTERM/SIGINT
- **Structured Logging** with tracing (JSON or human-readable)
- **Docker Support** with multi-stage builds

## Prerequisites

- Rust 1.85+
- PostgreSQL 14+
- Protocol Buffers compiler (protoc)

## Quick Start

1. **Clone and setup environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Setup database:**
   ```bash
   # Run the schema from ../db/schema.sql
   psql -U admin -d auth -f ../db/schema.sql
   ```

3. **Build and run:**
   ```bash
   cargo run
   ```

## Configuration

Environment variables (see [src/config.rs](src/config.rs)):

| Variable              | Required | Description                                    |
| --------------------- | -------- | ---------------------------------------------- |
| `GRPC_ADDRESS`        | No       | gRPC server address (default: `0.0.0.0:50051`) |
| `HTTP_ADDRESS`        | No       | HTTP server for file ops (e.g. `0.0.0.0:8080`) |
| `GRPC_WEB`            | No       | Enable gRPC-Web (HTTP/1.1) (`true`/`false`)    |
| `CORS_ALLOW_ORIGINS`  | No       | CORS origins (comma-separated or `*`)          |
| `JWT_SECRET_KEY`      | Yes      | Secret key for JWT signing                     |
| `DB_URL`              | Yes      | PostgreSQL connection URL                      |
| `DB_POOL_MIN`         | No       | Database pool min size                         |
| `DB_POOL_MAX`         | No       | Database pool max size                         |
| `DB_CONNECT_TIMEOUT`  | No       | DB connect timeout (seconds)                   |
| `GRPC_API_REFLECTION` | No       | Enable gRPC reflection                         |
| `LOG_LEVEL`           | No       | Log level (TRACE, DEBUG, INFO, WARN, ERROR)    |
| `LOG_HUMAN`           | No       | Human-readable logs (`true`/`false`)           |

## Debugging (no Envoy)

You can debug the service without Envoy/proxies using native gRPC tools.

### Native gRPC with grpcurl

1. Enable reflection (optional but convenient):
   - `GRPC_API_REFLECTION=true`
2. Call the service:
   - `grpcurl -plaintext localhost:50051 list`
   - `grpcurl -plaintext localhost:50051 auth.AuthService/SignIn -d "{\"email\":\"user@example.com\",\"password\":\"...\"}"`

### gRPC-Web (browser)

For browser clients, use `GRPC_WEB=true`. In production, use a reverse proxy (nginx, Envoy) for CORS.
For local development, your frontend dev server can proxy gRPC-Web requests.

## API Endpoints

### Authentication

- `SignIn(SignInRequest) -> AuthInfo` - Authenticate user with email/password
- `SignOut(Empty) -> ResultReply` - End user session
- `RefreshTokens(RefreshTokenRequest) -> RefreshTokenReply` - Refresh access token
- `ValidateCredentials(Empty) -> ResultReply` - Validate current JWT

### Password Management

- `ResetPassword(ResetPasswordRequest) -> ResultReply` - Request password reset
- `SetPassword(SetPasswordRequest) -> ResultReply` - Set new password

### User Management

- `LoadUsersInfo(Empty) -> stream UserInfo` - Get all users' basic info
- `LoadUserAvatar(LoadUserAvatarRequest) -> stream UserAvatar` - Get user avatars
- `LoadUsers(UserId) -> stream User` - Get all users with details
- `CreateUser(CreateUserRequest) -> ResultReply` - Create new user
- `UpdateUser(UpdateUserRequest) -> ResultReply` - Update existing user
- `SaveUserPhoto(UserPhoto) -> ResultReply` - Upload user photo

## Project Structure

```
src/
│   ├── main.rs           # Entry point and server setup
│   ├── lib.rs            # Library exports
│   ├── config.rs         # Configuration management
│   ├── error.rs          # Error types
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs        # JWT token generation/validation
│   │   ├── encrypt.rs    # Password hashing
│   │   └── interceptor.rs # gRPC authentication interceptor
│   ├── db/
│   │   ├── mod.rs
│   │   ├── models.rs     # Database models
│   │   └── repository.rs # Database queries
│   ├── proto/
│   │   └── *.rs          # Generated protobuf code
│   ├── service/
│   │   ├── mod.rs
│   │   └── auth_service.rs # gRPC service implementation
│   └── util/
│       ├── mod.rs
│       └── image.rs      # Image processing utilities
proto/
│   ├── auth.proto        # Service definitions
│   └── core.proto        # Shared types
Cargo.toml
build.rs              # Protobuf compilation
Dockerfile
Makefile
```

## Development

```bash
# Watch mode (auto-rebuild on changes)
make watch

# Run tests
make test

# Format and lint
make fmt lint

# Pre-commit checks
make pre-commit
```

## Docker

```bash
# Build image
make docker

# Run container
make docker-run
```

## License

See [LICENSE](../LICENSE) file.
