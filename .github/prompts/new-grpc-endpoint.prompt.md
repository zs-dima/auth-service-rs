# New gRPC Endpoint

Add a new RPC endpoint to the auth service.

## Steps
1. Define request/response messages in `proto/auth.proto`
2. Add RPC to `AuthService` in `proto/auth.proto`
3. Run `make grpc` to regenerate Rust code
4. Implement handler in `src/services/auth.rs`
5. Add SQL queries to `crates/db/sql/` if needed
6. Run `make db-prepare` to update SQLx cache

## Handler Template
```rust
#[instrument(skip(self))]
async fn my_rpc(
    &self,
    request: Request<MyRequest>,
) -> Result<Response<MyReply>, Status> {
    let req = request.into_inner().validate()?;
    // Implementation
    Ok(Response::new(MyReply { /* ... */ }))
}
```
