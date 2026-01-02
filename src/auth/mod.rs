//! Authentication utilities module.
//!
//! This module provides:
//! - `Encryptor` - Password hashing with Argon2
//! - `TokenGenerator` - JWT token generation
//!
//! Note: Authentication middleware is now in the `middleware` crate module,
//! providing unified auth for both gRPC and REST endpoints.

pub mod encrypt;
pub mod jwt;

pub use encrypt::Encryptor;
pub use jwt::TokenGenerator;
