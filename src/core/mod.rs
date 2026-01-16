//! Core module with encryption and service-specific utilities.

pub mod client_context;
pub mod email_provider;
pub mod geolocation_service;
pub mod identifier;
pub mod password;
pub mod service_context;
pub mod urls;

pub use client_context::ClientContext;
pub use email_provider::EmailProvider;
pub use geolocation_service::GeolocationService;
pub use identifier::{canonical_email, canonical_phone};
pub use service_context::ServiceContext;
pub use urls::{UrlBuilder, error_codes};
