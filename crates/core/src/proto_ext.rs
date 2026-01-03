//! Extension traits for protobuf type conversions.
//!
//! Provides convenient conversions between Rust types and protobuf types,
//! with proper error handling via gRPC Status codes.

use tonic::Status;
use uuid::Uuid;

/// Generic protobuf UUID wrapper.
///
/// This trait abstracts over different proto UUID types that share the same structure.
pub trait ProtoUuidValue {
    fn value(&self) -> &str;
}

// Blanket impl: any &T where T: ProtoUuidValue also implements ProtoUuidValue
impl<T: ProtoUuidValue> ProtoUuidValue for &T {
    fn value(&self) -> &str {
        (*self).value()
    }
}

/// Extension trait for parsing `Option<T>` where T implements `ProtoUuidValue` into `Uuid`.
pub trait UuidExt {
    /// Parse the UUID or return a `Status::invalid_argument` error.
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` if UUID is missing or invalid.
    fn parse_or_status(&self) -> Result<Uuid, Status>;

    /// Parse the UUID with a custom field name for the error message.
    ///
    /// # Errors
    /// Returns `Status::invalid_argument` with the field name if UUID is missing or invalid.
    fn parse_or_status_with_field(&self, field: &str) -> Result<Uuid, Status>;
}

impl<T: ProtoUuidValue> UuidExt for Option<T> {
    fn parse_or_status(&self) -> Result<Uuid, Status> {
        self.parse_or_status_with_field("UUID")
    }

    fn parse_or_status_with_field(&self, field: &str) -> Result<Uuid, Status> {
        let uuid_str = self
            .as_ref()
            .map(ProtoUuidValue::value)
            .ok_or_else(|| Status::invalid_argument(format!("Missing {field}")))?;

        Uuid::parse_str(uuid_str)
            .map_err(|_| Status::invalid_argument(format!("Invalid {field}: {uuid_str}")))
    }
}

/// Extension trait for converting `Uuid` to protobuf UUID type.
pub trait ToProtoUuid<T> {
    fn to_proto(&self) -> T;
}

/// Macro to implement `ProtoUuidValue` for generated proto types.
#[macro_export]
macro_rules! impl_proto_uuid {
    ($type:ty) => {
        impl $crate::proto_ext::ProtoUuidValue for $type {
            fn value(&self) -> &str {
                &self.value
            }
        }

        impl $crate::proto_ext::ToProtoUuid<$type> for uuid::Uuid {
            fn to_proto(&self) -> $type {
                <$type>::from(self.to_string())
            }
        }

        impl From<String> for $type {
            fn from(value: String) -> Self {
                Self { value }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test struct that mimics a proto UUID type
    #[derive(Clone)]
    struct TestProtoUuid {
        value: String,
    }

    impl ProtoUuidValue for TestProtoUuid {
        fn value(&self) -> &str {
            &self.value
        }
    }

    #[test]
    fn test_parse_valid_uuid() {
        let uuid = Uuid::new_v4();
        let proto = TestProtoUuid {
            value: uuid.to_string(),
        };
        assert_eq!(Some(proto).parse_or_status().unwrap(), uuid);
    }

    #[test]
    fn test_parse_missing_uuid() {
        let result: Result<Uuid, Status> = None::<TestProtoUuid>.parse_or_status();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_invalid_uuid() {
        let proto = TestProtoUuid {
            value: "not-a-uuid".to_string(),
        };
        assert!(Some(proto).parse_or_status().is_err());
    }
}
