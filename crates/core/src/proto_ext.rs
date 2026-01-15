//! Extension traits for protobuf type conversions.
//!
//! Provides convenient conversions between Rust types and protobuf types,
//! with proper error handling via gRPC Status codes.

use prost_types::value::Kind;
use tonic::Status;
use uuid::Uuid;

// =============================================================================
// Proto UUID
// =============================================================================

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

// =============================================================================
// Proto Struct <-> JSON Conversions
// =============================================================================

/// Convert `serde_json::Value` to `prost_types::Struct`.
///
/// Returns `None` if the value is not a JSON object.
#[must_use]
pub fn json_to_proto_struct(value: serde_json::Value) -> Option<prost_types::Struct> {
    match value {
        serde_json::Value::Object(obj) => Some(prost_types::Struct {
            fields: obj
                .into_iter()
                .map(|(k, v)| (k, json_to_proto_value(v)))
                .collect(),
        }),
        _ => None,
    }
}

/// Convert `prost_types::Struct` to `serde_json::Value`.
#[must_use]
pub fn proto_struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), proto_value_to_json(v)))
            .collect(),
    )
}

fn json_to_proto_value(v: serde_json::Value) -> prost_types::Value {
    let kind = match v {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Kind::StringValue(s),
        serde_json::Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.into_iter().map(json_to_proto_value).collect(),
        }),
        serde_json::Value::Object(obj) => Kind::StructValue(prost_types::Struct {
            fields: obj
                .into_iter()
                .map(|(k, v)| (k, json_to_proto_value(v)))
                .collect(),
        }),
    };
    prost_types::Value { kind: Some(kind) }
}

fn proto_value_to_json(v: &prost_types::Value) -> serde_json::Value {
    match &v.kind {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::NumberValue(n)) => serde_json::Number::from_f64(*n)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.iter().map(proto_value_to_json).collect())
        }
        Some(Kind::StructValue(st)) => proto_struct_to_json(st),
    }
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

    #[test]
    fn test_json_to_proto_struct_roundtrip() {
        // Note: Proto Struct uses f64 for all numbers, so integers become floats
        let json = serde_json::json!({
            "string": "hello",
            "number": 42.5,
            "bool": true,
            "null": null,
            "array": [1.0, 2.0, 3.0],
            "nested": {"key": "value"}
        });

        let proto = json_to_proto_struct(json.clone()).unwrap();
        let back = proto_struct_to_json(&proto);

        assert_eq!(json, back);
    }

    #[test]
    fn test_json_to_proto_struct_returns_none_for_non_object() {
        assert!(json_to_proto_struct(serde_json::json!("string")).is_none());
        assert!(json_to_proto_struct(serde_json::json!(123)).is_none());
        assert!(json_to_proto_struct(serde_json::json!([1, 2, 3])).is_none());
    }
}
