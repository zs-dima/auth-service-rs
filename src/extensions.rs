//! Extension traits to reduce boilerplate across the codebase.

use tonic::Status;
use uuid::Uuid;

use crate::proto::core::Uuid as ProtoUuid;

/// Extension trait for parsing `Option<&ProtoUuid>` into `Uuid`.
pub trait UuidExt {
    /// Parse the UUID or return a `Status::invalid_argument` error.
    fn parse_or_status(&self) -> Result<Uuid, Status>;

    /// Parse the UUID with a custom field name for the error message.
    fn parse_or_status_with_field(&self, field: &str) -> Result<Uuid, Status>;
}

impl UuidExt for Option<&ProtoUuid> {
    fn parse_or_status(&self) -> Result<Uuid, Status> {
        self.parse_or_status_with_field("UUID")
    }

    fn parse_or_status_with_field(&self, field: &str) -> Result<Uuid, Status> {
        let uuid_str = self
            .map(|u| u.value.as_str())
            .ok_or_else(|| Status::invalid_argument(format!("Missing {field}")))?;

        Uuid::parse_str(uuid_str)
            .map_err(|_| Status::invalid_argument(format!("Invalid {field}: {uuid_str}")))
    }
}

impl UuidExt for Option<ProtoUuid> {
    fn parse_or_status(&self) -> Result<Uuid, Status> {
        self.as_ref().parse_or_status()
    }

    fn parse_or_status_with_field(&self, field: &str) -> Result<Uuid, Status> {
        self.as_ref().parse_or_status_with_field(field)
    }
}

/// Extension trait for converting `Uuid` to `ProtoUuid`.
pub trait ToProtoUuid {
    fn to_proto(&self) -> ProtoUuid;
}

impl ToProtoUuid for Uuid {
    fn to_proto(&self) -> ProtoUuid {
        ProtoUuid {
            value: self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_uuid() {
        let uuid = Uuid::new_v4();
        let proto = ProtoUuid {
            value: uuid.to_string(),
        };

        let result = Some(&proto).parse_or_status();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn test_parse_missing_uuid() {
        let result: Result<Uuid, Status> = None::<&ProtoUuid>.parse_or_status();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_invalid_uuid() {
        let proto = ProtoUuid {
            value: "not-a-uuid".to_string(),
        };
        let result = Some(&proto).parse_or_status();
        assert!(result.is_err());
    }

    #[test]
    fn test_to_proto_uuid() {
        let uuid = Uuid::new_v4();
        let proto = uuid.to_proto();
        assert_eq!(proto.value, uuid.to_string());
    }
}
