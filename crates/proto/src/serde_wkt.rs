//! Serde adapters for prost types that lack native `Serialize`/`Deserialize`.
//!
//! ## Well-known types (`prost_types`)
//!
//! - **Timestamp** → RFC 3339 string (`"2025-01-15T09:30:00Z"`)
//! - **Duration**  → seconds string with `s` suffix (`"300s"`)
//! - **`FieldMask`** → comma-separated camelCase paths (`"name,email,role"`)
//!
//! ## Proto enums (i32 fields)
//!
//! Proto3 enum fields are `i32` in prost. The [`define_enum_serde`] macro
//! generates `#[serde(with)]` modules that serialize as proto enum name
//! strings (e.g., `"USER_ROLE_ADMIN"`) following Google's protobuf JSON mapping.
//!
//! Each invocation generates three sub-modules:
//! - `{name}`      — for `i32` fields
//! - `opt_{name}`  — for `Option<i32>` fields (`optional` in proto3)
//! - `vec_{name}`  — for `Vec<i32>` fields (`repeated` in proto3)

/// Serde adapter for `Option<prost_types::Timestamp>` ↔ RFC 3339 string.
#[allow(clippy::missing_errors_doc)]
pub mod opt_timestamp {
    use prost_types::Timestamp;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(ts) => {
                let nanos = u32::try_from(ts.nanos)
                    .map_err(|_| serde::ser::Error::custom("negative nanos in Timestamp"))?;
                let dt = chrono::DateTime::from_timestamp(ts.seconds, nanos)
                    .ok_or_else(|| serde::ser::Error::custom("timestamp out of range"))?;
                serializer.serialize_str(&dt.to_rfc3339())
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let dt =
                    chrono::DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)?;
                #[allow(clippy::cast_possible_wrap)]
                Ok(Some(Timestamp {
                    seconds: dt.timestamp(),
                    nanos: dt.timestamp_subsec_nanos() as i32,
                }))
            }
            None => Ok(None),
        }
    }
}

/// Serde adapter for `Option<prost_types::Duration>` ↔ seconds string with `s` suffix.
///
/// Follows the protobuf JSON mapping: `"300s"`, `"1.500s"`, `"0s"`.
/// Per proto3 spec, `seconds` and `nanos` must have the same sign.
#[allow(clippy::missing_errors_doc)]
pub mod opt_duration {
    use prost_types::Duration;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(d) => {
                let negative = d.seconds < 0 || d.nanos < 0;
                let abs_secs = d.seconds.unsigned_abs();
                let abs_nanos = d.nanos.unsigned_abs();

                if abs_nanos == 0 {
                    let sign = if negative { "-" } else { "" };
                    serializer.serialize_str(&format!("{sign}{abs_secs}s"))
                } else {
                    let sign = if negative { "-" } else { "" };
                    let frac = format!("{abs_nanos:09}");
                    let trimmed = frac.trim_end_matches('0');
                    serializer.serialize_str(&format!("{sign}{abs_secs}.{trimmed}s"))
                }
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_suffix('s').unwrap_or(&s);
                let negative = s.starts_with('-');
                let s = s.strip_prefix('-').unwrap_or(s);

                let (secs, nanos) = if let Some((whole, frac)) = s.split_once('.') {
                    let secs: i64 = whole.parse().map_err(serde::de::Error::custom)?;
                    let capped = &frac[..frac.len().min(9)];
                    let padded = format!("{capped:0<9}");
                    let nanos: i32 = padded.parse().map_err(serde::de::Error::custom)?;
                    (secs, nanos)
                } else {
                    let secs: i64 = s.parse().map_err(serde::de::Error::custom)?;
                    (secs, 0)
                };

                if negative {
                    Ok(Some(Duration {
                        seconds: -secs,
                        nanos: -nanos,
                    }))
                } else {
                    Ok(Some(Duration {
                        seconds: secs,
                        nanos,
                    }))
                }
            }
            None => Ok(None),
        }
    }
}

/// Serde adapter for `Option<prost_types::FieldMask>` ↔ comma-separated paths string.
///
/// Proto JSON mapping uses camelCase paths: `"displayName,email"`.
/// Paths are normalized to `snake_case` on deserialization to match prost field names.
#[allow(clippy::missing_errors_doc)]
pub mod opt_field_mask {
    use prost_types::FieldMask;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<FieldMask>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(fm) => {
                let camel: Vec<String> = fm.paths.iter().map(|p| snake_to_camel(p)).collect();
                serializer.serialize_str(&camel.join(","))
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<FieldMask>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) if !s.is_empty() => Ok(Some(FieldMask {
                paths: s
                    .split(',')
                    .map(|p| camel_to_snake(p.trim()))
                    .collect(),
            })),
            _ => Ok(None),
        }
    }

    /// Convert `snake_case` → `camelCase` for proto JSON mapping.
    ///
    /// Proto JSON mapping requires `FieldMask` paths in camelCase on the wire
    /// (e.g. `"displayName"`). Internally prost stores paths in `snake_case`.
    fn snake_to_camel(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut upper_next = false;
        for ch in s.chars() {
            if ch == '_' {
                upper_next = true;
            } else if upper_next {
                result.extend(ch.to_uppercase());
                upper_next = false;
            } else {
                result.push(ch);
            }
        }
        result
    }

    /// Convert `camelCase` → `snake_case`, handling consecutive uppercase (acronyms).
    ///
    /// Proto JSON mapping sends field mask paths in camelCase
    /// (e.g. `"displayName"`), but prost uses `snake_case` field names
    /// (e.g. `"display_name"`). Handles acronyms correctly:
    /// `"userURL"` → `"user_url"`, `"getHTTPSValue"` → `"get_https_value"`.
    fn camel_to_snake(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 4);
        let chars: Vec<char> = s.chars().collect();
        for (i, &ch) in chars.iter().enumerate() {
            if ch.is_uppercase() {
                // Insert underscore before: uppercase after lowercase,
                // or uppercase followed by lowercase (end of acronym run)
                if i > 0
                    && (chars[i - 1].is_lowercase()
                        || (i + 1 < chars.len() && chars[i + 1].is_lowercase()))
                {
                    result.push('_');
                }
                result.extend(ch.to_lowercase());
            } else {
                result.push(ch);
            }
        }
        result
    }
}

// =============================================================================
// Proto enum serde adapters
// =============================================================================

/// Generates `#[serde(with)]` modules for proto3 enum fields (`i32` in prost).
///
/// Serializes as the proto enum name string (e.g., `"USER_ROLE_ADMIN"`) following
/// Google's protobuf JSON mapping.
///
/// With an optional prefix, strips the prefix and lowercases for REST-friendly output:
/// `define_enum_serde!(health_status, HealthStatus, "HEALTH_STATUS_")` →
/// `"healthy"` / `"unhealthy"` instead of `"HEALTH_STATUS_HEALTHY"`.
///
/// For each invocation, three sub-modules are created inside `{name}`:
/// - `{name}`            — for `i32` fields (`#[serde(with = "serde_wkt::user_role")]`)
/// - `{name}::optional`  — for `Option<i32>` fields
/// - `{name}::repeated`  — for `Vec<i32>` fields
macro_rules! define_enum_serde {
    ($name:ident, $enum_type:ty) => {
        define_enum_serde!(@impl $name, $enum_type, |s: &str| s.to_string(), |s: &str| s.to_string());
    };
    ($name:ident, $enum_type:ty, $prefix:literal) => {
        define_enum_serde!(@impl $name, $enum_type,
            |s: &str| s.strip_prefix($prefix).unwrap_or(s).to_lowercase(),
            |s: &str| {
                let upper = s.to_uppercase();
                format!("{}{}", $prefix, upper)
            });
    };
    (@impl $name:ident, $enum_type:ty, $to_wire:expr, $from_wire:expr) => {
        #[allow(clippy::missing_errors_doc)]
        pub mod $name {
            use serde::{Deserializer, Serializer};

            /// Serialize `i32` → wire string.
            pub fn serialize<S: Serializer>(value: &i32, serializer: S) -> Result<S::Ok, S::Error> {
                let to_wire: fn(&str) -> String = $to_wire;
                match <$enum_type>::try_from(*value) {
                    Ok(e) => serializer.serialize_str(&to_wire(e.as_str_name())),
                    Err(_) => serializer.serialize_i32(*value),
                }
            }

            /// Deserialize from wire string or integer.
            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<i32, D::Error> {
                use serde::de;

                struct EnumVisitor;

                impl de::Visitor<'_> for EnumVisitor {
                    type Value = i32;

                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a proto enum name string or integer")
                    }

                    fn visit_str<E: de::Error>(self, v: &str) -> Result<i32, E> {
                        // Try exact proto name first
                        if let Some(e) = <$enum_type>::from_str_name(v) {
                            return Ok(e as i32);
                        }
                        // Try converting from wire format (e.g. "healthy" → "HEALTH_STATUS_HEALTHY")
                        let from_wire: fn(&str) -> String = $from_wire;
                        let canonical = from_wire(v);
                        <$enum_type>::from_str_name(&canonical)
                            .map(|e| e as i32)
                            .ok_or_else(|| {
                                E::custom(
                                    concat!("unknown ", stringify!($enum_type), " value: ")
                                        .to_string()
                                        + v,
                                )
                            })
                    }

                    fn visit_i64<E: de::Error>(self, v: i64) -> Result<i32, E> {
                        i32::try_from(v).map_err(E::custom)
                    }

                    fn visit_u64<E: de::Error>(self, v: u64) -> Result<i32, E> {
                        i32::try_from(v).map_err(E::custom)
                    }
                }

                deserializer.deserialize_any(EnumVisitor)
            }

            /// Serde adapter for `Option<i32>` proto enum fields.
            #[allow(clippy::missing_errors_doc)]
            pub mod optional {
                use serde::{Deserializer, Serializer};

                pub fn serialize<S: Serializer>(
                    value: &Option<i32>,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    match value {
                        Some(v) => super::serialize(v, serializer),
                        None => serializer.serialize_none(),
                    }
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Option<i32>, D::Error> {
                    use serde::de;

                    struct OptionalEnumVisitor;

                    impl<'de> de::Visitor<'de> for OptionalEnumVisitor {
                        type Value = Option<i32>;

                        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                            write!(f, "a proto enum name string, integer, or null")
                        }

                        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                            Ok(None)
                        }

                        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                            Ok(None)
                        }

                        fn visit_some<D2: de::Deserializer<'de>>(
                            self,
                            deserializer: D2,
                        ) -> Result<Self::Value, D2::Error> {
                            super::deserialize(deserializer).map(Some)
                        }
                    }

                    deserializer.deserialize_option(OptionalEnumVisitor)
                }
            }

            /// Serde adapter for `Vec<i32>` repeated proto enum fields.
            #[allow(clippy::missing_errors_doc)]
            pub mod repeated {
                use serde::{Deserializer, Serialize, Serializer};

                pub fn serialize<S: Serializer>(
                    values: &[i32],
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    let to_wire: fn(&str) -> String = $to_wire;
                    let strings: Vec<String> = values
                        .iter()
                        .map(|v| {
                            <$enum_type>::try_from(*v)
                                .map(|e| to_wire(e.as_str_name()))
                                .unwrap_or_else(|_| "UNKNOWN".to_string())
                        })
                        .collect();
                    strings.serialize(serializer)
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Vec<i32>, D::Error> {
                    use serde::de;

                    struct EnumSeqVisitor;

                    impl<'de> de::Visitor<'de> for EnumSeqVisitor {
                        type Value = Vec<i32>;

                        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                            write!(f, "a sequence of proto enum name strings or integers")
                        }

                        fn visit_seq<A: de::SeqAccess<'de>>(
                            self,
                            mut seq: A,
                        ) -> Result<Self::Value, A::Error> {
                            let mut values =
                                Vec::with_capacity(seq.size_hint().unwrap_or(0));
                            while let Some(val) = seq.next_element_seed(EnumSeed)? {
                                values.push(val);
                            }
                            Ok(values)
                        }
                    }

                    struct EnumSeed;

                    impl<'de> de::DeserializeSeed<'de> for EnumSeed {
                        type Value = i32;

                        fn deserialize<D2: de::Deserializer<'de>>(
                            self,
                            deserializer: D2,
                        ) -> Result<Self::Value, D2::Error> {
                            super::deserialize(deserializer)
                        }
                    }

                    deserializer.deserialize_seq(EnumSeqVisitor)
                }
            }
        }
    };
}

// Operations enums — custom serde for REST JSON contract
// HealthStatus serializes as lowercase "healthy" / "unhealthy" (not "HEALTH_STATUS_HEALTHY").
define_enum_serde!(health_status, crate::operations::HealthStatus, "HEALTH_STATUS_");

// Core enums
define_enum_serde!(user_role, crate::core::UserRole);
define_enum_serde!(user_status, crate::core::UserStatus);

// Auth enums
define_enum_serde!(identifier_type, crate::auth::IdentifierType);
define_enum_serde!(oauth_provider, crate::auth::OAuthProvider);
define_enum_serde!(auth_status, crate::auth::AuthStatus);
define_enum_serde!(verification_type, crate::auth::VerificationType);
define_enum_serde!(mfa_method, crate::auth::MfaMethod);
