//! Extension traits for `str` type conversions.
//!
//! Provides utilities for handling empty-as-none semantics, commonly needed
//! when working with protobuf string fields that default to empty strings.

/// Extension trait for `str` to handle empty-as-none semantics.
pub trait StrExt {
    /// Returns `Some(String)` if non-empty, `None` if empty.
    ///
    /// Useful for converting protobuf string fields to `Option<String>`.
    #[must_use]
    fn to_opt(&self) -> Option<String>;

    /// Returns self if non-empty, otherwise returns `default`.
    #[must_use]
    fn or_str<'a>(&'a self, default: &'a str) -> &'a str;
}

impl StrExt for str {
    #[inline]
    fn to_opt(&self) -> Option<String> {
        (!self.is_empty()).then(|| self.to_string())
    }

    #[inline]
    fn or_str<'a>(&'a self, default: &'a str) -> &'a str {
        if self.is_empty() { default } else { self }
    }
}

/// Extension trait for `Option<String>` to provide default value semantics.
pub trait OptionStrExt {
    /// Returns the inner `String` if `Some`, otherwise returns `default.to_string()`.
    ///
    /// # Example
    /// ```
    /// use auth_core::OptionStrExt;
    ///
    /// let some: Option<String> = Some("value".to_string());
    /// let none: Option<String> = None;
    ///
    /// assert_eq!(some.or_str("default"), "value");
    /// assert_eq!(none.or_str("default"), "default");
    /// ```
    #[must_use]
    fn or_str(self, default: &str) -> String;
}

impl OptionStrExt for Option<String> {
    #[inline]
    fn or_str(self, default: &str) -> String {
        self.unwrap_or_else(|| default.to_string())
    }
}
