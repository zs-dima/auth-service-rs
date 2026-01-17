//! Identifier normalization utilities.
//!
//! Shared functions for normalizing email and phone identifiers.

/// Normalizes email to lowercase.
#[inline]
#[must_use]
pub fn canonical_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Normalizes phone to E.164 format if valid, otherwise returns trimmed input.
#[must_use]
pub fn canonical_phone(phone: &str) -> String {
    let trimmed = phone.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let has_plus = trimmed.starts_with('+');
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();

    if !(7..=15).contains(&digits.len()) {
        return trimmed.to_string();
    }

    if has_plus {
        format!("+{digits}")
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization() {
        assert_eq!(canonical_email("  User@Example.COM  "), "user@example.com");
    }

    #[test]
    fn phone_normalization_with_plus() {
        assert_eq!(canonical_phone("+1 (555) 123-4567"), "+15551234567");
    }

    #[test]
    fn phone_normalization_without_plus() {
        assert_eq!(canonical_phone("5551234567"), "5551234567");
    }

    #[test]
    fn phone_too_short_returns_original() {
        assert_eq!(canonical_phone("123"), "123");
    }
}
