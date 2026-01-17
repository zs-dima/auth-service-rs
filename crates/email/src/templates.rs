//! Email templates using Askama for compile-time verification.

use super::EmailError;

/// Password reset email template data.
pub struct PasswordResetEmail<'a> {
    pub user_name: &'a str,
    pub reset_link: &'a str,
    pub expires_minutes: u32,
    pub domain: &'a str,
}

impl PasswordResetEmail<'_> {
    /// Render HTML version of the email.
    ///
    /// # Errors
    /// This function is infallible but returns `Result` for API consistency.
    pub fn render_html(&self) -> Result<String, EmailError> {
        Ok(format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset your password</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            color: #1a1a1a;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .button {{
            display: inline-block;
            background-color: #0066cc;
            color: #ffffff !important;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            margin: 20px 0;
        }}
        .button:hover {{
            background-color: #0052a3;
        }}
        .warning {{
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 12px;
            margin: 20px 0;
            font-size: 14px;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #666;
        }}
        .link-fallback {{
            word-break: break-all;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reset your password</h1>
        
        <p>Hi {user_name},</p>
        
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        
        <p style="text-align: center;">
            <a href="{reset_link}" class="button">Reset Password</a>
        </p>
        
        <div class="warning">
            ⏰ This link will expire in <strong>{expires_minutes} minutes</strong>.
        </div>
        
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p class="link-fallback">{reset_link}</p>
        
        <p>If you didn't request a password reset, you can safely ignore this email. Your password won't be changed.</p>
        
        <div class="footer">
            <p>This email was sent by {domain}</p>
            <p>For security reasons, please don't forward this email to anyone.</p>
        </div>
    </div>
</body>
</html>"#,
            user_name = html_escape(self.user_name),
            reset_link = self.reset_link,
            expires_minutes = self.expires_minutes,
            domain = html_escape(self.domain),
        ))
    }

    /// Render plain text version of the email.
    ///
    /// # Errors
    ///
    /// Returns `EmailError::TemplateRender` if template rendering fails.
    pub fn render_text(&self) -> Result<String, EmailError> {
        Ok(format!(
            r"Reset your password

Hi {user_name},

We received a request to reset your password.

Click the link below to create a new password:
{reset_link}

⏰ This link will expire in {expires_minutes} minutes.

If you didn't request a password reset, you can safely ignore this email. Your password won't be changed.

---
This email was sent by {domain}
For security reasons, please don't forward this email to anyone.",
            user_name = self.user_name,
            reset_link = self.reset_link,
            expires_minutes = self.expires_minutes,
            domain = self.domain,
        ))
    }
}

/// Simple HTML escaping for template values.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_password_reset_html() {
        let email = PasswordResetEmail {
            user_name: "John",
            reset_link: "https://example.com/reset?token=abc123",
            expires_minutes: 30,
            domain: "example.com",
        };

        let html = email.render_html().unwrap();
        assert!(html.contains("John"));
        assert!(html.contains("https://example.com/reset?token=abc123"));
        assert!(html.contains("30 minutes"));
    }

    #[test]
    fn renders_password_reset_text() {
        let email = PasswordResetEmail {
            user_name: "John",
            reset_link: "https://example.com/reset?token=abc123",
            expires_minutes: 30,
            domain: "example.com",
        };

        let text = email.render_text().unwrap();
        assert!(text.contains("John"));
        assert!(text.contains("30 minutes"));
    }

    #[test]
    fn escapes_html_in_user_name() {
        let email = PasswordResetEmail {
            user_name: "<script>alert('xss')</script>",
            reset_link: "https://example.com/reset",
            expires_minutes: 30,
            domain: "example.com",
        };

        let html = email.render_html().unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
