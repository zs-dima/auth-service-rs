//! Client IP address extraction middleware.
//!
//! Extracts client IP from standard proxy headers or connection info.
//! Supports: `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` (Cloudflare).
//! Falls back to socket peer address via `ConnectInfo`.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use http::Request;

/// Header priority for IP extraction (highest to lowest).
const IP_HEADERS: &[&str] = &[
    "cf-connecting-ip", // Cloudflare
    "x-real-ip",        // Nginx
    "x-forwarded-for",  // Standard proxy header (first IP in chain)
];

/// Client IP address extracted from request.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    /// Extract client IP from request headers or connection info.
    #[must_use]
    pub fn from_request<T>(req: &Request<T>) -> Self {
        Self(extract_client_ip(req))
    }

    /// Get the IP address if available.
    #[inline]
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        self.0
    }
}

/// Extract client IP from request headers, falling back to socket address.
fn extract_client_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    // First, try proxy headers (in case we're behind a reverse proxy)
    for header in IP_HEADERS {
        let ip = req
            .headers()
            .get(*header)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok());

        if ip.is_some() {
            return ip;
        }
    }

    // Fallback to socket peer address (direct connections, gRPC-web)
    // This is set by axum's into_make_service_with_connect_info
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn extracts_x_forwarded_for_single() {
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.195")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("203.0.113.195".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn extracts_x_forwarded_for_chain() {
        let req = Request::builder()
            .header(
                "x-forwarded-for",
                "203.0.113.195, 70.41.3.18, 150.172.238.178",
            )
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("203.0.113.195".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn extracts_x_real_ip() {
        let req = Request::builder()
            .header("x-real-ip", "192.0.2.1")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("192.0.2.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn extracts_cf_connecting_ip() {
        let req = Request::builder()
            .header("cf-connecting-ip", "198.51.100.178")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("198.51.100.178".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn prefers_cloudflare_over_others() {
        let req = Request::builder()
            .header("cf-connecting-ip", "198.51.100.1")
            .header("x-forwarded-for", "203.0.113.1")
            .header("x-real-ip", "192.0.2.1")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("198.51.100.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn returns_none_for_missing_headers() {
        let req = Request::builder().body(()).unwrap();
        let ip = ClientIp::from_request(&req);
        assert!(ip.ip().is_none());
    }

    #[test]
    fn handles_ipv6() {
        let req = Request::builder()
            .header("x-forwarded-for", "2001:db8::1")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert_eq!(ip.ip(), Some("2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn handles_invalid_ip() {
        let req = Request::builder()
            .header("x-forwarded-for", "not-an-ip")
            .body(())
            .unwrap();
        let ip = ClientIp::from_request(&req);
        assert!(ip.ip().is_none());
    }
}
