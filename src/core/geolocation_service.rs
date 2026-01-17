//! `GeoIP` lookup service for IP address to country code resolution.
//!
//! Uses `MaxMind` `GeoLite2` Country database for offline, fast lookups.
//! Returns ISO 3166-1 alpha-2 country codes or "ZZ" for private IPs.

use maxminddb::{MaxMindDbError, Reader};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// Geolocation service for IP address to country code lookup.
///
/// Uses `MaxMind` `GeoLite2` Country database for offline, fast lookups.
#[derive(Clone)]
pub struct GeolocationService {
    reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeolocationService {
    /// Create a new geolocation service with optional database path.
    ///
    /// If path is None or database fails to load, service will work in degraded mode (returning None).
    #[must_use]
    pub fn new(db_path: Option<String>) -> Self {
        if let Some(path) = db_path {
            Self::with_database_path(&path)
        } else {
            debug!("GeoIP database path not configured. Geolocation will be disabled.");
            Self { reader: None }
        }
    }

    /// Create a new geolocation service with a custom database path.
    #[must_use]
    pub fn with_database_path(path: &str) -> Self {
        match Self::load_database(path) {
            Ok(reader) => {
                debug!("GeoIP database loaded successfully from {path}");
                Self {
                    reader: Some(Arc::new(reader)),
                }
            }
            Err(e) => {
                warn!(
                    "Failed to load GeoIP database from {}: {}. Geolocation will be disabled.",
                    path, e
                );
                Self { reader: None }
            }
        }
    }

    /// Load `MaxMind` database from file.
    fn load_database(path: &str) -> Result<Reader<Vec<u8>>, MaxMindDbError> {
        Reader::open_readfile(path)
    }

    /// Check if IP address is private/local.
    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
        }
    }

    /// Get ISO 3166-1 alpha-2 country code for an IP address.
    ///
    /// Returns:
    /// - `Some("ZZ")` for private/local IP addresses
    /// - `Some(country_code)` for public IP addresses found in database
    /// - `None` if database is not loaded or lookup fails
    #[must_use]
    pub fn get_country_code(&self, ip: IpAddr) -> Option<String> {
        // Check if IP is private/local
        if Self::is_private_ip(ip) {
            debug!("IP {ip} is private/local, returning ZZ");
            return Some("ZZ".to_string());
        }

        let reader = self.reader.as_ref()?;

        // Perform lookup using let-chains
        if let Ok(lookup_result) = reader.lookup(ip)
            && let Ok(Some(record)) = lookup_result.decode::<CountryRecord>()
            && let Some(country_code) = record.country?.iso_code
        {
            debug!("IP {ip} resolved to country: {country_code}");
            return Some(country_code);
        }

        debug!("IP {ip} not found or error in GeoIP database");
        None
    }

    /// Check if geolocation service is available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }
}

impl Default for GeolocationService {
    fn default() -> Self {
        Self::new(None)
    }
}

/// `MaxMind` `GeoLite2` Country database record structure.
#[derive(serde::Deserialize)]
struct CountryRecord {
    country: Option<Country>,
}

#[derive(serde::Deserialize)]
struct Country {
    iso_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_service_creation() {
        let _service = GeolocationService::new(None);
        // Service should be created even if database is not available
    }

    #[test]
    #[allow(clippy::ip_constant)]
    fn test_private_ip_returns_zz() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        // Private IPv4 addresses
        let private_ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ];

        for ip in private_ips {
            let result = service.get_country_code(ip);
            assert_eq!(
                result,
                Some("ZZ".to_string()),
                "Private IP {ip} should return ZZ"
            );
        }
    }

    #[test]
    fn test_private_ipv6_returns_zz() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        // Private/special IPv6 addresses
        let private_ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1)), // multicast
        ];

        for ip in private_ips {
            let result = service.get_country_code(ip);
            assert_eq!(
                result,
                Some("ZZ".to_string()),
                "Private IPv6 {ip} should return ZZ"
            );
        }
    }

    #[test]
    fn test_public_ip_lookup() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        if !service.is_available() {
            println!("GeoIP database not available, skipping test");
            return;
        }

        // Google DNS (US)
        let google_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = service.get_country_code(google_dns);

        if let Some(country) = result {
            assert_eq!(country, "US", "Google DNS should be in US");
        }
    }

    #[test]
    fn test_specific_ip_188_169_57_69() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        if !service.is_available() {
            println!("GeoIP database not available, skipping test");
            return;
        }

        // Test the specific IP from requirements
        let test_ip = IpAddr::V4(Ipv4Addr::new(188, 169, 57, 69));
        let result = service.get_country_code(test_ip);

        assert!(
            result.is_some(),
            "IP 188.169.57.69 should return a country code"
        );

        if let Some(country) = result {
            // This IP is in Georgia
            assert_eq!(country, "GE", "IP 188.169.57.69 should be in GE");
            println!("IP 188.169.57.69 country: {country}");
        }
    }

    #[test]
    fn test_ipv6_lookup() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        if !service.is_available() {
            println!("GeoIP database not available, skipping test");
            return;
        }

        // Google DNS IPv6 (US)
        let google_dns_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        let result = service.get_country_code(google_dns_v6);

        if let Some(country) = result {
            assert_eq!(country, "US", "Google DNS IPv6 should be in US");
        }
    }

    #[test]
    #[allow(clippy::ip_constant)]
    fn test_broadcast_ip_returns_zz() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        // Broadcast address is considered special/private
        let broadcast = IpAddr::V4(Ipv4Addr::BROADCAST);
        let result = service.get_country_code(broadcast);
        assert_eq!(
            result,
            Some("ZZ".to_string()),
            "Broadcast IP should return ZZ"
        );
    }

    #[test]
    fn test_service_is_cloneable() {
        let service1 = GeolocationService::new(None);
        let service2 = service1.clone();

        assert_eq!(service1.is_available(), service2.is_available());
    }

    #[test]
    fn test_comprehensive_ip_classification() {
        let service = GeolocationService::new(Some("./assets/GeoLite2-Country.mmdb".to_string()));

        if !service.is_available() {
            println!("GeoIP database not available, skipping comprehensive test");
            return;
        }

        // Test local/private IPs - should all return ZZ
        let local_ips = [
            ("127.0.0.1", "ZZ"),       // Loopback
            ("192.168.1.1", "ZZ"),     // Private network
            ("10.0.0.1", "ZZ"),        // Private network
            ("172.16.0.1", "ZZ"),      // Private network
            ("0.0.0.0", "ZZ"),         // Unspecified
            ("255.255.255.255", "ZZ"), // Broadcast
        ];

        for (ip_str, expected) in local_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = service.get_country_code(ip);
            assert_eq!(
                result,
                Some(expected.to_string()),
                "IP {ip_str} should return {expected}"
            );
        }

        // Test public IPs - should return actual country codes
        let public_ips = [
            ("8.8.8.8", "US"),       // Google DNS
            ("188.169.57.69", "GE"), // Georgia
        ];

        for (ip_str, expected) in public_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = service.get_country_code(ip);
            if let Some(country) = result {
                assert_eq!(country, expected, "IP {ip_str} should return {expected}");
            }
        }
    }
}
