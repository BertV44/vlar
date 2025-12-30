//! Embedded regex patterns for log parsing
//!
//! All patterns are compiled at startup and cached for performance.
//! Patterns can be overridden via external configuration file.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

lazy_static! {
    /// Pattern to match SMTP server configurations
    pub static ref SMTP_SERVER: Regex = Regex::new(
        r#"(?i)(?:smtp|mail)[\s_-]*(?:server|host|relay)?[\s:="']+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#
    ).unwrap();

    /// Pattern to match Veeam server names in various log formats
    pub static ref VEEAM_SERVER: Regex = Regex::new(
        r#"(?i)(?:veeam|vbr|backup)[\s_-]*(?:server|host)?[\s:="']+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)"#
    ).unwrap();

    /// Pattern to match vCenter server names
    pub static ref VCENTER: Regex = Regex::new(
        r#"(?i)(?:vcenter|vsphere|vmware[\s_-]*(?:vcenter|server))[\s:="']+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#
    ).unwrap();

    /// Pattern to match ESXi host names
    pub static ref ESXI_SERVER: Regex = Regex::new(
        r#"(?i)(?:esxi|esx|vmhost|hypervisor)[\s:="']+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#
    ).unwrap();

    /// Pattern to match Hyper-V host names
    pub static ref HYPERV_SERVER: Regex = Regex::new(
        r#"(?i)(?:hyper-?v|hvhost)[\s:="']+([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#
    ).unwrap();

    /// Pattern to match email addresses (RFC 5322 compliant)
    pub static ref EMAIL: Regex = Regex::new(
        r#"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"#
    ).unwrap();

    /// Pattern to match Windows domain\user format
    pub static ref DOMAIN_USER: Regex = Regex::new(
        r#"(?i)(?:[a-zA-Z][a-zA-Z0-9.-]{0,14})\\([a-zA-Z][a-zA-Z0-9._-]{0,63})"#
    ).unwrap();

    /// Pattern to match UPN format (user@domain)
    pub static ref UPN_USER: Regex = Regex::new(
        r#"(?i)([a-zA-Z][a-zA-Z0-9._-]{0,63})@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)"#
    ).unwrap();

    /// Pattern to match UNC paths / network locations
    pub static ref UNC_PATH: Regex = Regex::new(
        r#"\\\\([a-zA-Z0-9._-]+)(?:\\([a-zA-Z0-9._\s-]+))+"#
    ).unwrap();

    /// Pattern to match local Windows paths with drive letters
    pub static ref LOCAL_PATH: Regex = Regex::new(
        r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#
    ).unwrap();

    /// Pattern to match IPv4 addresses
    pub static ref IPV4: Regex = Regex::new(
        r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#
    ).unwrap();

    /// Pattern to match IPv4 in IPv6 format [::ffff:x.x.x.x]
    pub static ref IPV4_IN_IPV6: Regex = Regex::new(
        r#"\[::ffff:((?:\d{1,3}\.){3}\d{1,3})\]"#
    ).unwrap();

    /// Pattern to match IPv6 addresses
    pub static ref IPV6: Regex = Regex::new(
        r#"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?::[0-9a-f]{1,4}){1,7}|::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"#
    ).unwrap();

    /// Pattern to match FQDN
    pub static ref FQDN: Regex = Regex::new(
        r#"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"#
    ).unwrap();

    /// Pattern to match hostnames in connection strings
    pub static ref CONNECTION_HOST: Regex = Regex::new(
        r#"(?i)(?:server|host|data\s*source|hostname)[\s]*[=:][\s]*([a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?)"#
    ).unwrap();

    /// Pattern to match repository paths
    pub static ref REPOSITORY_PATH: Regex = Regex::new(
        r#"(?i)(?:repository|repo|backup[\s_-]*path)[\s:="']+([^\s"'<>|]+)"#
    ).unwrap();

    /// Pattern to match VM names in logs
    pub static ref VM_NAME: Regex = Regex::new(
        r#"(?i)(?:vm[\s_-]*name|virtual[\s_-]*machine|guest)[\s:="']+([a-zA-Z0-9][a-zA-Z0-9._-]{0,63})"#
    ).unwrap();

    /// Pattern to match datastore names
    pub static ref DATASTORE: Regex = Regex::new(
        r#"(?i)(?:datastore|storage)[\s:="']+\[?([a-zA-Z0-9][a-zA-Z0-9._\s-]{0,63})\]?"#
    ).unwrap();

    /// Pattern to match cluster names
    pub static ref CLUSTER: Regex = Regex::new(
        r#"(?i)(?:cluster|resource[\s_-]*pool)[\s:="']+([a-zA-Z0-9][a-zA-Z0-9._\s-]{0,63})"#
    ).unwrap();
}

/// Version-like IP patterns that should NOT be anonymized
const VERSION_PREFIXES: &[&str] = &["7.", "8.", "0.", "1.0.", "2.0."];

/// Check if a string is a valid FQDN
pub fn is_fqdn(s: &str) -> bool {
    FQDN.is_match(s)
}

/// Check if a string is a valid IPv4 address
pub fn is_ipv4(s: &str) -> bool {
    if !IPV4.is_match(s) {
        return false;
    }
    s.split('.').all(|octet| octet.parse::<u8>().is_ok())
}

/// Check if an IP looks like a version number (e.g., 7.0.0.1, 8.0.1.0)
pub fn is_version_like_ip(ip: &str) -> bool {
    VERSION_PREFIXES.iter().any(|prefix| ip.starts_with(prefix))
}

/// Check if IP is a loopback or link-local address (should not anonymize)
pub fn is_special_ip(ip: &str) -> bool {
    ip.starts_with("127.") || 
    ip.starts_with("169.254.") ||
    ip == "0.0.0.0" ||
    ip == "255.255.255.255"
}

/// Load custom patterns from a JSON file
pub fn load_custom_patterns(path: &Path) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read patterns file: {}", e))?;
    
    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse patterns file: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_fqdn() {
        assert!(is_fqdn("server.example.com"));
        assert!(is_fqdn("mail.corp.local"));
        assert!(is_fqdn("a.co"));
        assert!(!is_fqdn("server"));
        assert!(!is_fqdn("192.168.1.1"));
        assert!(!is_fqdn("-invalid.com"));
    }

    #[test]
    fn test_is_ipv4() {
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("10.0.0.1"));
        assert!(is_ipv4("0.0.0.0"));
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("server.local"));
        assert!(!is_ipv4("1.2.3"));
    }

    #[test]
    fn test_version_detection() {
        assert!(is_version_like_ip("7.0.3.0"));
        assert!(is_version_like_ip("8.0.1.0"));
        assert!(!is_version_like_ip("192.168.1.1"));
        assert!(!is_version_like_ip("10.0.0.1"));
    }

    #[test]
    fn test_special_ip() {
        assert!(is_special_ip("127.0.0.1"));
        assert!(is_special_ip("169.254.1.1"));
        assert!(!is_special_ip("192.168.1.1"));
    }

    #[test]
    fn test_email_pattern() {
        let text = "Contact admin@example.com or support@corp.local for help";
        let caps: Vec<_> = EMAIL.find_iter(text).collect();
        assert_eq!(caps.len(), 2);
    }

    #[test]
    fn test_domain_user_pattern() {
        let text = r"User DOMAIN\administrator logged in";
        let caps: Vec<_> = DOMAIN_USER.captures_iter(text).collect();
        assert_eq!(caps.len(), 1);
        assert_eq!(&caps[0][1], "administrator");
    }

    #[test]
    fn test_unc_path_pattern() {
        let text = r"Accessing \\fileserver\share\backup\data";
        assert!(UNC_PATH.is_match(text));
    }
}
