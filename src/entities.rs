//! Entity types and their anonymization logic

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Length of random replacement strings
const RANDOM_STRING_LENGTH: usize = 12;

/// Characters used for random string generation (URL-safe)
const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

/// Generate a random alphanumeric string
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a random string with default length
pub fn random_id() -> String {
    generate_random_string(RANDOM_STRING_LENGTH)
}

/// Generate a random hostname-like string
pub fn random_hostname() -> String {
    let mut rng = rand::thread_rng();
    let prefixes = ["srv", "host", "node", "sys", "vm", "app"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    format!("{}-{}", prefix, generate_random_string(6).to_lowercase())
}

/// Generate a random domain-like string
pub fn random_domain() -> String {
    format!("{}.local", generate_random_string(8).to_lowercase())
}

/// Anonymize an IPv4 address by masking the first two octets
pub fn anonymize_ipv4(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("**.**.{}.{}", parts[2], parts[3])
    } else {
        ip.to_string()
    }
}

/// Anonymize an IPv6 address
pub fn anonymize_ipv6(ip: &str) -> String {
    // Mask the first 64 bits (network portion)
    let parts: Vec<&str> = ip.split(':').collect();
    if parts.len() >= 4 {
        let masked: Vec<String> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| if i < 4 { "****".to_string() } else { p.to_string() })
            .collect();
        masked.join(":")
    } else {
        ip.to_string()
    }
}

/// Extract domain from an email address
pub fn extract_email_domain(email: &str) -> Option<String> {
    email.split('@').nth(1).map(|s| s.to_lowercase())
}

/// Extract local part from an email address
pub fn extract_email_local(email: &str) -> Option<String> {
    email.split('@').next().map(|s| s.to_string())
}

/// Extract hostname from FQDN
pub fn extract_hostname(fqdn: &str) -> String {
    fqdn.split('.').next().unwrap_or(fqdn).to_string()
}

/// Extract domain part from FQDN (everything after first dot)
pub fn extract_domain_from_fqdn(fqdn: &str) -> Option<String> {
    let parts: Vec<&str> = fqdn.split('.').collect();
    if parts.len() > 1 {
        Some(parts[1..].join("."))
    } else {
        None
    }
}

/// Extract main domain (last two parts) from a domain
pub fn extract_main_domain(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[parts.len() - 2..].join("."))
    } else {
        None
    }
}

/// Extract server name from UNC path
pub fn extract_unc_server(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('\\');
    trimmed.split('\\').next().map(|s| s.to_string())
}

/// Extract path components from UNC path (excluding server and filename)
pub fn extract_unc_components(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.len() > 2 {
        parts[1..parts.len() - 1]
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

/// Types of entities we can anonymize
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum EntityType {
    VeeamServer,
    VeeamUser,
    SmtpServer,
    VCenter,
    EsxiHost,
    HyperVHost,
    Domain,
    Email,
    Location,
    Ipv4,
    Ipv6,
    VmName,
    Datastore,
    Cluster,
    Repository,
    UncServer,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::VeeamServer => write!(f, "Veeam Server"),
            EntityType::VeeamUser => write!(f, "User Account"),
            EntityType::SmtpServer => write!(f, "SMTP Server"),
            EntityType::VCenter => write!(f, "vCenter Server"),
            EntityType::EsxiHost => write!(f, "ESXi Host"),
            EntityType::HyperVHost => write!(f, "Hyper-V Host"),
            EntityType::Domain => write!(f, "Domain"),
            EntityType::Email => write!(f, "Email Address"),
            EntityType::Location => write!(f, "Path/Location"),
            EntityType::Ipv4 => write!(f, "IPv4 Address"),
            EntityType::Ipv6 => write!(f, "IPv6 Address"),
            EntityType::VmName => write!(f, "VM Name"),
            EntityType::Datastore => write!(f, "Datastore"),
            EntityType::Cluster => write!(f, "Cluster"),
            EntityType::Repository => write!(f, "Repository"),
            EntityType::UncServer => write!(f, "Network Server"),
        }
    }
}

impl EntityType {
    /// Get the JSON key name for this entity type
    pub fn json_key(&self) -> &'static str {
        match self {
            EntityType::VeeamServer => "veeam_servers",
            EntityType::VeeamUser => "user_accounts",
            EntityType::SmtpServer => "smtp_servers",
            EntityType::VCenter => "vcenter_servers",
            EntityType::EsxiHost => "esxi_hosts",
            EntityType::HyperVHost => "hyperv_hosts",
            EntityType::Domain => "domains",
            EntityType::Email => "email_addresses",
            EntityType::Location => "locations",
            EntityType::Ipv4 => "ipv4_addresses",
            EntityType::Ipv6 => "ipv6_addresses",
            EntityType::VmName => "vm_names",
            EntityType::Datastore => "datastores",
            EntityType::Cluster => "clusters",
            EntityType::Repository => "repositories",
            EntityType::UncServer => "network_servers",
        }
    }

    /// Get display order for consistent output
    pub fn display_order(&self) -> u8 {
        match self {
            EntityType::VeeamServer => 0,
            EntityType::SmtpServer => 1,
            EntityType::VCenter => 2,
            EntityType::EsxiHost => 3,
            EntityType::HyperVHost => 4,
            EntityType::Domain => 5,
            EntityType::Email => 6,
            EntityType::VeeamUser => 7,
            EntityType::VmName => 8,
            EntityType::Datastore => 9,
            EntityType::Cluster => 10,
            EntityType::Repository => 11,
            EntityType::UncServer => 12,
            EntityType::Location => 13,
            EntityType::Ipv4 => 14,
            EntityType::Ipv6 => 15,
        }
    }
}

/// An entity that needs to be anonymized
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entity {
    pub entity_type: EntityType,
    pub original: String,
    pub anonymized: String,
}

impl Entity {
    /// Create a new entity with an appropriate anonymized value
    pub fn new(entity_type: EntityType, original: String) -> Self {
        let anonymized = Self::generate_anonymized(&entity_type, &original);
        Self {
            entity_type,
            original,
            anonymized,
        }
    }

    /// Create entity with specific anonymized value
    pub fn with_anonymized(entity_type: EntityType, original: String, anonymized: String) -> Self {
        Self {
            entity_type,
            original,
            anonymized,
        }
    }

    /// Generate an appropriate anonymized value based on entity type
    fn generate_anonymized(entity_type: &EntityType, original: &str) -> String {
        match entity_type {
            EntityType::Ipv4 => anonymize_ipv4(original),
            EntityType::Ipv6 => anonymize_ipv6(original),
            EntityType::Email => {
                format!("{}@{}", random_id().to_lowercase(), random_domain())
            }
            EntityType::Domain => random_domain(),
            EntityType::VeeamServer
            | EntityType::SmtpServer
            | EntityType::VCenter
            | EntityType::EsxiHost
            | EntityType::HyperVHost
            | EntityType::UncServer => random_hostname(),
            EntityType::VmName => format!("vm-{}", generate_random_string(8).to_lowercase()),
            EntityType::Datastore => format!("datastore-{}", generate_random_string(6).to_lowercase()),
            EntityType::Cluster => format!("cluster-{}", generate_random_string(6).to_lowercase()),
            EntityType::Repository => format!("repo-{}", generate_random_string(6).to_lowercase()),
            EntityType::VeeamUser => format!("user_{}", generate_random_string(8).to_lowercase()),
            EntityType::Location => random_id(),
        }
    }

    /// Check if this entity should be replaced before another
    /// (longer strings should be replaced first to avoid partial matches)
    pub fn replacement_priority(&self) -> usize {
        self.original.len()
    }
}

impl PartialOrd for Entity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort by length descending (longer strings first)
        other.original.len().cmp(&self.original.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_ipv4() {
        assert_eq!(anonymize_ipv4("192.168.1.100"), "**.**.1.100");
        assert_eq!(anonymize_ipv4("10.0.0.1"), "**.**.0.1");
        assert_eq!(anonymize_ipv4("172.16.255.1"), "**.**.255.1");
    }

    #[test]
    fn test_anonymize_ipv6() {
        let result = anonymize_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        assert!(result.starts_with("****:****:****:****:"));
    }

    #[test]
    fn test_extract_email_domain() {
        assert_eq!(extract_email_domain("user@example.com"), Some("example.com".to_string()));
        assert_eq!(extract_email_domain("admin@CORP.LOCAL"), Some("corp.local".to_string()));
        assert_eq!(extract_email_domain("invalid"), None);
    }

    #[test]
    fn test_extract_hostname() {
        assert_eq!(extract_hostname("server.example.com"), "server");
        assert_eq!(extract_hostname("standalone"), "standalone");
    }

    #[test]
    fn test_extract_unc_server() {
        assert_eq!(extract_unc_server(r"\\fileserver\share"), Some("fileserver".to_string()));
        assert_eq!(extract_unc_server(r"\\nas01.corp.local\backup"), Some("nas01.corp.local".to_string()));
    }

    #[test]
    fn test_extract_unc_components() {
        let components = extract_unc_components(r"\\server\share\folder\subfolder\file.txt");
        assert_eq!(components, vec!["share", "folder", "subfolder"]);
    }

    #[test]
    fn test_random_string_length() {
        let s = generate_random_string(20);
        assert_eq!(s.len(), 20);
    }

    #[test]
    fn test_entity_ordering() {
        let short = Entity::new(EntityType::Domain, "a.com".to_string());
        let long = Entity::new(EntityType::Domain, "subdomain.example.com".to_string());
        
        let mut entities = vec![short.clone(), long.clone()];
        entities.sort();
        
        // Longer should come first
        assert_eq!(entities[0].original, "subdomain.example.com");
    }
}
