//! VeeamLogAnonymizer — Rust Edition v2.6
//!
//! High-performance anonymization tool for Veeam Backup & Replication logs.
//!
//! Coverage aligned with Veeam KB2462 (sensitive data types in VBR logs):
//! <https://www.veeam.com/kb2462>
//!   - User names (DOMAIN\, .\, naked-user, --user-list)
//!   - Hostnames / FQDN / NetBIOS (--hostname-list)
//!   - IPv4 and IPv6 addresses
//!   - MAC addresses
//!   - SSH host fingerprints (SHA256/MD5/public keys)
//!   - PEM certificates / private keys / JWT tokens
//!   - Backup file names (.vbk, .vib, .vbm, .vrb)
//!   - Customer object names (VMs, datastores, hosts) via --object-list
//!   - Database names (SQL/Oracle/PG/Mongo/Hana) via --db-list
//!
//! Philosophy: "Better to miss some entities than to anonymize garbage."
//!
//! ⚠ COMMUNITY PROJECT — NO OFFICIAL VEEAM SUPPORT.
//!   Use at your own risk. See README for full disclaimer.
//!
//! Author: Bertrand Castagnet (EMEA TAM at Veeam France)

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rand::Rng;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const BANNER: &str = r#"
╦  ╦┌─┐┌─┐┌─┐┌┬┐  ╦  ┌─┐┌─┐  ╔═╗┌┐┌┌─┐┌┐┌┬ ┬┌┬┐┬┌─┐┌─┐┬─┐
╚╗╔╝├┤ ├┤ ├─┤│││  ║  │ ││ ┬  ╠═╣││││ ││││└┬┘│││││┌─┘├┤ ├┬┘
 ╚╝ └─┘└─┘┴ ┴┴ ┴  ╩═╝└─┘└─┘  ╩ ╩┘└┘└─┘┘└┘ ┴ ┴ ┴┴└└─┘└─┘┴└─
"#;

/// Characters used for random string generation
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// File extensions that should NOT be treated as email TLDs
const FILE_EXTENSIONS: &[&str] = &[
    "log", "txt", "cfg", "xml", "json", "bak", "tmp", "dat", "db", "ini", "exe", "dll", "sys",
    "bat", "ps1", "cmd", "vbs", "js", "msi", "cab", "zip", "gz", "tar", "rar", "7z", "iso", "img",
    "vmdk", "vhdx", "vhd", "bco", "bkf", "vbk", "vib", "vrb", "vbm",
];

/// System accounts and technical terms to reject as usernames
const SYSTEM_ACCOUNTS: &[&str] = &[
    "system",
    "local",
    "network",
    "administrator",
    "admin",
    "localservice",
    "networkservice",
    "localsystem",
    "nt authority",
    "builtin",
    "everyone",
    "users",
    "guests",
    "defaultaccount",
    "wdagutilityaccount",
];

/// Technical terms to reject as usernames (case-insensitive)
const TECH_TERMS: &[&str] = &[
    "chrome",
    "firefox",
    "edge",
    "safari",
    "opera",
    "veeambackup",
    "backupservice",
    "veeamagent",
    "veeamtransport",
    "veeamdeployer",
    "veeamnfssvc",
    "veeamfilesysvsssvc",
    "powershell",
    "windowsupdate",
    "trustedinstaller",
    "wmiprvse",
    "svchost",
    "csrss",
    "lsass",
    "winlogon",
    "spoolsv",
    "msdtc",
    "dllhost",
    "taskhost",
];

/// Technical suffixes to reject
const TECH_SUFFIXES: &[&str] = &[
    "mutex", "service", "cache", "worker", "handler", "manager", "provider", "listener", "monitor",
    "agent", "helper", "host", "engine", "process", "thread", "task", "job", "session",
];

/// Common words that are NOT valid TLDs for our purposes.
/// Note: ".local", ".corp", ".lan", ".internal" ARE legitimate internal TLDs
/// in Veeam environments and SHOULD be anonymized — they're not in this list.
const INVALID_TLDS: &[&str] = &["log", "tmp", "bak", "dat", "config"];

/// Whitelist of TLDs considered for standalone FQDN detection (--aggressive).
/// Limits false positives by requiring a recognized TLD.
const VALID_FQDN_TLDS: &[&str] = &[
    // gTLDs
    "com", "net", "org", "edu", "gov", "mil", "info", "biz", "name", "pro",
    // tech / cloud
    "io", "app", "dev", "cloud", "tech", "ai", "co", "me", // common country
    "fr", "de", "uk", "us", "ca", "it", "es", "nl", "be", "ch", "at", "se", "no", "dk", "fi", "pl",
    "cz", "ie", "pt", "jp", "cn", "in", "br", "au", // Veeam/IT internal
    "local", "corp", "lan", "internal", "home", "intra", "private", "lab", "test", "office",
];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Regex patterns (compiled once via LazyLock, embedded in binary)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Email pattern: local@domain.tld
static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap()
});

/// Domain\Username pattern (Windows-style). Allows hyphens in domain.
/// Also matches local-machine prefix (.\user) — fix for v2.3 leak.
static RE_DOMAIN_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-zA-Z][a-zA-Z0-9-]{1,14})\\([a-zA-Z][a-zA-Z0-9._-]{2,30})\b").unwrap()
});

/// Local-machine user pattern: ".\username" (no domain prefix).
/// Captures the username group only.
static RE_LOCAL_USER: LazyLock<Regex> = LazyLock::new(|| {
    // r#"..."# avoids the need to escape ", and lets us write \\ for a literal backslash.
    Regex::new(r#"(?i)(?:^|[\s,'"\\\[(])\.\\([a-zA-Z][a-zA-Z0-9._-]{2,30})\b"#).unwrap()
});

/// Naked username with contextual prefix (--aggressive mode).
/// Matches "User: name", "Account: name", "for user name", "as name", etc.
static RE_NAKED_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:User|Account|Username|UserName|Owner|Principal|Created\s+by|Authenticated\s+as|logged\s+in\s+as|for\s+user|by\s+user)[\s:=]+([a-zA-Z][a-zA-Z0-9._-]{2,30})\b",
    )
    .unwrap()
});

/// IPv4 pattern (validated post-extraction)
static RE_IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap());

/// IPv4-mapped IPv6 pattern: [::ffff:x.x.x.x]
static RE_IPV4_MAPPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]").unwrap());

/// UUID pattern (to reject as usernames)
static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap()
});

/// Standalone FQDN pattern (--aggressive). Requires ≥3 segments
/// (e.g. host.subdomain.example.com or host.apps.cluster.home).
/// Validation against VALID_FQDN_TLDS happens post-match.
static RE_FQDN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62}){2,})\b").unwrap()
});

/// PEM block (certificates, public keys). Captured to mask the base64 body.
/// Matches `-----BEGIN <TYPE>----- ... -----END <TYPE2>-----`. Because the
/// Rust `regex` crate does not support backreferences, BEGIN and END types
/// are NOT enforced to match in the regex — we verify equality in the
/// replacement closure and bail out if mismatched.
static RE_PEM_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN ([A-Z0-9 ]+)-----.*?-----END ([A-Z0-9 ]+)-----").unwrap()
});

/// PEM PRIVATE KEY block — removed entirely (no support value).
/// Same backreference workaround as RE_PEM_BLOCK.
static RE_PEM_PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END ([A-Z ]*PRIVATE KEY)-----")
        .unwrap()
});

/// JWT-like token: three base64url segments separated by dots, ≥20 chars total.
static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap()
});

// ─── v2.4 additions ─────────────────────────────────────────────────────

/// IPv6 (full and compressed forms). Excludes simple loopback/link-local
/// fragments that are too short to be meaningful.
/// Matches 8 hextets, OR uses `::` compression, with at least 3 colons total.
/// Trailing `%iface` zone identifier is captured as part of the match for
/// proper anonymization but not required.
static RE_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}(?:[0-9a-f]{1,4}|:)(?:%[a-zA-Z0-9_-]+)?\b").unwrap()
});

/// MAC address — two common formats:
///   - Canonical: `XX:XX:XX:XX:XX:XX` (colon) or `XX-XX-XX-XX-XX-XX` (hyphen)
///   - Compact: `XXXXXXXXXXXX` (12 hex chars, no separator) — only when
///     inside a recognized field like "Physical Address."
static RE_MAC_COLON: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap());

/// Compact 12-hex MAC. We capture only with a leading "Physical Address" or
/// "MAC" context word to avoid false positives on UUID fragments.
static RE_MAC_COMPACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Physical\s+Address[\s:.=]+|MAC[\s:=]+)([0-9a-fA-F]{12})\b").unwrap()
});

/// SSH host key fingerprint — SHA256 form (43 base64 chars + optional `=`).
static RE_SSH_FP_SHA256: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bSHA256:[A-Za-z0-9+/]{43}=?\b").unwrap());

/// SSH host key fingerprint — MD5 form (16 hex pairs colon-separated).
static RE_SSH_FP_MD5: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bMD5:([0-9a-f]{2}:){15}[0-9a-f]{2}\b").unwrap());

/// SSH public key — rsa/ed25519/ecdsa with base64 payload.
static RE_SSH_PUBKEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+)\s+[A-Za-z0-9+/=]{20,}")
        .unwrap()
});

/// Backup file name — anything ending in .vbk/.vib/.vbm/.vrb. Captures the
/// whole filename so we can replace the stem and keep the extension.
static RE_BACKUP_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z0-9][A-Za-z0-9._-]{2,80})\.(vbk|vib|vbm|vrb)\b").unwrap()
});

// (Note: RE_PEM_INLINE removed in favor of unified handling in PEM_BLOCK
// closure — see apply_replacements. The Rust regex crate's NFA can be
// finicky with quantifier interactions; one regex + closure logic is simpler.)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Exclude filter
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EntityKind {
    Email,
    DomainUser,
    Domain,
    Ip,
    /// Naked username (--aggressive). E.g. "User: veeamadmin".
    NakedUser,
    /// Standalone FQDN (--aggressive). E.g. "k10-route.apps.cluster.home".
    Fqdn,
    /// PEM certificate / public key block (default ON).
    Pem,
    /// PEM private key block (default ON).
    PrivateKey,
    /// JWT token (default ON).
    Jwt,
    // v2.4 additions
    /// IPv6 address (default ON).
    Ipv6,
    /// MAC address (default ON).
    Mac,
    /// SSH host key fingerprint / public key (default ON).
    SshFp,
    /// Backup file names (.vbk/.vib/.vbm/.vrb) (default ON).
    BackupFile,
    /// Hostname (from --hostname-list, exact match).
    Hostname,
    /// Customer object name (VM, datastore, host) from --object-list.
    Object,
    /// Database name (SQL/Oracle/PG/Mongo/Hana) from --db-list.
    Db,
}

impl std::fmt::Display for EntityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityKind::Email => write!(f, "email"),
            EntityKind::DomainUser => write!(f, "user"),
            EntityKind::Domain => write!(f, "domain"),
            EntityKind::Ip => write!(f, "ip"),
            EntityKind::NakedUser => write!(f, "naked-user"),
            EntityKind::Fqdn => write!(f, "fqdn"),
            EntityKind::Pem => write!(f, "pem"),
            EntityKind::PrivateKey => write!(f, "private-key"),
            EntityKind::Jwt => write!(f, "jwt"),
            EntityKind::Ipv6 => write!(f, "ipv6"),
            EntityKind::Mac => write!(f, "mac"),
            EntityKind::SshFp => write!(f, "ssh-fp"),
            EntityKind::BackupFile => write!(f, "backup-file"),
            EntityKind::Hostname => write!(f, "hostname"),
            EntityKind::Object => write!(f, "object"),
            EntityKind::Db => write!(f, "db"),
        }
    }
}

#[derive(Debug, Clone)]
struct ExcludeFilter {
    excluded: HashSet<EntityKind>,
}

impl ExcludeFilter {
    #[allow(dead_code)] // Used in unit tests
    fn none() -> Self {
        Self {
            excluded: HashSet::new(),
        }
    }

    fn from_strings(inputs: &[String]) -> Result<Self, String> {
        let mut excluded = HashSet::new();
        for input in inputs {
            for part in input.split(',') {
                match part.trim().to_lowercase().as_str() {
                    "email" | "emails" => {
                        excluded.insert(EntityKind::Email);
                    }
                    "user" | "users" | "domainuser" | "domain_user" | "domain-user" => {
                        excluded.insert(EntityKind::DomainUser);
                    }
                    "domain" | "domains" => {
                        excluded.insert(EntityKind::Domain);
                    }
                    "ip" | "ips" | "ipv4" | "ipaddress" | "ip_address" => {
                        excluded.insert(EntityKind::Ip);
                    }
                    "naked-user" | "naked_user" | "nakeduser" => {
                        excluded.insert(EntityKind::NakedUser);
                    }
                    "fqdn" | "fqdns" => {
                        excluded.insert(EntityKind::Fqdn);
                    }
                    "pem" | "cert" | "certificate" | "certificates" => {
                        excluded.insert(EntityKind::Pem);
                    }
                    "private-key" | "private_key" | "privatekey" | "key" | "keys" => {
                        excluded.insert(EntityKind::PrivateKey);
                    }
                    "jwt" | "jwts" | "token" | "tokens" => {
                        excluded.insert(EntityKind::Jwt);
                    }
                    // v2.4
                    "ipv6" | "ipv6s" => {
                        excluded.insert(EntityKind::Ipv6);
                    }
                    "mac" | "macs" | "mac-address" | "macaddress" => {
                        excluded.insert(EntityKind::Mac);
                    }
                    "ssh-fp" | "ssh_fp" | "sshfp" | "ssh-fingerprint" | "ssh" => {
                        excluded.insert(EntityKind::SshFp);
                    }
                    "backup-file" | "backup_file" | "backupfile" | "backup-files" | "vbk" => {
                        excluded.insert(EntityKind::BackupFile);
                    }
                    "hostname" | "hostnames" | "host" | "hosts" => {
                        excluded.insert(EntityKind::Hostname);
                    }
                    "object" | "objects" | "vm" | "vms" | "datastore" | "datastores" => {
                        excluded.insert(EntityKind::Object);
                    }
                    "db" | "dbs" | "database" | "databases" => {
                        excluded.insert(EntityKind::Db);
                    }
                    "" => {}
                    other => {
                        return Err(format!(
                            "Unknown entity type '{}'. Valid: email, user, domain, ip, ipv6, mac, ssh-fp, backup-file, naked-user, fqdn, hostname, object, db, pem, private-key, jwt",
                            other
                        ));
                    }
                }
            }
        }
        Ok(Self { excluded })
    }

    fn process_emails(&self) -> bool {
        !self.excluded.contains(&EntityKind::Email)
    }
    fn process_domain_users(&self) -> bool {
        !self.excluded.contains(&EntityKind::DomainUser)
    }
    fn process_domains(&self) -> bool {
        !self.excluded.contains(&EntityKind::Domain)
    }
    fn process_ips(&self) -> bool {
        !self.excluded.contains(&EntityKind::Ip)
    }
    fn process_naked_users(&self) -> bool {
        !self.excluded.contains(&EntityKind::NakedUser)
    }
    fn process_fqdns(&self) -> bool {
        !self.excluded.contains(&EntityKind::Fqdn)
    }
    fn process_pem(&self) -> bool {
        !self.excluded.contains(&EntityKind::Pem)
    }
    fn process_private_keys(&self) -> bool {
        !self.excluded.contains(&EntityKind::PrivateKey)
    }
    fn process_jwt(&self) -> bool {
        !self.excluded.contains(&EntityKind::Jwt)
    }
    // v2.4
    fn process_ipv6(&self) -> bool {
        !self.excluded.contains(&EntityKind::Ipv6)
    }
    fn process_mac(&self) -> bool {
        !self.excluded.contains(&EntityKind::Mac)
    }
    fn process_ssh_fp(&self) -> bool {
        !self.excluded.contains(&EntityKind::SshFp)
    }
    fn process_backup_files(&self) -> bool {
        !self.excluded.contains(&EntityKind::BackupFile)
    }
    fn process_hostnames(&self) -> bool {
        !self.excluded.contains(&EntityKind::Hostname)
    }
    fn process_objects(&self) -> bool {
        !self.excluded.contains(&EntityKind::Object)
    }
    fn process_dbs(&self) -> bool {
        !self.excluded.contains(&EntityKind::Db)
    }
    fn is_empty(&self) -> bool {
        self.excluded.is_empty()
    }

    fn excluded_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.excluded.iter().map(|k| k.to_string()).collect();
        names.sort();
        names
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Progress bar helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn make_scan_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} {prefix} {bar:30.cyan/dark_gray} {pos}/{len} files  ({msg})",
        )
        .unwrap()
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .progress_chars("█▓▒░"),
    );
    pb.set_prefix("[1/2] Scanning  ");
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

fn make_anon_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} {prefix} {bar:30.green/dark_gray} {pos}/{len} files  ({msg})",
        )
        .unwrap()
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        .progress_chars("█▓▒░"),
    );
    pb.set_prefix("[2/2] Anonymizing");
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Anonymization map
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
struct AnonymizationMap {
    emails: HashMap<String, String>,
    domain_users: HashMap<String, String>,
    domains: HashMap<String, String>,
    ip_addresses: HashMap<String, String>,
    /// Naked usernames (e.g. "veeamadmin") detected via --aggressive or --user-list.
    naked_users: HashMap<String, String>,
    /// Standalone FQDNs (e.g. "k10-route.apps.cluster.home") via --aggressive.
    fqdns: HashMap<String, String>,
    // v2.4 additions
    /// IPv6 addresses.
    ipv6_addresses: HashMap<String, String>,
    /// MAC addresses (both `XX:XX:...` and `XXXXXXXXXXXX` compact forms).
    mac_addresses: HashMap<String, String>,
    /// SSH host fingerprints / public keys.
    ssh_fps: HashMap<String, String>,
    /// Backup file names (.vbk/.vib/.vbm/.vrb) — stem replaced, extension kept.
    backup_files: HashMap<String, String>,
    /// Short hostnames (from --hostname-list).
    hostnames: HashMap<String, String>,
    /// Object names (VM/datastore/host, from --object-list).
    objects: HashMap<String, String>,
    /// Database names (from --db-list).
    dbs: HashMap<String, String>,
}

impl AnonymizationMap {
    fn new() -> Self {
        Self {
            emails: HashMap::new(),
            domain_users: HashMap::new(),
            domains: HashMap::new(),
            ip_addresses: HashMap::new(),
            naked_users: HashMap::new(),
            fqdns: HashMap::new(),
            ipv6_addresses: HashMap::new(),
            mac_addresses: HashMap::new(),
            ssh_fps: HashMap::new(),
            backup_files: HashMap::new(),
            hostnames: HashMap::new(),
            objects: HashMap::new(),
            dbs: HashMap::new(),
        }
    }

    fn total_entities(&self) -> usize {
        self.emails.len()
            + self.domain_users.len()
            + self.domains.len()
            + self.ip_addresses.len()
            + self.naked_users.len()
            + self.fqdns.len()
            + self.ipv6_addresses.len()
            + self.mac_addresses.len()
            + self.ssh_fps.len()
            + self.backup_files.len()
            + self.hostnames.len()
            + self.objects.len()
            + self.dbs.len()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dictionary JSON structures (for -D export and --reverse import)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Serialize, Deserialize)]
struct OutputDictionary {
    metadata: DictMetadata,
    mappings: DictMappings,
}

#[derive(Serialize, Deserialize)]
struct DictMetadata {
    version: String,
    created_at: String,
    files_processed: usize,
    total_entities: usize,
}

#[derive(Serialize, Deserialize)]
struct DictMappings {
    #[serde(default)]
    emails: Vec<DictEntry>,
    #[serde(default)]
    domains: Vec<DictEntry>,
    #[serde(default)]
    domain_users: Vec<DictEntry>,
    #[serde(default)]
    ip_addresses: Vec<DictEntry>,
    #[serde(default)]
    naked_users: Vec<DictEntry>,
    #[serde(default)]
    fqdns: Vec<DictEntry>,
    // v2.4 — backward-compatible thanks to #[serde(default)]
    #[serde(default)]
    ipv6_addresses: Vec<DictEntry>,
    #[serde(default)]
    mac_addresses: Vec<DictEntry>,
    #[serde(default)]
    ssh_fps: Vec<DictEntry>,
    #[serde(default)]
    backup_files: Vec<DictEntry>,
    #[serde(default)]
    hostnames: Vec<DictEntry>,
    #[serde(default)]
    objects: Vec<DictEntry>,
    #[serde(default)]
    dbs: Vec<DictEntry>,
}

#[derive(Serialize, Deserialize)]
struct DictEntry {
    original: String,
    anonymized: String,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CLI definition
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// High-performance log anonymization tool for Veeam Backup & Replication
#[derive(Parser, Debug)]
#[command(name = "veeam-log-anonymizer")]
#[command(author = "Bertrand Castagnet (EMEA TAM at Veeam France)")]
#[command(version = VERSION)]
#[command(about = "Anonymize Veeam Backup & Replication logs")]
#[command(after_help = "EXAMPLES:
    veeam-log-anonymizer -i backup.log -o ./output -f
    veeam-log-anonymizer -d /var/log/veeam -o ./anonymized -f -v -D
    veeam-log-anonymizer -d ./logs -o ./output -f --exclude ip
    veeam-log-anonymizer --reverse dict.json -d ./anonymized -o ./restored -f
    veeam-log-anonymizer -d ./logs --validate-only --report-output audit.json
    veeam-log-anonymizer -d bundle.zip --output-zip anon.zip -f -D --dict-output ./safe
    veeam-log-anonymizer -d ./logs -o ./out -f -D --dict-output ./safe --encrypt-dict
")]
struct Cli {
    /// Input log file
    #[arg(
        short = 'i',
        long = "input",
        group = "input_source",
        value_name = "FILE"
    )]
    input_file: Option<PathBuf>,

    /// Input directory containing log files (recursive). Also accepts a `.zip`
    /// support bundle directly (auto-detected by extension / magic bytes).
    #[arg(
        short = 'd',
        long = "directory",
        group = "input_source",
        value_name = "DIR_OR_ZIP"
    )]
    input_directory: Option<PathBuf>,

    /// Output directory for anonymized files. Not required for --validate-only
    /// or when --output-zip is used.
    #[arg(
        short = 'o',
        long = "output",
        required_unless_present_any = ["validate_only", "output_zip"],
        value_name = "DIR"
    )]
    output_directory: Option<PathBuf>,

    /// Repack the anonymized result into a new `.zip` at this path (instead of
    /// writing a directory). Recommended when the input is a `.zip` bundle —
    /// this is what you send back to support. The dictionary is NEVER written
    /// inside the zip.
    #[arg(long = "output-zip", value_name = "FILE")]
    output_zip: Option<PathBuf>,

    /// Force overwrite existing files and create directories
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Display the mapping table of anonymized entities
    #[arg(short = 'm', long = "mapping")]
    mapping: bool,

    /// Show verbose output (filenames in progress bar)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Export JSON dictionary of all anonymized mappings
    #[arg(short = 'D', long = "dictionary")]
    dictionary: bool,

    /// Separate directory for the dictionary file (recommended: NOT inside the
    /// output directory you send to support). If unset, dictionary is written
    /// to the output directory with a visible warning.
    #[arg(long = "dict-output", value_name = "DIR")]
    dict_output: Option<PathBuf>,

    /// Show detailed statistics by entity type
    #[arg(short = 's', long = "stats")]
    stats: bool,

    /// Exclude entity types from anonymization (comma-separated).
    /// Valid types: email, user, domain, ip, naked-user, fqdn, pem, private-key, jwt
    #[arg(
        short = 'e',
        long = "exclude",
        value_name = "TYPES",
        value_delimiter = ','
    )]
    exclude: Vec<String>,

    /// Preview what would be anonymized without writing files (human-readable
    /// console listing of every mapping).
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Validate-only mode: scan without writing anything and emit a machine-
    /// readable JSON report (entity counts by kind and by file — never the
    /// original values). Exit code: 0 if no entities detected, 2 if entities
    /// were detected, 1 on error. Useful for pipelines / agent orchestration.
    #[arg(long = "validate-only")]
    validate_only: bool,

    /// Write the --validate-only JSON report to this file instead of stdout.
    #[arg(long = "report-output", value_name = "FILE")]
    report_output: Option<PathBuf>,

    /// Reverse anonymization using a dictionary JSON file
    #[arg(long = "reverse", value_name = "DICT_FILE")]
    reverse: Option<PathBuf>,

    /// Re-scan output files after anonymization to detect any leaked entities
    /// (safety net for false negatives in detection regexes).
    #[arg(long = "paranoid")]
    paranoid: bool,

    /// Enable aggressive detection: standalone FQDNs and naked usernames
    /// (User:/Account:/.\user contexts). May increase false positives.
    #[arg(long = "aggressive")]
    aggressive: bool,

    /// File with explicit usernames to anonymize (one per line).
    /// Exact whole-word matches, case-insensitive. Zero false positives.
    #[arg(long = "user-list", value_name = "FILE")]
    user_list: Option<PathBuf>,

    /// File with short hostnames to anonymize (one per line, e.g. "vsa1").
    /// Exact whole-word matches, case-insensitive.
    #[arg(long = "hostname-list", value_name = "FILE")]
    hostname_list: Option<PathBuf>,

    /// File with customer object names to anonymize: VM, datastore, host,
    /// cluster names (one per line). Exact whole-word matches.
    #[arg(long = "object-list", value_name = "FILE")]
    object_list: Option<PathBuf>,

    /// File with database names to anonymize (SQL/Oracle/PG/Mongo/Hana)
    /// (one per line). Exact whole-word matches.
    #[arg(long = "db-list", value_name = "FILE")]
    db_list: Option<PathBuf>,

    /// Keep original file and directory names in the output (opt-out).
    /// By default, sensitive entities (hostnames, VM/object names, FQDNs,
    /// backup file names, …) found in file/directory names are anonymized
    /// too — recognizable prefixes (Task./Agent./Svc.) and the .log
    /// extension are preserved. Use this flag to disable path renaming.
    /// Note: IPv4/IPv6/MAC/DOMAIN\user are never altered in path names
    /// (their masked forms contain characters invalid in filenames).
    #[arg(long = "keep-path-names")]
    keep_path_names: bool,

    /// Encrypt the exported dictionary (used with -D) with a passphrase using
    /// the `age` format. Output file gets a `.age` suffix. The passphrase is
    /// read from the VLAR_DICT_PASSPHRASE env var if set, otherwise prompted
    /// interactively (never passed as a CLI argument). --reverse transparently
    /// decrypts a `.age` dictionary. Optional / opt-in.
    #[arg(long = "encrypt-dict")]
    encrypt_dict: bool,
}

impl Cli {
    /// Resolve the output directory, erroring if it was not provided. clap only
    /// requires `-o` outside --validate-only / --output-zip, so callers that
    /// always need a directory use this.
    fn require_output_dir(&self) -> Result<&Path> {
        self.output_directory
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("an output directory (-o/--output) is required here"))
    }

    /// True when the input is a `.zip` bundle (by extension or PK magic bytes).
    fn input_is_zip(&self) -> bool {
        match (&self.input_directory, &self.input_file) {
            (Some(p), _) | (_, Some(p)) => path_is_zip(p),
            _ => false,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Utility functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Validation functions — strict to minimize false positives
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Validate that a string is a real email address worth anonymizing
fn is_valid_email(email: &str) -> bool {
    let lower = email.to_lowercase();

    // Must contain @
    let parts: Vec<&str> = lower.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part: at least 2 chars
    if local.len() < 2 {
        return false;
    }

    // Domain must have at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Extract TLD (last segment after final dot)
    let tld = match domain.rsplit('.').next() {
        Some(t) => t,
        None => return false,
    };

    // TLD must be alphabetic and at least 2 chars
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Reject file extensions as TLDs
    if FILE_EXTENSIONS
        .iter()
        .any(|&ext| tld.eq_ignore_ascii_case(ext))
    {
        return false;
    }

    // Reject invalid/technical TLDs
    if INVALID_TLDS.iter().any(|&t| tld.eq_ignore_ascii_case(t)) {
        return false;
    }

    // Reject if domain looks like an IP address
    if domain.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }

    // Reject systemd-style (user@1000.service)
    if local.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Reject asset hashes (assets@veeam-20d3d104.js)
    if domain.contains('-') && tld.len() <= 3 && domain.chars().any(|c| c.is_ascii_digit()) {
        // Check if the part before TLD looks like a hash
        let domain_body = &domain[..domain.len() - tld.len() - 1];
        if domain_body.chars().filter(|c| c.is_ascii_digit()).count() > 4 {
            return false;
        }
    }

    true
}

/// Validate that a string is a real username worth anonymizing
fn is_valid_username(username: &str) -> bool {
    let lower = username.to_lowercase();

    // Length checks
    if username.len() < 3 || username.len() > 30 {
        return false;
    }

    // Must start with a letter
    if !username
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false)
    {
        return false;
    }

    // Reject system accounts
    if SYSTEM_ACCOUNTS.iter().any(|&acct| lower == acct) {
        return false;
    }

    // Reject known technical terms
    if TECH_TERMS.iter().any(|&term| lower == term) {
        return false;
    }

    // Reject technical suffixes (GlobalMutex, AppCache, etc.)
    if TECH_SUFFIXES
        .iter()
        .any(|&suffix| lower.ends_with(suffix) && lower.len() > suffix.len())
    {
        return false;
    }

    // Reject UUIDs
    if RE_UUID.is_match(username) {
        return false;
    }

    // Reject strings that are all uppercase and look like constants (e.g., BACKUP_JOB)
    if username.len() > 5
        && username.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && username.contains('_')
    {
        return false;
    }

    // Reject if it contains path separators
    if username.contains('/') || username.contains('\\') {
        return false;
    }

    true
}

/// Determine if an IP address should be anonymized
fn should_anonymize_ip(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();

    if octets.len() != 4 {
        return false;
    }

    let first = octets[0];

    // Skip VMware vSphere version numbers (7.x.x.x, 8.x.x.x)
    if first == 7 || first == 8 {
        return false;
    }

    // Skip loopback (127.x.x.x)
    if first == 127 {
        return false;
    }

    // Skip all zeros (0.0.0.0)
    if octets.iter().all(|&o| o == 0) {
        return false;
    }

    // Skip broadcast (255.255.255.255)
    if octets.iter().all(|&o| o == 255) {
        return false;
    }

    // Skip link-local (169.254.x.x)
    if first == 169 && octets[1] == 254 {
        return false;
    }

    // Skip multicast (224-239.x.x.x)
    if (224..=239).contains(&first) {
        return false;
    }

    true
}

/// Anonymize an IPv4 address by masking the first two octets
fn anonymize_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("**.**.{}.{}", parts[2], parts[3])
    } else {
        ip.to_string()
    }
}

// ─── v2.4 IPv6 / MAC helpers ─────────────────────────────────────────────

/// Test whether an IPv6 candidate should be anonymized.
/// Rejects timestamps and other false positives that look IPv6-ish but aren't.
/// Preserves loopback (::1), link-local (fe80::), multicast (ff..),
/// and unspecified (::).
fn should_anonymize_ipv6(ipv6: &str) -> bool {
    // Strip zone identifier
    let raw = ipv6.split('%').next().unwrap_or(ipv6);
    let lower = raw.to_lowercase();

    // Need ≥2 colons to be a real IPv6
    if lower.matches(':').count() < 2 {
        return false;
    }

    // Reject false positives that match the regex but aren't real IPv6:
    //   - timestamps "HH:MM:SS" or "HH:MM:SS.mmm" — purely decimal, ≤3 colons
    //   - "year-month-day HH:MM:SS" forms
    //   - any pure-decimal small-digit sequence
    //
    // Heuristic: a real IPv6 either has a hex letter (a-f), or uses `::`
    // compression, or has the full 7 colons (8 hextets).
    let has_hex_letter = lower.chars().any(|c| matches!(c, 'a'..='f'));
    let has_compression = lower.contains("::");
    let colon_count = lower.matches(':').count();
    let has_full_form = colon_count >= 7;
    if !has_hex_letter && !has_compression && !has_full_form {
        return false;
    }

    // Loopback / unspecified
    if lower == "::1" || lower == "::" {
        return false;
    }
    // Link-local fe80::/10
    if lower.starts_with("fe8")
        || lower.starts_with("fe9")
        || lower.starts_with("fea")
        || lower.starts_with("feb")
    {
        return false;
    }
    // Multicast ff..::
    if lower.starts_with("ff") {
        return false;
    }
    true
}

/// Anonymize an IPv6: keep the last hextet, mask the rest.
/// Preserves zone identifier if present.
fn anonymize_ipv6(ipv6: &str) -> String {
    let (addr, zone) = match ipv6.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (ipv6, None),
    };

    // Take the last segment after the final ':' (works for compressed forms too)
    let last = addr.rsplit(':').next().unwrap_or("");
    let last = if last.is_empty() { "0" } else { last };

    let result = format!("****:****:****:****:****:****:****:{}", last);
    match zone {
        Some(z) => format!("{}%{}", result, z),
        None => result,
    }
}

/// Anonymize a colon/hyphen-separated MAC: keep the last byte (last 2 hex).
fn anonymize_mac_colon(mac: &str) -> String {
    let sep = if mac.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = mac.split(sep).collect();
    if parts.len() == 6 {
        format!("**{0}**{0}**{0}**{0}**{0}{1}", sep, parts[5])
    } else {
        mac.to_string()
    }
}

/// Anonymize a compact 12-hex MAC: keep last 2 hex chars.
fn anonymize_mac_compact(mac_compact: &str) -> String {
    if mac_compact.len() == 12 {
        format!("**********{}", &mac_compact[10..])
    } else {
        mac_compact.to_string()
    }
}

/// Validate that a string is a standalone FQDN worth anonymizing.
/// Requires ≥3 dot-separated segments and a known TLD from VALID_FQDN_TLDS.
fn is_valid_fqdn(fqdn: &str) -> bool {
    let lower = fqdn.to_lowercase();

    // Must have at least 3 segments (host.domain.tld minimum for "standalone")
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return false;
    }

    // Last segment is the TLD — must be in whitelist
    let tld = parts[parts.len() - 1];
    if !VALID_FQDN_TLDS.iter().any(|&t| t.eq_ignore_ascii_case(tld)) {
        return false;
    }

    // Reject all-numeric segments (IP-like) — already handled by IP regex
    if parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }

    // Reject if any segment is purely numeric AND > 3 chars (looks like version)
    // E.g. "12.0.1.2131" should not match (VBR version).
    if parts
        .iter()
        .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
        .count()
        >= 2
    {
        return false;
    }

    // Reject obvious file paths
    if fqdn.contains('/') || fqdn.contains('\\') {
        return false;
    }

    // Each segment must start with alphanumeric
    if !parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().next().unwrap().is_ascii_alphanumeric())
    {
        return false;
    }

    true
}

/// Validate that a captured naked username is real (not a noise word).
fn is_valid_naked_user(username: &str) -> bool {
    // Reuse the existing username validator (rejects SYSTEM, technical terms, etc.)
    if !is_valid_username(username) {
        return false;
    }

    let lower = username.to_lowercase();

    // Reject single-token English words that frequently appear after
    // "user: ", "account: ", "owner: " in logs — these are false positives.
    const NOISE_WORDS: &[&str] = &[
        // Articles / pronouns / determiners
        "the",
        "this",
        "that",
        "these",
        "those",
        "his",
        "her",
        "its",
        // Conjunctions
        "and",
        "or",
        "but",
        "nor",
        "yet",
        "so",
        "if",
        // Common verbs/auxiliaries
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "has",
        "have",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "should",
        "could",
        "may",
        "might",
        "can",
        "must",
        "shall",
        // Prepositions
        "with",
        "from",
        "into",
        "onto",
        "upon",
        "over",
        "under",
        "above",
        "below",
        "between",
        "among",
        "before",
        "after",
        "during",
        "until",
        "since",
        "through",
        "across",
        "against",
        "without",
        "within",
        "for",
        "of",
        "to",
        "in",
        "on",
        "at",
        "by",
        // Common adverbs
        "very",
        "just",
        "only",
        "also",
        "even",
        "still",
        "yet",
        "again",
        "ever",
        "never",
        "always",
        "often",
        "sometimes",
        "now",
        "then",
        "here",
        "there",
        "where",
        "when",
        "why",
        "how",
        // Boolean / status
        "true",
        "false",
        "null",
        "none",
        "yes",
        "no",
        "ok",
        "done",
        "failed",
        "success",
        "error",
        "warning",
        "info",
        "debug",
        "trace",
        // Other noise frequently after "Created by", "User:", etc.
        "name",
        "key",
        "job",
        "type",
        "value",
        "data",
        "default",
        "system",
        "all",
        "any",
        "some",
        "more",
        "less",
        "many",
        "few",
        "got",
    ];
    if NOISE_WORDS.iter().any(|&w| lower == w) {
        return false;
    }
    true
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Entity extraction
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Aggregated entities extracted from one or more files.
#[derive(Debug, Default)]
struct ExtractedEntities {
    emails: HashSet<String>,
    domain_users: HashSet<String>,
    domains: HashSet<String>,
    ips: HashSet<String>,
    naked_users: HashSet<String>,
    fqdns: HashSet<String>,
    // v2.4
    ipv6s: HashSet<String>,
    macs_colon: HashSet<String>,
    macs_compact: HashSet<String>,
    ssh_fps: HashSet<String>,
    backup_files: HashSet<String>,
}

impl ExtractedEntities {
    fn merge(&mut self, other: ExtractedEntities) {
        self.emails.extend(other.emails);
        self.domain_users.extend(other.domain_users);
        self.domains.extend(other.domains);
        self.ips.extend(other.ips);
        self.naked_users.extend(other.naked_users);
        self.fqdns.extend(other.fqdns);
        self.ipv6s.extend(other.ipv6s);
        self.macs_colon.extend(other.macs_colon);
        self.macs_compact.extend(other.macs_compact);
        self.ssh_fps.extend(other.ssh_fps);
        self.backup_files.extend(other.backup_files);
    }
}

/// Configuration for the extraction phase.
#[derive(Debug, Clone, Default)]
struct ExtractConfig {
    /// If true, extract standalone FQDNs and naked usernames.
    aggressive: bool,
    /// Explicit list of usernames (from --user-list) — always captured if present.
    user_list: HashSet<String>,
    /// Explicit list of hostnames (from --hostname-list).
    hostname_list: HashSet<String>,
    /// Explicit list of object names (from --object-list).
    object_list: HashSet<String>,
    /// Explicit list of database names (from --db-list).
    db_list: HashSet<String>,
}

/// Extract all entities from file content (v2.3 extended).
fn extract_entities(content: &str, cfg: &ExtractConfig) -> ExtractedEntities {
    let mut out = ExtractedEntities::default();

    // Extract emails
    for cap in RE_EMAIL.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let email = m.as_str().to_string();
            if is_valid_email(&email) {
                if let Some(at_pos) = email.find('@') {
                    let domain = email[at_pos + 1..].to_lowercase();
                    out.domains.insert(domain);
                }
                out.emails.insert(email.to_lowercase());
            }
        }
    }

    // Extract DOMAIN\username
    for cap in RE_DOMAIN_USER.captures_iter(content) {
        if let (Some(domain_match), Some(user_match)) = (cap.get(1), cap.get(2)) {
            let domain = domain_match.as_str();
            let username = user_match.as_str();
            // Reject when the "domain" segment is actually a file extension.
            // Backup-file paths like "disk.vib\next" or "chain.vbk\n1024" make
            // the DOMAIN\user regex fire with domain = vib/vbk/vbm/vrb/... — a
            // false positive that --paranoid then re-flags as a leak (issue #2),
            // because the backup-file stem replacement keeps the ".vib\..." tail.
            if FILE_EXTENSIONS
                .iter()
                .any(|&ext| domain.eq_ignore_ascii_case(ext))
            {
                continue;
            }
            if is_valid_username(username) {
                if let Some(full_match) = cap.get(0) {
                    out.domain_users.insert(full_match.as_str().to_string());
                }
            }
        }
    }

    // Extract local-machine user (.\username) — captures just the username part
    for cap in RE_LOCAL_USER.captures_iter(content) {
        if let Some(user_match) = cap.get(1) {
            let username = user_match.as_str().to_string();
            if is_valid_username(&username) {
                out.naked_users.insert(username.to_lowercase());
            }
        }
    }

    // Aggressive mode: naked usernames in well-known contexts
    if cfg.aggressive {
        for cap in RE_NAKED_USER.captures_iter(content) {
            if let Some(user_match) = cap.get(1) {
                let username = user_match.as_str();
                if is_valid_naked_user(username) {
                    out.naked_users.insert(username.to_lowercase());
                }
            }
        }
    }

    // User-list: every username explicitly provided. We add them to the
    // naked_users set; replacement (literal match) will catch them.
    for u in &cfg.user_list {
        out.naked_users.insert(u.to_lowercase());
    }

    // Aggressive mode: standalone FQDNs
    if cfg.aggressive {
        for cap in RE_FQDN.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let fqdn = m.as_str().to_lowercase();
                if is_valid_fqdn(&fqdn) {
                    out.fqdns.insert(fqdn);
                }
            }
        }
    }

    // Extract IPv4 addresses
    for cap in RE_IPV4.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let ip = m.as_str().to_string();
            if should_anonymize_ip(&ip) {
                out.ips.insert(ip);
            }
        }
    }

    // Extract IPv4-mapped IPv6 addresses
    for cap in RE_IPV4_MAPPED.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let ip = m.as_str().to_string();
            if should_anonymize_ip(&ip) {
                out.ips.insert(ip);
            }
        }
    }

    // ─── v2.4 detections ───────────────────────────────────────────

    // IPv6 addresses
    for m in RE_IPV6.find_iter(content) {
        let s = m.as_str();
        // Skip if it's a date/time fragment (e.g. timestamps like 12:34:56)
        // Real IPv6 has hex (a-f) OR multiple :: groups; pure decimal short
        // strings should be skipped.
        if !s.contains(':') {
            continue;
        }
        if should_anonymize_ipv6(s) {
            out.ipv6s.insert(s.to_string());
        }
    }

    // MAC addresses (colon/hyphen format)
    for m in RE_MAC_COLON.find_iter(content) {
        out.macs_colon.insert(m.as_str().to_string());
    }

    // MAC addresses (compact 12-hex, contextual)
    for cap in RE_MAC_COMPACT.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            // Reject all-zero MAC (loopback) — `000000000000`
            let mac = m.as_str();
            if mac.chars().all(|c| c == '0') {
                continue;
            }
            out.macs_compact.insert(mac.to_string());
        }
    }

    // SSH fingerprints (SHA256, MD5, public keys)
    for m in RE_SSH_FP_SHA256.find_iter(content) {
        out.ssh_fps.insert(m.as_str().to_string());
    }
    for m in RE_SSH_FP_MD5.find_iter(content) {
        out.ssh_fps.insert(m.as_str().to_string());
    }
    for m in RE_SSH_PUBKEY.find_iter(content) {
        out.ssh_fps.insert(m.as_str().to_string());
    }

    // Backup file names (.vbk/.vib/.vbm/.vrb) — keep extension
    for cap in RE_BACKUP_FILE.captures_iter(content) {
        if let (Some(stem), Some(_ext)) = (cap.get(1), cap.get(2)) {
            // Reject single-char stems or pure-digit (probably versions)
            let s = stem.as_str();
            if s.len() < 3 || s.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            // Save the FULL match (stem + ext) as the key
            out.backup_files
                .insert(cap.get(0).unwrap().as_str().to_string());
        }
    }

    // ─── Lists are NOT injected here ─────────────────────────────
    // hostname_list, object_list, db_list are applied directly at the map
    // build stage in collect_entities (literal entries; no extraction needed).

    out
}

/// Extract entities from a file's content AND its (relative) path name.
/// An email / FQDN / IP / backup-file present ONLY in a file or directory name
/// must still be detected so it can be anonymized in the output path. Short bare
/// hostnames remain non-auto-detectable by design (use --hostname-list /
/// --object-list). Shared by the filesystem scan and the `.zip` scan.
fn extract_entities_with_path(content: &str, rel: &str, cfg: &ExtractConfig) -> ExtractedEntities {
    let mut entities = extract_entities(content, cfg);
    if !rel.is_empty() {
        entities.merge(extract_entities(rel, cfg));
        // Also scan with the trailing file extension stripped: a FQDN at the end
        // of a name (host.example.com.log) would otherwise be swallowed by the
        // ".log" extension and rejected (TLD "log").
        if let Some((stem, _ext)) = rel.rsplit_once('.') {
            if stem != rel && stem.contains('.') {
                entities.merge(extract_entities(stem, cfg));
            }
        }
    }
    entities
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// File reading with encoding detection (UTF-8 / UTF-16 BOM)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Read file with encoding detection.
/// Handles UTF-8 (with/without BOM), UTF-16 LE/BE (with BOM), and lossy
/// fallback for everything else.
fn read_file_smart(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;
    Ok(decode_bytes(&bytes))
}

/// Decode a byte buffer to String with encoding detection. Handles UTF-8
/// (with/without BOM), UTF-16 LE/BE (with BOM), and lossy fallback. Shared by
/// `read_file_smart` (filesystem) and the `.zip` reader (in-memory entries).
fn decode_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    // BOM-based detection
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        // UTF-8 BOM
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        // UTF-16 LE BOM
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(&bytes[2..]);
        return cow.into_owned();
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // UTF-16 BE BOM
        let (cow, _, _) = encoding_rs::UTF_16BE.decode(&bytes[2..]);
        return cow.into_owned();
    }

    // No BOM — try UTF-8 strict, fall back to lossy
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Entity collection (parallel scan + domain consistency + exclusions)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Generate a random replacement string and guard against collisions.
/// Tries up to `max_attempts` times to produce a value not present in `used`.
/// On exhaustion, falls back to a longer string (still unique with high prob).
fn unique_random(used: &mut HashSet<String>, length: usize) -> String {
    const MAX_ATTEMPTS: usize = 16;
    for _ in 0..MAX_ATTEMPTS {
        let candidate = generate_random_string(length);
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    // Fallback: extend length until we get uniqueness
    let mut len = length + 4;
    loop {
        let candidate = generate_random_string(len);
        if used.insert(candidate.clone()) {
            return candidate;
        }
        len += 4;
    }
}

fn collect_entities(
    input_files: &[PathBuf],
    exclude: &ExcludeFilter,
    extract_cfg: &ExtractConfig,
    base_dir: Option<&Path>,
    verbose: bool,
) -> Result<AnonymizationMap> {
    let scan_bar = make_scan_bar(input_files.len() as u64);

    // Parallel scan with lock-free reduction (no Mutex contention)
    let raw: ExtractedEntities = input_files
        .par_iter()
        .progress_with(scan_bar.clone())
        .map(|file| -> ExtractedEntities {
            if verbose {
                if let Some(name) = file.file_name().and_then(|n| n.to_str()) {
                    scan_bar.set_message(name.to_string());
                }
            }
            let content = read_file_smart(file).unwrap_or_default();
            let rel = relative_path_str(file, base_dir);
            extract_entities_with_path(&content, &rel, extract_cfg)
        })
        .reduce(ExtractedEntities::default, |mut acc, item| {
            acc.merge(item);
            acc
        });

    scan_bar.finish_with_message("done");

    Ok(build_map(raw, exclude, extract_cfg))
}

/// Build the anonymization map from raw extracted entities: apply the exclusion
/// filter, then generate consistent, collision-checked replacements (domains
/// first as the single source of truth, then everything keyed off them).
/// Pure (no IO) so both the filesystem scan and the `.zip` scan reuse it.
fn build_map(
    raw: ExtractedEntities,
    exclude: &ExcludeFilter,
    extract_cfg: &ExtractConfig,
) -> AnonymizationMap {
    // Apply exclusion filter
    let emails = if exclude.process_emails() {
        raw.emails
    } else {
        if !raw.emails.is_empty() {
            eprintln!("  Skipped {} email(s) (excluded)", raw.emails.len());
        }
        HashSet::new()
    };

    let domain_users = if exclude.process_domain_users() {
        raw.domain_users
    } else {
        if !raw.domain_users.is_empty() {
            eprintln!(
                "  Skipped {} domain user(s) (excluded)",
                raw.domain_users.len()
            );
        }
        HashSet::new()
    };

    let domains = if exclude.process_domains() {
        raw.domains
    } else {
        if !raw.domains.is_empty() {
            eprintln!("  Skipped {} domain(s) (excluded)", raw.domains.len());
        }
        HashSet::new()
    };

    let ips = if exclude.process_ips() {
        raw.ips
    } else {
        if !raw.ips.is_empty() {
            eprintln!("  Skipped {} IP address(es) (excluded)", raw.ips.len());
        }
        HashSet::new()
    };

    let naked_users = if exclude.process_naked_users() {
        raw.naked_users
    } else {
        if !raw.naked_users.is_empty() {
            eprintln!(
                "  Skipped {} naked user(s) (excluded)",
                raw.naked_users.len()
            );
        }
        HashSet::new()
    };

    let fqdns = if exclude.process_fqdns() {
        raw.fqdns
    } else {
        if !raw.fqdns.is_empty() {
            eprintln!("  Skipped {} FQDN(s) (excluded)", raw.fqdns.len());
        }
        HashSet::new()
    };

    // ─── v2.4 exclusion filters ───────────────────────────────────
    let ipv6s = if exclude.process_ipv6() {
        raw.ipv6s
    } else {
        if !raw.ipv6s.is_empty() {
            eprintln!("  Skipped {} IPv6 address(es) (excluded)", raw.ipv6s.len());
        }
        HashSet::new()
    };

    let (macs_colon, macs_compact) = if exclude.process_mac() {
        (raw.macs_colon, raw.macs_compact)
    } else {
        let n = raw.macs_colon.len() + raw.macs_compact.len();
        if n > 0 {
            eprintln!("  Skipped {} MAC address(es) (excluded)", n);
        }
        (HashSet::new(), HashSet::new())
    };

    let ssh_fps = if exclude.process_ssh_fp() {
        raw.ssh_fps
    } else {
        if !raw.ssh_fps.is_empty() {
            eprintln!(
                "  Skipped {} SSH fingerprint(s) (excluded)",
                raw.ssh_fps.len()
            );
        }
        HashSet::new()
    };

    let backup_files = if exclude.process_backup_files() {
        raw.backup_files
    } else {
        if !raw.backup_files.is_empty() {
            eprintln!(
                "  Skipped {} backup file name(s) (excluded)",
                raw.backup_files.len()
            );
        }
        HashSet::new()
    };

    // Build the anonymization map with domain consistency + collision detection
    let mut map = AnonymizationMap::new();
    let mut used_domain_repls: HashSet<String> = HashSet::new();
    let mut used_email_locals: HashSet<String> = HashSet::new();
    let mut used_user_pairs: HashSet<String> = HashSet::new();
    let mut used_naked_users: HashSet<String> = HashSet::new();
    let mut used_fqdns: HashSet<String> = HashSet::new();
    let mut used_hostnames: HashSet<String> = HashSet::new();
    let mut used_objects: HashSet<String> = HashSet::new();
    let mut used_dbs: HashSet<String> = HashSet::new();
    let mut used_ssh: HashSet<String> = HashSet::new();
    let mut used_backup: HashSet<String> = HashSet::new();

    // STEP 1: Generate domain replacements FIRST (single source of truth)
    for domain in &domains {
        let body = unique_random(&mut used_domain_repls, 12);
        map.domains.insert(domain.clone(), format!("{}.com", body));
    }

    // Also extract and register parent/main domains for subdomains
    let domain_list: Vec<String> = map.domains.keys().cloned().collect();
    for domain in &domain_list {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            let main_domain = parts[parts.len() - 2..].join(".");
            map.domains.entry(main_domain).or_insert_with(|| {
                let body = unique_random(&mut used_domain_repls, 12);
                format!("{}.com", body)
            });
        }
    }

    // STEP 2: Generate email replacements USING existing domain mappings
    for email in &emails {
        if let Some(at_pos) = email.find('@') {
            let domain_part = &email[at_pos + 1..];
            let domain_replacement = if let Some(existing) = map.domains.get(domain_part) {
                existing.clone()
            } else {
                let body = unique_random(&mut used_domain_repls, 12);
                let new_domain = format!("{}.com", body);
                map.domains
                    .insert(domain_part.to_string(), new_domain.clone());
                new_domain
            };
            let local = unique_random(&mut used_email_locals, 8);
            let replacement = format!("{}@{}", local, domain_replacement);
            map.emails.insert(email.clone(), replacement);
        }
    }

    // STEP 3: Generate domain user replacements (collision-checked)
    for domain_user in &domain_users {
        let candidate = loop {
            let c = format!(
                "{}\\{}",
                generate_random_string(8),
                generate_random_string(10)
            );
            if used_user_pairs.insert(c.clone()) {
                break c;
            }
        };
        map.domain_users.insert(domain_user.clone(), candidate);
    }

    // STEP 4: Generate IP replacements
    for ip in &ips {
        let replacement = anonymize_ip(ip);
        map.ip_addresses.insert(ip.clone(), replacement);
    }

    // STEP 5: Generate naked-user replacements
    for u in &naked_users {
        let body = unique_random(&mut used_naked_users, 10);
        map.naked_users.insert(u.clone(), body);
    }

    // STEP 6: Generate FQDN replacements (reuse parent domain if known)
    for fqdn in &fqdns {
        // If a parent domain was already anonymized, reuse it for consistency
        let parts: Vec<&str> = fqdn.split('.').collect();
        let tld = parts.last().copied().unwrap_or("");
        let host_body = unique_random(&mut used_fqdns, 10);
        // Build a fresh FQDN preserving the TLD
        let replacement = format!("{}.anon.{}", host_body, tld);
        map.fqdns.insert(fqdn.clone(), replacement);
    }

    // ─── v2.4 STEPS ─────────────────────────────────────────────────

    // STEP 7: IPv6 — anonymize each occurrence; the zone identifier is
    // preserved so logical interface mapping isn't broken.
    let mut used_ipv6: HashSet<String> = HashSet::new();
    for ip in &ipv6s {
        let repl_base = anonymize_ipv6(ip);
        // Disambiguate identical replacements if collision
        let mut repl = repl_base.clone();
        let mut i = 0;
        while !used_ipv6.insert(repl.clone()) {
            i += 1;
            repl = format!("{}#{}", repl_base, i);
        }
        map.ipv6_addresses.insert(ip.clone(), repl);
    }

    // STEP 8: MAC addresses (both formats keep last byte / last 2 hex)
    let mut used_mac: HashSet<String> = HashSet::new();
    for mac in &macs_colon {
        let repl_base = anonymize_mac_colon(mac);
        let mut repl = repl_base.clone();
        let mut i = 0;
        while !used_mac.insert(repl.clone()) {
            i += 1;
            repl = format!("{}#{}", repl_base, i);
        }
        map.mac_addresses.insert(mac.clone(), repl);
    }
    for mac in &macs_compact {
        let repl_base = anonymize_mac_compact(mac);
        let mut repl = repl_base.clone();
        let mut i = 0;
        while !used_mac.insert(repl.clone()) {
            i += 1;
            repl = format!("{}#{}", repl_base, i);
        }
        map.mac_addresses.insert(mac.clone(), repl);
    }

    // STEP 9: SSH fingerprints — fully redacted, kept type prefix
    for fp in &ssh_fps {
        // Determine prefix to keep readability
        let prefix = if fp.starts_with("SHA256:") {
            "SHA256:[REDACTED]"
        } else if fp.starts_with("MD5:") {
            "MD5:[REDACTED]"
        } else if fp.starts_with("ssh-rsa") {
            "ssh-rsa [REDACTED]"
        } else if fp.starts_with("ssh-ed25519") {
            "ssh-ed25519 [REDACTED]"
        } else if fp.starts_with("ssh-dss") {
            "ssh-dss [REDACTED]"
        } else if fp.starts_with("ecdsa-") {
            "ecdsa-[REDACTED]"
        } else {
            "[REDACTED SSH KEY]"
        };
        let _ = unique_random(&mut used_ssh, 6); // bump counter
        map.ssh_fps.insert(fp.clone(), prefix.to_string());
    }

    // STEP 10: Backup file names — replace stem, keep extension.
    for fname in &backup_files {
        // Split last '.' to get stem and ext
        let (stem, ext) = match fname.rsplit_once('.') {
            Some((s, e)) => (s, e),
            None => continue,
        };
        let new_stem = unique_random(&mut used_backup, stem.len().clamp(8, 24));
        map.backup_files
            .insert(fname.clone(), format!("{}.{}", new_stem, ext));
    }

    // STEP 11: Hostnames from --hostname-list (literal entries)
    for h in &extract_cfg.hostname_list {
        if !exclude.process_hostnames() {
            continue;
        }
        let body = unique_random(&mut used_hostnames, h.len().clamp(6, 16));
        map.hostnames.insert(h.clone(), format!("host-{}", body));
    }

    // STEP 12: Object names from --object-list
    for o in &extract_cfg.object_list {
        if !exclude.process_objects() {
            continue;
        }
        let body = unique_random(&mut used_objects, o.len().clamp(8, 20));
        map.objects.insert(o.clone(), format!("obj-{}", body));
    }

    // STEP 13: DB names from --db-list
    for d in &extract_cfg.db_list {
        if !exclude.process_dbs() {
            continue;
        }
        let body = unique_random(&mut used_dbs, d.len().clamp(8, 20));
        map.dbs.insert(d.clone(), format!("db-{}", body));
    }

    map
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Replacement engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Apply all anonymization replacements to content.
///
/// Pipeline:
///   1. Mask PEM private keys (removed entirely if not excluded)
///   2. Mask PEM certificate bodies (kept BEGIN/END markers)
///   3. Mask JWT tokens
///   4. Apply literal replacements (Aho-Corasick, case-insensitive)
///
/// Aho-Corasick replaces the previous regex-alternation engine for
/// step 4 — it scales linearly with input size regardless of pattern
/// count (5-10x faster on logs with hundreds of entities).
fn apply_replacements(content: &str, map: &AnonymizationMap, exclude: &ExcludeFilter) -> String {
    // Step 1-4: regex-based preprocessing (sensitive blocks)
    let mut work = content.to_string();

    // PEM blocks (certificates, public keys). Inline JSON-escaped form
    // (literal `\n`) and multiline form are both handled by the same
    // RE_PEM_BLOCK regex; the closure distinguishes them.
    if exclude.process_pem() {
        work = RE_PEM_BLOCK
            .replace_all(&work, |caps: &regex::Captures| {
                let whole = caps.get(0).unwrap().as_str();
                let begin_type = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let end_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                // Backreference workaround: enforce type match here.
                if begin_type != end_type {
                    return whole.to_string();
                }
                // Skip private keys — handled by RE_PEM_PRIVATE_KEY below
                // (we run PEM_BLOCK before PRIVATE_KEY in this version, so
                // we must not redact private keys here or PRIVATE_KEY won't
                // see them).
                if begin_type.to_uppercase().contains("PRIVATE KEY") {
                    return whole.to_string();
                }
                // Distinguish INLINE (JSON-escaped \n, no real newline) from
                // multiline PEM. INLINE = contains "\\n" AND no real '\n'.
                let has_literal_backslash_n = whole.contains("\\n");
                let has_real_newline = whole.contains('\n');
                if has_literal_backslash_n && !has_real_newline {
                    return format!(
                        "-----BEGIN {}-----\\n[REDACTED INLINE CONTENT]\\n-----END {}-----",
                        begin_type, begin_type
                    );
                }
                format!(
                    "-----BEGIN {}-----\n[REDACTED CONTENT]\n-----END {}-----",
                    begin_type, begin_type
                )
            })
            .into_owned();
    }

    if exclude.process_private_keys() {
        work = RE_PEM_PRIVATE_KEY
            .replace_all(&work, |caps: &regex::Captures| {
                let begin_type = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let end_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if begin_type != end_type {
                    return caps.get(0).unwrap().as_str().to_string();
                }
                format!("[REDACTED {}]", begin_type)
            })
            .into_owned();
    }

    if exclude.process_jwt() {
        work = RE_JWT.replace_all(&work, "[REDACTED JWT]").into_owned();
    }

    // Step 5: literal replacements via Aho-Corasick
    let pairs = collect_replacement_pairs(map);
    apply_pairs(&work, &pairs)
}

/// Collect all (original, replacement) pairs from the map, sorted longest-first
/// to enforce maximal-munch semantics (Aho-Corasick LeftmostLongest also does this).
fn collect_replacement_pairs(map: &AnonymizationMap) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(map.total_entities());
    for (orig, anon) in &map.emails {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.domain_users {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.domains {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.ip_addresses {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.naked_users {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.fqdns {
        pairs.push((orig.clone(), anon.clone()));
    }
    // v2.4
    for (orig, anon) in &map.ipv6_addresses {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.mac_addresses {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.ssh_fps {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.backup_files {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.hostnames {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.objects {
        pairs.push((orig.clone(), anon.clone()));
    }
    for (orig, anon) in &map.dbs {
        pairs.push((orig.clone(), anon.clone()));
    }
    pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
    pairs
}

/// Collect only the (original, replacement) pairs whose replacement value is
/// safe to use inside a file or directory name. Excludes IPv4/IPv6/MAC
/// (masked forms contain `*` and `:`) and DOMAIN\user (contains `\`), all of
/// which are invalid in path components on Windows. PEM/JWT/SSH are content-only
/// and never appear in the literal map. Sorted longest-first (maximal munch).
fn collect_path_replacement_pairs(map: &AnonymizationMap) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let sections: &[&HashMap<String, String>] = &[
        &map.emails,
        &map.domains,
        &map.naked_users,
        &map.fqdns,
        &map.backup_files,
        &map.hostnames,
        &map.objects,
        &map.dbs,
    ];
    for section in sections {
        for (orig, anon) in *section {
            pairs.push((orig.clone(), anon.clone()));
        }
    }
    pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
    pairs
}

/// Apply literal replacements using Aho-Corasick (case-insensitive, leftmost-longest).
/// This is the single-pass engine; replacement values are never re-matched.
fn apply_pairs(content: &str, pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return content.to_string();
    }

    let patterns: Vec<&str> = pairs.iter().map(|(o, _)| o.as_str()).collect();
    let replacements: Vec<&str> = pairs.iter().map(|(_, r)| r.as_str()).collect();

    let ac = match AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(&patterns)
    {
        Ok(a) => a,
        Err(_) => return content.to_string(),
    };

    ac_replace_all(&ac, content, &replacements)
}

/// Helper: stream replacements through Aho-Corasick into a fresh string.
fn ac_replace_all(ac: &AhoCorasick, haystack: &str, replacements: &[&str]) -> String {
    let mut out = String::with_capacity(haystack.len());
    let mut last_end = 0usize;
    for mat in ac.find_iter(haystack) {
        out.push_str(&haystack[last_end..mat.start()]);
        out.push_str(replacements[mat.pattern().as_usize()]);
        last_end = mat.end();
    }
    out.push_str(&haystack[last_end..]);
    out
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// File processing (parallel anonymization with progress bar)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn process_files(
    input_files: &[PathBuf],
    map: &AnonymizationMap,
    exclude: &ExcludeFilter,
    cli: &Cli,
) -> Result<()> {
    let anon_bar = make_anon_bar(input_files.len() as u64);
    let output_dir = cli.require_output_dir()?;

    // Path-safe replacement pairs for anonymizing file/directory names.
    let path_pairs = collect_path_replacement_pairs(map);

    input_files
        .par_iter()
        .progress_with(anon_bar.clone())
        .try_for_each(|input_file| -> Result<()> {
            // Compute output path (preserving subdirectory structure, with
            // sensitive entities in path names anonymized unless --keep-path-names)
            let output_file = compute_output_path(input_file, output_dir, cli, &path_pairs);

            // Create parent directories if needed
            if let Some(parent) = output_file.parent() {
                if !parent.exists() && cli.force {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create directory: {}", parent.display())
                    })?;
                }
            }

            // Check overwrite protection
            if output_file.exists() && !cli.force {
                anyhow::bail!(
                    "Output file {} already exists. Use -f to overwrite.",
                    output_file.display()
                );
            }

            // Read content with encoding detection
            let content = read_file_smart(input_file)?;

            // Apply all replacements (regex preprocessing + Aho-Corasick literals)
            let anonymized = apply_replacements(&content, map, exclude);

            // Write output
            fs::write(&output_file, &anonymized)
                .with_context(|| format!("Failed to write: {}", output_file.display()))?;

            // Show filename in verbose mode
            if cli.verbose {
                if let Some(name) = input_file.file_name().and_then(|n| n.to_str()) {
                    anon_bar.set_message(name.to_string());
                }
            }

            Ok(())
        })?;

    anon_bar.finish_with_message("done");
    Ok(())
}

/// Return the path of `input_file` relative to `base_dir` as a lossy string.
/// If `base_dir` is None (single-file mode), returns just the file name.
/// Used both for scanning path names and for anonymizing the output path.
fn relative_path_str(input_file: &Path, base_dir: Option<&Path>) -> String {
    match base_dir {
        Some(base) => input_file
            .strip_prefix(base)
            .unwrap_or(input_file)
            .to_string_lossy()
            .into_owned(),
        None => input_file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
}

/// Anonymize each component of a relative path using the path-safe replacement
/// pairs, then rebuild the path. Directory and file names are both processed.
/// The `.log` extension and recognizable prefixes (Task./Agent./Svc.) survive
/// because they are not entities. Returns the relative anonymized PathBuf.
fn anonymize_relative_path(relative: &Path, path_pairs: &[(String, String)]) -> PathBuf {
    if path_pairs.is_empty() {
        return relative.to_path_buf();
    }
    let mut out = PathBuf::new();
    for component in relative.components() {
        let part = component.as_os_str().to_string_lossy();
        let anon = apply_pairs(&part, path_pairs);
        out.push(anon);
    }
    out
}

/// Compute the output file path, preserving directory structure and (unless
/// `--keep-path-names`) anonymizing sensitive entities in path components.
fn compute_output_path(
    input_file: &Path,
    output_dir: &Path,
    cli: &Cli,
    path_pairs: &[(String, String)],
) -> PathBuf {
    // Relative path under the output directory (file name in single-file mode).
    let relative: PathBuf = if let Some(ref input_dir) = cli.input_directory {
        input_file
            .strip_prefix(input_dir)
            .unwrap_or(input_file)
            .to_path_buf()
    } else {
        PathBuf::from(input_file.file_name().unwrap_or_default())
    };

    // Anonymize path components unless the user opted out.
    let relative = if cli.keep_path_names {
        relative
    } else {
        anonymize_relative_path(&relative, path_pairs)
    };

    output_dir.join(relative)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Input file collection
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn collect_input_files(cli: &Cli) -> Result<Vec<PathBuf>> {
    if let Some(ref file) = cli.input_file {
        if !file.exists() {
            anyhow::bail!("Input file does not exist: {}", file.display());
        }
        Ok(vec![file.clone()])
    } else if let Some(ref dir) = cli.input_directory {
        if !dir.is_dir() {
            anyhow::bail!("Input directory does not exist: {}", dir.display());
        }
        let files: Vec<PathBuf> = WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "log")
                    .unwrap_or(false)
            })
            .map(|e| e.into_path())
            .collect();

        if files.is_empty() {
            anyhow::bail!("No .log files found in: {}", dir.display());
        }
        Ok(files)
    } else {
        anyhow::bail!("You must specify either -i/--input or -d/--directory");
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Display functions: mapping, stats, dry-run
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn print_mapping(map: &AnonymizationMap) {
    println!();
    let sections: &[(&str, &HashMap<String, String>)] = &[
        ("Emails", &map.emails),
        ("Domain Users", &map.domain_users),
        ("Domains", &map.domains),
        ("IP Addresses", &map.ip_addresses),
        ("IPv6 Addresses", &map.ipv6_addresses),
        ("MAC Addresses", &map.mac_addresses),
        ("Naked Users", &map.naked_users),
        ("FQDNs", &map.fqdns),
        ("Hostnames", &map.hostnames),
        ("Objects", &map.objects),
        ("Databases", &map.dbs),
        ("Backup Files", &map.backup_files),
        ("SSH Fingerprints", &map.ssh_fps),
    ];
    for (label, m) in sections {
        if !m.is_empty() {
            println!("  {}:", label);
            for (orig, anon) in *m {
                println!("    {} -> {}", orig, anon);
            }
        }
    }
    println!();
}

fn print_statistics(map: &AnonymizationMap, file_count: usize, elapsed: Duration) {
    let total = map.total_entities();
    println!();
    println!("  ┌────────────────────────────────────┐");
    println!("  │       Anonymization Statistics      │");
    println!("  ├────────────────────────────────────┤");
    println!("  │  Files processed:  {:>13}  │", file_count);
    println!("  │  ─────────────────────────────────  │");
    println!("  │  Emails:           {:>13}  │", map.emails.len());
    println!("  │  Domain Users:     {:>13}  │", map.domain_users.len());
    println!("  │  Domains:          {:>13}  │", map.domains.len());
    println!("  │  IPv4 Addresses:   {:>13}  │", map.ip_addresses.len());
    println!("  │  IPv6 Addresses:   {:>13}  │", map.ipv6_addresses.len());
    println!("  │  MAC Addresses:    {:>13}  │", map.mac_addresses.len());
    println!("  │  Naked Users:      {:>13}  │", map.naked_users.len());
    println!("  │  FQDNs:            {:>13}  │", map.fqdns.len());
    println!("  │  Hostnames:        {:>13}  │", map.hostnames.len());
    println!("  │  Objects:          {:>13}  │", map.objects.len());
    println!("  │  Databases:        {:>13}  │", map.dbs.len());
    println!("  │  Backup Files:     {:>13}  │", map.backup_files.len());
    println!("  │  SSH Fingerprints: {:>13}  │", map.ssh_fps.len());
    println!("  │  ─────────────────────────────────  │");
    println!("  │  Total entities:   {:>13}  │", total);
    println!("  │  Time elapsed:     {:>10.2}s  │", elapsed.as_secs_f64());
    println!("  └────────────────────────────────────┘");
}

fn print_dry_run_report(map: &AnonymizationMap) {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║       DRY RUN — No files written     ║");
    println!("  ╚══════════════════════════════════════╝");

    let sections: &[(&str, &HashMap<String, String>)] = &[
        ("Emails", &map.emails),
        ("Domain Users", &map.domain_users),
        ("Domains", &map.domains),
        ("IP Addresses", &map.ip_addresses),
        ("IPv6 Addresses", &map.ipv6_addresses),
        ("MAC Addresses", &map.mac_addresses),
        ("Naked Users", &map.naked_users),
        ("FQDNs", &map.fqdns),
        ("Hostnames", &map.hostnames),
        ("Objects", &map.objects),
        ("Databases", &map.dbs),
        ("Backup Files", &map.backup_files),
        ("SSH Fingerprints", &map.ssh_fps),
    ];
    for (label, m) in sections {
        if !m.is_empty() {
            println!("\n  {} ({}):", label, m.len());
            for (orig, repl) in *m {
                println!("    {} -> {}", orig, repl);
            }
        }
    }

    println!(
        "\n  Total: {} entities. Re-run without --dry-run to process.",
        map.total_entities()
    );
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dictionary export & reverse anonymization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn export_dictionary(
    map: &AnonymizationMap,
    output_dir: &Path,
    file_count: usize,
    encrypt: bool,
) -> Result<PathBuf> {
    let now = Local::now();
    let base = format!("veeam-anonymizer-{}.json", now.format("%Y%m%d_%H%M%S"));

    let dict = OutputDictionary {
        metadata: DictMetadata {
            version: VERSION.to_string(),
            created_at: now.to_rfc3339(),
            files_processed: file_count,
            total_entities: map.total_entities(),
        },
        mappings: DictMappings {
            emails: to_entries(&map.emails),
            domains: to_entries(&map.domains),
            domain_users: to_entries(&map.domain_users),
            ip_addresses: to_entries(&map.ip_addresses),
            naked_users: to_entries(&map.naked_users),
            fqdns: to_entries(&map.fqdns),
            ipv6_addresses: to_entries(&map.ipv6_addresses),
            mac_addresses: to_entries(&map.mac_addresses),
            ssh_fps: to_entries(&map.ssh_fps),
            backup_files: to_entries(&map.backup_files),
            hostnames: to_entries(&map.hostnames),
            objects: to_entries(&map.objects),
            dbs: to_entries(&map.dbs),
        },
    };

    let json = serde_json::to_string_pretty(&dict)?;

    if encrypt {
        // Opt-in: encrypt the dictionary with a passphrase (age format).
        let passphrase = read_passphrase(true)?;
        let encrypted = encrypt_with_passphrase(json.as_bytes(), &passphrase)?;
        let path = output_dir.join(format!("{}.age", base));
        fs::write(&path, encrypted)?;
        println!("  🔒 Dictionary encrypted (age). Keep the passphrase safe — losing it means");
        println!("     the anonymization can never be reversed.");
        Ok(path)
    } else {
        let path = output_dir.join(&base);
        fs::write(&path, json)?;
        Ok(path)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Optional dictionary encryption (age + passphrase). Opt-in via --encrypt-dict.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Read the dictionary passphrase from the VLAR_DICT_PASSPHRASE env var (for
/// automation) or, failing that, an interactive hidden prompt. Never accepted
/// as a CLI argument (would leak via shell history / `ps`). When `confirm` is
/// set (encryption), the interactive prompt asks twice and checks they match.
fn read_passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("VLAR_DICT_PASSPHRASE") {
        if p.is_empty() {
            anyhow::bail!("VLAR_DICT_PASSPHRASE is set but empty");
        }
        return Ok(p);
    }
    let pass = rpassword::prompt_password("  Dictionary passphrase: ")
        .context("Failed to read passphrase")?;
    if pass.is_empty() {
        anyhow::bail!("Passphrase must not be empty");
    }
    if confirm {
        let again = rpassword::prompt_password("  Confirm passphrase: ")
            .context("Failed to read passphrase confirmation")?;
        if pass != again {
            anyhow::bail!("Passphrases do not match");
        }
    }
    Ok(pass)
}

/// Encrypt bytes with a scrypt passphrase using the age format.
fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    use std::io::Write;
    let secret = age::secrecy::SecretString::from(passphrase.to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to initialize age encryptor")?;
    writer
        .write_all(plaintext)
        .context("Failed to write encrypted dictionary")?;
    writer.finish().context("Failed to finalize encryption")?;
    Ok(encrypted)
}

/// Decrypt age passphrase-encrypted bytes. Returns a clear error (no panic) on
/// a wrong passphrase or malformed input.
fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let secret = age::secrecy::SecretString::from(passphrase.to_owned());
    let decryptor = age::Decryptor::new(ciphertext)
        .context("Not a valid age file (is this an encrypted dictionary?)")?;
    let identity = age::scrypt::Identity::new(secret);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase?"))?;
    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .context("Failed to read decrypted dictionary")?;
    Ok(decrypted)
}

/// Load a dictionary JSON, transparently decrypting if it is age-encrypted
/// (`.age` extension or age magic header).
fn load_dictionary(dict_path: &Path) -> Result<OutputDictionary> {
    let bytes = fs::read(dict_path)
        .with_context(|| format!("Failed to read dictionary: {}", dict_path.display()))?;
    let is_age = dict_path.extension().map(|e| e == "age").unwrap_or(false)
        || bytes.starts_with(b"age-encryption.org/");
    let json = if is_age {
        let passphrase = read_passphrase(false)?;
        let decrypted = decrypt_with_passphrase(&bytes, &passphrase)?;
        decode_bytes(&decrypted)
    } else {
        decode_bytes(&bytes)
    };
    serde_json::from_str(&json).context("Failed to parse dictionary JSON")
}

/// Convert a HashMap<String,String> into a Vec<DictEntry> for serialization.
fn to_entries(m: &HashMap<String, String>) -> Vec<DictEntry> {
    m.iter()
        .map(|(k, v)| DictEntry {
            original: k.clone(),
            anonymized: v.clone(),
        })
        .collect()
}

fn reverse_anonymize(dict_path: &Path, input_files: &[PathBuf], cli: &Cli) -> Result<()> {
    // Transparently decrypts an age-encrypted (.age) dictionary if needed.
    let dict: OutputDictionary = load_dictionary(dict_path)?;

    // Integrity check: metadata count vs actual mappings
    let actual_count = dict.mappings.emails.len()
        + dict.mappings.domains.len()
        + dict.mappings.domain_users.len()
        + dict.mappings.ip_addresses.len()
        + dict.mappings.naked_users.len()
        + dict.mappings.fqdns.len()
        + dict.mappings.ipv6_addresses.len()
        + dict.mappings.mac_addresses.len()
        + dict.mappings.ssh_fps.len()
        + dict.mappings.backup_files.len()
        + dict.mappings.hostnames.len()
        + dict.mappings.objects.len()
        + dict.mappings.dbs.len();
    if dict.metadata.total_entities != actual_count {
        eprintln!(
            "  ⚠ Dictionary integrity warning: metadata says {} entities, found {} mappings",
            dict.metadata.total_entities, actual_count
        );
    }

    // Build reverse mapping: anonymized -> original
    let mut reverse_pairs: Vec<(String, String)> = Vec::with_capacity(actual_count);

    let sections: &[&Vec<DictEntry>] = &[
        &dict.mappings.emails,
        &dict.mappings.domains,
        &dict.mappings.domain_users,
        &dict.mappings.ip_addresses,
        &dict.mappings.naked_users,
        &dict.mappings.fqdns,
        &dict.mappings.ipv6_addresses,
        &dict.mappings.mac_addresses,
        &dict.mappings.ssh_fps,
        &dict.mappings.backup_files,
        &dict.mappings.hostnames,
        &dict.mappings.objects,
        &dict.mappings.dbs,
    ];
    for section in sections {
        for entry in *section {
            // SSH fingerprints are redacted (no recoverable original).
            // Skip them in reverse to avoid '[REDACTED]' → fingerprint collisions.
            if entry.anonymized.contains("[REDACTED") {
                continue;
            }
            reverse_pairs.push((entry.anonymized.clone(), entry.original.clone()));
        }
    }

    // Sort longest first for maximal munch
    reverse_pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));

    // Detect collisions in anonymized values (would make reverse ambiguous)
    let mut seen = HashSet::new();
    for (anon, _) in &reverse_pairs {
        if !seen.insert(anon.to_lowercase()) {
            anyhow::bail!(
                "Dictionary corruption: anonymized value '{}' appears multiple times — reverse mapping is ambiguous",
                anon
            );
        }
    }

    println!("  Loaded {} mappings from dictionary", reverse_pairs.len());

    // Reverse path-safe pairs (anonymized → original) to restore the original
    // file/directory names. Mirrors collect_path_replacement_pairs: only the
    // sections whose replacement is path-safe are eligible.
    let path_safe_sections: &[&Vec<DictEntry>] = &[
        &dict.mappings.emails,
        &dict.mappings.domains,
        &dict.mappings.naked_users,
        &dict.mappings.fqdns,
        &dict.mappings.backup_files,
        &dict.mappings.hostnames,
        &dict.mappings.objects,
        &dict.mappings.dbs,
    ];
    let mut reverse_path_pairs: Vec<(String, String)> = Vec::new();
    for section in path_safe_sections {
        for entry in *section {
            if entry.anonymized.contains("[REDACTED") {
                continue;
            }
            reverse_path_pairs.push((entry.anonymized.clone(), entry.original.clone()));
        }
    }
    reverse_path_pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));

    let anon_bar = make_anon_bar(input_files.len() as u64);
    anon_bar.set_prefix("[1/1] Reversing ");
    let output_dir = cli.require_output_dir()?;

    input_files
        .par_iter()
        .progress_with(anon_bar.clone())
        .try_for_each(|input_file| -> Result<()> {
            let output_file = compute_output_path(input_file, output_dir, cli, &reverse_path_pairs);

            if let Some(parent) = output_file.parent() {
                if !parent.exists() && cli.force {
                    fs::create_dir_all(parent)?;
                }
            }

            if output_file.exists() && !cli.force {
                anyhow::bail!(
                    "Output {} exists. Use -f to overwrite.",
                    output_file.display()
                );
            }

            let content = read_file_smart(input_file)?;
            // Single-pass replacement (same engine as forward direction)
            let restored = apply_pairs(&content, &reverse_pairs);

            fs::write(&output_file, &restored)?;
            Ok(())
        })?;

    anon_bar.finish_with_message("done");
    println!("\n  Reverse anonymization complete!");
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Paranoid post-anonymization scan
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Re-scan output files for any sensitive entities the main pass might have missed.
/// Returns the count of detected leaks across all files.
/// Uses Aho-Corasick so scanning thousands of entities stays linear in file size.
fn paranoid_rescan(input_files: &[PathBuf], map: &AnonymizationMap, cli: &Cli) -> Result<usize> {
    // Build set of all original values (lowercased) we expected to remove.
    // We pre-filter values that are too short and purely alphabetic — these
    // create massive false-positive noise (e.g. "name", "key", "job", "and"
    // all match inside ordinary English words like "filename", "keyword",
    // "joblist", "command"). They are also unlikely to be sensitive on
    // their own; if the user really has a 3-letter sensitive name, they
    // should use --user-list with a longer explicit context.
    let mut originals: Vec<String> = Vec::new();
    let sections: &[&HashMap<String, String>] = &[
        &map.emails,
        &map.domain_users,
        &map.domains,
        &map.ip_addresses,
        &map.naked_users,
        &map.fqdns,
        &map.ipv6_addresses,
        &map.mac_addresses,
        &map.ssh_fps,
        &map.backup_files,
        &map.hostnames,
        &map.objects,
        &map.dbs,
    ];
    for section in sections {
        for k in section.keys() {
            let lower = k.to_lowercase();
            // Skip values too short OR purely alphabetic short words
            // (likely false positives in natural text).
            if lower.len() < 5 && lower.chars().all(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            originals.push(lower);
        }
    }

    if originals.is_empty() {
        return Ok(0);
    }

    // Build a single Aho-Corasick automaton — scanning is O(n + m) per file
    let ac = match AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(&originals)
    {
        Ok(a) => a,
        Err(_) => return Ok(0),
    };

    // Path-safe pairs are used to locate the (possibly renamed) output file.
    let path_pairs = collect_path_replacement_pairs(map);
    let output_dir = cli.require_output_dir()?;

    // Word-boundary leak scan helper, shared by content and path-name checks.
    let scan_leaks = |text: &str, sink: &mut HashSet<usize>| {
        let bytes = text.as_bytes();
        for mat in ac.find_iter(text) {
            // Require word-boundary on both sides to avoid matching
            // 'name' inside 'username', 'filename', etc.
            let start = mat.start();
            let end = mat.end();
            let left_is_boundary =
                start == 0 || !bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'_';
            let right_is_boundary =
                end == bytes.len() || !bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_';
            if left_is_boundary && right_is_boundary {
                sink.insert(mat.pattern().as_usize());
            }
        }
    };

    let total_leaks: usize = input_files
        .par_iter()
        .map(|input_file| -> usize {
            let output_file = compute_output_path(input_file, output_dir, cli, &path_pairs);

            // Check the output path NAME itself (file + directory components).
            // Catches sensitive tokens — e.g. short hostnames not provided via
            // --hostname-list — still present in a renamed path.
            let mut name_leaks: HashSet<usize> = HashSet::new();
            let rel_name = output_file
                .strip_prefix(output_dir)
                .unwrap_or(&output_file)
                .to_string_lossy();
            scan_leaks(&rel_name, &mut name_leaks);
            for &idx in &name_leaks {
                eprintln!(
                    "  ⚠ Leak detected in path name {}: '{}' still present",
                    output_file.display(),
                    originals[idx]
                );
            }

            let content = match read_file_smart(&output_file) {
                Ok(c) => c,
                Err(_) => return name_leaks.len(),
            };
            let mut leaks_in_file: HashSet<usize> = HashSet::new();
            scan_leaks(&content, &mut leaks_in_file);
            for &idx in &leaks_in_file {
                eprintln!(
                    "  ⚠ Leak detected in {}: '{}' still present",
                    output_file.display(),
                    originals[idx]
                );
            }
            leaks_in_file.len() + name_leaks.len()
        })
        .sum();

    Ok(total_leaks)
}

/// Load a one-entry-per-line list file. Ignores empty lines and `#` comments.
/// Returns lowercased entries. If `path` is None, returns an empty set.
fn load_list_file(path: &Option<PathBuf>, label: &str) -> Result<HashSet<String>> {
    match path {
        None => Ok(HashSet::new()),
        Some(p) => {
            let content = fs::read_to_string(p)
                .with_context(|| format!("Failed to read {}: {}", label, p.display()))?;
            let set: HashSet<String> = content
                .lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if !set.is_empty() {
                eprintln!("  {}: {} entries loaded", label, set.len());
            }
            Ok(set)
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main entry point
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Exit codes (deterministic, for pipeline / agent orchestration).
const EXIT_OK: i32 = 0;
const EXIT_ENTITIES_DETECTED: i32 = 2; // --validate-only found entities

fn main() {
    match run() {
        Ok(code) => {
            // Flush before exiting (process::exit does not run destructors).
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("Error: {:#}", e);
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let start = Instant::now();

    // In --validate-only the JSON report owns stdout, so all human chatter goes
    // to stderr (keeps `vlar … --validate-only | jq` clean).
    let quiet = cli.validate_only;

    // Banner
    banner_line(quiet, BANNER);
    banner_line(quiet, &format!("  v{} — Rust Edition", VERSION));
    banner_line(
        quiet,
        "  Author: Bertrand Castagnet (EMEA TAM at Veeam France)",
    );
    banner_line(
        quiet,
        "  Coverage aligned with Veeam KB2462 — https://www.veeam.com/kb2462",
    );
    banner_line(quiet, "");
    banner_line(
        quiet,
        "  ⚠ COMMUNITY PROJECT — no official Veeam support. Use at your own risk.",
    );
    banner_line(
        quiet,
        "  ⚠ Always verify anonymized output before sharing with third parties.",
    );
    banner_line(quiet, "");

    // Parse exclusion filter (fail fast on invalid types)
    let exclude = ExcludeFilter::from_strings(&cli.exclude).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    if !exclude.is_empty() {
        banner_line(
            quiet,
            &format!("  Excluding: {}\n", exclude.excluded_names().join(", ")),
        );
    }

    if cli.aggressive {
        banner_line(
            quiet,
            "  Aggressive detection: standalone FQDNs + naked usernames\n",
        );
    }

    // Load explicit lists if provided
    let user_list = load_list_file(&cli.user_list, "user list")?;
    let hostname_list = load_list_file(&cli.hostname_list, "hostname list")?;
    let object_list = load_list_file(&cli.object_list, "object list")?;
    let db_list = load_list_file(&cli.db_list, "db list")?;

    let extract_cfg = ExtractConfig {
        aggressive: cli.aggressive,
        user_list,
        hostname_list,
        object_list,
        db_list,
    };

    // ── VALIDATE-ONLY MODE ── (scan only, JSON report, deterministic exit code).
    // Checked early so stdout carries only the JSON report.
    if cli.validate_only {
        if cli.reverse.is_some() {
            anyhow::bail!("--validate-only cannot be combined with --reverse");
        }
        return run_validate_only(&cli, &exclude, &extract_cfg);
    }

    // ── ZIP INPUT ── (anonymize a .zip bundle directly)
    if cli.input_is_zip() {
        if cli.reverse.is_some() {
            anyhow::bail!("--reverse is not supported with a .zip input; extract it first.");
        }
        return run_zip(&cli, &exclude, &extract_cfg);
    }

    // Collect input files (directory / single file mode)
    let files = collect_input_files(&cli)?;
    println!("  Found {} log file(s)\n", files.len());

    // ── REVERSE MODE ──
    if let Some(ref dict_path) = cli.reverse {
        reverse_anonymize(dict_path, &files, &cli)?;
        return Ok(EXIT_OK);
    }

    let output_dir = cli.require_output_dir()?;

    // Ensure output directory exists
    if !output_dir.exists() {
        if cli.force {
            fs::create_dir_all(output_dir)
                .with_context(|| format!("Failed to create: {}", output_dir.display()))?;
        } else {
            anyhow::bail!(
                "Output directory does not exist: {}. Use -f to create it.",
                output_dir.display()
            );
        }
    }

    // Phase 1: Scan and collect entities (content + path names)
    let map = collect_entities(
        &files,
        &exclude,
        &extract_cfg,
        cli.input_directory.as_deref(),
        cli.verbose,
    )?;

    print_found_summary(&map);

    // ── DRY-RUN MODE ──
    if cli.dry_run {
        print_dry_run_report(&map);
        return Ok(EXIT_OK);
    }

    // Show mapping if requested
    if cli.mapping {
        print_mapping(&map);
    }

    // Export dictionary if requested
    if cli.dictionary {
        export_dictionary_for_cli(&map, &cli, files.len())?;
    }

    // Phase 2: Anonymize files
    process_files(&files, &map, &exclude, &cli)?;

    // Paranoid mode: re-scan output to detect leaked entities
    if cli.paranoid {
        report_paranoid(paranoid_rescan(&files, &map, &cli)?);
    }

    // Show statistics if requested
    let elapsed = start.elapsed();
    if cli.stats {
        print_statistics(&map, files.len(), elapsed);
    }

    // Summary
    println!(
        "\n  Anonymization complete: {} files, {} entities in {:.2}s",
        files.len(),
        map.total_entities(),
        elapsed.as_secs_f64()
    );
    println!("  Output: {}", output_dir.display());

    Ok(EXIT_OK)
}

/// Print a banner/info line to stdout, or to stderr when `quiet` (so that
/// --validate-only keeps stdout reserved for the JSON report).
fn banner_line(quiet: bool, line: &str) {
    if quiet {
        eprintln!("{}", line);
    } else {
        println!("{}", line);
    }
}

/// Print the "Found: N emails, …" two-line entity summary to stdout.
fn print_found_summary(map: &AnonymizationMap) {
    println!(
        "\n  Found: {} emails, {} users, {} domains, {} IPv4, {} IPv6, {} MACs",
        map.emails.len(),
        map.domain_users.len(),
        map.domains.len(),
        map.ip_addresses.len(),
        map.ipv6_addresses.len(),
        map.mac_addresses.len(),
    );
    println!(
        "         {} naked-users, {} FQDNs, {} hostnames, {} objects, {} dbs, {} backup-files, {} ssh-fps\n",
        map.naked_users.len(),
        map.fqdns.len(),
        map.hostnames.len(),
        map.objects.len(),
        map.dbs.len(),
        map.backup_files.len(),
        map.ssh_fps.len(),
    );
}

/// Print the paranoid-rescan outcome.
fn report_paranoid(leaks: usize) {
    if leaks > 0 {
        eprintln!(
            "\n  ⚠ PARANOID CHECK: {} potentially sensitive entities found in output",
            leaks
        );
        eprintln!("  ⚠ Review output before sharing. This may indicate false negatives in detection regexes.");
    } else {
        println!("\n  ✓ Paranoid check: no leaked entities detected in output.");
    }
}

/// Resolve the dictionary directory, export, and print the appropriate warning.
/// Shared by the file pipeline and the zip pipeline.
fn export_dictionary_for_cli(map: &AnonymizationMap, cli: &Cli, file_count: usize) -> Result<()> {
    // For zip output, the dictionary must land OUTSIDE the zip — default to the
    // current directory if neither --dict-output nor -o is available.
    let (dict_dir, in_output) = match (&cli.dict_output, &cli.output_directory) {
        (Some(p), _) => (p.clone(), false),
        (None, Some(o)) => (o.clone(), true),
        (None, None) => (PathBuf::from("."), false),
    };
    if !dict_dir.exists() {
        if cli.force {
            fs::create_dir_all(&dict_dir).with_context(|| {
                format!("Failed to create dict directory: {}", dict_dir.display())
            })?;
        } else {
            anyhow::bail!(
                "Dictionary directory does not exist: {}. Use -f to create it.",
                dict_dir.display()
            );
        }
    }
    let dict_path = export_dictionary(map, &dict_dir, file_count, cli.encrypt_dict)?;
    println!("  Dictionary: {}", dict_path.display());
    if in_output {
        eprintln!(
            "  ⚠ WARNING: dictionary is inside the OUTPUT directory ({}).",
            dict_dir.display()
        );
        eprintln!(
            "  ⚠ Do NOT include it in your support bundle — it can reverse the anonymization."
        );
        eprintln!("  ⚠ Use --dict-output <DIR> next time to keep it separate.\n");
    } else {
        println!();
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// --validate-only : scan, no writes, JSON report, deterministic exit code
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Serialize)]
struct ValidateReport {
    tool_version: String,
    mode: String,
    scanned_at: String,
    source: String,
    product: String,
    summary: ValidateSummary,
    by_file: Vec<FileEntities>,
}

#[derive(Serialize)]
struct ValidateSummary {
    files_scanned: usize,
    entities_total: usize,
    by_kind: std::collections::BTreeMap<String, usize>,
}

#[derive(Serialize)]
struct FileEntities {
    file: String,
    entity_count: usize,
    entities: Vec<KindCount>,
}

#[derive(Serialize)]
struct KindCount {
    kind: String,
    occurrences: usize,
}

/// Distinct count of each auto-detected kind in one file's extracted entities,
/// honoring the exclusion filter. Stable order. List-injected kinds
/// (hostname/object/db) are global, not per-file, so they're omitted here and
/// only appear in the summary.
fn kind_counts(e: &ExtractedEntities, exclude: &ExcludeFilter) -> Vec<(EntityKind, usize)> {
    let mac = e.macs_colon.len() + e.macs_compact.len();
    let candidates = [
        (EntityKind::Email, e.emails.len(), exclude.process_emails()),
        (
            EntityKind::DomainUser,
            e.domain_users.len(),
            exclude.process_domain_users(),
        ),
        (
            EntityKind::Domain,
            e.domains.len(),
            exclude.process_domains(),
        ),
        (EntityKind::Ip, e.ips.len(), exclude.process_ips()),
        (
            EntityKind::NakedUser,
            e.naked_users.len(),
            exclude.process_naked_users(),
        ),
        (EntityKind::Fqdn, e.fqdns.len(), exclude.process_fqdns()),
        (EntityKind::Ipv6, e.ipv6s.len(), exclude.process_ipv6()),
        (EntityKind::Mac, mac, exclude.process_mac()),
        (EntityKind::SshFp, e.ssh_fps.len(), exclude.process_ssh_fp()),
        (
            EntityKind::BackupFile,
            e.backup_files.len(),
            exclude.process_backup_files(),
        ),
    ];
    candidates
        .into_iter()
        .filter(|&(_, n, on)| on && n > 0)
        .map(|(k, n, _)| (k, n))
        .collect()
}

/// One scanned unit (a file on disk or a zip entry) and its extracted entities.
struct ScannedUnit {
    rel: String,
    entities: ExtractedEntities,
}

/// Build the validate-only JSON report from scanned units + the explicit lists.
fn build_validate_report(
    units: Vec<ScannedUnit>,
    exclude: &ExcludeFilter,
    cfg: &ExtractConfig,
    source: &str,
) -> ValidateReport {
    let files_scanned = units.len();

    // Per-file section.
    let mut by_file: Vec<FileEntities> = Vec::with_capacity(units.len());
    let mut union = ExtractedEntities::default();
    for unit in units {
        let counts = kind_counts(&unit.entities, exclude);
        let entity_count: usize = counts.iter().map(|(_, n)| n).sum();
        if entity_count > 0 {
            by_file.push(FileEntities {
                file: unit.rel,
                entity_count,
                entities: counts
                    .into_iter()
                    .map(|(k, n)| KindCount {
                        kind: k.to_string(),
                        occurrences: n,
                    })
                    .collect(),
            });
        }
        union.merge(unit.entities);
    }
    by_file.sort_by(|a, b| {
        b.entity_count
            .cmp(&a.entity_count)
            .then(a.file.cmp(&b.file))
    });

    // Global summary: unique auto-detected counts + explicit-list sizes.
    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (k, n) in kind_counts(&union, exclude) {
        by_kind.insert(k.to_string(), n);
    }
    if exclude.process_hostnames() && !cfg.hostname_list.is_empty() {
        by_kind.insert(EntityKind::Hostname.to_string(), cfg.hostname_list.len());
    }
    if exclude.process_objects() && !cfg.object_list.is_empty() {
        by_kind.insert(EntityKind::Object.to_string(), cfg.object_list.len());
    }
    if exclude.process_dbs() && !cfg.db_list.is_empty() {
        by_kind.insert(EntityKind::Db.to_string(), cfg.db_list.len());
    }
    let entities_total: usize = by_kind.values().sum();

    ValidateReport {
        tool_version: VERSION.to_string(),
        mode: "validate-only".to_string(),
        scanned_at: Local::now().to_rfc3339(),
        source: source.to_string(),
        product: "VBR".to_string(),
        summary: ValidateSummary {
            files_scanned,
            entities_total,
            by_kind,
        },
        by_file,
    }
}

/// `--validate-only` entry point. Scans (directory/file or zip), emits the JSON
/// report to stdout or `--report-output`, writes nothing, and returns the
/// deterministic exit code (2 if any entity detected, else 0).
fn run_validate_only(cli: &Cli, exclude: &ExcludeFilter, cfg: &ExtractConfig) -> Result<i32> {
    let (units, source) = if cli.input_is_zip() {
        let zip_path = zip_input_path(cli);
        (
            scan_zip_units(zip_path, cfg)?,
            zip_path.display().to_string(),
        )
    } else {
        let files = collect_input_files(cli)?;
        let base = cli.input_directory.as_deref();
        let units: Vec<ScannedUnit> = files
            .par_iter()
            .map(|file| {
                let content = read_file_smart(file).unwrap_or_default();
                let rel = relative_path_str(file, base);
                ScannedUnit {
                    entities: extract_entities_with_path(&content, &rel, cfg),
                    rel,
                }
            })
            .collect();
        let source = cli
            .input_directory
            .as_ref()
            .or(cli.input_file.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        (units, source)
    };

    let report = build_validate_report(units, exclude, cfg, &source);
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(path) = &cli.report_output {
        fs::write(path, &json)
            .with_context(|| format!("Failed to write report: {}", path.display()))?;
        println!("  Validation report written to {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(if report.summary.entities_total > 0 {
        EXIT_ENTITIES_DETECTED
    } else {
        EXIT_OK
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// .zip bundle input (scan + repack / extract)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Path of the `.zip` input (from -d or -i).
fn zip_input_path(cli: &Cli) -> &Path {
    cli.input_directory
        .as_deref()
        .or(cli.input_file.as_deref())
        .expect("zip input path present")
}

/// True if `p` looks like a zip (extension `.zip` or PK magic bytes).
fn path_is_zip(p: &Path) -> bool {
    if p.extension()
        .map(|e| e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
    {
        return true;
    }
    use std::io::Read;
    if let Ok(mut f) = fs::File::open(p) {
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() {
            return &magic == b"PK\x03\x04" || &magic == b"PK\x05\x06";
        }
    }
    false
}

/// Whether a zip entry name denotes a `.log` file (content gets anonymized).
fn entry_is_log(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .map(|e| e.eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

/// Anonymize a zip entry path (forward-slash separated) component-by-component.
fn anonymize_entry_name(name: &str, pairs: &[(String, String)], keep: bool) -> String {
    if keep || pairs.is_empty() {
        return name.to_string();
    }
    name.split('/')
        .map(|seg| {
            if seg.is_empty() {
                seg.to_string()
            } else {
                apply_pairs(seg, pairs)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Scan all entries of a zip into ScannedUnits (content for `.log`, path name
/// for every entry). One entry in memory at a time (memory bounded).
fn scan_zip_units(zip_path: &Path, cfg: &ExtractConfig) -> Result<Vec<ScannedUnit>> {
    use std::io::Read;
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open zip: {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Failed to read zip archive: {}", zip_path.display()))?;

    let mut units = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let content = if entry_is_log(&name) {
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut bytes)?;
            decode_bytes(&bytes)
        } else {
            String::new()
        };
        units.push(ScannedUnit {
            entities: extract_entities_with_path(&content, &name, cfg),
            rel: name,
        });
    }
    Ok(units)
}

/// Scan a zip into a raw entity set for map building (+ count of file entries).
fn scan_zip_entities(zip_path: &Path, cfg: &ExtractConfig) -> Result<(ExtractedEntities, usize)> {
    let units = scan_zip_units(zip_path, cfg)?;
    let count = units.len();
    let mut raw = ExtractedEntities::default();
    for u in units {
        raw.merge(u.entities);
    }
    Ok((raw, count))
}

/// Anonymize a `.zip` bundle: repack into `--output-zip` if set, else extract
/// into `-o DIR`. Anonymizes `.log` content and every entry name; copies other
/// entries byte-for-byte. The dictionary is never written inside the zip.
fn run_zip(cli: &Cli, exclude: &ExcludeFilter, cfg: &ExtractConfig) -> Result<i32> {
    let zip_path = zip_input_path(cli).to_path_buf();

    // Phase 1: scan
    let (raw, file_count) = scan_zip_entities(&zip_path, cfg)?;
    let map = build_map(raw, exclude, cfg);
    print_found_summary(&map);

    if cli.dry_run {
        print_dry_run_report(&map);
        return Ok(EXIT_OK);
    }
    if cli.mapping {
        print_mapping(&map);
    }
    if cli.dictionary {
        export_dictionary_for_cli(&map, cli, file_count)?;
    }

    let path_pairs = collect_path_replacement_pairs(&map);

    // Phase 2: write
    if let Some(out_zip) = &cli.output_zip {
        if out_zip.exists() && !cli.force {
            anyhow::bail!(
                "Output zip {} already exists. Use -f to overwrite.",
                out_zip.display()
            );
        }
        write_zip_output(&zip_path, out_zip, &map, exclude, &path_pairs, cli)?;
        println!("\n  Output zip: {}", out_zip.display());
    } else {
        let out_dir = cli.require_output_dir()?;
        if !out_dir.exists() {
            if cli.force {
                fs::create_dir_all(out_dir)
                    .with_context(|| format!("Failed to create: {}", out_dir.display()))?;
            } else {
                anyhow::bail!(
                    "Output directory does not exist: {}. Use -f to create it.",
                    out_dir.display()
                );
            }
        }
        extract_zip_output(&zip_path, out_dir, &map, exclude, &path_pairs, cli)?;
        println!("\n  Output: {}", out_dir.display());
    }

    if cli.paranoid {
        eprintln!("\n  ℹ --paranoid is not applied to .zip output in this version (the same");
        eprintln!("     detection engine is used; extract and re-run with -d to paranoid-check).");
    }

    Ok(EXIT_OK)
}

/// Transform one zip entry's bytes: anonymize `.log` content, copy others.
fn transform_entry(
    name: &str,
    bytes: Vec<u8>,
    map: &AnonymizationMap,
    exclude: &ExcludeFilter,
) -> Vec<u8> {
    if entry_is_log(name) {
        let content = decode_bytes(&bytes);
        apply_replacements(&content, map, exclude).into_bytes()
    } else {
        bytes
    }
}

/// Repack: read each entry, anonymize, write into a new zip preserving the
/// (anonymized) tree and last-modified timestamps. One entry at a time.
fn write_zip_output(
    zip_path: &Path,
    out_zip: &Path,
    map: &AnonymizationMap,
    exclude: &ExcludeFilter,
    path_pairs: &[(String, String)],
    cli: &Cli,
) -> Result<()> {
    use std::io::{Read, Write};
    let in_file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(in_file)?;

    if let Some(parent) = out_zip.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() && cli.force {
            fs::create_dir_all(parent)?;
        }
    }
    let out_file = fs::File::create(out_zip)
        .with_context(|| format!("Failed to create output zip: {}", out_zip.display()))?;
    let mut writer = zip::ZipWriter::new(out_file);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        let anon_name = anonymize_entry_name(&name, path_pairs, cli.keep_path_names);

        let mut options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        if let Some(mtime) = entry.last_modified() {
            options = options.last_modified_time(mtime);
        }

        if entry.is_dir() {
            writer.add_directory(anon_name, options)?;
            continue;
        }

        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        let out_bytes = transform_entry(&name, bytes, map, exclude);

        writer.start_file(anon_name, options)?;
        writer.write_all(&out_bytes)?;
    }

    writer.finish()?;
    Ok(())
}

/// Extract: write each entry anonymized into `out_dir`, preserving the
/// (anonymized) tree.
fn extract_zip_output(
    zip_path: &Path,
    out_dir: &Path,
    map: &AnonymizationMap,
    exclude: &ExcludeFilter,
    path_pairs: &[(String, String)],
    cli: &Cli,
) -> Result<()> {
    use std::io::Read;
    let in_file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(in_file)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let anon_name = anonymize_entry_name(&name, path_pairs, cli.keep_path_names);
        let out_path = out_dir.join(&anon_name);

        if let Some(parent) = out_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        if out_path.exists() && !cli.force {
            anyhow::bail!(
                "Output file {} already exists. Use -f to overwrite.",
                out_path.display()
            );
        }

        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        let out_bytes = transform_entry(&name, bytes, map, exclude);
        fs::write(&out_path, &out_bytes)
            .with_context(|| format!("Failed to write: {}", out_path.display()))?;
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Unit tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: legacy 4-tuple extraction (without aggressive/user-list).
    fn extract_legacy(
        content: &str,
    ) -> (
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
        HashSet<String>,
    ) {
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        (r.emails, r.domain_users, r.domains, r.ips)
    }

    /// Test helper: apply_replacements without exclude filter (all preprocessing enabled).
    fn apply_legacy(content: &str, map: &AnonymizationMap) -> String {
        apply_replacements(content, map, &ExcludeFilter::none())
    }

    // ── Email validation ────────────────────────────────

    #[test]
    fn email_valid_standard() {
        assert!(is_valid_email("admin@company.com"));
        assert!(is_valid_email("john.doe@example.org"));
        assert!(is_valid_email("user@mail.corp.local"));
        assert!(is_valid_email("user+tag@domain.com"));
        assert!(is_valid_email("contact@my-company.net"));
    }

    #[test]
    fn email_reject_file_paths() {
        assert!(!is_valid_email("user@file.log"));
        assert!(!is_valid_email("name@document.txt"));
        assert!(!is_valid_email("config@backup.bak"));
        assert!(!is_valid_email("data@archive.zip"));
    }

    #[test]
    fn email_reject_systemd() {
        assert!(!is_valid_email("a@domain.com")); // too short local
    }

    #[test]
    fn email_reject_no_tld() {
        assert!(!is_valid_email("user@localhost"));
    }

    #[test]
    fn email_reject_numeric_domain() {
        assert!(!is_valid_email("user@192.168.1.1"));
    }

    // ── Username validation ─────────────────────────────

    #[test]
    fn username_valid_human() {
        assert!(is_valid_username("jmousqueton"));
        assert!(is_valid_username("john.doe"));
        assert!(is_valid_username("svc_backup"));
    }

    #[test]
    fn username_reject_system() {
        assert!(!is_valid_username("SYSTEM"));
        assert!(!is_valid_username("System"));
        assert!(!is_valid_username("Administrator"));
        assert!(!is_valid_username("LocalService"));
        assert!(!is_valid_username("NetworkService"));
    }

    #[test]
    fn username_reject_browsers() {
        assert!(!is_valid_username("Chrome"));
        assert!(!is_valid_username("Firefox"));
        assert!(!is_valid_username("Edge"));
    }

    #[test]
    fn username_reject_veeam_services() {
        assert!(!is_valid_username("VeeamBackup"));
        assert!(!is_valid_username("BackupService"));
    }

    #[test]
    fn username_reject_tech_suffixes() {
        assert!(!is_valid_username("GlobalMutex"));
        assert!(!is_valid_username("AppCache"));
        assert!(!is_valid_username("WorkerService"));
    }

    #[test]
    fn username_reject_uuid() {
        assert!(!is_valid_username("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn username_reject_length() {
        assert!(!is_valid_username("ab"));
    }

    // ── IP validation ───────────────────────────────────

    #[test]
    fn ip_anonymize_private() {
        assert!(should_anonymize_ip("192.168.1.100"));
        assert!(should_anonymize_ip("10.0.0.50"));
        assert!(should_anonymize_ip("172.16.0.1"));
    }

    #[test]
    fn ip_preserve_special() {
        assert!(!should_anonymize_ip("127.0.0.1"));
        assert!(!should_anonymize_ip("7.0.0.1"));
        assert!(!should_anonymize_ip("8.0.3.0"));
        assert!(!should_anonymize_ip("169.254.1.1"));
        assert!(!should_anonymize_ip("255.255.255.255"));
        assert!(!should_anonymize_ip("0.0.0.0"));
        assert!(!should_anonymize_ip("224.0.0.1"));
        assert!(!should_anonymize_ip("239.255.255.250"));
    }

    #[test]
    fn ip_anonymization_format() {
        assert_eq!(anonymize_ip("192.168.1.100"), "**.**.1.100");
        assert_eq!(anonymize_ip("10.0.0.1"), "**.**.0.1");
    }

    // ── Exclude filter ──────────────────────────────────

    #[test]
    fn exclude_parse_single() {
        let f = ExcludeFilter::from_strings(&["email".into()]).unwrap();
        assert!(!f.process_emails());
        assert!(f.process_ips());
    }

    #[test]
    fn exclude_parse_csv() {
        let f = ExcludeFilter::from_strings(&["email,ip".into()]).unwrap();
        assert!(!f.process_emails());
        assert!(!f.process_ips());
        assert!(f.process_domains());
    }

    #[test]
    fn exclude_parse_multiple_flags() {
        let f = ExcludeFilter::from_strings(&["email".into(), "ip".into()]).unwrap();
        assert!(!f.process_emails());
        assert!(!f.process_ips());
        assert!(f.process_domains());
        assert!(f.process_domain_users());
    }

    #[test]
    fn exclude_parse_aliases() {
        let f = ExcludeFilter::from_strings(&["users,ips,emails,domains".into()]).unwrap();
        assert!(!f.process_emails());
        assert!(!f.process_ips());
        assert!(!f.process_domains());
        assert!(!f.process_domain_users());
    }

    #[test]
    fn exclude_reject_invalid() {
        let result = ExcludeFilter::from_strings(&["foobar".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn exclude_empty_processes_all() {
        let f = ExcludeFilter::none();
        assert!(f.is_empty());
        assert!(f.process_emails());
        assert!(f.process_ips());
        assert!(f.process_domains());
        assert!(f.process_domain_users());
    }

    // ── Entity extraction ───────────────────────────────

    #[test]
    fn extract_email_from_log() {
        let content = "[2025-01-01 10:00:00] Notification sent to admin@example.com";
        let (emails, _, _, _) = extract_legacy(content);
        assert!(emails.contains("admin@example.com"));
    }

    #[test]
    fn extract_domain_user_from_log() {
        let content = "[2025-01-01] CORP\\john.doe authenticated successfully";
        let (_, domain_users, _, _) = extract_legacy(content);
        assert!(domain_users
            .iter()
            .any(|u| u.to_lowercase().contains("john.doe")));
    }

    #[test]
    fn domain_user_rejects_backup_extension_false_positive() {
        // issue #2: backup-file paths like "disk.vib\next" / "chain.vbk\n1024"
        // must NOT be captured as DOMAIN\user (domain segment = file extension).
        let content = "Restore disk foo.vib\\next started; chain chain.vbk\\n1024 verified";
        let (_, domain_users, _, _) = extract_legacy(content);
        assert!(
            domain_users.is_empty(),
            "no domain users expected, got: {:?}",
            domain_users
        );
    }

    #[test]
    fn extract_ip_from_log() {
        let content = "[2025-01-01] Connected to 192.168.1.100:9392";
        let (_, _, _, ips) = extract_legacy(content);
        assert!(ips.contains("192.168.1.100"));
    }

    #[test]
    fn no_false_positive_version() {
        let content = "Veeam Backup & Replication 12.1.0.2131";
        let (emails, domain_users, _, _) = extract_legacy(content);
        assert!(emails.is_empty());
        assert!(domain_users.is_empty());
    }

    #[test]
    fn domain_extracted_from_email() {
        let content = "[2025-01-01] admin@company.com logged in";
        let (_, _, domains, _) = extract_legacy(content);
        assert!(domains.contains("company.com"));
    }

    // ── Replacement correctness ─────────────────────────

    #[test]
    fn replace_all_occurrences() {
        let content = "admin@test.com sent to admin@test.com";
        let mut map = AnonymizationMap::new();
        map.emails
            .insert("admin@test.com".into(), "anon@anon.com".into());

        let result = apply_legacy(content, &map);
        assert!(!result.contains("admin@test.com"));
        assert_eq!(result.matches("anon@anon.com").count(), 2);
    }

    #[test]
    fn replace_preserves_surrounding() {
        let content = "Connecting to [192.168.1.100]:9392 via TCP";
        let mut map = AnonymizationMap::new();
        map.ip_addresses
            .insert("192.168.1.100".into(), "**.**.1.100".into());

        let result = apply_legacy(content, &map);
        assert!(result.contains("**.**.1.100"));
        assert!(result.contains("]:9392 via TCP"));
    }

    // ── Domain consistency ──────────────────────────────

    #[test]
    fn domain_consistent_in_email_and_standalone() {
        let content = "user admin@company.com DNS: company.com";
        let (emails, _, domains, _) = extract_legacy(content);

        // Both email's domain and standalone domain should be captured
        assert!(emails.contains("admin@company.com"));
        assert!(domains.contains("company.com"));
    }

    // ── Regression tests for v2.2 critical fixes ────────

    /// Single-pass replacement: ensures a replacement value cannot be
    /// re-matched by a later case-insensitive substring rule.
    /// Bug v2.1: "abc" → "X" applied after "company.com" → "ABC123.com"
    /// would corrupt the first output.
    #[test]
    fn no_transitive_corruption_between_replacements() {
        let content = "abc and company.com";
        let mut map = AnonymizationMap::new();
        map.domains
            .insert("company.com".into(), "ABC123xyz789.com".into());
        map.domain_users.insert("abc".into(), "ZZZ".into());

        let result = apply_legacy(content, &map);
        // The substring "ABC" inside the domain replacement must NOT be
        // overwritten by the "abc" rule.
        assert!(result.contains("ABC123xyz789.com"), "Got: {}", result);
        assert!(result.contains("ZZZ"), "Got: {}", result);
    }

    /// Maximal munch: longer matches take precedence over shorter ones.
    #[test]
    fn longest_match_wins() {
        let content = "user@company.com and company.com alone";
        let mut map = AnonymizationMap::new();
        map.emails
            .insert("user@company.com".into(), "EMAIL_REPLACED".into());
        map.domains
            .insert("company.com".into(), "DOMAIN_REPLACED".into());

        let result = apply_legacy(content, &map);
        // The standalone "company.com" should be replaced as a domain,
        // but the email occurrence should be replaced as a whole email.
        assert!(result.contains("EMAIL_REPLACED"));
        assert!(result.contains("DOMAIN_REPLACED"));
        assert!(!result.contains("@company.com"));
    }

    /// Round-trip: anonymize then reverse must yield the original.
    #[test]
    fn round_trip_anonymize_then_reverse() {
        let original = "Notification sent to admin@company.com from CORP\\jdoe at 192.168.1.50";
        let (emails, domain_users, domains, ips) = extract_legacy(original);
        assert!(!emails.is_empty(), "Should detect email");

        let mut map = AnonymizationMap::new();
        for d in &domains {
            map.domains
                .insert(d.clone(), format!("anon-{}.com", d.len()));
        }
        for e in &emails {
            let dom_part = &e[e.find('@').unwrap() + 1..];
            let dom_repl = map.domains.get(dom_part).cloned().unwrap();
            map.emails
                .insert(e.clone(), format!("anonlocal@{}", dom_repl));
        }
        for u in &domain_users {
            map.domain_users
                .insert(u.clone(), "ANONDOM\\anonuser".into());
        }
        for ip in &ips {
            map.ip_addresses.insert(ip.clone(), anonymize_ip(ip));
        }

        let anonymized = apply_legacy(original, &map);
        assert!(!anonymized.contains("admin@company.com"));

        // Build reverse pairs (same as reverse_anonymize would)
        let mut reverse: Vec<(String, String)> = Vec::new();
        for (k, v) in &map.emails {
            reverse.push((v.clone(), k.clone()));
        }
        for (k, v) in &map.domains {
            reverse.push((v.clone(), k.clone()));
        }
        for (k, v) in &map.domain_users {
            reverse.push((v.clone(), k.clone()));
        }
        for (k, v) in &map.ip_addresses {
            reverse.push((v.clone(), k.clone()));
        }
        reverse.sort_by_key(|p| std::cmp::Reverse(p.0.len()));

        let restored = apply_pairs(&anonymized, &reverse);
        assert!(restored.contains("admin@company.com"), "Got: {}", restored);
        assert!(restored.contains("CORP\\jdoe"), "Got: {}", restored);
        assert!(restored.contains("192.168.1.50") || restored.contains("**.**.1.50"));
    }

    /// Internal TLDs like .local must be anonymized (regression).
    #[test]
    fn internal_tlds_are_anonymizable() {
        assert!(is_valid_email("admin@mail.corp.local"));
        assert!(is_valid_email("user@server.internal"));
    }

    /// Domain names with hyphens must match the user pattern.
    #[test]
    fn domain_user_with_hyphen() {
        let content = "[2025-01-01] MY-CORP\\john.doe authenticated";
        let (_, domain_users, _, _) = extract_legacy(content);
        assert!(
            domain_users.iter().any(|u| u.contains("john.doe")),
            "Hyphenated domain MY-CORP\\ should be captured. Got: {:?}",
            domain_users
        );
    }

    /// Collision detection: unique_random must never produce duplicates.
    #[test]
    fn unique_random_no_collisions() {
        let mut used = HashSet::new();
        // Generate 1000 distinct values
        for _ in 0..1000 {
            let v = unique_random(&mut used, 8);
            // Inserted into `used` automatically; presence check is implicit.
            assert!(!v.is_empty());
        }
        assert_eq!(used.len(), 1000);
    }

    // ── v2.3 regression tests ───────────────────────────

    /// Local-machine user `.\veeamadmin` must be detected.
    #[test]
    fn local_user_dot_backslash_detected() {
        let content = "Created by .\\veeamadmin at 17/03/2026 17:31.";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert!(
            r.naked_users.contains("veeamadmin"),
            "Expected 'veeamadmin' in naked_users, got: {:?}",
            r.naked_users
        );
    }

    /// Naked user "User: xxx" only detected in --aggressive mode.
    #[test]
    fn naked_user_requires_aggressive() {
        let content = "[User: veeamadmin][GET] request";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert!(
            !r.naked_users.contains("veeamadmin"),
            "Should NOT detect without --aggressive"
        );

        let cfg_agg = ExtractConfig {
            aggressive: true,
            user_list: HashSet::new(),
            ..Default::default()
        };
        let r2 = extract_entities(content, &cfg_agg);
        assert!(
            r2.naked_users.contains("veeamadmin"),
            "Should detect with --aggressive. Got: {:?}",
            r2.naked_users
        );
    }

    /// User list captures exact usernames regardless of context.
    #[test]
    fn user_list_captures_explicit_names() {
        let content = "Job started by bcastagnet from console";
        let mut user_list = HashSet::new();
        user_list.insert("bcastagnet".to_string());
        let cfg = ExtractConfig {
            aggressive: false,
            user_list,
            ..Default::default()
        };
        let r = extract_entities(content, &cfg);
        assert!(r.naked_users.contains("bcastagnet"));
    }

    /// FQDN detected only with --aggressive and a valid TLD.
    #[test]
    fn fqdn_aggressive_with_valid_tld() {
        let content = "Connecting to k10-route.apps.cluster.home for backup";
        let cfg_off = ExtractConfig::default();
        assert!(extract_entities(content, &cfg_off).fqdns.is_empty());

        let cfg_on = ExtractConfig {
            aggressive: true,
            user_list: HashSet::new(),
            ..Default::default()
        };
        let fqdns = extract_entities(content, &cfg_on).fqdns;
        assert!(
            fqdns.iter().any(|f| f.contains("apps.cluster.home")),
            "Expected FQDN capture. Got: {:?}",
            fqdns
        );
    }

    /// FQDN with unknown TLD must NOT be captured (false positive prevention).
    #[test]
    fn fqdn_rejects_unknown_tld() {
        let content = "some.weird.foobarbaz random text";
        let cfg = ExtractConfig {
            aggressive: true,
            user_list: HashSet::new(),
            ..Default::default()
        };
        let r = extract_entities(content, &cfg);
        assert!(
            !r.fqdns.iter().any(|f| f.contains("foobarbaz")),
            "Unknown TLD should not be captured. Got: {:?}",
            r.fqdns
        );
    }

    /// FQDN must reject version-looking strings (e.g. VBR version).
    #[test]
    fn fqdn_rejects_version_strings() {
        let content = "Veeam Backup & Replication 12.1.0.2131 detected";
        let cfg = ExtractConfig {
            aggressive: true,
            user_list: HashSet::new(),
            ..Default::default()
        };
        let r = extract_entities(content, &cfg);
        assert!(r.fqdns.is_empty(), "Got: {:?}", r.fqdns);
    }

    /// PEM certificate body must be masked, BEGIN/END kept.
    #[test]
    fn pem_certificate_body_masked() {
        let content = "Cert: -----BEGIN CERTIFICATE-----\nMIIDVzCCAj+gAwIBAgI\nbase64morelines==\n-----END CERTIFICATE-----\nDone";
        let map = AnonymizationMap::new();
        let result = apply_replacements(content, &map, &ExcludeFilter::none());
        assert!(result.contains("-----BEGIN CERTIFICATE-----"));
        assert!(result.contains("-----END CERTIFICATE-----"));
        assert!(result.contains("[REDACTED CONTENT]"));
        assert!(!result.contains("MIIDVzCCAj"));
    }

    /// PEM private key must be removed entirely (not just body).
    #[test]
    fn pem_private_key_redacted() {
        let content =
            "-----BEGIN RSA PRIVATE KEY-----\nsecretkeymaterial==\n-----END RSA PRIVATE KEY-----";
        let map = AnonymizationMap::new();
        let result = apply_replacements(content, &map, &ExcludeFilter::none());
        assert!(!result.contains("secretkeymaterial"));
        assert!(result.contains("[REDACTED"));
    }

    /// JWT tokens must be redacted by default.
    #[test]
    fn jwt_token_redacted() {
        let content = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let map = AnonymizationMap::new();
        let result = apply_replacements(content, &map, &ExcludeFilter::none());
        assert!(result.contains("[REDACTED JWT]"));
        assert!(!result.contains("eyJhbGciOiJIUzI1NiIs"));
    }

    /// Aho-Corasick engine must handle case-insensitive replacement correctly.
    #[test]
    fn ahocorasick_case_insensitive() {
        let mut map = AnonymizationMap::new();
        map.domains.insert("company.com".into(), "ANON.com".into());
        let result = apply_replacements("Visit COMPANY.COM today", &map, &ExcludeFilter::none());
        assert!(result.contains("ANON.com"));
        assert!(!result.to_lowercase().contains("company.com"));
    }

    /// PEM exclusion: when excluded, certificate bodies remain intact.
    #[test]
    fn pem_exclude_keeps_certificate() {
        let content = "-----BEGIN CERTIFICATE-----\nMIIDVzCC\n-----END CERTIFICATE-----";
        let map = AnonymizationMap::new();
        let exclude = ExcludeFilter::from_strings(&["pem".into()]).unwrap();
        let result = apply_replacements(content, &map, &exclude);
        assert!(result.contains("MIIDVzCC"));
    }

    // ── v2.4 regression tests (KB2462 coverage) ──────────

    /// IPv6 must be detected and anonymized (loopback preserved).
    #[test]
    fn ipv6_detected_and_anonymized() {
        let content = "Listening on 2a01:cb05:8c57:6800:250:56ff:fe96:aa77 and ::1";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert!(
            r.ipv6s.iter().any(|i| i.contains("2a01:cb05")),
            "Public IPv6 must be captured. Got: {:?}",
            r.ipv6s
        );
        // ::1 must be preserved (loopback)
        assert!(!r.ipv6s.iter().any(|i| i == "::1"));
    }

    /// IPv6 link-local fe80:: must NOT be anonymized.
    #[test]
    fn ipv6_link_local_preserved() {
        assert!(!should_anonymize_ipv6("fe80::250:56ff:fe96:aa77"));
        assert!(!should_anonymize_ipv6("fe80::1%eth0"));
    }

    /// IPv6 anonymization keeps last hextet for cross-reference.
    #[test]
    fn ipv6_keeps_last_hextet() {
        let result = anonymize_ipv6("2a01:cb05:8c57:6800:250:56ff:fe96:aa77");
        assert!(result.ends_with(":aa77"), "Got: {}", result);
        assert!(result.starts_with("****:"));
    }

    /// MAC address (colon) detected and anonymized.
    #[test]
    fn mac_colon_anonymized() {
        let result = anonymize_mac_colon("00:50:56:96:AA:77");
        assert_eq!(result, "**:**:**:**:**:77");
    }

    /// MAC address (compact 12-hex) detected via contextual regex.
    #[test]
    fn mac_compact_detected_with_context() {
        let content = "Physical Address. . . . : 005056962A77";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert!(
            r.macs_compact.iter().any(|m| m == "005056962A77"),
            "Got: {:?}",
            r.macs_compact
        );
    }

    /// SSH SHA256 fingerprint detected.
    #[test]
    fn ssh_sha256_fp_detected() {
        let content =
            "ECDSA key fingerprint is SHA256:1234567890abcdefghijklmnopqrstuvwxyzABCDEFG.";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert_eq!(r.ssh_fps.len(), 1, "Got: {:?}", r.ssh_fps);
    }

    /// SSH MD5 fingerprint detected.
    #[test]
    fn ssh_md5_fp_detected() {
        let content =
            "Key fingerprint: MD5:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef and stuff";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert_eq!(r.ssh_fps.len(), 1, "Got: {:?}", r.ssh_fps);
    }

    /// Backup file names are captured for .vbk/.vib/.vbm/.vrb.
    #[test]
    fn backup_file_captured() {
        let content = "Loaded job-CRM-Daily-2026-05-17.vbk and metadata.vbm";
        let cfg = ExtractConfig::default();
        let r = extract_entities(content, &cfg);
        assert!(
            r.backup_files.iter().any(|f| f.contains("job-CRM-Daily")),
            "Got: {:?}",
            r.backup_files
        );
        assert!(
            r.backup_files.iter().any(|f| f.ends_with(".vbm")),
            "metadata.vbm should be captured"
        );
    }

    /// Inline PEM (JSON-escaped \n) is redacted.
    #[test]
    fn pem_inline_json_escape_redacted() {
        let content =
            "data: \"-----BEGIN CERTIFICATE-----\\nMIIDVzCCAj\\nmorebase64==\\n-----END CERTIFICATE-----\"";
        let map = AnonymizationMap::new();
        let result = apply_replacements(content, &map, &ExcludeFilter::none());
        assert!(
            result.contains("[REDACTED INLINE CONTENT]"),
            "Got: {}",
            result
        );
        assert!(!result.contains("MIIDVzCC"));
    }

    /// IPv6 loopback and link-local stay untouched end-to-end.
    #[test]
    fn ipv6_loopback_unchanged() {
        let mut map = AnonymizationMap::new();
        // Insert a real IPv6 so the engine builds the AC
        map.ipv6_addresses.insert(
            "2001:db8::1".into(),
            "****:****:****:****:****:****:****:1".into(),
        );
        let result = apply_replacements(
            "Server on 2001:db8::1, localhost ::1, link-local fe80::1",
            &map,
            &ExcludeFilter::none(),
        );
        assert!(result.contains("::1"));
        assert!(result.contains("fe80::1"));
    }
}
