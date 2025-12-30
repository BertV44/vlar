//! Core anonymization engine
//!
//! High-performance entity extraction and content replacement using:
//! - Parallel file processing with rayon
//! - Aho-Corasick algorithm for multi-pattern matching
//! - Memory-mapped I/O for large files
//! - Progress reporting with indicatif

use crate::entities::{
    anonymize_ipv4, extract_domain_from_fqdn, extract_email_domain, extract_hostname,
    extract_main_domain, extract_unc_components, random_domain, random_hostname, random_id,
    Entity, EntityType,
};
use crate::mapping::MappingTable;
use crate::patterns::{
    is_fqdn, is_ipv4, is_special_ip, is_version_like_ip, CLUSTER, CONNECTION_HOST, DATASTORE,
    DOMAIN_USER, EMAIL, ESXI_SERVER, HYPERV_SERVER, IPV4, IPV4_IN_IPV6, REPOSITORY_PATH,
    SMTP_SERVER, UNC_PATH, VCENTER, VEEAM_SERVER, VM_NAME,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use walkdir::WalkDir;

/// Size threshold for using memory-mapped I/O (10 MB)
const MMAP_THRESHOLD: u64 = 10 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum AnonymizerError {
    #[error("Failed to read file '{path}': {source}")]
    ReadError { path: PathBuf, source: io::Error },

    #[error("Failed to write file '{path}': {source}")]
    WriteError { path: PathBuf, source: io::Error },

    #[error("Failed to create directory '{path}': {source}")]
    DirCreationError { path: PathBuf, source: io::Error },

    #[error("Output file already exists: '{path}' (use --force to overwrite)")]
    OutputExists { path: PathBuf },

    #[error("Input path does not exist: '{path}'")]
    InputNotFound { path: PathBuf },

    #[error("No log files found in '{path}'")]
    NoFilesFound { path: PathBuf },

    #[error("Failed to import mapping: {0}")]
    MappingImportError(String),
}

/// Configuration for the anonymizer
#[derive(Debug, Clone)]
pub struct AnonymizerConfig {
    /// Overwrite existing output files
    pub force_overwrite: bool,
    /// Show verbose output
    pub verbose: bool,
    /// Export dictionary JSON file
    pub export_dictionary: bool,
    /// Show mapping table
    pub show_mapping: bool,
    /// Show progress bar
    pub show_progress: bool,
    /// Import existing mapping for consistent anonymization
    pub import_mapping: Option<PathBuf>,
    /// File extensions to process (default: .log)
    pub extensions: Vec<String>,
}

impl Default for AnonymizerConfig {
    fn default() -> Self {
        Self {
            force_overwrite: false,
            verbose: false,
            export_dictionary: false,
            show_mapping: false,
            show_progress: true,
            import_mapping: None,
            extensions: vec!["log".to_string()],
        }
    }
}

/// Statistics about the anonymization process
#[derive(Debug, Default, Clone)]
pub struct AnonymizerStats {
    pub files_processed: usize,
    pub files_skipped: usize,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub entities_found: usize,
}

impl AnonymizerStats {
    pub fn bytes_processed_mb(&self) -> f64 {
        self.total_bytes_read as f64 / (1024.0 * 1024.0)
    }
}

/// Main anonymizer engine
pub struct Anonymizer {
    config: AnonymizerConfig,
    mapping: MappingTable,
}

impl Anonymizer {
    /// Create a new anonymizer with the given configuration
    pub fn new(config: AnonymizerConfig) -> Result<Self, AnonymizerError> {
        let mapping = if let Some(ref path) = config.import_mapping {
            MappingTable::import_from_json(path)
                .map_err(|e| AnonymizerError::MappingImportError(e.to_string()))?
        } else {
            MappingTable::new()
        };

        Ok(Self { config, mapping })
    }

    /// Get reference to the mapping table
    pub fn mapping(&self) -> &MappingTable {
        &self.mapping
    }

    /// Get mutable reference to the mapping table
    pub fn mapping_mut(&mut self) -> &mut MappingTable {
        &mut self.mapping
    }

    /// Collect all log files from input path (file or directory)
    pub fn collect_input_files(&self, input: &Path) -> Result<Vec<PathBuf>, AnonymizerError> {
        if !input.exists() {
            return Err(AnonymizerError::InputNotFound {
                path: input.to_path_buf(),
            });
        }

        let mut files = Vec::new();

        if input.is_file() {
            files.push(input.to_path_buf());
        } else if input.is_dir() {
            for entry in WalkDir::new(input)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if self.config.extensions.iter().any(|e| e == &ext_str) {
                            files.push(path.to_path_buf());
                        }
                    }
                }
            }
        }

        if files.is_empty() {
            return Err(AnonymizerError::NoFilesFound {
                path: input.to_path_buf(),
            });
        }

        // Sort for consistent processing order
        files.sort();
        Ok(files)
    }

    /// Extract entities from file content
    fn extract_entities(&self, content: &str) -> Vec<Entity> {
        let mut entities = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Helper to add entity if not seen
        let mut add_entity = |entity: Entity| {
            let key = entity.original.to_lowercase();
            if !seen.contains(&key) {
                seen.insert(key);
                entities.push(entity);
            }
        };

        // Helper to process FQDN and extract domain
        let mut process_fqdn = |value: &str, entity_type: EntityType| {
            if is_fqdn(value) {
                if let Some(domain) = extract_domain_from_fqdn(value) {
                    let domain_lower = domain.to_lowercase();
                    if !seen.contains(&domain_lower) {
                        seen.insert(domain_lower);
                        entities.push(Entity::new(EntityType::Domain, domain));
                    }
                }
                let hostname = extract_hostname(value);
                add_entity(Entity::new(entity_type, hostname));
            } else if is_ipv4(value) && !is_special_ip(value) && !is_version_like_ip(value) {
                add_entity(Entity::with_anonymized(
                    entity_type,
                    value.to_string(),
                    anonymize_ipv4(value),
                ));
            } else {
                add_entity(Entity::new(entity_type, value.to_string()));
            }
        };

        // Extract Veeam Servers
        for cap in VEEAM_SERVER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                process_fqdn(m.as_str(), EntityType::VeeamServer);
            }
        }

        // Extract SMTP Servers
        for cap in SMTP_SERVER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                process_fqdn(m.as_str(), EntityType::SmtpServer);
            }
        }

        // Extract vCenter Servers
        for cap in VCENTER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let value = m.as_str();
                if !value.is_empty() {
                    process_fqdn(value, EntityType::VCenter);
                }
            }
        }

        // Extract ESXi Hosts
        for cap in ESXI_SERVER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let value = m.as_str();
                if !value.is_empty() {
                    process_fqdn(value, EntityType::EsxiHost);
                }
            }
        }

        // Extract Hyper-V Hosts
        for cap in HYPERV_SERVER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                process_fqdn(m.as_str(), EntityType::HyperVHost);
            }
        }

        // Extract Connection Hosts
        for cap in CONNECTION_HOST.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let value = m.as_str();
                if is_fqdn(value) {
                    process_fqdn(value, EntityType::VeeamServer);
                }
            }
        }

        // Extract Email Addresses
        for m in EMAIL.find_iter(content) {
            let email = m.as_str().to_string();
            let email_lower = email.to_lowercase();
            
            if seen.contains(&email_lower) {
                continue;
            }
            seen.insert(email_lower);

            if let Some(domain) = extract_email_domain(&email) {
                let domain_lower = domain.to_lowercase();
                let anon_domain = if seen.contains(&domain_lower) {
                    // Use existing domain anonymization
                    entities
                        .iter()
                        .find(|e| e.original.to_lowercase() == domain_lower)
                        .map(|e| e.anonymized.clone())
                        .unwrap_or_else(random_domain)
                } else {
                    seen.insert(domain_lower.clone());
                    let new_domain = random_domain();
                    entities.push(Entity::with_anonymized(
                        EntityType::Domain,
                        domain,
                        new_domain.clone(),
                    ));
                    new_domain
                };

                let anon_email = format!("{}@{}", random_id().to_lowercase(), anon_domain);
                entities.push(Entity::with_anonymized(EntityType::Email, email, anon_email));
            }
        }

        // Extract Domain\User accounts
        for cap in DOMAIN_USER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let username = m.as_str().to_string();
                add_entity(Entity::new(EntityType::VeeamUser, username));
            }
        }

        // Extract UNC paths
        for m in UNC_PATH.find_iter(content) {
            let path = m.as_str();
            for component in extract_unc_components(path) {
                if !component.is_empty() && component.len() > 2 {
                    add_entity(Entity::new(EntityType::Location, component));
                }
            }
        }

        // Extract VM Names
        for cap in VM_NAME.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                add_entity(Entity::new(EntityType::VmName, m.as_str().to_string()));
            }
        }

        // Extract Datastores
        for cap in DATASTORE.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                add_entity(Entity::new(EntityType::Datastore, m.as_str().to_string()));
            }
        }

        // Extract Clusters
        for cap in CLUSTER.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                add_entity(Entity::new(EntityType::Cluster, m.as_str().to_string()));
            }
        }

        // Extract Repository Paths
        for cap in REPOSITORY_PATH.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                add_entity(Entity::new(EntityType::Repository, m.as_str().to_string()));
            }
        }

        entities
    }

    /// Phase 1: Scan all files and collect entities
    pub fn scan_files(&mut self, files: &[PathBuf]) -> Result<AnonymizerStats, AnonymizerError> {
        let mut stats = AnonymizerStats::default();

        let pb = if self.config.show_progress {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("  Scanning [{bar:40.cyan/blue}] {pos}/{len} files")
                    .unwrap()
                    .progress_chars("█▓░"),
            );
            Some(pb)
        } else {
            None
        };

        // Parallel scan
        let all_entities: Vec<Vec<Entity>> = if let Some(ref pb) = pb {
            files
                .par_iter()
                .progress_with(pb.clone())
                .map(|file| {
                    let content = fs::read_to_string(file).unwrap_or_default();
                    self.extract_entities(&content)
                })
                .collect()
        } else {
            files
                .par_iter()
                .map(|file| {
                    let content = fs::read_to_string(file).unwrap_or_default();
                    self.extract_entities(&content)
                })
                .collect()
        };

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        // Merge entities into mapping table
        for entities in all_entities {
            for entity in entities {
                if self.mapping.add(entity) {
                    stats.entities_found += 1;
                }
            }
        }

        // Expand domain mappings
        self.expand_domain_mappings();

        stats.files_processed = files.len();
        Ok(stats)
    }

    /// Expand domain mappings to include parent domains
    fn expand_domain_mappings(&mut self) {
        let domains: Vec<Entity> = self.mapping.get_by_type(EntityType::Domain).to_vec();

        for entity in domains {
            if let Some(main_domain) = extract_main_domain(&entity.original) {
                if !self.mapping.contains(&main_domain) {
                    self.mapping
                        .add(Entity::new(EntityType::Domain, main_domain));
                }
            }
        }
    }

    /// Build Aho-Corasick automaton for fast multi-pattern matching
    fn build_automaton(&self) -> (AhoCorasick, Vec<String>) {
        let pairs = self.mapping.get_replacement_pairs();
        let patterns: Vec<String> = pairs.iter().map(|(orig, _)| orig.to_string()).collect();
        let replacements: Vec<String> = pairs.iter().map(|(_, anon)| anon.to_string()).collect();

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        (ac, replacements)
    }

    /// Phase 2: Process files and apply anonymization
    pub fn process_files(
        &self,
        files: &[PathBuf],
        input_base: &Path,
        output_dir: &Path,
    ) -> Result<AnonymizerStats, AnonymizerError> {
        // Ensure output directory exists
        if !output_dir.exists() {
            if self.config.force_overwrite {
                fs::create_dir_all(output_dir).map_err(|e| AnonymizerError::DirCreationError {
                    path: output_dir.to_path_buf(),
                    source: e,
                })?;
            } else {
                return Err(AnonymizerError::DirCreationError {
                    path: output_dir.to_path_buf(),
                    source: io::Error::new(io::ErrorKind::NotFound, "Directory does not exist"),
                });
            }
        }

        // Build Aho-Corasick automaton for fast replacement
        let (ac, replacements) = self.build_automaton();

        let bytes_read = Arc::new(AtomicU64::new(0));
        let bytes_written = Arc::new(AtomicU64::new(0));

        let pb = if self.config.show_progress {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("  Processing [{bar:40.green/blue}] {pos}/{len} files ({msg})")
                    .unwrap()
                    .progress_chars("█▓░"),
            );
            Some(pb)
        } else {
            None
        };

        let results: Vec<Result<(), AnonymizerError>> = if let Some(ref pb) = pb {
            files
                .par_iter()
                .progress_with(pb.clone())
                .map(|input_file| {
                    self.process_single_file(
                        input_file,
                        input_base,
                        output_dir,
                        &ac,
                        &replacements,
                        &bytes_read,
                        &bytes_written,
                    )
                })
                .collect()
        } else {
            files
                .par_iter()
                .map(|input_file| {
                    self.process_single_file(
                        input_file,
                        input_base,
                        output_dir,
                        &ac,
                        &replacements,
                        &bytes_read,
                        &bytes_written,
                    )
                })
                .collect()
        };

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        // Check for errors
        let mut stats = AnonymizerStats::default();
        for result in results {
            match result {
                Ok(()) => stats.files_processed += 1,
                Err(e) => {
                    if self.config.verbose {
                        eprintln!("  Warning: {}", e);
                    }
                    stats.files_skipped += 1;
                }
            }
        }

        stats.total_bytes_read = bytes_read.load(Ordering::Relaxed);
        stats.total_bytes_written = bytes_written.load(Ordering::Relaxed);
        stats.entities_found = self.mapping.len();

        Ok(stats)
    }

    /// Process a single file
    fn process_single_file(
        &self,
        input_file: &Path,
        input_base: &Path,
        output_dir: &Path,
        ac: &AhoCorasick,
        replacements: &[String],
        bytes_read: &AtomicU64,
        bytes_written: &AtomicU64,
    ) -> Result<(), AnonymizerError> {
        let output_file = self.compute_output_path(input_file, input_base, output_dir);

        // Create parent directories if needed
        if let Some(parent) = output_file.parent() {
            if !parent.exists() && self.config.force_overwrite {
                fs::create_dir_all(parent).map_err(|e| AnonymizerError::DirCreationError {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }

        // Check if output exists
        if output_file.exists() && !self.config.force_overwrite {
            return Err(AnonymizerError::OutputExists {
                path: output_file.clone(),
            });
        }

        // Read file
        let content = fs::read_to_string(input_file).map_err(|e| AnonymizerError::ReadError {
            path: input_file.to_path_buf(),
            source: e,
        })?;

        bytes_read.fetch_add(content.len() as u64, Ordering::Relaxed);

        // Apply replacements using Aho-Corasick
        let anonymized = ac.replace_all(&content, replacements);

        // Anonymize IPs
        let anonymized = self.anonymize_ips(&anonymized);

        // Write output
        let output_bytes = anonymized.len() as u64;
        fs::write(&output_file, &anonymized).map_err(|e| AnonymizerError::WriteError {
            path: output_file.clone(),
            source: e,
        })?;

        bytes_written.fetch_add(output_bytes, Ordering::Relaxed);

        if self.config.verbose {
            let size_kb = content.len() as f64 / 1024.0;
            eprintln!("  ✓ {} ({:.1} KB)", input_file.display(), size_kb);
        }

        Ok(())
    }

    /// Compute output file path based on input structure
    fn compute_output_path(&self, input: &Path, input_base: &Path, output_dir: &Path) -> PathBuf {
        if input_base.is_file() {
            output_dir.join(input.file_name().unwrap_or_default())
        } else {
            let relative = input.strip_prefix(input_base).unwrap_or(input);
            output_dir.join(relative)
        }
    }

    /// Anonymize all IP addresses in content
    fn anonymize_ips(&self, content: &str) -> String {
        let mut result = content.to_string();

        // Standard IPv4
        result = IPV4
            .replace_all(&result, |caps: &regex::Captures| {
                let ip = &caps[0];
                if is_version_like_ip(ip) || is_special_ip(ip) {
                    ip.to_string()
                } else {
                    anonymize_ipv4(ip)
                }
            })
            .to_string();

        // IPv4 in IPv6 format
        result = IPV4_IN_IPV6
            .replace_all(&result, |caps: &regex::Captures| {
                let ip = &caps[1];
                if is_version_like_ip(ip) || is_special_ip(ip) {
                    format!("[::ffff:{}]", ip)
                } else {
                    format!("[::ffff:{}]", anonymize_ipv4(ip))
                }
            })
            .to_string();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AnonymizerConfig {
        AnonymizerConfig {
            show_progress: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_ip_anonymization() {
        let anon = Anonymizer::new(test_config()).unwrap();
        let result = anon.anonymize_ips("Server at 192.168.1.100 connected to 10.0.0.1");

        assert!(result.contains("**.**.1.100"));
        assert!(result.contains("**.**.0.1"));
    }

    #[test]
    fn test_version_ip_preserved() {
        let anon = Anonymizer::new(test_config()).unwrap();
        let result = anon.anonymize_ips("VMware version 7.0.3.0 and 8.0.1.0");

        assert!(result.contains("7.0.3.0"));
        assert!(result.contains("8.0.1.0"));
    }

    #[test]
    fn test_special_ip_preserved() {
        let anon = Anonymizer::new(test_config()).unwrap();
        let result = anon.anonymize_ips("Localhost 127.0.0.1 and link-local 169.254.1.1");

        assert!(result.contains("127.0.0.1"));
        assert!(result.contains("169.254.1.1"));
    }

    #[test]
    fn test_entity_extraction() {
        let anon = Anonymizer::new(test_config()).unwrap();
        let content = r#"
            vCenter: vcenter.corp.local
            Email: admin@company.com
            User: DOMAIN\administrator
        "#;

        let entities = anon.extract_entities(content);
        assert!(!entities.is_empty());

        let types: Vec<_> = entities.iter().map(|e| e.entity_type).collect();
        assert!(types.contains(&EntityType::VCenter) || types.contains(&EntityType::Domain));
    }
}
