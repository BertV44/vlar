//! # Veeam Log Anonymizer
//!
//! A high-performance log anonymization library for Veeam Backup & Replication logs.
//!
//! ## Features
//!
//! - **Parallel Processing**: Uses rayon for multi-threaded file processing
//! - **Fast Pattern Matching**: Aho-Corasick algorithm for efficient multi-pattern replacement
//! - **Smart Entity Detection**: Recognizes servers, emails, domains, IPs, paths, and more
//! - **Case Preservation**: Maintains original case patterns during replacement
//! - **Consistent Anonymization**: Same input always produces same output within a session
//!
//! ## Example
//!
//! ```no_run
//! use veeam_log_anonymizer::{Anonymizer, AnonymizerConfig};
//! use std::path::Path;
//!
//! let config = AnonymizerConfig {
//!     force_overwrite: true,
//!     verbose: false,
//!     show_progress: true,
//!     ..Default::default()
//! };
//!
//! let mut anonymizer = Anonymizer::new(config).unwrap();
//! let files = anonymizer.collect_input_files(Path::new("/logs")).unwrap();
//! anonymizer.scan_files(&files).unwrap();
//! anonymizer.process_files(&files, Path::new("/logs"), Path::new("/output")).unwrap();
//!
//! // Access the mapping table
//! println!("Anonymized {} entities", anonymizer.mapping().len());
//! ```

pub mod anonymizer;
pub mod entities;
pub mod mapping;
pub mod patterns;

// Re-export main types for convenience
pub use anonymizer::{Anonymizer, AnonymizerConfig, AnonymizerError, AnonymizerStats};
pub use entities::{Entity, EntityType};
pub use mapping::MappingTable;
