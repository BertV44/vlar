//! Mapping table management for tracking original -> anonymized values

use crate::entities::{Entity, EntityType};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MappingError {
    #[error("Failed to write mapping file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to serialize mapping: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// A single mapping entry for JSON export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingEntry {
    pub original: String,
    pub anonymized: String,
}

/// Metadata about the anonymization run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingMetadata {
    pub version: String,
    pub created_at: String,
    pub files_processed: usize,
    pub total_entities: usize,
}

/// Full export structure for JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingExport {
    pub metadata: MappingMetadata,
    pub mappings: BTreeMap<String, Vec<MappingEntry>>,
}

/// Collection of all anonymization mappings
#[derive(Debug, Default)]
pub struct MappingTable {
    /// Maps entity type to list of entities
    by_type: HashMap<EntityType, Vec<Entity>>,

    /// Quick lookup: original value (lowercase) -> anonymized value
    lookup: HashMap<String, String>,

    /// Track seen originals to avoid duplicates (case-insensitive)
    seen: HashSet<String>,
}

impl MappingTable {
    /// Create a new empty mapping table
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entity to the mapping table
    /// Returns true if this was a new entry, false if it already existed
    pub fn add(&mut self, entity: Entity) -> bool {
        let key = entity.original.to_lowercase();
        
        if self.seen.contains(&key) {
            return false;
        }

        self.seen.insert(key.clone());
        self.lookup.insert(key, entity.anonymized.clone());
        self.by_type
            .entry(entity.entity_type)
            .or_default()
            .push(entity);
        true
    }

    /// Add entity only if original doesn't exist (case-insensitive)
    pub fn add_if_new(&mut self, entity: Entity) -> bool {
        if self.contains(&entity.original) {
            false
        } else {
            self.add(entity)
        }
    }

    /// Get the anonymized value for an original value (case-insensitive)
    pub fn get_anonymized(&self, original: &str) -> Option<&String> {
        self.lookup.get(&original.to_lowercase())
    }

    /// Check if an original value exists in the mapping (case-insensitive)
    pub fn contains(&self, original: &str) -> bool {
        self.seen.contains(&original.to_lowercase())
    }

    /// Get all entities of a specific type
    pub fn get_by_type(&self, entity_type: EntityType) -> &[Entity] {
        self.by_type
            .get(&entity_type)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all mappings for iteration
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.by_type.values().flatten()
    }

    /// Get count of all entities
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Get statistics by entity type
    pub fn stats(&self) -> BTreeMap<EntityType, usize> {
        self.by_type
            .iter()
            .map(|(k, v)| (*k, v.len()))
            .collect()
    }

    /// Get all original -> anonymized pairs sorted for replacement
    /// (longer strings first to avoid partial replacements)
    pub fn get_replacement_pairs(&self) -> Vec<(&str, &str)> {
        let mut pairs: Vec<_> = self.by_type
            .values()
            .flatten()
            .map(|e| (e.original.as_str(), e.anonymized.as_str()))
            .collect();

        // Sort by length descending
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        pairs
    }

    /// Print mapping table to stdout with formatting
    pub fn print_mapping(&self) {
        let mut types: Vec<_> = self.by_type.keys().collect();
        types.sort_by_key(|t| t.display_order());

        for entity_type in types {
            let entities = self.get_by_type(*entity_type);
            if !entities.is_empty() {
                println!("\n  {}:", entity_type);
                for entity in entities {
                    println!("    {} → {}", entity.original, entity.anonymized);
                }
            }
        }
    }

    /// Print summary statistics
    pub fn print_stats(&self) {
        let stats = self.stats();
        let mut types: Vec<_> = stats.keys().collect();
        types.sort_by_key(|t| t.display_order());

        println!("\n  Entity Statistics:");
        for entity_type in types {
            if let Some(count) = stats.get(entity_type) {
                println!("    {}: {}", entity_type, count);
            }
        }
        println!("    ─────────────────");
        println!("    Total: {}", self.len());
    }

    /// Export mapping table to JSON file
    pub fn export_to_json(
        &self,
        path: &Path,
        files_processed: usize,
    ) -> Result<(), MappingError> {
        let mut mappings: BTreeMap<String, Vec<MappingEntry>> = BTreeMap::new();

        let mut types: Vec<_> = self.by_type.keys().collect();
        types.sort_by_key(|t| t.display_order());

        for entity_type in types {
            let entities = self.get_by_type(*entity_type);
            if !entities.is_empty() {
                let entries: Vec<MappingEntry> = entities
                    .iter()
                    .map(|e| MappingEntry {
                        original: e.original.clone(),
                        anonymized: e.anonymized.clone(),
                    })
                    .collect();
                mappings.insert(entity_type.json_key().to_string(), entries);
            }
        }

        let export = MappingExport {
            metadata: MappingMetadata {
                version: env!("CARGO_PKG_VERSION").to_string(),
                created_at: chrono::Local::now().to_rfc3339(),
                files_processed,
                total_entities: self.len(),
            },
            mappings,
        };

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &export)?;

        Ok(())
    }

    /// Import mappings from a JSON file (for consistent re-anonymization)
    pub fn import_from_json(path: &Path) -> Result<Self, MappingError> {
        let file = File::open(path)?;
        let export: MappingExport = serde_json::from_reader(file)?;
        
        let mut table = Self::new();
        
        for (type_key, entries) in export.mappings {
            let entity_type = match type_key.as_str() {
                "veeam_servers" => EntityType::VeeamServer,
                "user_accounts" => EntityType::VeeamUser,
                "smtp_servers" => EntityType::SmtpServer,
                "vcenter_servers" => EntityType::VCenter,
                "esxi_hosts" => EntityType::EsxiHost,
                "hyperv_hosts" => EntityType::HyperVHost,
                "domains" => EntityType::Domain,
                "email_addresses" => EntityType::Email,
                "locations" => EntityType::Location,
                "vm_names" => EntityType::VmName,
                "datastores" => EntityType::Datastore,
                "clusters" => EntityType::Cluster,
                "repositories" => EntityType::Repository,
                "network_servers" => EntityType::UncServer,
                _ => continue,
            };

            for entry in entries {
                table.add(Entity::with_anonymized(
                    entity_type,
                    entry.original,
                    entry.anonymized,
                ));
            }
        }

        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_table_add() {
        let mut table = MappingTable::new();
        let entity = Entity::new(EntityType::VeeamUser, "admin".to_string());

        assert!(table.add(entity.clone()));
        assert!(!table.add(entity)); // Duplicate
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let mut table = MappingTable::new();
        table.add(Entity::with_anonymized(
            EntityType::VeeamUser,
            "Admin".to_string(),
            "anon123".to_string(),
        ));

        assert!(table.contains("admin"));
        assert!(table.contains("ADMIN"));
        assert!(table.contains("Admin"));
        assert_eq!(table.get_anonymized("admin"), Some(&"anon123".to_string()));
    }

    #[test]
    fn test_replacement_pairs_ordering() {
        let mut table = MappingTable::new();
        table.add(Entity::with_anonymized(
            EntityType::Domain,
            "a.com".to_string(),
            "x".to_string(),
        ));
        table.add(Entity::with_anonymized(
            EntityType::Domain,
            "sub.a.com".to_string(),
            "y".to_string(),
        ));

        let pairs = table.get_replacement_pairs();
        assert_eq!(pairs[0].0, "sub.a.com"); // Longer first
        assert_eq!(pairs[1].0, "a.com");
    }

    #[test]
    fn test_stats() {
        let mut table = MappingTable::new();
        table.add(Entity::new(EntityType::VeeamUser, "user1".to_string()));
        table.add(Entity::new(EntityType::VeeamUser, "user2".to_string()));
        table.add(Entity::new(EntityType::Domain, "example.com".to_string()));

        let stats = table.stats();
        assert_eq!(stats.get(&EntityType::VeeamUser), Some(&2));
        assert_eq!(stats.get(&EntityType::Domain), Some(&1));
    }
}
