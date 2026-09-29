use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("signature not found: {0}")]
    NotFound(String),
    #[error("integrity check failed: expected {expected}, got {actual}")]
    IntegrityFailed { expected: String, actual: String },
    #[error("duplicate signature: {0}")]
    Duplicate(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureProvenance {
    Bundled,
    Extracted {
        extracted_at: DateTime<Utc>,
        approved_by: String,
    },
}

#[derive(Clone, Debug)]
pub struct SignatureEntry {
    pub id: String,
    pub rule_text: String,
    pub description: String,
    pub provenance: SignatureProvenance,
    pub added_at: DateTime<Utc>,
    pub active: bool,
}

pub struct SignatureDatabase {
    bundled: Arc<RwLock<HashMap<String, SignatureEntry>>>,
    extracted: Arc<RwLock<HashMap<String, SignatureEntry>>>,
    archived: Arc<RwLock<HashMap<String, SignatureEntry>>>,
    bundled_hash: Arc<RwLock<String>>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self {
            bundled: Arc::new(RwLock::new(HashMap::new())),
            extracted: Arc::new(RwLock::new(HashMap::new())),
            archived: Arc::new(RwLock::new(HashMap::new())),
            bundled_hash: Arc::new(RwLock::new(String::new())),
        }
    }

    pub fn load_bundled(&self, entries: Vec<SignatureEntry>) {
        let mut hasher = Sha256::new();
        let mut bundled = self.bundled.write();
        bundled.clear();

        for entry in entries {
            hasher.update(entry.rule_text.as_bytes());
            bundled.insert(entry.id.clone(), entry);
        }

        *self.bundled_hash.write() = format!("{:x}", hasher.finalize());
    }

    pub fn bundled_hash(&self) -> String {
        self.bundled_hash.read().clone()
    }

    pub fn add_extracted(&self, entry: SignatureEntry) -> Result<(), DatabaseError> {
        let mut extracted = self.extracted.write();
        if extracted.contains_key(&entry.id) {
            return Err(DatabaseError::Duplicate(entry.id));
        }
        extracted.insert(entry.id.clone(), entry);
        Ok(())
    }

    pub fn rollback_extracted(&self, id: &str) -> Result<(), DatabaseError> {
        let mut extracted = self.extracted.write();
        let entry = extracted
            .remove(id)
            .ok_or_else(|| DatabaseError::NotFound(id.to_string()))?;
        self.archived.write().insert(id.to_string(), entry);
        Ok(())
    }

    pub fn get_all_active(&self) -> Vec<SignatureEntry> {
        let mut all = Vec::new();
        for entry in self.bundled.read().values() {
            if entry.active {
                all.push(entry.clone());
            }
        }
        for entry in self.extracted.read().values() {
            if entry.active {
                all.push(entry.clone());
            }
        }
        all
    }

    pub fn bundled_count(&self) -> usize {
        self.bundled.read().len()
    }

    pub fn extracted_count(&self) -> usize {
        self.extracted.read().len()
    }

    pub fn archived_count(&self) -> usize {
        self.archived.read().len()
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(id: &str) -> SignatureEntry {
        SignatureEntry {
            id: id.to_string(),
            rule_text: r#"rule test { strings: $a = { DE AD } condition: $a }"#.into(),
            description: "test signature".into(),
            provenance: SignatureProvenance::Bundled,
            added_at: Utc::now(),
            active: true,
        }
    }

    #[test]
    fn load_bundled_computes_hash() {
        let db = SignatureDatabase::new();
        db.load_bundled(vec![test_entry("b1"), test_entry("b2")]);
        assert_eq!(db.bundled_count(), 2);
        assert!(!db.bundled_hash().is_empty());
    }

    #[test]
    fn extracted_separate_from_bundled() {
        let db = SignatureDatabase::new();
        db.load_bundled(vec![test_entry("b1")]);

        let extracted = SignatureEntry {
            id: "e1".into(),
            provenance: SignatureProvenance::Extracted {
                extracted_at: Utc::now(),
                approved_by: "operator".into(),
            },
            ..test_entry("e1")
        };
        db.add_extracted(extracted).unwrap();

        assert_eq!(db.bundled_count(), 1);
        assert_eq!(db.extracted_count(), 1);
        assert_eq!(db.get_all_active().len(), 2);
    }

    #[test]
    fn rollback_moves_to_archive() {
        let db = SignatureDatabase::new();
        let extracted = SignatureEntry {
            id: "e1".into(),
            provenance: SignatureProvenance::Extracted {
                extracted_at: Utc::now(),
                approved_by: "operator".into(),
            },
            ..test_entry("e1")
        };
        db.add_extracted(extracted).unwrap();
        assert_eq!(db.extracted_count(), 1);

        db.rollback_extracted("e1").unwrap();
        assert_eq!(db.extracted_count(), 0);
        assert_eq!(db.archived_count(), 1);
    }

    #[test]
    fn duplicate_extracted_rejected() {
        let db = SignatureDatabase::new();
        let entry = SignatureEntry {
            id: "e1".into(),
            provenance: SignatureProvenance::Extracted {
                extracted_at: Utc::now(),
                approved_by: "op".into(),
            },
            ..test_entry("e1")
        };
        db.add_extracted(entry.clone()).unwrap();
        assert!(db.add_extracted(entry).is_err());
    }
}
