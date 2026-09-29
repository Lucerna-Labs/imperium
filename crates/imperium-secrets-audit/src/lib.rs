use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub secret_id: String,
    pub action: AuditAction,
    pub subsystem: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditAction {
    Read,
    Write,
    Delete,
}
