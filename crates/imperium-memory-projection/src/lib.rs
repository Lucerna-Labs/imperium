use std::sync::Arc;

use imperium_memory_log::MemoryLog;

pub struct ProjectionEngine {
    _log: Arc<MemoryLog>,
}

impl ProjectionEngine {
    pub fn new(log: Arc<MemoryLog>) -> Self {
        Self { _log: log }
    }
}
