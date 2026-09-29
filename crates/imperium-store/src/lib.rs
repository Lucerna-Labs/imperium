use std::collections::HashMap;
use std::path::PathBuf;

use parking_lot::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Store {
    data: RwLock<HashMap<String, Vec<u8>>>,
    _path: Option<PathBuf>,
}

impl Store {
    pub fn in_memory() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            _path: None,
        }
    }

    pub fn open(_path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Ok(Self::in_memory())
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.data
            .read()
            .get(key)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(key.to_string()))
    }

    pub fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.data.write().insert(key.to_string(), value);
        Ok(())
    }

    pub fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.data.write().remove(key);
        Ok(())
    }

    pub fn exists(&self, key: &str) -> bool {
        self.data.read().contains_key(key)
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::in_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn put_and_get() {
        let store = Store::in_memory();
        store.put("key1", b"value1".to_vec()).unwrap();
        let val = store.get("key1").unwrap();
        assert_eq!(val, b"value1");
    }

    #[test]
    fn get_missing_key_returns_not_found() {
        let store = Store::in_memory();
        let err = store.get("nonexistent").unwrap_err();
        match err {
            StoreError::NotFound(k) => assert_eq!(k, "nonexistent"),
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    #[test]
    fn put_overwrites_existing() {
        let store = Store::in_memory();
        store.put("k", b"v1".to_vec()).unwrap();
        store.put("k", b"v2".to_vec()).unwrap();
        assert_eq!(store.get("k").unwrap(), b"v2");
    }

    #[test]
    fn delete_removes_key() {
        let store = Store::in_memory();
        store.put("k", b"v".to_vec()).unwrap();
        assert!(store.exists("k"));
        store.delete("k").unwrap();
        assert!(!store.exists("k"));
        assert!(store.get("k").is_err());
    }

    #[test]
    fn delete_nonexistent_is_noop() {
        let store = Store::in_memory();
        store.delete("ghost").unwrap();
    }

    #[test]
    fn exists_reflects_state() {
        let store = Store::in_memory();
        assert!(!store.exists("k"));
        store.put("k", vec![]).unwrap();
        assert!(store.exists("k"));
        store.delete("k").unwrap();
        assert!(!store.exists("k"));
    }

    #[test]
    fn empty_value_roundtrip() {
        let store = Store::in_memory();
        store.put("empty", vec![]).unwrap();
        assert_eq!(store.get("empty").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn large_value_roundtrip() {
        let store = Store::in_memory();
        let big = vec![0xABu8; 1_000_000];
        store.put("big", big.clone()).unwrap();
        assert_eq!(store.get("big").unwrap(), big);
    }

    #[test]
    fn open_returns_working_store() {
        let store = Store::open("fake/path").unwrap();
        store.put("k", b"v".to_vec()).unwrap();
        assert_eq!(store.get("k").unwrap(), b"v");
    }

    #[test]
    fn default_is_in_memory() {
        let store = Store::default();
        store.put("k", b"v".to_vec()).unwrap();
        assert_eq!(store.get("k").unwrap(), b"v");
    }

    #[test]
    fn concurrent_reads_and_writes() {
        let store = Arc::new(Store::in_memory());
        let mut handles = vec![];

        for i in 0..4 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let key = format!("t{}-k{}", i, j);
                    store.put(&key, vec![i as u8, j as u8]).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        for i in 0..4u8 {
            for j in 0..100u8 {
                let key = format!("t{}-k{}", i, j);
                assert_eq!(store.get(&key).unwrap(), vec![i, j]);
            }
        }
    }

    #[test]
    fn concurrent_delete_while_reading() {
        let store = Arc::new(Store::in_memory());
        for i in 0..100 {
            store.put(&format!("k{}", i), vec![i as u8]).unwrap();
        }

        let store2 = Arc::clone(&store);
        let deleter = thread::spawn(move || {
            for i in 0..100 {
                store2.delete(&format!("k{}", i)).unwrap();
            }
        });

        let store3 = Arc::clone(&store);
        let reader = thread::spawn(move || {
            for i in 0..100 {
                let _ = store3.get(&format!("k{}", i));
            }
        });

        deleter.join().unwrap();
        reader.join().unwrap();

        for i in 0..100 {
            assert!(!store.exists(&format!("k{}", i)));
        }
    }
}
