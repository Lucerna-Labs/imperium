use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault sealed")]
    Sealed,
    #[error("store error: {0}")]
    Store(#[from] imperium_store::StoreError),
}

pub struct SecretId(pub String);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretValue(pub Vec<u8>);

pub struct Vault {
    store: imperium_store::Store,
    sealed: bool,
}

impl Vault {
    pub fn new(store: imperium_store::Store) -> Self {
        Self {
            store,
            sealed: false,
        }
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub fn unseal(&mut self) {
        self.sealed = false;
    }

    pub fn get(&self, id: &SecretId) -> Result<SecretValue, VaultError> {
        if self.sealed {
            return Err(VaultError::Sealed);
        }
        let bytes = self.store.get(&id.0)?;
        Ok(SecretValue(bytes))
    }

    pub fn put(&self, id: &SecretId, value: &SecretValue) -> Result<(), VaultError> {
        if self.sealed {
            return Err(VaultError::Sealed);
        }
        self.store.put(&id.0, value.0.clone())?;
        Ok(())
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_store::Store;

    fn vault() -> Vault {
        Vault::new(Store::in_memory())
    }

    fn id(s: &str) -> SecretId {
        SecretId(s.to_string())
    }

    fn secret(data: &[u8]) -> SecretValue {
        SecretValue(data.to_vec())
    }

    #[test]
    fn put_and_get() {
        let v = vault();
        v.put(&id("key"), &secret(b"hunter2")).unwrap();
        let got = v.get(&id("key")).unwrap();
        assert_eq!(got.0, b"hunter2");
    }

    #[test]
    fn get_missing_returns_error() {
        let v = vault();
        match v.get(&id("nope")) {
            Err(VaultError::Store(imperium_store::StoreError::NotFound(k))) => {
                assert_eq!(k, "nope");
            }
            Err(other) => panic!("expected Store(NotFound), got: {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn sealed_vault_rejects_get() {
        let mut v = vault();
        v.put(&id("k"), &secret(b"v")).unwrap();
        v.seal();
        match v.get(&id("k")) {
            Err(VaultError::Sealed) => {}
            Err(other) => panic!("expected Sealed, got: {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn sealed_vault_rejects_put() {
        let mut v = vault();
        v.seal();
        let err = v.put(&id("k"), &secret(b"v")).unwrap_err();
        assert!(matches!(err, VaultError::Sealed));
    }

    #[test]
    fn unseal_restores_access() {
        let mut v = vault();
        v.put(&id("k"), &secret(b"v")).unwrap();
        v.seal();
        assert!(v.get(&id("k")).is_err());
        v.unseal();
        assert_eq!(v.get(&id("k")).unwrap().0, b"v");
    }

    #[test]
    fn seal_unseal_state_tracking() {
        let mut v = vault();
        assert!(!v.is_sealed());
        v.seal();
        assert!(v.is_sealed());
        v.unseal();
        assert!(!v.is_sealed());
    }

    #[test]
    fn double_seal_is_idempotent() {
        let mut v = vault();
        v.seal();
        v.seal();
        assert!(v.is_sealed());
        v.unseal();
        assert!(!v.is_sealed());
    }

    #[test]
    fn overwrite_secret() {
        let v = vault();
        v.put(&id("k"), &secret(b"v1")).unwrap();
        v.put(&id("k"), &secret(b"v2")).unwrap();
        assert_eq!(v.get(&id("k")).unwrap().0, b"v2");
    }

    #[test]
    fn empty_secret_roundtrip() {
        let v = vault();
        v.put(&id("empty"), &secret(b"")).unwrap();
        assert_eq!(v.get(&id("empty")).unwrap().0, Vec::<u8>::new());
    }

    #[test]
    fn zeroize_clears_memory() {
        let mut sv = SecretValue(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        sv.zeroize();
        assert!(sv.0.iter().all(|b| *b == 0), "zeroize must clear all bytes");
    }

    #[test]
    fn multiple_secrets_independent() {
        let v = vault();
        v.put(&id("a"), &secret(b"alpha")).unwrap();
        v.put(&id("b"), &secret(b"beta")).unwrap();
        assert_eq!(v.get(&id("a")).unwrap().0, b"alpha");
        assert_eq!(v.get(&id("b")).unwrap().0, b"beta");
    }
}
