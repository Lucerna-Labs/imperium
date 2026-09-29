//! Operator identity persistence: HybridSigningKey + stable PeerId.
//!
//! The signature subsystem signs approvals with the operator key, and the
//! engine later verifies those approvals. An ephemeral key per boot would
//! make every prior approval unverifiable after a restart, so the key and
//! the operator PeerId live in one JSON file (mode 0600 on Unix) and are
//! generated only on first run. Fail closed: load/generation errors refuse
//! the signature subsystem instead of minting silent ephemeral keys.

use std::path::{Path, PathBuf};

use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_protocol::PeerId;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperatorKeyError {
    #[error("operator key home directory unavailable")]
    NoHome,
    #[error("io error on operator key file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("operator key file {path} is corrupt: {reason}")]
    Corrupt { path: PathBuf, reason: String },
}

#[derive(Serialize, Deserialize)]
struct OperatorKeyFile {
    signing_key: Vec<u8>,
    peer_id: PeerId,
}

pub struct OperatorIdentity {
    pub peer_id: PeerId,
    /// Signing key (secret material — deliberately no Debug impl on this struct).
    pub signing_key: HybridSigningKey,
    pub verify_key: imperium_net_crypto::HybridVerifyingKey,
}

/// Resolve the operator key path: `$IMPERIUM_OPERATOR_KEY` wins (tests and
/// explicit overrides), else `~/.config/imperium/imperium/operator-key`.
pub fn operator_key_path() -> Result<PathBuf, OperatorKeyError> {
    if let Ok(path) = std::env::var("IMPERIUM_OPERATOR_KEY") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var("HOME").map_err(|_| OperatorKeyError::NoHome)?;
    if home.trim().is_empty() {
        return Err(OperatorKeyError::NoHome);
    }
    Ok(Path::new(&home)
        .join(".config")
        .join("imperium")
        .join("imperium")
        .join("operator-key"))
}

/// Load or (first run only) generate + persist the operator identity.
/// Fails closed: any unreadable/corrupt state that cannot be generated is
/// an error, never a silent ephemeral fallback.
pub fn load_or_generate(path: &Path) -> Result<OperatorIdentity, OperatorKeyError> {
    if path.exists() {
        return load(path);
    }
    let mut rng = OsRng;
    let (signing_key, verify_key) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let peer_id = PeerId::new();
    let raw = HybridEd25519Mldsa::signing_key_to_bytes(&signing_key);
    let file = OperatorKeyFile {
        signing_key: raw.to_vec(),
        peer_id: peer_id.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| OperatorKeyError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("serialize: {e}"),
    })?;

    // Let the filesystem arbitrate a concurrent first run. Two nodes starting
    // at once would otherwise both generate a key and one would silently
    // overwrite the other, leaving the two nodes with different operator keys
    // and mutually invalid identity bindings.
    let created =
        crate::keyfile::create_new(path, &json).map_err(|source| OperatorKeyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !created {
        // Another process created it first. Use theirs, not the key just
        // generated here.
        return load(path);
    }

    restrict_permissions(path)?;
    Ok(OperatorIdentity {
        peer_id,
        signing_key,
        verify_key,
    })
}

fn load(path: &Path) -> Result<OperatorIdentity, OperatorKeyError> {
    let bytes = std::fs::read(path).map_err(|source| OperatorKeyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file: OperatorKeyFile =
        serde_json::from_slice(&bytes).map_err(|e| OperatorKeyError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("parse: {e}"),
        })?;
    let signing_key =
        HybridEd25519Mldsa::signing_key_from_bytes(&file.signing_key).map_err(|e| {
            OperatorKeyError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("decode signing key: {e}"),
            }
        })?;
    let verify_key = HybridEd25519Mldsa::verifying_key(&signing_key);
    Ok(OperatorIdentity {
        peer_id: file.peer_id,
        signing_key,
        verify_key,
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), OperatorKeyError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|source| OperatorKeyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), OperatorKeyError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "imperium-operator-key-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("operator-key")
    }

    #[test]
    fn round_trip_yields_same_peer_id() {
        let path = temp_path("roundtrip");
        // NOTE: ML-DSA-65 key generation allocates ~8KB+ on the stack; two
        // sequential load_or_generate calls (first-run generate + reload)
        // in one test need headroom, so the check thread gets a big stack.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let first = load_or_generate(&path).unwrap();
                let first_peer = first.peer_id.clone();
                let second = load_or_generate(&path).unwrap();
                assert_eq!(first_peer, second.peer_id);
                // Both identities sign verifiably under their own verify keys.
                let msg = b"round-trip approval";
                let sig = HybridEd25519Mldsa::sign(&second.signing_key, msg);
                HybridEd25519Mldsa::verify(&second.verify_key, msg, &sig).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn tampered_key_file_is_a_clean_error() {
        let path = temp_path("tampered");
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                load_or_generate(&path).unwrap();
                std::fs::write(&path, b"{not valid json").unwrap();
                let err = match load_or_generate(&path) {
                    Ok(_) => panic!("expected Corrupt error"),
                    Err(e) => e,
                };
                assert!(
                    matches!(err, OperatorKeyError::Corrupt { .. }),
                    "expected Corrupt, got {err:?}"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn empty_key_file_is_a_clean_error() {
        let path = temp_path("empty");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"").unwrap();
        let err = match load_or_generate(&path) {
            Ok(_) => panic!("expected Corrupt error"),
            Err(e) => e,
        };
        assert!(
            matches!(err, OperatorKeyError::Corrupt { .. }),
            "expected Corrupt, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                load_or_generate(&path).unwrap();
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "operator key must be 0600, got {mode:o}");
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
