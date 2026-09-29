//! Per-node mesh identity persistence: HybridSigningKey + stable PeerId.
//!
//! Two keys are in play and they are not the same thing:
//!
//! - the **operator key** (`operator_key.rs`) is the cluster trust anchor. It
//!   is shared by every node, and it is what signs a peer's identity *binding*
//!   — the statement "this peer id belongs to this identity key".
//! - the **mesh identity** here is the node's own. It is one per node, and it
//!   is what signs a handshake Hello or HelloResponse.
//!
//! Keeping the mesh identity stable matters for a reason beyond convenience:
//! a peer can pin the identity key it expects
//! (`MeshNodeConfig::expected_peer_identity_vk`), and the protocol does not bind
//! a HelloResponse's identity to its peer id — so a pin is the only thing that
//! makes the responder's identity authoritative. A fresh key per boot would
//! make that pin impossible.
//!
//! Same discipline as the operator key file: one JSON file, mode 0600 on Unix,
//! generated only on first run, and a corrupt file is an error rather than a
//! silent ephemeral fallback.

use std::path::{Path, PathBuf};

use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey, HybridVerifyingKey};
use imperium_protocol::PeerId;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshIdentityError {
    #[error("mesh identity home directory unavailable")]
    NoHome,
    #[error("io error on mesh identity file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("mesh identity file {path} is corrupt: {reason}")]
    Corrupt { path: PathBuf, reason: String },
}

#[derive(Serialize, Deserialize)]
struct MeshIdentityFile {
    signing_key: Vec<u8>,
    peer_id: PeerId,
}

pub struct MeshIdentity {
    pub peer_id: PeerId,
    /// Signing key (secret material — deliberately no Debug impl on this struct).
    pub signing_key: HybridSigningKey,
    pub verify_key: HybridVerifyingKey,
}

/// Resolve the mesh identity path: `$IMPERIUM_MESH_IDENTITY` wins, else
/// `~/.config/imperium/imperium/mesh-identity`.
pub fn mesh_identity_path() -> Result<PathBuf, MeshIdentityError> {
    if let Ok(path) = std::env::var("IMPERIUM_MESH_IDENTITY") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var("HOME").map_err(|_| MeshIdentityError::NoHome)?;
    if home.trim().is_empty() {
        return Err(MeshIdentityError::NoHome);
    }
    Ok(Path::new(&home)
        .join(".config")
        .join("imperium")
        .join("imperium")
        .join("mesh-identity"))
}

/// Load or (first run only) generate + persist this node's mesh identity.
pub fn load_or_generate(path: &Path) -> Result<MeshIdentity, MeshIdentityError> {
    if path.exists() {
        return load(path);
    }
    let mut rng = OsRng;
    let (signing_key, verify_key) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let peer_id = PeerId::new();
    let raw = HybridEd25519Mldsa::signing_key_to_bytes(&signing_key);
    let file = MeshIdentityFile {
        signing_key: raw.to_vec(),
        peer_id: peer_id.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| MeshIdentityError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("serialize: {e}"),
    })?;

    // Same arbitration as the operator key: two processes starting at once must
    // not both generate an identity for the same node.
    let created =
        crate::keyfile::create_new(path, &json).map_err(|source| MeshIdentityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !created {
        return load(path);
    }

    restrict_permissions(path)?;
    Ok(MeshIdentity {
        peer_id,
        signing_key,
        verify_key,
    })
}

/// Read just the public half of a peer's identity file, for pinning.
pub fn load_verify_key(path: &Path) -> Result<HybridVerifyingKey, MeshIdentityError> {
    let bytes = std::fs::read(path).map_err(|source| MeshIdentityError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file: MeshIdentityFile =
        serde_json::from_slice(&bytes).map_err(|e| MeshIdentityError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("parse: {e}"),
        })?;
    let signing_key =
        HybridEd25519Mldsa::signing_key_from_bytes(&file.signing_key).map_err(|e| {
            MeshIdentityError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("decode signing key: {e}"),
            }
        })?;
    Ok(HybridEd25519Mldsa::verifying_key(&signing_key))
}

fn load(path: &Path) -> Result<MeshIdentity, MeshIdentityError> {
    let bytes = std::fs::read(path).map_err(|source| MeshIdentityError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file: MeshIdentityFile =
        serde_json::from_slice(&bytes).map_err(|e| MeshIdentityError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("parse: {e}"),
        })?;
    let signing_key =
        HybridEd25519Mldsa::signing_key_from_bytes(&file.signing_key).map_err(|e| {
            MeshIdentityError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("decode signing key: {e}"),
            }
        })?;
    let verify_key = HybridEd25519Mldsa::verifying_key(&signing_key);
    Ok(MeshIdentity {
        peer_id: file.peer_id,
        signing_key,
        verify_key,
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), MeshIdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|source| MeshIdentityError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), MeshIdentityError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "imperium-mesh-identity-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trip_yields_a_stable_peer_id() {
        let path = temp_dir("roundtrip").join("mesh-identity");
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let first = load_or_generate(&path).unwrap();
                let first_peer = first.peer_id.clone();
                let second = load_or_generate(&path).unwrap();
                assert_eq!(first_peer, second.peer_id);
                // The pinned verify key survives a restart too.
                let pinned = load_verify_key(&path).unwrap();
                assert_eq!(
                    pinned.ed25519_vk.as_bytes(),
                    second.verify_key.ed25519_vk.as_bytes()
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_a_new_identity() {
        let path = temp_dir("corrupt").join("mesh-identity");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"{not valid json").unwrap();
        assert!(matches!(
            load_or_generate(&path),
            Err(MeshIdentityError::Corrupt { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn generated_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_dir("perms").join("mesh-identity");
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                load_or_generate(&path).unwrap();
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "mesh identity must be 0600, got {mode:o}");
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
