use ed25519_dalek::{
    Signature as Ed25519Sig, Signer, SigningKey as Ed25519Sk, Verifier, VerifyingKey as Ed25519Vk,
};
use ml_dsa::MlDsa65;
use rand_core::CryptoRngCore;
use signature_pq::Keypair as PqKeypair;
use signature_pq::Signer as PqSigner;
use signature_pq::Verifier as PqVerifier;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum HybridSignError {
    #[error("Ed25519 signature verification failed")]
    Ed25519VerifyFailed,
    #[error("ML-DSA-65 signature verification failed")]
    MlDsaVerifyFailed,
    #[error("invalid signing key bytes")]
    InvalidKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
}

type MlDsaSk = ml_dsa::SigningKey<MlDsa65>;
type MlDsaVk = ml_dsa::VerifyingKey<MlDsa65>;
type MlDsaSig = ml_dsa::Signature<MlDsa65>;

#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKey {
    ed25519_sk: Ed25519Sk,
    // NOTE (Item 9): ml-dsa 0.1.0 in this workspace is built WITHOUT its
    // `zeroize` feature, so MlDsaSk implements neither Zeroize nor
    // ZeroizeOnDrop and cannot be derived here (compile error E0599). Its
    // Drop impl still clears the seed when that feature is on; until the
    // workspace enables `ml-dsa/zeroize`, this half relies on that Drop
    // path. The Ed25519 half above IS zeroized on drop. Revisit when
    // workspace deps enable ml-dsa/zeroize.
    #[zeroize(skip)]
    mldsa_sk: MlDsaSk,
}

#[derive(Clone)]
pub struct HybridVerifyingKey {
    pub ed25519_vk: Ed25519Vk,
    pub mldsa_vk: MlDsaVk,
}

pub struct HybridSignature {
    pub ed25519_sig: Ed25519Sig,
    pub mldsa_sig: MlDsaSig,
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.ed25519_sig.to_bytes().as_ref());
        let encoded = self.mldsa_sig.encode();
        out.extend_from_slice(encoded.as_ref());
        out
    }

    /// Reconstruct from the `to_bytes` encoding (Ed25519 || ML-DSA-65).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        use std::convert::TryFrom as _;
        const ED_LEN: usize = 64;
        if bytes.len() <= ED_LEN {
            return Err(HybridSignError::InvalidSignatureEncoding);
        }
        let ed25519_sig = Ed25519Sig::from_bytes(
            &bytes[..ED_LEN]
                .try_into()
                .map_err(|_| HybridSignError::InvalidSignatureEncoding)?,
        );
        let mldsa_sig = MlDsaSig::try_from(&bytes[ED_LEN..])
            .map_err(|_| HybridSignError::InvalidSignatureEncoding)?;
        Ok(Self {
            ed25519_sig,
            mldsa_sig,
        })
    }
}

pub struct HybridEd25519Mldsa;

impl HybridEd25519Mldsa {
    pub fn generate_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (HybridSigningKey, HybridVerifyingKey) {
        let ed25519_sk = Ed25519Sk::generate(&mut *rng);
        let ed25519_vk = ed25519_sk.verifying_key();

        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let mldsa_sk = MlDsaSk::from_seed(&seed_bytes.into());
        seed_bytes.zeroize();
        let mldsa_vk = mldsa_sk.verifying_key();

        let signing = HybridSigningKey {
            ed25519_sk,
            mldsa_sk,
        };
        let verifying = HybridVerifyingKey {
            ed25519_vk,
            mldsa_vk,
        };
        (signing, verifying)
    }

    pub fn sign(key: &HybridSigningKey, message: &[u8]) -> HybridSignature {
        let ed25519_sig = key.ed25519_sk.sign(message);
        let mldsa_sig = key.mldsa_sk.sign(message);

        HybridSignature {
            ed25519_sig,
            mldsa_sig,
        }
    }

    /// Derive the verifying key matching a persisted signing key.
    pub fn verifying_key(key: &HybridSigningKey) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed25519_vk: key.ed25519_sk.verifying_key(),
            mldsa_vk: key.mldsa_sk.verifying_key(),
        }
    }

    /// Persist/restore a signing key: Ed25519 secret bytes || ML-DSA-65 seed
    /// (32 + 32 = 64 bytes, stable layout).
    pub fn signing_key_to_bytes(key: &HybridSigningKey) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&key.ed25519_sk.to_bytes());
        let seed = key.mldsa_sk.to_seed();
        out[32..].copy_from_slice(&seed[..]);
        out
    }

    /// Restore a signing key previously exported with `signing_key_to_bytes`.
    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<HybridSigningKey, HybridSignError> {
        if bytes.len() != 64 {
            return Err(HybridSignError::InvalidKey);
        }
        let ed25519_sk = Ed25519Sk::from_bytes(
            &bytes[..32]
                .try_into()
                .map_err(|_| HybridSignError::InvalidKey)?,
        );
        let seed: ml_dsa::Seed = bytes[32..]
            .try_into()
            .map_err(|_| HybridSignError::InvalidKey)?;
        let mldsa_sk = MlDsaSk::from_seed(&seed);
        Ok(HybridSigningKey {
            ed25519_sk,
            mldsa_sk,
        })
    }

    pub fn verify(
        key: &HybridVerifyingKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), HybridSignError> {
        key.ed25519_vk
            .verify(message, &signature.ed25519_sig)
            .map_err(|_| HybridSignError::Ed25519VerifyFailed)?;

        key.mldsa_vk
            .verify(message, &signature.mldsa_sig)
            .map_err(|_| HybridSignError::MlDsaVerifyFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_round_trip() {
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"operator-signed bootstrap token payload";

        let sig = HybridEd25519Mldsa::sign(&sk, msg);
        HybridEd25519Mldsa::verify(&vk, msg, &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"original message";
        let tampered = b"tampered message";

        let sig = HybridEd25519Mldsa::sign(&sk, msg);
        assert!(HybridEd25519Mldsa::verify(&vk, tampered, &sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut rng = OsRng;
        let (sk1, _vk1) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let (_sk2, vk2) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"test message";

        let sig = HybridEd25519Mldsa::sign(&sk1, msg);
        assert!(HybridEd25519Mldsa::verify(&vk2, msg, &sig).is_err());
    }

    #[test]
    fn signing_key_bytes_round_trip_verifies() {
        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"persisted operator key";

        let raw = HybridEd25519Mldsa::signing_key_to_bytes(&sk);
        let restored = HybridEd25519Mldsa::signing_key_from_bytes(&raw).unwrap();
        let vk = HybridEd25519Mldsa::verifying_key(&restored);
        let sig = HybridEd25519Mldsa::sign(&restored, msg);
        HybridEd25519Mldsa::verify(&vk, msg, &sig).unwrap();
    }

    #[test]
    fn signing_key_from_bytes_rejects_bad_input() {
        assert!(HybridEd25519Mldsa::signing_key_from_bytes(&[0u8; 63]).is_err());
        assert!(HybridEd25519Mldsa::signing_key_from_bytes(&[0u8; 65]).is_err());
        assert!(HybridEd25519Mldsa::signing_key_from_bytes(&[]).is_err());
    }

    #[test]
    fn tampered_signing_key_bytes_change_verifying_key() {
        // NOTE: kept separate from the rejects-bad-input test because each
        // ML-DSA-65 key generation allocates ~8KB+ on the stack; generating
        // two keypairs plus restores in a single test overflows the default
        // 8 MiB test-thread stack.
        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mut raw = HybridEd25519Mldsa::signing_key_to_bytes(&sk);
        raw[0] ^= 0xFF;
        let tampered = HybridEd25519Mldsa::signing_key_from_bytes(&raw).unwrap();
        let orig_vk = HybridEd25519Mldsa::verifying_key(&sk);
        let tampered_vk = HybridEd25519Mldsa::verifying_key(&tampered);
        assert_ne!(
            orig_vk.ed25519_vk.as_bytes(),
            tampered_vk.ed25519_vk.as_bytes()
        );
    }

    #[test]
    fn signature_bytes_round_trip_verifies() {
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"operator-approved rule";

        let sig = HybridEd25519Mldsa::sign(&sk, msg);
        let raw = sig.to_bytes();
        let decoded = HybridSignature::from_bytes(&raw).unwrap();
        HybridEd25519Mldsa::verify(&vk, msg, &decoded).unwrap();
    }

    #[test]
    fn signature_from_bytes_rejects_truncated_input() {
        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let sig = HybridEd25519Mldsa::sign(&sk, b"rule bytes");
        let raw = sig.to_bytes();
        assert!(HybridSignature::from_bytes(&raw[..64]).is_err());
        assert!(HybridSignature::from_bytes(&raw[..raw.len() / 2]).is_err());
    }
}
