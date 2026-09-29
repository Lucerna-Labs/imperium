use hkdf::Hkdf;
use hybrid_array::{typenum::Unsigned, Array};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::HYBRID_SESSION_KEY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum HybridKexError {
    #[error("ML-KEM decapsulation failed")]
    MlKemDecapsulationFailed,
    #[error("HKDF expand failed")]
    HkdfExpandFailed,
    #[error("invalid ciphertext length")]
    InvalidCiphertextLength,
    #[error("invalid public key length")]
    InvalidPublicKeyLength,
}

type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemCtSize = <MlKem768 as KemCore>::CiphertextSize;
type MlKemCt = Array<u8, MlKemCtSize>;

/// x25519 public keys are a fixed 32 bytes on the wire.
const X25519_PUBLIC_LEN: usize = 32;
/// Encoded length of an ML-KEM-768 encapsulation key (1184 bytes).
const MLKEM_EK_LEN: usize = <MlKemEk as EncodedSizeUser>::EncodedSize::USIZE;
/// Encoded length of an ML-KEM-768 ciphertext (1088 bytes).
const MLKEM_CT_LEN: usize = MlKemCtSize::USIZE;

pub struct HybridKexSecretKey {
    x25519_secret: EphemeralSecret,
    mlkem_dk: MlKemDk,
}

#[derive(Clone)]
pub struct HybridKexPublicKey {
    pub x25519_public: X25519Public,
    pub mlkem_ek: MlKemEk,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSessionKey {
    key: [u8; HYBRID_SESSION_KEY_LEN],
}

impl HybridSessionKey {
    pub fn as_bytes(&self) -> &[u8; HYBRID_SESSION_KEY_LEN] {
        &self.key
    }
}

pub struct HybridEncapsulation {
    pub x25519_public: X25519Public,
    mlkem_ct: MlKemCt,
}

impl HybridEncapsulation {
    pub fn mlkem_ciphertext_bytes(&self) -> &[u8] {
        self.mlkem_ct.as_ref()
    }

    /// Wire length of a packed encapsulation.
    pub const fn encoded_len() -> usize {
        X25519_PUBLIC_LEN + MLKEM_CT_LEN
    }

    /// Rebuild a packed encapsulation from its wire form:
    /// `x25519_ephemeral_public (32B) || ML-KEM-768 ciphertext`.
    ///
    /// The initiator needs this to decapsulate a handshake response, because
    /// the ML-KEM half of this struct is private and cannot be assembled from
    /// bytes outside this module. Fails closed on any length mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, HybridKexError> {
        if bytes.len() != Self::encoded_len() {
            return Err(HybridKexError::InvalidCiphertextLength);
        }
        let x25519_public = X25519Public::from(
            <[u8; X25519_PUBLIC_LEN]>::try_from(&bytes[..X25519_PUBLIC_LEN])
                .map_err(|_| HybridKexError::InvalidCiphertextLength)?,
        );
        let mlkem_ct = MlKemCt::try_from(&bytes[X25519_PUBLIC_LEN..])
            .map_err(|_| HybridKexError::InvalidCiphertextLength)?;
        Ok(Self {
            x25519_public,
            mlkem_ct,
        })
    }

    /// Split the packed encapsulation at the x25519 boundary, because the
    /// mesh HelloResponse carries the two halves in separate fields
    /// (`classical_pubkey` then `pqc_ciphertext`).
    pub fn encode_split(&self) -> (Vec<u8>, Vec<u8>) {
        let ciphertext: &[u8] = self.mlkem_ct.as_ref();
        (self.x25519_public.as_bytes().to_vec(), ciphertext.to_vec())
    }

    /// Reassemble an encapsulation from the two HelloResponse fields.
    pub fn decode_split(classical: &[u8], pqc_ciphertext: &[u8]) -> Result<Self, HybridKexError> {
        let mut packed = Vec::with_capacity(classical.len() + pqc_ciphertext.len());
        packed.extend_from_slice(classical);
        packed.extend_from_slice(pqc_ciphertext);
        Self::decode(&packed)
    }
}

impl HybridKexPublicKey {
    /// Wire length of a packed KEX public key.
    pub const fn encoded_len() -> usize {
        X25519_PUBLIC_LEN + MLKEM_EK_LEN
    }

    /// Pack for the wire: `x25519_public (32B) || ML-KEM-768 encapsulation
    /// key`. This is the form a mesh handshake Hello carries so the peer can
    /// encapsulate a session key toward the sender.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::encoded_len());
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(self.mlkem_ek.as_bytes().as_ref());
        out
    }

    /// Rebuild a packed KEX public key from the wire form produced by
    /// `encode`. Fails closed on any length mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, HybridKexError> {
        if bytes.len() != Self::encoded_len() {
            return Err(HybridKexError::InvalidPublicKeyLength);
        }
        let x25519_public = X25519Public::from(
            <[u8; X25519_PUBLIC_LEN]>::try_from(&bytes[..X25519_PUBLIC_LEN])
                .map_err(|_| HybridKexError::InvalidPublicKeyLength)?,
        );
        let ek_encoded = Encoded::<MlKemEk>::try_from(&bytes[X25519_PUBLIC_LEN..])
            .map_err(|_| HybridKexError::InvalidPublicKeyLength)?;
        let mlkem_ek = MlKemEk::from_bytes(&ek_encoded);
        Ok(Self {
            x25519_public,
            mlkem_ek,
        })
    }

    /// Split the packed encoding at the x25519 boundary, because the mesh
    /// Hello carries the two halves in separate fields
    /// (`classical_pubkey` then `pqc_pubkey`). Keeping the split here means
    /// the wire contract is defined in exactly one place.
    pub fn encode_split(&self) -> (Vec<u8>, Vec<u8>) {
        let encoded = self.mlkem_ek.as_bytes();
        let encoded: &[u8] = encoded.as_ref();
        (self.x25519_public.as_bytes().to_vec(), encoded.to_vec())
    }

    /// Reassemble a public key from the two Hello fields.
    pub fn decode_split(classical: &[u8], pqc: &[u8]) -> Result<Self, HybridKexError> {
        let mut packed = Vec::with_capacity(classical.len() + pqc.len());
        packed.extend_from_slice(classical);
        packed.extend_from_slice(pqc);
        Self::decode(&packed)
    }
}

pub struct HybridX25519Mlkem;

impl HybridX25519Mlkem {
    pub fn generate_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (HybridKexSecretKey, HybridKexPublicKey) {
        let x25519_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(rng);

        let secret = HybridKexSecretKey {
            x25519_secret,
            mlkem_dk,
        };
        let public = HybridKexPublicKey {
            x25519_public,
            mlkem_ek,
        };
        (secret, public)
    }

    pub fn encapsulate(
        rng: &mut impl CryptoRngCore,
        responder_public: &HybridKexPublicKey,
    ) -> (HybridEncapsulation, HybridSessionKey) {
        let x25519_ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
        let x25519_public = X25519Public::from(&x25519_ephemeral);
        let x25519_shared = x25519_ephemeral.diffie_hellman(&responder_public.x25519_public);

        let (mlkem_ct, mlkem_ss) = responder_public
            .mlkem_ek
            .encapsulate(rng)
            .expect("ML-KEM encapsulation cannot fail");

        let session_key = derive_hybrid_key(&x25519_shared, mlkem_ss.as_ref());

        let encap = HybridEncapsulation {
            x25519_public,
            mlkem_ct,
        };
        (encap, session_key)
    }

    pub fn decapsulate(
        secret: HybridKexSecretKey,
        encapsulation: &HybridEncapsulation,
    ) -> Result<HybridSessionKey, HybridKexError> {
        let x25519_shared = secret
            .x25519_secret
            .diffie_hellman(&encapsulation.x25519_public);

        let mlkem_ss = secret
            .mlkem_dk
            .decapsulate(&encapsulation.mlkem_ct)
            .map_err(|_| HybridKexError::MlKemDecapsulationFailed)?;

        Ok(derive_hybrid_key(&x25519_shared, mlkem_ss.as_ref()))
    }
}

fn derive_hybrid_key(x25519_shared: &SharedSecret, mlkem_shared: &[u8]) -> HybridSessionKey {
    let mut ikm = Vec::with_capacity(32 + mlkem_shared.len());
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(b"imperium-hybrid-kex-v1"), &ikm);
    let mut key = [0u8; HYBRID_SESSION_KEY_LEN];
    hk.expand(b"session-key", &mut key)
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");

    ikm.zeroize();
    HybridSessionKey { key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn key_exchange_round_trip() {
        let mut rng = OsRng;

        let (secret_b, public_b) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encap, session_key_a) = HybridX25519Mlkem::encapsulate(&mut rng, &public_b);
        let session_key_b = HybridX25519Mlkem::decapsulate(secret_b, &encap).unwrap();

        assert_eq!(session_key_a.as_bytes(), session_key_b.as_bytes());
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let mut rng = OsRng;

        let (_s1, p1) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_, key1) = HybridX25519Mlkem::encapsulate(&mut rng, &p1);

        let (_s2, p2) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_, key2) = HybridX25519Mlkem::encapsulate(&mut rng, &p2);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    /// The mesh handshake's crypto core, driven entirely across the wire
    /// encoding: the initiator publishes its KEX public key, the responder
    /// encapsulates toward it, and the initiator decapsulates from the wire
    /// bytes alone. This is the path no production code exercised before.
    #[test]
    fn hybrid_kex_round_trips_through_wire_encoding() {
        let mut rng = OsRng;

        // Initiator generates and publishes its public key (the Hello).
        let (initiator_secret, initiator_public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let public_wire = initiator_public.encode();
        assert_eq!(public_wire.len(), HybridKexPublicKey::encoded_len());

        // Responder rebuilds the public key from the wire and encapsulates.
        let decoded_public = HybridKexPublicKey::decode(&public_wire).unwrap();
        let (encapsulation, responder_key) =
            HybridX25519Mlkem::encapsulate(&mut rng, &decoded_public);

        // The response carries the ephemeral public and the ML-KEM ciphertext
        // as one packed blob.
        let mut response_wire = Vec::new();
        response_wire.extend_from_slice(encapsulation.x25519_public.as_bytes());
        response_wire.extend_from_slice(encapsulation.mlkem_ciphertext_bytes());
        assert_eq!(response_wire.len(), HybridEncapsulation::encoded_len());

        // Initiator rebuilds the encapsulation from the wire and decapsulates.
        let decoded_encapsulation = HybridEncapsulation::decode(&response_wire).unwrap();
        let initiator_key =
            HybridX25519Mlkem::decapsulate(initiator_secret, &decoded_encapsulation).unwrap();

        assert_eq!(initiator_key.as_bytes(), responder_key.as_bytes());
    }

    #[test]
    fn wire_decoding_fails_closed_on_bad_lengths() {
        let mut rng = OsRng;
        let (_s, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let wire = public.encode();

        assert!(matches!(
            HybridKexPublicKey::decode(&wire[..wire.len() - 1]),
            Err(HybridKexError::InvalidPublicKeyLength)
        ));
        assert!(matches!(
            HybridKexPublicKey::decode(&[]),
            Err(HybridKexError::InvalidPublicKeyLength)
        ));
        assert!(matches!(
            HybridEncapsulation::decode(&[0u8; 8]),
            Err(HybridKexError::InvalidCiphertextLength)
        ));
    }
}
