//! Session AEAD for the mesh data path.
//!
//! Each established session's hybrid key (X25519 + ML-KEM through HKDF) is
//! split into two direction keys — initiator→responder and responder→initiator
//! — so the two peers never encrypt under the same key and a 64-bit frame
//! counter is safe to number from zero in each direction. The counter forms
//! the ChaCha20-Poly1305 nonce (4-byte zero prefix + counter, little endian)
//! and rides in the clear frame header so the receiver can decrypt and check
//! replay before touching anything else.
//!
//! Replay protection is a 64-frame sliding window per direction (IPsec/
//! WireGuard style): duplicates and stale frames are rejected, moderate UDP
//! reordering is tolerated.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use imperium_net_crypto::HybridSessionKey;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HKDF_LABEL: &[u8] = b"imperium-mesh-aead-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed (wrong key, tampered frame, or counter mismatch)")]
    DecryptFailed,
    #[error("replayed or out-of-window frame counter")]
    Replay,
}

/// Per-session transmit/receive keys derived from the hybrid session key.
/// The initiator's send key is the responder's receive key, and vice versa.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DirectionKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

impl DirectionKeys {
    pub fn derive(session_key: &HybridSessionKey, initiator: bool) -> Self {
        Self::derive_bound(session_key, initiator, &[], &[])
    }

    /// Identity-bound derivation (Item 7): both peers' operator-certified
    /// identity bytes feed HKDF info, so a session key negotiated with peer
    /// A cannot replay as peer B — different identities derive different
    /// direction keys from the same session secret. Pass the initiator's
    /// identity bytes first, then the responder's (order-fixed, role-known
    /// to both sides). Unbound callers use `derive` (empty identities).
    pub fn derive_bound(
        session_key: &HybridSessionKey,
        initiator: bool,
        initiator_identity: &[u8],
        responder_identity: &[u8],
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_LABEL), session_key.as_bytes());
        let mut info_i2r = Vec::with_capacity(
            b"initiator-to-responder".len()
                + initiator_identity.len()
                + responder_identity.len()
                + 2,
        );
        info_i2r.extend_from_slice(b"initiator-to-responder");
        info_i2r.push(0x00);
        info_i2r.extend_from_slice(initiator_identity);
        info_i2r.push(0x01);
        info_i2r.extend_from_slice(responder_identity);
        let mut info_r2i = Vec::with_capacity(
            b"responder-to-initiator".len()
                + initiator_identity.len()
                + responder_identity.len()
                + 2,
        );
        info_r2i.extend_from_slice(b"responder-to-initiator");
        info_r2i.push(0x00);
        info_r2i.extend_from_slice(responder_identity);
        info_r2i.push(0x01);
        info_r2i.extend_from_slice(initiator_identity);

        let mut initiator_to_responder = [0u8; 32];
        let mut responder_to_initiator = [0u8; 32];
        hk.expand(&info_i2r, &mut initiator_to_responder)
            .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
        hk.expand(&info_r2i, &mut responder_to_initiator)
            .expect("HKDF-SHA256 expand to 32 bytes cannot fail");

        if initiator {
            Self {
                send: initiator_to_responder,
                recv: responder_to_initiator,
            }
        } else {
            Self {
                send: responder_to_initiator,
                recv: initiator_to_responder,
            }
        }
    }

    pub fn seal(&self, counter: u64, plaintext: &[u8]) -> Vec<u8> {
        seal_with(&self.send, counter, plaintext)
    }

    pub fn open(&self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        open_with(&self.recv, counter, ciphertext)
    }
}

pub fn seal_with(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(&frame_nonce(counter), plaintext)
        .expect("chacha20poly1305 encryption cannot fail")
}

pub fn open_with(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&frame_nonce(counter), ciphertext)
        .map_err(|_| CryptoError::DecryptFailed)
}

fn frame_nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(bytes)
}

/// 64-frame sliding replay window. Bit 0 tracks the highest counter seen;
/// older accepted counters occupy higher bits. Counters older than 63 below
/// the highest are rejected outright.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, counter: u64) -> Result<(), CryptoError> {
        if !self.initialized {
            self.initialized = true;
            self.highest = counter;
            self.bitmap = 1;
            return Ok(());
        }

        if counter > self.highest {
            let shift = counter - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = counter;
            return Ok(());
        }

        if self.highest.saturating_sub(counter) >= 64 {
            return Err(CryptoError::Replay);
        }

        let bit = 1u64 << (self.highest - counter);
        if self.bitmap & bit != 0 {
            return Err(CryptoError::Replay);
        }
        self.bitmap |= bit;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_crypto::HybridX25519Mlkem;
    use rand::rngs::OsRng;

    fn session_keys() -> (DirectionKeys, DirectionKeys) {
        let mut rng = OsRng;
        let (responder_secret, responder_public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &responder_public);
        let _responder_key = HybridX25519Mlkem::decapsulate(responder_secret, &encap).unwrap();
        (
            DirectionKeys::derive(&key, true),
            DirectionKeys::derive(&key, false),
        )
    }

    #[test]
    fn directions_round_trip_and_are_distinct() {
        let (initiator, responder) = session_keys();
        let plaintext = b"{\"mesh\":\"ping\"}";

        let sealed = initiator.seal(7, plaintext);
        assert_eq!(responder.open(7, &sealed).unwrap(), plaintext);

        let reply = responder.seal(7, plaintext);
        assert_eq!(initiator.open(7, &reply).unwrap(), plaintext);

        // Direction keys are role-mirrored but the two streams differ.
        assert_ne!(&initiator.send, &responder.send);
        assert_eq!(&initiator.send, &responder.recv);
    }

    #[test]
    fn tampered_frames_fail() {
        let (initiator, responder) = session_keys();
        let mut sealed = initiator.seal(1, b"integrity check");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            responder.open(1, &sealed),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn wrong_counter_fails_to_open() {
        let (initiator, responder) = session_keys();
        let sealed = initiator.seal(1, b"counter binding");
        assert!(responder.open(2, &sealed).is_err());
    }

    #[test]
    fn replay_window_accepts_reorder_rejects_duplicates_and_stale() {
        let mut window = ReplayWindow::new();

        // Delivery order 5, 3, 4 — in-window reordering is fine.
        window.accept(5).unwrap();
        window.accept(3).unwrap();
        window.accept(4).unwrap();

        // Duplicates rejected.
        assert!(matches!(window.accept(5), Err(CryptoError::Replay)));
        assert!(matches!(window.accept(3), Err(CryptoError::Replay)));

        // Advancing forward works and slides the window.
        window.accept(10).unwrap();
        // Counter 5 is inside the window but already seen → replay.
        assert!(matches!(window.accept(5), Err(CryptoError::Replay)));

        // A large jump clears the bitmap: old-but-unseen counters inside the
        // new window are fine, counters below it are stale.
        window.accept(100).unwrap();
        assert!(matches!(window.accept(100), Err(CryptoError::Replay)));
        window.accept(90).unwrap(); // in window, unseen
        assert!(matches!(window.accept(30), Err(CryptoError::Replay))); // below window
        window.accept(101).unwrap();
    }

    #[test]
    fn identity_binding_changes_direction_keys() {
        // Item 7: same session secret + different peer identities ->
        // different direction keys, so a key for peer A cannot replay as
        // peer B. Same identities -> same keys (deterministic).
        use imperium_net_crypto::HybridX25519Mlkem;
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);

        let id_a = b"peer-a-identity";
        let id_b = b"peer-b-identity";
        let bound_a = DirectionKeys::derive_bound(&key, true, id_a, id_b);
        let bound_b = DirectionKeys::derive_bound(&key, true, id_b, id_a);
        let unbound = DirectionKeys::derive(&key, true);
        assert_ne!(bound_a.send, bound_b.send);
        assert_ne!(bound_a.send, unbound.send);
        // Deterministic: same inputs derive the same keys.
        let bound_a2 = DirectionKeys::derive_bound(&key, true, id_a, id_b);
        assert_eq!(bound_a.send, bound_a2.send);
        assert_eq!(bound_a.recv, bound_a2.recv);
        // Role mirroring still holds under binding.
        let responder = DirectionKeys::derive_bound(&key, false, id_a, id_b);
        assert_eq!(bound_a.send, responder.recv);
        assert_eq!(bound_a.recv, responder.send);
    }
}
