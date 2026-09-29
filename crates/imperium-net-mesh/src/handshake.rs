//! Authenticated mesh handshake (Item 6).
//!
//! Verifies, in order: (1) the operator's signature on the peer's identity
//! binding (grant or token binding peer_id -> identity VK -> cluster +
//! expiry), (2) the peer identity key's signature over the ephemeral KEX
//! keys, (3) cluster membership of the remote peer_id. Only then does the
//! KEX encapsulate/decapsulate run and the session establish.
//!
//! Payload layouts mirror the Item 5 `MeshHello` / `MeshHelloResponse`
//! contract. All failures are fail-closed with no key material in error
//! paths.

use imperium_net_crypto::{
    HybridEd25519Mldsa, HybridKexPublicKey, HybridSessionKey, HybridSignature, HybridVerifyingKey,
    HybridX25519Mlkem,
};
use imperium_protocol::{ClusterId, MeshHello, MeshHelloResponse, SessionId};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("operator identity binding invalid")]
    BadIdentityBinding,
    #[error("handshake signature invalid (not peer-identity-signed)")]
    BadHandshakeSignature,
    #[error("peer is not a cluster member")]
    NotMember,
    #[error("key exchange failed: {0}")]
    Kex(String),
    #[error("malformed handshake field")]
    Malformed,
    #[error("peer belongs to a different cluster")]
    WrongCluster,
}

/// Operator-signed binding of peer_id -> identity VK -> cluster + expiry.
/// Serialized form carried in `MeshHello.identity_grant`.
#[derive(Clone, Debug)]
pub struct IdentityBinding {
    pub peer_id_bytes: [u8; 16],
    pub identity_vk_bytes: Vec<u8>,
    pub cluster_id_bytes: [u8; 16],
    pub expires_at_unix: i64,
    pub operator_signature: Vec<u8>,
}

impl IdentityBinding {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.peer_id_bytes);
        out.extend_from_slice(&(self.identity_vk_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.identity_vk_bytes);
        out.extend_from_slice(&self.cluster_id_bytes);
        out.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        out.extend_from_slice(&(self.operator_signature.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.operator_signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let mut cursor = 0usize;
        let take = |cursor: &mut usize, n: usize| -> Result<&[u8], HandshakeError> {
            let end = cursor.saturating_add(n);
            if end > bytes.len() {
                return Err(HandshakeError::Malformed);
            }
            let slice = &bytes[*cursor..end];
            *cursor = end;
            Ok(slice)
        };
        let peer_id_bytes: [u8; 16] = take(&mut cursor, 16)?
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        let vk_len = u64::from_le_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| HandshakeError::Malformed)?,
        ) as usize;
        let identity_vk_bytes = take(&mut cursor, vk_len)?.to_vec();
        let cluster_id_bytes: [u8; 16] = take(&mut cursor, 16)?
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?;
        let expires_at_unix = i64::from_le_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| HandshakeError::Malformed)?,
        );
        let sig_len = u64::from_le_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| HandshakeError::Malformed)?,
        ) as usize;
        let operator_signature = take(&mut cursor, sig_len)?.to_vec();
        if cursor != bytes.len() {
            return Err(HandshakeError::Malformed);
        }
        Ok(Self {
            peer_id_bytes,
            identity_vk_bytes,
            cluster_id_bytes,
            expires_at_unix,
            operator_signature,
        })
    }

    /// Payload the operator signs: peer || identity_vk || cluster || expiry.
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.peer_id_bytes);
        out.extend_from_slice(&self.identity_vk_bytes);
        out.extend_from_slice(&self.cluster_id_bytes);
        out.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        out
    }

    pub fn verify(
        &self,
        operator_vk: &HybridVerifyingKey,
        now_unix: i64,
    ) -> Result<(), HandshakeError> {
        if now_unix > self.expires_at_unix {
            return Err(HandshakeError::BadIdentityBinding);
        }
        let sig = HybridSignature::from_bytes(&self.operator_signature)
            .map_err(|_| HandshakeError::BadIdentityBinding)?;
        HybridEd25519Mldsa::verify(operator_vk, &self.signed_payload(), &sig)
            .map_err(|_| HandshakeError::BadIdentityBinding)?;
        Ok(())
    }
}

/// Hello payload the initiator's identity key signs:
/// session_id/nonce || classical_pubkey || pqc_pubkey || peer_id || grant.
pub fn hello_signed_payload(hello: &MeshHello) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(hello.session_id.0.as_bytes());
    out.extend_from_slice(&hello.classical_pubkey);
    out.extend_from_slice(&hello.pqc_pubkey);
    out.extend_from_slice(hello.peer_id.0.as_bytes());
    out.extend_from_slice(&hello.identity_grant);
    out
}

/// Transcript hash binding the Hello into the response signature.
pub fn hello_transcript_hash(hello: &MeshHello) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(hello.session_id.0.as_bytes());
    hasher.update(hello.peer_id.0.as_bytes());
    hasher.update(&hello.classical_pubkey);
    hasher.update(&hello.pqc_pubkey);
    hasher.update(&hello.identity_vk);
    hasher.update(&hello.identity_grant);
    hasher.update(&hello.handshake_signature);
    hasher.finalize().into()
}

/// Response payload the responder's identity key signs:
/// session_id || pqc_ciphertext || classical_pubkey || transcript-hash(Hello).
pub fn response_signed_payload(resp: &MeshHelloResponse, hello_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(resp.session_id.0.as_bytes());
    out.extend_from_slice(&resp.pqc_ciphertext);
    out.extend_from_slice(&resp.classical_pubkey);
    // The responder's own binding is inside the signature, so it cannot be
    // swapped for one belonging to a different identity.
    out.extend_from_slice(&resp.identity_grant);
    out.extend_from_slice(hello_hash);
    out
}

/// Verify an inbound Hello: operator binding -> identity signature ->
/// membership predicate. Returns the decoded binding and the peer identity
/// VK bytes on success.
pub fn verify_hello(
    hello: &MeshHello,
    operator_vk: &HybridVerifyingKey,
    expected_cluster: &ClusterId,
    now_unix: i64,
    is_member: impl FnOnce() -> bool,
) -> Result<IdentityBinding, HandshakeError> {
    let binding = IdentityBinding::decode(&hello.identity_grant)?;
    binding.verify(operator_vk, now_unix)?;
    // The Hello's claimed identity VK must match the operator-bound one.
    if binding.identity_vk_bytes != hello.identity_vk {
        return Err(HandshakeError::BadIdentityBinding);
    }
    // The operator signs the cluster id, but nothing compared it until now, so
    // a peer from a different cluster was accepted as long as the operator key
    // matched. A shared operator key across clusters is a real deployment, so
    // this check is what keeps the clusters separate.
    if binding.cluster_id_bytes != *expected_cluster.0.as_bytes() {
        return Err(HandshakeError::WrongCluster);
    }
    // The claimed peer id must be the one the operator bound to this identity
    // key. Without this the operator's "this key belongs to peer P" statement
    // is decorative on the initiator path: the identity signature covers the
    // CLAIMED id and the claimant's own key is free to sign that, so any
    // operator-blessed peer could present itself as any other. The response
    // path always made this comparison; the Hello path did not.
    if binding.peer_id_bytes != *hello.peer_id.0.as_bytes() {
        return Err(HandshakeError::BadIdentityBinding);
    }
    // Identity signature over the ephemeral KEX keys.
    let payload = hello_signed_payload(hello);
    let identity_vk = decode_identity_vk(&hello.identity_vk)?;
    let sig = HybridSignature::from_bytes(&hello.handshake_signature)
        .map_err(|_| HandshakeError::BadHandshakeSignature)?;
    HybridEd25519Mldsa::verify(&identity_vk, &payload, &sig)
        .map_err(|_| HandshakeError::BadHandshakeSignature)?;
    if !is_member() {
        return Err(HandshakeError::NotMember);
    }
    Ok(binding)
}

/// Verify an inbound HelloResponse against the Hello it answers.
pub fn verify_hello_response(
    resp: &MeshHelloResponse,
    hello: &MeshHello,
    operator_vk: &HybridVerifyingKey,
    expected_cluster: &ClusterId,
    now_unix: i64,
) -> Result<(), HandshakeError> {
    if resp.session_id != hello.session_id {
        return Err(HandshakeError::BadHandshakeSignature);
    }

    // The initiator's binding, carried in the Hello.
    let initiator_binding = IdentityBinding::decode(&hello.identity_grant)?;
    initiator_binding.verify(operator_vk, now_unix)?;
    if initiator_binding.identity_vk_bytes != hello.identity_vk {
        return Err(HandshakeError::BadIdentityBinding);
    }
    if initiator_binding.cluster_id_bytes != *expected_cluster.0.as_bytes() {
        return Err(HandshakeError::WrongCluster);
    }

    // The RESPONDER's OWN binding, carried in the response. This is the check
    // that was missing: without it the response's identity key is self-asserted
    // and the signature below proves only that *someone* holds a key, not that
    // the key belongs to the peer id claiming it.
    let responder_binding = IdentityBinding::decode(&resp.identity_grant)?;
    responder_binding.verify(operator_vk, now_unix)?;
    if responder_binding.identity_vk_bytes != resp.identity_vk {
        return Err(HandshakeError::BadIdentityBinding);
    }
    if responder_binding.peer_id_bytes != *resp.peer_id.0.as_bytes() {
        return Err(HandshakeError::BadIdentityBinding);
    }
    if responder_binding.cluster_id_bytes != *expected_cluster.0.as_bytes() {
        return Err(HandshakeError::WrongCluster);
    }

    // Only now is the signature meaningful: the key it is checked against is
    // operator-bound to the peer id that presented it.
    let responder_vk = decode_identity_vk(&resp.identity_vk)?;
    let hash = hello_transcript_hash(hello);
    let payload = response_signed_payload(resp, &hash);
    let sig = HybridSignature::from_bytes(&resp.handshake_signature)
        .map_err(|_| HandshakeError::BadHandshakeSignature)?;
    HybridEd25519Mldsa::verify(&responder_vk, &payload, &sig)
        .map_err(|_| HandshakeError::BadHandshakeSignature)?;
    Ok(())
}

/// Decode an identity VK from its wire bytes (Ed25519 32B || ML-DSA-65
/// verifying-key encoding). Uses the same HybridSignature machinery
/// indirectly: the VK bytes are the concatenation produced by
/// `encode_identity_vk`.
pub fn decode_identity_vk(bytes: &[u8]) -> Result<HybridVerifyingKey, HandshakeError> {
    use ed25519_dalek::VerifyingKey as Ed25519Vk;
    const ED_LEN: usize = 32;
    if bytes.len() <= ED_LEN {
        return Err(HandshakeError::Malformed);
    }
    let ed25519_vk = Ed25519Vk::from_bytes(
        &bytes[..ED_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed)?,
    )
    .map_err(|_| HandshakeError::Malformed)?;
    let mldsa_vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(
        &ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&bytes[ED_LEN..])
            .map_err(|_| HandshakeError::Malformed)?,
    );
    Ok(HybridVerifyingKey {
        ed25519_vk,
        mldsa_vk,
    })
}

/// Encode an identity VK to wire bytes (Ed25519 32B || ML-DSA-65 encoding).
pub fn encode_identity_vk(vk: &HybridVerifyingKey) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(vk.ed25519_vk.as_bytes());
    let encoded = vk.mldsa_vk.encode();
    out.extend_from_slice(encoded.as_ref());
    out
}

/// Initiator step: KEX-encapsulate to the responder's KEX public key.
pub fn initiator_encapsulate(
    rng: &mut impl CryptoRngCore,
    responder_kex: &HybridKexPublicKey,
) -> (Vec<u8>, Vec<u8>, HybridSessionKey) {
    let (encap, key) = HybridX25519Mlkem::encapsulate(rng, responder_kex);
    let mut ct = Vec::new();
    ct.extend_from_slice(encap.x25519_public.as_bytes());
    ct.extend_from_slice(encap.mlkem_ciphertext_bytes());
    // Classical pubkey echo omitted (carried in Hello); ciphertext layout is
    // x25519_ephemeral(32B) || ml-kem-ct.
    (ct, Vec::new(), key)
}

/// Session-id helper for the handshake nonce role.
pub fn fresh_session_id() -> SessionId {
    SessionId::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use imperium_protocol::{ClusterId, PeerId};

    fn operator_binding(
        peer: &PeerId,
        identity_vk: &HybridVerifyingKey,
        cluster: &ClusterId,
        op_sk: &imperium_net_crypto::HybridSigningKey,
    ) -> IdentityBinding {
        let proto = IdentityBinding {
            peer_id_bytes: *peer.0.as_bytes(),
            identity_vk_bytes: encode_identity_vk(identity_vk),
            cluster_id_bytes: *cluster.0.as_bytes(),
            expires_at_unix: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
            operator_signature: Vec::new(),
        };
        let sig = HybridEd25519Mldsa::sign(op_sk, &proto.signed_payload());
        IdentityBinding {
            operator_signature: sig.to_bytes(),
            ..proto
        }
    }

    #[test]
    fn binding_encode_decode_round_trip() {
        // NOTE: ML-DSA-65 frames are ~8KB+ each; two keypairs + sign/verify
        // in one test need headroom (precedent: operator_key tests).
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                use rand::rngs::OsRng;
                let mut rng = OsRng;
                let (op_sk, op_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
                let (_id_sk, id_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
                let peer = PeerId::new();
                let cluster = ClusterId::new();
                let binding = operator_binding(&peer, &id_vk, &cluster, &op_sk);
                let raw = binding.encode();
                let decoded = IdentityBinding::decode(&raw).unwrap();
                decoded.verify(&op_vk, Utc::now().timestamp()).unwrap();
                assert_eq!(decoded.identity_vk_bytes, binding.identity_vk_bytes);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn hello_verify_accepts_good_rejects_forged() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                hello_verify_body();
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn hello_verify_body() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let (op_sk, op_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let (id_sk, id_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let peer = PeerId::new();
        let cluster = ClusterId::new();
        let binding = operator_binding(&peer, &id_vk, &cluster, &op_sk);

        let session_id = SessionId::new();
        let hello_unsigned = MeshHello {
            peer_id: peer.clone(),
            endpoint: "127.0.0.1:9000".parse().unwrap(),
            classical_pubkey: vec![1, 2, 3],
            pqc_pubkey: vec![4, 5, 6],
            session_id,
            identity_vk: encode_identity_vk(&id_vk),
            identity_grant: binding.encode(),
            handshake_signature: Vec::new(),
        };
        let sig = HybridEd25519Mldsa::sign(&id_sk, &hello_signed_payload(&hello_unsigned));
        let hello = MeshHello {
            handshake_signature: sig.to_bytes(),
            ..hello_unsigned
        };
        verify_hello(&hello, &op_vk, &cluster, Utc::now().timestamp(), || true).unwrap();
        // Forged KEX bytes fail the identity signature.
        let forged = MeshHello {
            classical_pubkey: vec![9, 9, 9],
            ..hello.clone()
        };
        assert!(matches!(
            verify_hello(&forged, &op_vk, &cluster, Utc::now().timestamp(), || true),
            Err(HandshakeError::BadHandshakeSignature)
        ));
        // Non-member rejected even with good signatures.
        assert!(matches!(
            verify_hello(&hello, &op_vk, &cluster, Utc::now().timestamp(), || false),
            Err(HandshakeError::NotMember)
        ));
        // Wrong operator key rejected.
        let (_other_sk, other_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        assert!(matches!(
            verify_hello(&hello, &other_vk, &cluster, Utc::now().timestamp(), || true),
            Err(HandshakeError::BadIdentityBinding)
        ));
        // A different cluster is rejected even though the operator key matches.
        // The operator signs the cluster id; nothing compared it before this.
        let other_cluster = ClusterId::new();
        assert!(matches!(
            verify_hello(
                &hello,
                &op_vk,
                &other_cluster,
                Utc::now().timestamp(),
                || true
            ),
            Err(HandshakeError::WrongCluster)
        ));
    }

    /// KNOWN DEFECT, pinned so it cannot be missed. See the NAT adversarial
    /// review (2026-09-26), where five independent lenses found this.
    ///
    /// `verify_hello` compares the operator binding's identity key against the
    /// Hello's, checks the cluster, and verifies the identity signature — but
    /// never compares the binding's `peer_id_bytes` against `hello.peer_id`.
    /// `verify_hello_response` DOES make that comparison, so the omission is an
    /// asymmetry rather than a design choice.
    ///
    /// Consequence: a peer the operator has legitimately bound for id P can send
    /// a Hello CLAIMING id Q and be accepted as Q. Nothing stops it — the
    /// identity signature covers the claimed id, and the claimant's own key is
    /// free to sign that. The responder then evaluates membership against the
    /// claimed id and adopts the session under it.
    ///
    /// `verify_hello` now makes that comparison, so this asserts the fix. It
    /// FAILS if the comparison is ever removed.
    #[test]
    fn hello_rejects_a_peer_claiming_another_peers_id() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                use rand::rngs::OsRng;
                let mut rng = OsRng;
                let (op_sk, op_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
                let cluster = ClusterId::new();

                // The attacker legitimately holds an operator binding for its OWN
                // id, and its own identity key.
                let (attacker_sk, attacker_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
                let attacker_peer = PeerId::new();
                let victim_peer = PeerId::new();
                let binding = operator_binding(&attacker_peer, &attacker_vk, &cluster, &op_sk);

                // The Hello claims the VICTIM's id while carrying the attacker's
                // key and the attacker's own binding.
                let unsigned = MeshHello {
                    peer_id: victim_peer.clone(),
                    endpoint: "127.0.0.1:9000".parse().unwrap(),
                    classical_pubkey: vec![1, 2, 3],
                    pqc_pubkey: vec![4, 5, 6],
                    session_id: SessionId::new(),
                    identity_vk: encode_identity_vk(&attacker_vk),
                    identity_grant: binding.encode(),
                    handshake_signature: Vec::new(),
                };
                let signature =
                    HybridEd25519Mldsa::sign(&attacker_sk, &hello_signed_payload(&unsigned));
                let hello = MeshHello {
                    handshake_signature: signature.to_bytes(),
                    ..unsigned
                };

                // The binding is for the attacker's id, NOT the claimed one.
                assert_ne!(
                    binding.peer_id_bytes,
                    *victim_peer.0.as_bytes(),
                    "the binding must be for a different id than the one claimed"
                );

                // A legitimate binding for the attacker's OWN id, presented
                // under a claim to be someone else, must be refused.
                let result =
                    verify_hello(&hello, &op_vk, &cluster, Utc::now().timestamp(), || true);
                assert!(
                    matches!(result, Err(HandshakeError::BadIdentityBinding)),
                    "a Hello claiming an id the operator did not bind this key to \
                     must be refused, got {result:?}"
                );

                // The control: the same Hello claiming its OWN id is accepted,
                // so the refusal above is the peer-id check and not something
                // else about the message.
                let honest_unsigned = MeshHello {
                    peer_id: attacker_peer.clone(),
                    identity_grant: binding.encode(),
                    ..hello.clone()
                };
                let signature =
                    HybridEd25519Mldsa::sign(&attacker_sk, &hello_signed_payload(&honest_unsigned));
                let honest = MeshHello {
                    handshake_signature: signature.to_bytes(),
                    ..honest_unsigned
                };
                verify_hello(&honest, &op_vk, &cluster, Utc::now().timestamp(), || true)
                    .expect("a Hello claiming its own bound id must be accepted");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn response_verify_rejects_an_unbound_responder_identity() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(response_verify_body)
            .unwrap()
            .join()
            .unwrap();
    }

    fn response_verify_body() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let (op_sk, op_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let cluster = ClusterId::new();

        // The initiator.
        let (init_sk, init_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let init_peer = PeerId::new();
        let init_binding = operator_binding(&init_peer, &init_vk, &cluster, &op_sk);
        let session_id = SessionId::new();
        let hello_unsigned = MeshHello {
            peer_id: init_peer.clone(),
            endpoint: "127.0.0.1:9000".parse().unwrap(),
            classical_pubkey: vec![1, 2, 3],
            pqc_pubkey: vec![4, 5, 6],
            session_id: session_id.clone(),
            identity_vk: encode_identity_vk(&init_vk),
            identity_grant: init_binding.encode(),
            handshake_signature: Vec::new(),
        };
        let sig = HybridEd25519Mldsa::sign(&init_sk, &hello_signed_payload(&hello_unsigned));
        let hello = MeshHello {
            handshake_signature: sig.to_bytes(),
            ..hello_unsigned
        };

        // The responder, properly bound.
        let (resp_sk, resp_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let resp_peer = PeerId::new();
        let resp_binding = operator_binding(&resp_peer, &resp_vk, &cluster, &op_sk);
        let build_response = |binding_bytes: Vec<u8>, peer: PeerId| {
            let unsigned = MeshHelloResponse {
                peer_id: peer,
                endpoint: "127.0.0.1:9001".parse().unwrap(),
                classical_pubkey: vec![7, 8, 9],
                pqc_ciphertext: vec![10, 11],
                session_id: session_id.clone(),
                identity_vk: encode_identity_vk(&resp_vk),
                identity_grant: binding_bytes,
                handshake_signature: Vec::new(),
            };
            let payload = response_signed_payload(&unsigned, &hello_transcript_hash(&hello));
            let sig = HybridEd25519Mldsa::sign(&resp_sk, &payload);
            MeshHelloResponse {
                handshake_signature: sig.to_bytes(),
                ..unsigned
            }
        };

        // A properly bound response verifies.
        let good = build_response(resp_binding.encode(), resp_peer.clone());
        verify_hello_response(&good, &hello, &op_vk, &cluster, Utc::now().timestamp())
            .expect("a properly bound response must verify");

        // The same response with NO binding is refused. This is the case that
        // used to pass: the signature is valid, but nothing proved the key
        // belongs to the peer id claiming it.
        let unbound = build_response(Vec::new(), resp_peer.clone());
        assert!(
            verify_hello_response(&unbound, &hello, &op_vk, &cluster, Utc::now().timestamp())
                .is_err(),
            "a response with no operator binding must be refused"
        );

        // A binding belonging to a DIFFERENT peer id is refused: an
        // operator-blessed peer must not be able to answer as another.
        let other_peer = PeerId::new();
        let other_binding = operator_binding(&other_peer, &resp_vk, &cluster, &op_sk);
        let impostor = build_response(other_binding.encode(), resp_peer.clone());
        assert!(
            verify_hello_response(&impostor, &hello, &op_vk, &cluster, Utc::now().timestamp())
                .is_err(),
            "a binding for another peer id must not be accepted"
        );

        // And a binding for a different cluster is refused.
        let other_cluster = ClusterId::new();
        let wrong_cluster_binding = operator_binding(&resp_peer, &resp_vk, &other_cluster, &op_sk);
        let wrong_cluster = build_response(wrong_cluster_binding.encode(), resp_peer.clone());
        assert!(matches!(
            verify_hello_response(
                &wrong_cluster,
                &hello,
                &op_vk,
                &cluster,
                Utc::now().timestamp()
            ),
            Err(HandshakeError::WrongCluster)
        ));
    }
}
