use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_net_crypto::HybridSessionKey;

use crate::crypto::{CryptoError, DirectionKeys, ReplayWindow};
use imperium_protocol::{PeerId, SessionId};
use parking_lot::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0:?}")]
    NotFound(SessionId),
    #[error("session expired: {0:?}")]
    Expired(SessionId),
    #[error("key exchange failed: {0}")]
    KexFailed(String),
    #[error("peer already has an active session")]
    DuplicateSession,
    #[error("session id already belongs to another peer: {0:?}")]
    SessionIdInUse(SessionId),
    #[error("session not established: {0:?}")]
    NotEstablished(SessionId),
    #[error("session has no key material: {0:?}")]
    NoKey(SessionId),
    #[error("replayed or out-of-window frame")]
    Replay,
    #[error("send counter exhausted: rekey required before any further seal")]
    CounterExhausted,
    #[error("rekey required: policy limit exceeded (re-establish the session)")]
    RekeyRequired,
}

/// Nonce-reuse guard: sealing halts this many counters before u64::MAX so a
/// counter can never wrap or stick. The margin is generous on purpose — a
/// session sealing 2^64 frames is not a real workload, and the fail-closed
/// error forces rotation long before the catastrophic case.
pub const COUNTER_EXHAUST_MARGIN: u64 = 1 << 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    Established,
    Expired,
}

pub struct PeerSession {
    pub session_id: SessionId,
    pub peer_id: PeerId,
    pub remote_addr: SocketAddr,
    pub state: SessionState,
    // NOTE (Item 9): the pre-refactor code kept a redundant
    // `Option<Arc<HybridSessionKey>>` copy here alongside direction_keys.
    // It was write-only (never read outside establish/rekey) and doubled
    // the key's lifetime in memory, so it is removed. DirectionKeys remain
    // the single key holder (Zeroize+ZeroizeOnDrop in crypto.rs).
    pub established_at: Option<DateTime<Utc>>,
    pub last_activity: DateTime<Utc>,
    pub ping_seq: u64,
    pub rtt_ms: Option<u64>,
    /// True for the peer that created the session (the KEX initiator).
    pub initiator: bool,
    /// Per-direction AEAD keys, derived when the session is established.
    direction_keys: Option<DirectionKeys>,
    /// Outgoing frame counter for this session's send direction.
    send_counter: u64,
    /// Plaintext bytes sealed under the current direction keys, counted against
    /// the budget the caller passes to `seal`. That budget is
    /// `MeshNodeConfig::session_max_bytes`, sourced from `--rekey-bytes` — NOT
    /// `RekeyPolicy.max_key_bytes`, which `imperium-net-transport` validates and
    /// reports but the mesh does not enforce.
    bytes_sealed_in_epoch: u64,
    /// Replay window for this session's receive direction.
    replay: ReplayWindow,
}

impl PeerSession {
    fn new(
        session_id: SessionId,
        peer_id: PeerId,
        remote_addr: SocketAddr,
        initiator: bool,
    ) -> Self {
        Self {
            session_id,
            peer_id,
            remote_addr,
            state: SessionState::Handshaking,
            established_at: None,
            last_activity: Utc::now(),
            ping_seq: 0,
            rtt_ms: None,
            initiator,
            direction_keys: None,
            send_counter: 0,
            bytes_sealed_in_epoch: 0,
            replay: ReplayWindow::default(),
        }
    }

    /// Adopt fresh key material for this session.
    ///
    /// The two operator-certified identities are fed into the key derivation, so
    /// the direction keys are bound to WHO negotiated them and not merely to the
    /// secret. `derive_bound` existed for this but was never called on the live
    /// path, so the property its documentation claimed was absent.
    pub fn establish(
        &mut self,
        key: HybridSessionKey,
        initiator_identity: &[u8],
        responder_identity: &[u8],
    ) {
        self.direction_keys = Some(DirectionKeys::derive_bound(
            &key,
            self.initiator,
            initiator_identity,
            responder_identity,
        ));
        self.state = SessionState::Established;
        self.established_at = Some(Utc::now());
        self.last_activity = Utc::now();
        self.send_counter = 0;
        self.bytes_sealed_in_epoch = 0;
    }

    /// Rotate the session onto fresh key material (rekey): new direction
    /// keys, counters and byte accounting reset. The caller performs the
    /// actual KEX exchange; this only adopts the resulting key.
    pub fn rekey(
        &mut self,
        key: HybridSessionKey,
        initiator_identity: &[u8],
        responder_identity: &[u8],
    ) -> Result<(), SessionError> {
        if !self.is_established() {
            return Err(SessionError::NotEstablished(self.session_id.clone()));
        }
        self.direction_keys = Some(DirectionKeys::derive_bound(
            &key,
            self.initiator,
            initiator_identity,
            responder_identity,
        ));
        self.send_counter = 0;
        self.bytes_sealed_in_epoch = 0;
        self.established_at = Some(Utc::now());
        self.last_activity = Utc::now();
        Ok(())
    }

    /// Encrypt a payload for this session's send direction. Returns the
    /// frame counter used (rides in the clear header) and the ciphertext
    /// (ciphertext + 16-byte Poly1305 tag).
    ///
    /// Fail-closed on counter exhaustion: sealing halts with
    /// `CounterExhausted` COUNTER_EXHAUST_MARGIN counters before u64::MAX
    /// and never wraps or sticks (the old saturating_add path reused the
    /// final nonce under the same key — catastrophic for ChaCha20-Poly1305).
    /// `max_key_bytes` enforces RekeyPolicy on the data path: once the
    /// epoch budget is spent, seal returns `RekeyRequired` until `rekey()`
    /// rotates the direction keys.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        max_key_bytes: Option<u64>,
    ) -> Result<(u64, Vec<u8>), SessionError> {
        if !self.is_established() {
            return Err(SessionError::NotEstablished(self.session_id.clone()));
        }
        if self.send_counter >= u64::MAX - COUNTER_EXHAUST_MARGIN {
            return Err(SessionError::CounterExhausted);
        }
        if let Some(budget) = max_key_bytes {
            if self
                .bytes_sealed_in_epoch
                .saturating_add(plaintext.len() as u64)
                > budget
            {
                return Err(SessionError::RekeyRequired);
            }
        }
        let keys = self
            .direction_keys
            .as_ref()
            .ok_or_else(|| SessionError::NoKey(self.session_id.clone()))?;
        let counter = self.send_counter;
        self.send_counter += 1;
        self.bytes_sealed_in_epoch = self
            .bytes_sealed_in_epoch
            .saturating_add(plaintext.len() as u64);
        Ok((counter, keys.seal(counter, plaintext)))
    }

    /// Decrypt an inbound frame. AEAD open runs FIRST (authenticity before
    /// replay bookkeeping), then the replay window tracks the counter — so
    /// forged frames never pollute the bitmap (Item 10).
    pub fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.is_established() {
            return Err(SessionError::NotEstablished(self.session_id.clone()));
        }
        let keys = self
            .direction_keys
            .as_ref()
            .ok_or_else(|| SessionError::NoKey(self.session_id.clone()))?;
        let plaintext = keys
            .open(counter, ciphertext)
            .map_err(|e: CryptoError| SessionError::KexFailed(e.to_string()))?;
        // Only authentic frames advance the replay window. A forged frame
        // that guesses an unseen in-window counter fails open above and
        // leaves the bitmap untouched, so it cannot shadow the real frame.
        self.replay
            .accept(counter)
            .map_err(|_| SessionError::Replay)?;
        Ok(plaintext)
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    pub fn next_ping_seq(&mut self) -> u64 {
        self.ping_seq += 1;
        self.ping_seq
    }

    pub fn record_rtt(&mut self, rtt_ms: u64) {
        self.rtt_ms = Some(rtt_ms);
        self.touch();
    }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<SessionId, PeerSession>>>,
    peer_sessions: Arc<RwLock<HashMap<PeerId, SessionId>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            peer_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_session(
        &self,
        peer_id: PeerId,
        remote_addr: SocketAddr,
        initiator: bool,
    ) -> Result<SessionId, SessionError> {
        let session_id = SessionId::new();
        // Keep the two indexes under write locks from validation through
        // insertion. Otherwise concurrent handshakes can both pass a read
        // check and leave an orphaned or wrongly owned session.
        let mut sessions = self.sessions.write();
        let mut peer_sessions = self.peer_sessions.write();
        if peer_sessions.contains_key(&peer_id) {
            return Err(SessionError::DuplicateSession);
        }
        if sessions.contains_key(&session_id) {
            return Err(SessionError::SessionIdInUse(session_id));
        }
        let session = PeerSession::new(session_id.clone(), peer_id.clone(), remote_addr, initiator);
        sessions.insert(session_id.clone(), session);
        peer_sessions.insert(peer_id, session_id.clone());

        Ok(session_id)
    }

    /// Register a session with a known id (the responder adopting the
    /// initiator's session during handshake).
    pub fn adopt_session(
        &self,
        session_id: SessionId,
        peer_id: PeerId,
        remote_addr: SocketAddr,
        initiator: bool,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write();
        let mut peer_sessions = self.peer_sessions.write();
        if peer_sessions.contains_key(&peer_id) {
            return Err(SessionError::DuplicateSession);
        }
        if sessions.contains_key(&session_id) {
            return Err(SessionError::SessionIdInUse(session_id));
        }
        let session = PeerSession::new(session_id.clone(), peer_id.clone(), remote_addr, initiator);
        sessions.insert(session_id.clone(), session);
        peer_sessions.insert(peer_id, session_id);
        Ok(())
    }

    pub fn establish_session(
        &self,
        session_id: &SessionId,
        key: HybridSessionKey,
        initiator_identity: &[u8],
        responder_identity: &[u8],
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.establish(key, initiator_identity, responder_identity);
        Ok(())
    }

    /// Encrypt for the session's send direction (see `PeerSession::seal`).
    /// `max_key_bytes` carries the active RekeyPolicy budget; None disables
    /// the byte check (counter-exhaustion guard always applies).
    pub fn seal_for_session(
        &self,
        session_id: &SessionId,
        plaintext: &[u8],
        max_key_bytes: Option<u64>,
    ) -> Result<(u64, Vec<u8>), SessionError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.seal(plaintext, max_key_bytes)
    }

    /// Adopt fresh key material for an established session (rekey rotation).
    pub fn rekey_session(
        &self,
        session_id: &SessionId,
        key: HybridSessionKey,
        initiator_identity: &[u8],
        responder_identity: &[u8],
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.rekey(key, initiator_identity, responder_identity)
    }

    /// Decrypt an inbound frame for the session (see `PeerSession::open`).
    pub fn open_for_session(
        &self,
        session_id: &SessionId,
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.clone()))?;
        session.open(counter, ciphertext)
    }

    pub fn get_session_state(&self, session_id: &SessionId) -> Option<SessionState> {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.state.clone())
    }

    pub fn get_session_for_peer(&self, peer_id: &PeerId) -> Option<SessionId> {
        self.peer_sessions.read().get(peer_id).cloned()
    }

    /// Require both indexes to agree before a peer's session can be used.
    pub fn session_belongs_to_peer(&self, session_id: &SessionId, peer_id: &PeerId) -> bool {
        let sessions = self.sessions.read();
        let peer_sessions = self.peer_sessions.read();
        sessions
            .get(session_id)
            .is_some_and(|session| &session.peer_id == peer_id)
            && peer_sessions.get(peer_id) == Some(session_id)
    }

    /// Reverse index: the session whose recorded remote address matches
    /// `addr`, in any handshake state. The receive loop needs this because an
    /// inbound datagram arrives with nothing but a source address, and
    /// `open_for_session` requires the session first.
    ///
    /// The scan is linear on purpose: mesh peer counts are small, and the
    /// address a datagram arrives from is NOT authoritative. Behind NAT the
    /// source address differs from the endpoint the peer advertised, so
    /// callers must treat the handshake (which learns the live address) as
    /// the thing that establishes the binding, not configuration.
    pub fn session_for_addr(&self, addr: &SocketAddr) -> Option<SessionId> {
        self.sessions
            .read()
            .values()
            .find(|s| s.remote_addr == *addr)
            .map(|s| s.session_id.clone())
    }

    /// The peer a session belongs to.
    pub fn session_peer_id(&self, session_id: &SessionId) -> Option<PeerId> {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.peer_id.clone())
    }

    /// The recorded remote address for a session.
    pub fn session_remote_addr(&self, session_id: &SessionId) -> Option<SocketAddr> {
        self.sessions.read().get(session_id).map(|s| s.remote_addr)
    }

    /// Whether the local side created (initiated) the session.
    pub fn session_is_initiator(&self, session_id: &SessionId) -> Option<bool> {
        self.sessions.read().get(session_id).map(|s| s.initiator)
    }

    /// Rebind a session's recorded remote address. Used when the address a
    /// peer is actually reachable at is learned from a live datagram rather
    /// than from configuration (NAT, roaming, or a relayed path).
    pub fn rebind_session_addr(&self, session_id: &SessionId, addr: SocketAddr) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.remote_addr = addr;
        }
    }

    pub fn touch_session(&self, session_id: &SessionId) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.touch();
        }
    }

    pub fn record_pong(&self, session_id: &SessionId, rtt_ms: u64) {
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.record_rtt(rtt_ms);
        }
    }

    pub fn remove_session(&self, session_id: &SessionId) {
        let mut sessions = self.sessions.write();
        let mut peer_sessions = self.peer_sessions.write();
        if let Some(session) = sessions.remove(session_id) {
            if peer_sessions.get(&session.peer_id) == Some(session_id) {
                peer_sessions.remove(&session.peer_id);
            }
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_established())
            .count()
    }

    pub fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.read().keys().cloned().collect()
    }

    pub fn expire_stale_sessions(&self, max_idle_secs: i64) -> Vec<SessionId> {
        let now = Utc::now();
        let mut expired = Vec::new();

        let mut sessions = self.sessions.write();
        let session_ids: Vec<SessionId> = sessions.keys().cloned().collect();

        for sid in session_ids {
            if let Some(session) = sessions.get(&sid) {
                let idle = (now - session.last_activity).num_seconds();
                if idle > max_idle_secs {
                    expired.push(sid.clone());
                }
            }
        }

        for sid in &expired {
            if let Some(session) = sessions.remove(sid) {
                self.peer_sessions.write().remove(&session.peer_id);
            }
        }

        expired
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_crypto::HybridX25519Mlkem;
    use rand::rngs::OsRng;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000))
    }

    #[test]
    fn create_and_establish_session() {
        // Identity bytes are empty here on purpose: these tests exercise session
        // mechanics, and the identity binding is covered by the handshake tests
        // and by `crypto::tests::identity_binding_changes_direction_keys`.
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        let sid = mgr.create_session(peer.clone(), test_addr(), true).unwrap();

        assert_eq!(mgr.get_session_state(&sid), Some(SessionState::Handshaking));

        let mut rng = OsRng;
        let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);

        mgr.establish_session(&sid, key, &[], &[]).unwrap();
        assert_eq!(mgr.get_session_state(&sid), Some(SessionState::Established));
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn duplicate_session_rejected() {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        mgr.create_session(peer.clone(), test_addr(), true).unwrap();
        assert!(mgr.create_session(peer, test_addr(), true).is_err());
    }

    #[test]
    fn adopted_id_cannot_replace_another_peers_session() {
        let mgr = SessionManager::new();
        let first = PeerId::new();
        let second = PeerId::new();
        let session_id = SessionId::new();
        let other_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        mgr.adopt_session(session_id.clone(), first.clone(), test_addr(), false)
            .unwrap();

        let error = mgr
            .adopt_session(session_id.clone(), second.clone(), other_addr, false)
            .unwrap_err();
        assert!(matches!(error, SessionError::SessionIdInUse(id) if id == session_id));
        assert_eq!(mgr.get_session_for_peer(&first), Some(session_id.clone()));
        assert_eq!(mgr.get_session_for_peer(&second), None);
        assert!(mgr.session_belongs_to_peer(&session_id, &first));
        assert!(!mgr.session_belongs_to_peer(&session_id, &second));
        assert_eq!(mgr.session_peer_id(&session_id), Some(first));
        assert_eq!(mgr.session_remote_addr(&session_id), Some(test_addr()));
        assert_eq!(mgr.all_session_ids(), vec![session_id]);
    }

    #[test]
    fn concurrent_adoption_of_one_id_has_one_owner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let mgr = Arc::new(SessionManager::new());
        let session_id = SessionId::new();
        let peers = [PeerId::new(), PeerId::new()];
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = peers
            .iter()
            .cloned()
            .map(|peer| {
                let mgr = Arc::clone(&mgr);
                let barrier = Arc::clone(&barrier);
                let id = session_id.clone();
                thread::spawn(move || {
                    barrier.wait();
                    mgr.adopt_session(id, peer, test_addr(), false)
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(mgr.all_session_ids(), vec![session_id.clone()]);
        let owner = mgr.session_peer_id(&session_id).unwrap();
        assert_eq!(mgr.get_session_for_peer(&owner), Some(session_id));
        let other = peers.into_iter().find(|peer| peer != &owner).unwrap();
        assert_eq!(mgr.get_session_for_peer(&other), None);
    }

    #[test]
    fn concurrent_creation_for_one_peer_has_one_session() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let mgr = Arc::new(SessionManager::new());
        let peer = PeerId::new();
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let mgr = Arc::clone(&mgr);
                let barrier = Arc::clone(&barrier);
                let peer = peer.clone();
                thread::spawn(move || {
                    barrier.wait();
                    mgr.create_session(peer, test_addr(), true)
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        let session_id = mgr.get_session_for_peer(&peer).unwrap();
        assert_eq!(mgr.all_session_ids(), vec![session_id.clone()]);
        assert!(mgr.session_belongs_to_peer(&session_id, &peer));
    }

    #[test]
    fn remove_session_clears_peer_mapping() {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        let sid = mgr.create_session(peer.clone(), test_addr(), true).unwrap();
        mgr.remove_session(&sid);
        assert!(mgr.get_session_for_peer(&peer).is_none());
        assert_eq!(mgr.active_session_count(), 0);
    }

    fn established_mgr() -> (SessionManager, SessionId) {
        let mgr = SessionManager::new();
        let peer = PeerId::new();
        let sid = mgr.create_session(peer, test_addr(), true).unwrap();
        let mut rng = OsRng;
        let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
        mgr.establish_session(&sid, key, &[], &[]).unwrap();
        (mgr, sid)
    }

    #[test]
    fn seal_open_round_trip() {
        // Same-direction seal/open on one manager is NOT expected to work
        // (direction keys differ per role) — use an initiator/responder pair
        // like transport.rs established_pair does.
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let peer = PeerId::new();
        let sid = initiator
            .create_session(peer.clone(), test_addr(), true)
            .unwrap();
        responder
            .adopt_session(sid.clone(), peer, test_addr(), false)
            .unwrap();
        let mut rng = OsRng;
        let (secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encap, initiator_key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
        let responder_key = HybridX25519Mlkem::decapsulate(secret, &encap).unwrap();
        initiator
            .establish_session(&sid, initiator_key, &[], &[])
            .unwrap();
        responder
            .establish_session(&sid, responder_key, &[], &[])
            .unwrap();

        let (counter, ct) = initiator
            .seal_for_session(&sid, b"hello mesh", None)
            .unwrap();
        assert_eq!(counter, 0);
        assert_eq!(
            responder.open_for_session(&sid, counter, &ct).unwrap(),
            b"hello mesh"
        );
        // Counters advance monotonically — no nonce reuse.
        let (counter2, ct2) = initiator.seal_for_session(&sid, b"again", None).unwrap();
        assert_eq!(counter2, 1);
        assert_eq!(
            responder.open_for_session(&sid, counter2, &ct2).unwrap(),
            b"again"
        );
    }

    #[test]
    fn counter_exhaustion_fails_closed_without_nonce_reuse() {
        let (mgr, sid) = established_mgr();
        // Drive the counter to the exhaustion threshold directly.
        {
            let mut sessions = mgr.sessions.write();
            let session = sessions.get_mut(&sid).unwrap();
            session.send_counter = u64::MAX - COUNTER_EXHAUST_MARGIN;
        }
        assert!(matches!(
            mgr.seal_for_session(&sid, b"one too many", None),
            Err(SessionError::CounterExhausted)
        ));
        // Counter did not advance or wrap — still exhausted, still no reuse.
        assert!(matches!(
            mgr.seal_for_session(&sid, b"still exhausted", None),
            Err(SessionError::CounterExhausted)
        ));
    }

    #[test]
    fn rekey_policy_enforced_on_data_path() {
        let (mgr, sid) = established_mgr();
        // Tiny budget: first 2-byte seal fits exactly, next byte exceeds.
        assert!(mgr.seal_for_session(&sid, b"ab", Some(2)).is_ok());
        assert!(matches!(
            mgr.seal_for_session(&sid, b"c", Some(2)),
            Err(SessionError::RekeyRequired)
        ));
        // Rotating with fresh key material resets the epoch budget.
        let mut rng = OsRng;
        let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
        mgr.rekey_session(&sid, key, &[], &[]).unwrap();
        assert!(mgr.seal_for_session(&sid, b"cd", Some(4)).is_ok());
    }

    #[test]
    fn forged_frame_does_not_pollute_replay_window() {
        // Item 10: decrypt-then-track — a forged frame guessing an unseen
        // in-window counter fails AEAD open and leaves the bitmap untouched,
        // so the genuine frame still decrypts afterwards.
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let peer = PeerId::new();
        let sid = initiator
            .create_session(peer.clone(), test_addr(), true)
            .unwrap();
        responder
            .adopt_session(sid.clone(), peer, test_addr(), false)
            .unwrap();
        let mut rng = OsRng;
        let (secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encap, initiator_key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
        let responder_key = HybridX25519Mlkem::decapsulate(secret, &encap).unwrap();
        initiator
            .establish_session(&sid, initiator_key, &[], &[])
            .unwrap();
        responder
            .establish_session(&sid, responder_key, &[], &[])
            .unwrap();

        let (c0, ct0) = initiator.seal_for_session(&sid, b"genuine", None).unwrap();
        assert_eq!(c0, 0);
        // Forged frame guessing the real counter: fails AEAD open, must not
        // mark the counter as seen.
        let mut forged = ct0.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert!(responder.open_for_session(&sid, 0, &forged).is_err());
        // Genuine frame still opens — bitmap was not polluted by the forgery.
        assert_eq!(
            responder.open_for_session(&sid, 0, &ct0).unwrap(),
            b"genuine"
        );
    }
}
