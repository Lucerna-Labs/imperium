use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_protocol::{PeerId, SessionId};
use parking_lot::RwLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    Discovered,
    Connecting,
    Connected,
    Disconnected,
}

pub struct PeerInfo {
    pub endpoints: Vec<SocketAddr>,
    pub state: PeerState,
    pub session_id: Option<SessionId>,
    pub capabilities: Vec<String>,
    pub last_seen: DateTime<Utc>,
}

impl PeerInfo {
    fn new(endpoints: Vec<SocketAddr>) -> Self {
        Self {
            endpoints,
            state: PeerState::Discovered,
            session_id: None,
            capabilities: Vec::new(),
            last_seen: Utc::now(),
        }
    }
}

/// A stable per-peer token, used for per-link accounting (cover traffic).
///
/// Derived from the peer id, so it survives a rekey, which changes the session
/// id but not the peer.
pub(crate) fn peer_token(peer_id: &PeerId) -> u64 {
    let bytes = peer_id.0.as_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("a uuid is 16 bytes"))
}

pub struct PeerManager {
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_peer(&self, peer_id: PeerId, endpoints: Vec<SocketAddr>) {
        let mut peers = self.peers.write();
        peers
            .entry(peer_id.clone())
            .and_modify(|info| {
                info.endpoints = endpoints.clone();
                info.last_seen = Utc::now();
            })
            .or_insert_with(|| PeerInfo::new(endpoints));
    }

    pub fn update_state(&self, peer_id: &PeerId, state: PeerState) {
        if let Some(info) = self.peers.write().get_mut(peer_id) {
            info.state = state;
            info.last_seen = Utc::now();
        }
    }

    pub fn set_session(&self, peer_id: &PeerId, session_id: SessionId) {
        if let Some(info) = self.peers.write().get_mut(peer_id) {
            info.session_id = Some(session_id);
            info.state = PeerState::Connected;
            info.last_seen = Utc::now();
        }
    }

    pub fn get_state(&self, peer_id: &PeerId) -> Option<PeerState> {
        self.peers.read().get(peer_id).map(|i| i.state.clone())
    }

    pub fn get_endpoints(&self, peer_id: &PeerId) -> Option<Vec<SocketAddr>> {
        self.peers.read().get(peer_id).map(|i| i.endpoints.clone())
    }

    pub fn last_seen(&self, peer_id: &PeerId) -> Option<DateTime<Utc>> {
        self.peers.read().get(peer_id).map(|i| i.last_seen)
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, info)| info.state == PeerState::Connected)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn all_peers(&self) -> Vec<PeerId> {
        self.peers.read().keys().cloned().collect()
    }

    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    pub fn set_capabilities(&self, peer_id: &PeerId, capabilities: Vec<String>) {
        if let Some(info) = self.peers.write().get_mut(peer_id) {
            info.capabilities = capabilities;
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_query_peer() {
        let mgr = PeerManager::new();
        let peer = PeerId::new();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        mgr.add_peer(peer.clone(), vec![addr]);

        assert_eq!(mgr.get_state(&peer), Some(PeerState::Discovered));
        assert_eq!(mgr.peer_count(), 1);
        assert!(mgr.last_seen(&peer).is_some());
    }

    #[test]
    fn connected_peers_filter() {
        let mgr = PeerManager::new();
        let p1 = PeerId::new();
        let p2 = PeerId::new();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        mgr.add_peer(p1.clone(), vec![addr]);
        mgr.add_peer(p2.clone(), vec![addr]);
        mgr.update_state(&p1, PeerState::Connected);

        let connected = mgr.connected_peers();
        assert_eq!(connected.len(), 1);
        assert_eq!(connected[0], p1);
    }
}
