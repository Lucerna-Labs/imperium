//! Live two-daemon pressure test for the no-copy observer.
//!
//! A real handshake runs over loopback, a real sealed payload crosses, and the
//! observer records redacted frame classes while the closure and sweep run.
//! The VPN path is untouched: the observer only reads sealed frame lengths
//! before send and after open, plus lightcone receipts already on the bus.

use std::sync::Arc;
use std::time::Duration;

use imperium_net_mesh::{MeshDaemon, MeshNodeConfig, PeerConfig};
use imperium_nocopy_vpn_observer::VpnObserver;
use imperium_protocol::{ClusterId, PeerId};
use tokio::net::UdpSocket;

const BIG_STACK: usize = 64 * 1024 * 1024;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn with_big_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(BIG_STACK)
        .spawn(body)
        .expect("spawn test thread")
        .join()
        .expect("test thread panicked");
}

#[test]
fn nocopy_observer_records_live_sealed_traffic() {
    with_big_stack(|| {
        runtime().block_on(async {
            use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey, HybridVerifyingKey};
            use rand::rngs::OsRng;
            use tokio::sync::Notify;
            use tokio::task::JoinHandle;

            let mut rng = OsRng;
            let (op_signing, op_verifying) = HybridEd25519Mldsa::generate_keypair(&mut rng);
            let operator_signing = |signing: &HybridSigningKey| {
                let bytes = HybridEd25519Mldsa::signing_key_to_bytes(signing);
                HybridEd25519Mldsa::signing_key_from_bytes(&bytes).expect("operator key round trip")
            };
            let (signing_a, verifying_a) = HybridEd25519Mldsa::generate_keypair(&mut rng);
            let (signing_b, verifying_b) = HybridEd25519Mldsa::generate_keypair(&mut rng);
            let cluster_id = ClusterId::new();
            let peer_a = PeerId::new();
            let peer_b = PeerId::new();

            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();

            let node_config =
                |peer_id: PeerId,
                 signing: HybridSigningKey,
                 verifying: HybridVerifyingKey,
                 bind: std::net::SocketAddr,
                 peer: Option<(PeerId, std::net::SocketAddr)>| {
                    MeshNodeConfig {
                        peer_id,
                        cluster_id: cluster_id.clone(),
                        bind_addr: bind,
                        peers: peer
                            .into_iter()
                            .map(|(peer_id, addr)| PeerConfig {
                                peer_id,
                                addr: Some(addr),
                                pinned_identity_vk: None,
                                routes: Vec::new(),
                            })
                            .collect(),
                        identity_signing_key: signing,
                        identity_verifying_key: verifying,
                        operator_signing_key: operator_signing(&op_signing),
                        operator_verifying_key: op_verifying.clone(),
                        identity_ttl: chrono::Duration::hours(1),
                        handshake_retry: Duration::from_millis(500),
                        max_handshake_attempts: 8,
                        session_idle_secs: 120,
                        session_max_bytes: None,
                    }
                };

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon_a, _rx_a) = MeshDaemon::with_socket(
                node_config(
                    peer_a,
                    signing_a,
                    verifying_a,
                    addr_a,
                    Some((peer_b.clone(), addr_b)),
                ),
                Arc::clone(&bus),
                socket_a,
            );
            let (daemon_b, mut rx_b) = MeshDaemon::with_socket(
                node_config(peer_b.clone(), signing_b, verifying_b, addr_b, None),
                Arc::clone(&bus),
                socket_b,
            );

            let mut tasks: Vec<JoinHandle<()>> = Vec::new();
            for daemon in [Arc::clone(&daemon_a), Arc::clone(&daemon_b)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }

            assert!(
                daemon_a
                    .wait_established(std::time::Duration::from_secs(10))
                    .await,
                "initiator never established; stats {:?}",
                daemon_a.stats()
            );
            assert!(
                daemon_b
                    .wait_established(std::time::Duration::from_secs(10))
                    .await,
                "responder never established; stats {:?}",
                daemon_b.stats()
            );

            let mut observer = VpnObserver::new();
            let payload = vec![0xABu8; 200];
            let sealed = daemon_a
                .seal_payload_frame(&payload)
                .await
                .expect("live session seals");
            observer.observe_frame(sealed.len());
            // A routes to B: B's peer table has no configured peers, so only
            // `send_payload_to` names the destination. Reading from B's own
            // inbox proves the sealed frame crossed loopback and opened.
            daemon_a
                .send_payload_to(&peer_b, &payload)
                .await
                .expect("live session sends");

            let inbound = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
                .await
                .expect("loopback delivery arrives")
                .expect("inbound channel open");
            observer.observe_frame(inbound.payload.len() + 64);
            assert_eq!(inbound.payload, payload);

            // Measurement evidence only: the closure records redacted classes,
            // and the sweep runs from the observed seed. No verdicts.
            let record = observer.generator_snapshot(4);
            assert!(!record.visited.is_empty());
            let deltas = observer.linear_sweep();
            assert_eq!(deltas.len(), 3);
            assert!(observer.frames() >= 2);
            let _ = observer.second_copy_count(&record, 4);
        });
    });
}
