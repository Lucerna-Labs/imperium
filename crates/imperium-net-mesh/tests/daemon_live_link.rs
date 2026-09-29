//! Two daemons, two real UDP sockets, one live handshake.
//!
//! This test did not exist before the daemon. Nothing bound a listening
//! socket, ran a receive loop, drove the handshake, or resolved an inbound
//! datagram to a session by its source address. Everything here is real UDP
//! on 127.0.0.1 — no mocks, no hand-built sessions, no hand-passed session ids.
//!
//! It also records what a live listener actually exposes rather than asserting
//! safety: the handshake datagram size, and the fact that an unauthenticated
//! Hello from an unknown address reaches a full hybrid signature verification.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey, HybridVerifyingKey};
use imperium_net_mesh::{
    encode_hello, DaemonError, Destination, MeshDaemon, MeshInbound, MeshNodeConfig, PeerConfig,
};
use imperium_protocol::{
    BusEvent, ClusterId, KillSwitchCommand, KillSwitchState, MeshHello, Message, PeerId, SessionId,
};
use rand::rngs::OsRng;
use spiderweb::BusPublisher;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

/// ML-DSA-65 sign/verify frames need far more than the default 2 MiB stack.
const BIG_STACK: usize = 64 * 1024 * 1024;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Run a test body on a thread with enough stack for hybrid signature work.
fn with_big_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(BIG_STACK)
        .spawn(body)
        .expect("spawn test thread")
        .join()
        .expect("test thread panicked");
}

/// One shared operator trust anchor, which is what a cluster actually has.
struct Operator {
    cluster_id: ClusterId,
    signing: HybridSigningKey,
    verifying: HybridVerifyingKey,
}

fn operator() -> Operator {
    let mut rng = OsRng;
    let (signing, verifying) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    Operator {
        cluster_id: ClusterId::new(),
        signing,
        verifying,
    }
}

impl Operator {
    /// The signing key is not `Clone`, so a node that needs its own copy gets
    /// it through the wire encoding — the same path a real deploy would use.
    fn signing_key(&self) -> HybridSigningKey {
        let bytes = HybridEd25519Mldsa::signing_key_to_bytes(&self.signing);
        HybridEd25519Mldsa::signing_key_from_bytes(&bytes).expect("operator key round trip")
    }
}

struct NodeKeys {
    signing: HybridSigningKey,
    verifying: HybridVerifyingKey,
}

fn node_keys() -> NodeKeys {
    let mut rng = OsRng;
    let (signing, verifying) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    NodeKeys { signing, verifying }
}

fn config(
    operator: &Operator,
    keys: NodeKeys,
    peer_id: PeerId,
    bind_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    expected_peer: Option<PeerId>,
    expected_peer_identity_vk: Option<HybridVerifyingKey>,
) -> MeshNodeConfig {
    MeshNodeConfig {
        peer_id,
        cluster_id: operator.cluster_id.clone(),
        bind_addr,
        peers: match expected_peer {
            Some(peer_id) => vec![PeerConfig {
                peer_id,
                addr: peer_addr,
                pinned_identity_vk: expected_peer_identity_vk,
                routes: Vec::new(),
            }],
            None => Vec::new(),
        },
        identity_signing_key: keys.signing,
        identity_verifying_key: keys.verifying,
        operator_signing_key: operator.signing_key(),
        operator_verifying_key: operator.verifying.clone(),
        identity_ttl: chrono::Duration::hours(1),
        handshake_retry: Duration::from_millis(500),
        max_handshake_attempts: 8,
        session_idle_secs: 120,
        session_max_bytes: None,
    }
}

/// A live two-node pair with both receive loops running.
struct Pair {
    daemon_a: Arc<MeshDaemon>,
    daemon_b: Arc<MeshDaemon>,
    rx_a: mpsc::Receiver<MeshInbound>,
    rx_b: mpsc::Receiver<MeshInbound>,
    peer_a: PeerId,
    peer_b: PeerId,
    addr_b: SocketAddr,
    /// A second handle on A's own UDP socket, so a test can inject bytes that
    /// arrive from A's address — the only way to reach the AEAD path with a
    /// frame the daemon did not itself produce.
    injector: UdpSocket,
    /// The bus both daemons share, so a test can publish operator commands.
    bus: Arc<BusPublisher>,
    tasks: Vec<JoinHandle<()>>,
}

impl Pair {
    async fn spawn() -> Self {
        Self::spawn_with_budget(None).await
    }

    /// Same pair, but with a session key budget so rotation can be exercised.
    async fn spawn_with_budget(session_max_bytes: Option<u64>) -> Self {
        let operator = operator();
        // Bind with std so the address can be duplicated: `try_clone` on a
        // tokio socket does not exist, and a test needs a second handle that
        // sends from A's own address.
        let std_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_a.set_nonblocking(true).unwrap();
        let injector = UdpSocket::from_std(std_a.try_clone().unwrap()).unwrap();
        let socket_a = UdpSocket::from_std(std_a).unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        let peer_a = PeerId::new();
        let peer_b = PeerId::new();
        let keys_a = node_keys();
        let keys_b = node_keys();
        let vk_b = keys_b.verifying.clone();

        // A dials B and pins B's identity key, because the protocol does not
        // bind the responder's identity to its peer id.
        let mut config_a = config(
            &operator,
            keys_a,
            peer_a.clone(),
            addr_a,
            Some(addr_b),
            Some(peer_b.clone()),
            Some(vk_b),
        );
        // B is a pure responder that accepts only A.
        let mut config_b = config(
            &operator,
            keys_b,
            peer_b.clone(),
            addr_b,
            None,
            Some(peer_a.clone()),
            None,
        );
        config_a.session_max_bytes = session_max_bytes;
        config_b.session_max_bytes = session_max_bytes;

        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let (daemon_a, rx_a) = MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
        let (daemon_b, rx_b) = MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);

        let mut tasks = Vec::new();
        for daemon in [Arc::clone(&daemon_a), Arc::clone(&daemon_b)] {
            let shutdown = Arc::new(Notify::new());
            tasks.push(tokio::spawn(async move {
                let _ = daemon.run(shutdown).await;
            }));
        }

        Self {
            daemon_a,
            daemon_b,
            rx_a,
            rx_b,
            peer_a,
            peer_b,
            addr_b,
            injector,
            bus,
            tasks,
        }
    }

    /// Both sides must agree before the pair is usable.
    async fn await_established(&self) {
        assert!(
            self.daemon_a
                .wait_established(Duration::from_secs(10))
                .await,
            "initiator never established; stats {:?}",
            self.daemon_a.stats()
        );
        assert!(
            self.daemon_b
                .wait_established(Duration::from_secs(10))
                .await,
            "responder never established; stats {:?}",
            self.daemon_b.stats()
        );
    }

    async fn recv_b(&mut self) -> MeshInbound {
        tokio::time::timeout(Duration::from_secs(5), self.rx_b.recv())
            .await
            .expect("responder receive timed out")
            .expect("responder inbound channel closed")
    }

    async fn recv_a(&mut self) -> MeshInbound {
        tokio::time::timeout(Duration::from_secs(5), self.rx_a.recv())
            .await
            .expect("initiator receive timed out")
            .expect("initiator inbound channel closed")
    }

    fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

#[test]
fn two_daemons_handshake_and_exchange_payloads_both_ways() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            // Both sides converged on one session, and each learned the
            // other's peer id.
            let (session_a, linked_b) = pair.daemon_a.linked_peer().unwrap();
            let (session_b, linked_a) = pair.daemon_b.linked_peer().unwrap();
            assert_eq!(session_a, session_b, "session ids diverged");
            assert_eq!(linked_b, pair.peer_b);
            assert_eq!(linked_a, pair.peer_a);

            // Data crosses in both directions.
            pair.daemon_a.send_payload(b"from-a").await.unwrap();
            let to_b = pair.recv_b().await;
            assert_eq!(to_b.payload, b"from-a");
            assert_eq!(to_b.peer_id, pair.peer_a);

            pair.daemon_b.send_payload(b"from-b").await.unwrap();
            let to_a = pair.recv_a().await;
            assert_eq!(to_a.payload, b"from-b");
            assert_eq!(to_a.peer_id, pair.peer_b);

            // Each direction has its own counter, so both started near zero.
            assert!(to_a.counter < 4);
            assert!(to_b.counter < 4);

            assert_eq!(pair.daemon_a.stats().handshakes_completed, 1);
            assert_eq!(pair.daemon_b.stats().handshakes_completed, 1);
            assert_eq!(pair.daemon_a.stats().frames_failed, 0);
            assert_eq!(pair.daemon_b.stats().frames_failed, 0);

            pair.stop();
        });
    });
}

/// An unauthenticated probe must be measured, not guessed at. This is also the
/// measurement behind the handshake DoS note: an unrecognised datagram
/// carrying a Hello reaches a full hybrid signature verification.
#[test]
fn an_unauthenticated_probe_is_rejected_and_measured() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let cfg = config(
                &operator,
                node_keys(),
                PeerId::new(),
                addr,
                None,
                None,
                None,
            );
            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon, _rx) = MeshDaemon::with_socket(cfg, Arc::clone(&bus), socket);
            let shutdown = Arc::new(Notify::new());
            let runner = Arc::clone(&daemon);
            let task = tokio::spawn(async move {
                let _ = runner.run(shutdown).await;
            });

            tokio::time::sleep(Duration::from_millis(150)).await;

            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // 1. Garbage. Must be counted, never parsed as anything.
            attacker
                .send_to(b"not a mesh datagram", addr)
                .await
                .unwrap();
            // 2. A well-formed frame with no session for the source.
            let mut frame = vec![0x03u8, 0x00];
            frame.extend_from_slice(&0u64.to_le_bytes());
            frame.push(0x00);
            frame.extend_from_slice(&[0xAB; 8]);
            attacker.send_to(&frame, addr).await.unwrap();
            // 3. A handshake datagram that decodes as a Hello but cannot
            //    authenticate. This is the expensive path: decode succeeds, so
            //    the sender has forced a full hybrid Ed25519 + ML-DSA-65
            //    verification from an address we have never spoken to.
            let forged_hello = MeshHello {
                peer_id: PeerId::new(),
                endpoint: "127.0.0.1:9".parse().unwrap(),
                classical_pubkey: vec![0u8; 32],
                pqc_pubkey: vec![0u8; 1184],
                session_id: SessionId::new(),
                identity_vk: vec![0u8; 64],
                identity_grant: vec![0u8; 200],
                handshake_signature: vec![0u8; 64],
            };
            let datagram = encode_hello(&forged_hello).unwrap();
            attacker.send_to(&datagram, addr).await.unwrap();

            tokio::time::sleep(Duration::from_millis(400)).await;

            let stats = daemon.stats();
            assert!(stats.datagrams_received >= 3, "{stats:?}");
            assert!(
                stats.datagrams_unclassified >= 1,
                "the unrecognized datagram must be counted: {stats:?}"
            );
            assert!(
                stats.frames_failed >= 1,
                "a frame with no session must count as failed: {stats:?}"
            );
            // The gate: a forged Hello earns a cookie and NOTHING else. This is
            // the assertion that failed before the gate existed — a decodable
            // Hello from an unknown address used to force a full hybrid
            // Ed25519 + ML-DSA-65 verification.
            assert_eq!(
                stats.handshake_verifications, 0,
                "a Hello that has not completed the cookie round trip must never \
                 reach verification: {stats:?}"
            );
            assert_eq!(
                stats.handshake_cookies_sent, 1,
                "it must have been answered with a cookie instead: {stats:?}"
            );
            assert_eq!(stats.handshakes_completed, 0);
            assert_eq!(stats.payloads_delivered, 0);
            assert!(!daemon.is_established());

            task.abort();
        });
    });
}

/// A flood of Hellos from one source must not buy verification work.
///
/// The cookie alone does not stop this — a real source can complete the round
/// trip — so the per-source token bucket is what bounds it. Both mechanisms are
/// needed and both are exercised here.
#[test]
fn a_handshake_flood_buys_bounded_work() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let cfg = config(
                &operator,
                node_keys(),
                PeerId::new(),
                addr,
                None,
                None,
                None,
            );
            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon, _rx) = MeshDaemon::with_socket(cfg, Arc::clone(&bus), socket);
            let shutdown = Arc::new(Notify::new());
            let runner = Arc::clone(&daemon);
            let task = tokio::spawn(async move {
                let _ = runner.run(shutdown).await;
            });
            tokio::time::sleep(Duration::from_millis(150)).await;

            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let forged = encode_hello(&MeshHello {
                peer_id: PeerId::new(),
                endpoint: "127.0.0.1:9".parse().unwrap(),
                classical_pubkey: vec![0u8; 32],
                pqc_pubkey: vec![0u8; 1184],
                session_id: SessionId::new(),
                identity_vk: vec![0u8; 64],
                identity_grant: vec![0u8; 200],
                handshake_signature: vec![0u8; 64],
            })
            .unwrap();

            const FLOOD: usize = 200;
            for _ in 0..FLOOD {
                attacker.send_to(&forged, addr).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(600)).await;

            let stats = daemon.stats();
            assert!(
                stats.datagrams_received >= 1,
                "the flood must reach the socket: {stats:?}"
            );
            // The whole point: 200 datagrams, zero post-quantum verifications.
            assert_eq!(
                stats.handshake_verifications, 0,
                "a flood must never reach verification: {stats:?}"
            );
            // And the bucket bounded how much work the flood could buy. Some
            // datagrams are coalesced by the socket buffer, so this is an upper
            // bound rather than an exact count.
            assert!(
                stats.handshake_cookies_sent <= 20,
                "cookies must be rate limited, not one per datagram: {stats:?}"
            );
            // Whatever got past the socket buffer was refused by the bucket.
            assert!(
                stats.handshake_cookies_sent + stats.handshake_rate_limited
                    <= stats.datagrams_received,
                "every datagram is either answered or refused: {stats:?}"
            );
            assert_eq!(stats.handshakes_completed, 0);
            assert!(!daemon.is_established());

            task.abort();
        });
    });
}

/// A handshake message is far larger than a path MTU, so it must be split.
///
/// The message itself is multi-kilobyte hybrid post-quantum material; what goes
/// on the wire is fragments. This measures both halves: the message is larger
/// than any MTU, and it was actually reassembled rather than sent whole.
#[test]
fn handshake_messages_exceed_a_path_mtu_and_are_fragmented() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            let stats_a = pair.daemon_a.stats();
            let stats_b = pair.daemon_b.stats();
            let largest = stats_a
                .handshake_datagram_bytes
                .max(stats_b.handshake_datagram_bytes);
            assert!(
                largest > 1500,
                "expected a handshake message over a 1500-byte MTU, saw {largest}"
            );
            // And it got there by being fragmented, not by being sent whole.
            assert!(
                stats_a.handshake_datagrams_reassembled >= 1
                    && stats_b.handshake_datagrams_reassembled >= 1,
                "both sides must have reassembled a fragmented message: {stats_a:?} {stats_b:?}"
            );
            assert_eq!(
                stats_a.handshake_fragments_rejected, 0,
                "no fragment set should have been refused: {stats_a:?}"
            );

            pair.stop();
        });
    });
}

/// A tampered frame arriving from the peer's own address must fail AEAD and
/// never reach the delivery queue.
#[test]
fn a_tampered_frame_from_the_peers_address_is_rejected() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            let before = pair.daemon_b.stats();

            // Take a real frame the daemon would have sent, then corrupt it.
            let mut frame = pair.daemon_a.seal_payload_frame(b"payload").await.unwrap();
            let last = frame.len() - 1;
            frame[last] ^= 0x01;
            pair.injector.send_to(&frame, pair.addr_b).await.unwrap();

            tokio::time::sleep(Duration::from_millis(400)).await;

            let after = pair.daemon_b.stats();
            assert!(
                after.frames_failed > before.frames_failed,
                "a tampered frame from a known peer must be counted as failed \
                 (before {:?}, after {:?})",
                before.frames_failed,
                after.frames_failed
            );
            assert_eq!(
                after.payloads_delivered, before.payloads_delivered,
                "a tampered frame must never be delivered"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(300), pair.rx_b.recv())
                    .await
                    .is_err(),
                "nothing may reach the inbound queue"
            );

            pair.stop();
        });
    });
}

/// A replayed frame must be rejected. The counter is the nonce, so this is the
/// session's replay window firing on a live link.
#[test]
fn a_replayed_frame_is_rejected() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            let frame = pair.daemon_a.seal_payload_frame(b"once").await.unwrap();
            pair.injector.send_to(&frame, pair.addr_b).await.unwrap();

            let first = pair.recv_b().await;
            assert_eq!(first.payload, b"once");

            let before = pair.daemon_b.stats().frames_failed;
            // Byte-for-byte identical: same counter, same ciphertext.
            pair.injector.send_to(&frame, pair.addr_b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;

            let after = pair.daemon_b.stats();
            assert!(
                after.frames_failed > before,
                "a replay must be counted as failed ({before} -> {})",
                after.frames_failed
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(200), pair.rx_b.recv())
                    .await
                    .is_err(),
                "a replayed frame must not be delivered twice"
            );

            pair.stop();
        });
    });
}

/// A killed link seals nothing, and unkilling restores it.
#[test]
fn kill_switch_stops_the_data_path() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            pair.daemon_a.send_payload(b"before-kill").await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"before-kill");

            pair.daemon_a.kill();
            // A suppressed send must NOT report success. Reporting Ok made the
            // host bridge count the packet as delivered, so the health report
            // showed traffic flowing while the data path was stopped.
            let suppressed = pair.daemon_a.send_payload(b"after-kill").await;
            assert!(
                matches!(suppressed, Err(DaemonError::SuppressedByKillSwitch)),
                "a killed send must report suppression, not success: {suppressed:?}"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(500), pair.rx_b.recv())
                    .await
                    .is_err(),
                "a killed link must not deliver"
            );

            pair.daemon_a.unkill();
            pair.daemon_a.send_payload(b"resumed").await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"resumed");

            pair.stop();
        });
    });
}
/// A wrong pinned identity must stop the initiator from establishing.
///
/// This is the check that makes the responder authoritative: the protocol does
/// not bind a HelloResponse's identity key to its peer id, so without a pin the
/// response only proves the responder holds *some* operator-blessed key.
#[test]
fn a_wrong_pinned_identity_is_refused() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();

            let peer_a = PeerId::new();
            let peer_b = PeerId::new();
            let keys_a = node_keys();
            let keys_b = node_keys();

            // A pins an identity that is NOT B's.
            let wrong = node_keys().verifying;
            let config_a = config(
                &operator,
                keys_a,
                peer_a.clone(),
                addr_a,
                Some(addr_b),
                Some(peer_b.clone()),
                Some(wrong),
            );
            let config_b = config(
                &operator,
                keys_b,
                peer_b.clone(),
                addr_b,
                None,
                Some(peer_a.clone()),
                None,
            );

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon_a, _rx_a) = MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
            let (daemon_b, _rx_b) = MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);

            let mut tasks = Vec::new();
            for daemon in [Arc::clone(&daemon_a), Arc::clone(&daemon_b)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }

            // The responder side completes the handshake, because from its
            // point of view nothing is wrong.
            assert!(daemon_b.wait_established(Duration::from_secs(10)).await);

            // The initiator must refuse: it pinned a different identity.
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(
                !daemon_a.is_established(),
                "a wrong pin must not establish; stats {:?}",
                daemon_a.stats()
            );
            assert_eq!(daemon_a.stats().handshakes_completed, 0);
            assert!(
                daemon_a.stats().handshake_failures >= 1,
                "the refusal must be counted: {:?}",
                daemon_a.stats()
            );
            // And it may never deliver anything.
            assert_eq!(daemon_a.stats().payloads_delivered, 0);

            for task in tasks {
                task.abort();
            }
        });
    });
}

/// Spending a session's key budget must actually rotate the key.
///
/// Before this, the byte budget was never enforced on the data path — the
/// daemon passed `None` — so the session key lived for the life of the session
/// no matter how much data crossed it. The hardening layer's byte/epoch
/// accounting, which looked like rotation and performed none, has since been
/// removed outright.
#[test]
fn spending_the_key_budget_rotates_the_session() {
    with_big_stack(|| {
        runtime().block_on(async {
            // Small enough that a couple of payloads exhaust it.
            let mut pair = Pair::spawn_with_budget(Some(64)).await;
            pair.await_established().await;

            let first_session = pair.daemon_a.linked_peer().unwrap().0;
            let handshakes_before = pair.daemon_b.stats().handshakes_completed;

            // Send until the budget is spent, then STOP. Continuing to send
            // would feed the freshly rotated session and spend its budget too —
            // the limit is per session, so a busy link rotates repeatedly.
            for i in 0..6u8 {
                let payload = vec![i; 32];
                let _ = pair.daemon_a.send_payload(&payload).await;
                tokio::time::sleep(Duration::from_millis(120)).await;
                if pair.daemon_a.stats().sessions_rekeyed >= 1 {
                    break;
                }
            }

            // The rotation is a re-handshake, so wait for the link to come back.
            let mut reestablished = false;
            for _ in 0..80 {
                if pair.daemon_a.is_established()
                    && pair.daemon_a.linked_peer().map(|(s, _)| s) != Some(first_session.clone())
                {
                    reestablished = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            let stats = pair.daemon_a.stats();
            assert!(
                stats.sessions_rekeyed >= 1,
                "the budget must have forced a rotation: {stats:?}"
            );
            assert!(
                reestablished,
                "the link must come back on a NEW session after rotating: {stats:?}"
            );
            assert!(
                pair.daemon_b.stats().handshakes_completed > handshakes_before,
                "rotation is a re-handshake, so the peer must see another one: {:?}",
                pair.daemon_b.stats()
            );

            // And the rotated link still carries traffic.
            let after = pair.daemon_a.send_payload(b"after-rotation").await;
            assert!(
                after.is_ok(),
                "the rotated link must accept a payload: {after:?} | stats {:?}",
                pair.daemon_a.stats()
            );
            let delivered = tokio::time::timeout(Duration::from_secs(5), pair.rx_b.recv()).await;
            assert!(
                delivered.is_ok(),
                "the rotated link must still deliver: {stats:?}"
            );

            pair.stop();
        });
    });
}

/// An operator kill-switch command on the bus must actually stop the data path.
///
/// The control socket only publishes intent; the daemon owns the data path and
/// is the component that can act on it. Before this subscription existed the
/// command had no consumer on the mesh side at all.
#[test]
fn a_bus_killswitch_command_stops_and_resumes_the_data_path() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
            pair.bus.subscribe_exact(
                "net.transport.leak_guard.status",
                Box::new(move |_socket, payload| {
                    if let Ok(event) = payload.downcast::<BusEvent>() {
                        if let Message::LeakGuardStatus(status) = event.message {
                            let _ = status_tx.send(status);
                        }
                    }
                }),
            );

            // A working link delivers.
            pair.daemon_a.send_payload(b"before").await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"before");
            assert!(!pair.daemon_a.is_killed());

            let command = |state| {
                Message::KillSwitchCommand(KillSwitchCommand {
                    state,
                    reason: "test".to_string(),
                    issued_at: chrono::Utc::now(),
                })
            };

            // Arming is a policy state, not an action: traffic must continue.
            BusEvent::publish(
                &pair.bus,
                "net.transport.killswitch.command",
                command(KillSwitchState::Armed),
            )
            .unwrap();
            let armed_status = status_rx.recv().await.expect("armed acknowledgement");
            assert_eq!(armed_status.kill_switch, KillSwitchState::Armed);
            assert!(!armed_status.dns_guard_enabled);
            assert!(!armed_status.route_guard_enabled);
            while status_rx.try_recv().is_ok() {}
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(
                !pair.daemon_a.is_killed(),
                "arming must not black-hole a healthy link"
            );
            pair.daemon_a.send_payload(b"while-armed").await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"while-armed");

            // Engaging stops it.
            BusEvent::publish(
                &pair.bus,
                "net.transport.killswitch.command",
                command(KillSwitchState::Engaged),
            )
            .unwrap();
            assert_eq!(
                status_rx
                    .recv()
                    .await
                    .expect("engaged acknowledgement")
                    .kill_switch,
                KillSwitchState::Engaged
            );
            assert!(
                pair.daemon_a.is_killed(),
                "ENGAGE must apply before publish returns"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                pair.daemon_a.is_killed(),
                "an engaged kill switch must stop the data path"
            );
            let _ = pair.daemon_a.send_payload(b"while-engaged").await;
            assert!(
                tokio::time::timeout(Duration::from_millis(400), pair.rx_b.recv())
                    .await
                    .is_err(),
                "nothing may cross an engaged kill switch"
            );

            // An authenticated peer may still transmit. The engaged receiver
            // must discard inbound payloads before they reach the host bridge.
            pair.daemon_b.unkill();
            pair.daemon_b
                .send_payload(b"inbound-while-engaged")
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(400), pair.rx_a.recv())
                    .await
                    .is_err(),
                "inbound payload must not cross an engaged kill switch"
            );

            // Disarming resumes.
            BusEvent::publish(
                &pair.bus,
                "net.transport.killswitch.command",
                command(KillSwitchState::Disarmed),
            )
            .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!pair.daemon_a.is_killed());
            pair.daemon_a.send_payload(b"after").await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"after");

            pair.stop();
        });
    });
}

/// A peer whose address changes mid-session must keep working.
///
/// This is the NAT case. A session is keyed to the address the peer was last
/// reachable at; behind NAT that address changes, the address index stops
/// matching, and every frame was previously dropped. The fallback tries the one
/// session this link could belong to, and a successful open rebinds — so the
/// fast path resumes after a single frame.
#[test]
fn a_frame_from_a_new_address_rebinds_the_session() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            // A socket that is NOT the one the session was established from,
            // standing in for the peer's new NAT mapping.
            let moved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let moved_addr = moved.local_addr().unwrap();
            assert_ne!(moved_addr, pair.injector.local_addr().unwrap());

            let before = pair.daemon_b.stats();

            let frame = pair
                .daemon_a
                .seal_payload_frame(b"from-a-new-address")
                .await
                .unwrap();
            moved.send_to(&frame, pair.addr_b).await.unwrap();

            let got = pair.recv_b().await;
            assert_eq!(got.payload, b"from-a-new-address");

            let after = pair.daemon_b.stats();
            assert_eq!(
                after.nat_rebinds,
                before.nat_rebinds + 1,
                "the session must be rebound to the new address: {after:?}"
            );
            assert_eq!(after.frames_failed, before.frames_failed);

            // The rebind is persistent: the next frame from the same new
            // address takes the fast path, with no further rebind.
            let frame = pair.daemon_a.seal_payload_frame(b"second").await.unwrap();
            moved.send_to(&frame, pair.addr_b).await.unwrap();
            assert_eq!(pair.recv_b().await.payload, b"second");
            assert_eq!(
                pair.daemon_b.stats().nat_rebinds,
                after.nat_rebinds,
                "a rebind is not needed twice for the same address"
            );

            pair.stop();
        });
    });
}

/// A frame from an address that is not the peer's must not be accepted, and
/// must not be retried indefinitely.
#[test]
fn a_frame_from_a_stranger_is_not_accepted() {
    with_big_stack(|| {
        runtime().block_on(async {
            let mut pair = Pair::spawn().await;
            pair.await_established().await;

            let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            // A well-formed frame the stranger cannot have produced: take one
            // of A's and corrupt the tag so it cannot open.
            let mut frame = pair.daemon_a.seal_payload_frame(b"payload").await.unwrap();
            let last = frame.len() - 1;
            frame[last] ^= 0x01;

            let before = pair.daemon_b.stats();
            stranger.send_to(&frame, pair.addr_b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;

            let after = pair.daemon_b.stats();
            assert_eq!(
                after.nat_rebinds, before.nat_rebinds,
                "a frame that fails to open must not rebind anything"
            );
            assert!(
                after.frames_failed > before.frames_failed,
                "it must be counted as a failure: {after:?}"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(300), pair.rx_b.recv())
                    .await
                    .is_err(),
                "nothing may be delivered"
            );

            pair.stop();
        });
    });
}

/// A minimal IPv4 header with the given destination, plus one identifying byte.
fn ipv4_packet(destination: [u8; 4], tag: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45; // version 4, header length 5 words
    packet[2..4].copy_from_slice(&(21u16).to_be_bytes()); // total length
    packet[9] = 17; // UDP
    packet[16..20].copy_from_slice(&destination);
    packet.push(tag);
    packet
}

/// Three nodes: one hub with two peers, each peer serving a different prefix.
///
/// This is the multi-peer case. The hub has no per-peer send call — the packet's
/// own destination decides which peer it goes to, which is what makes a node
/// with several peers behave like a router rather than a hub that must be told
/// which way to send.
#[test]
fn a_hub_routes_each_packet_to_the_peer_that_serves_its_destination() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();
            let addr_c = socket_c.local_addr().unwrap();

            let peer_a = PeerId::new();
            let peer_b = PeerId::new();
            let peer_c = PeerId::new();
            let keys_a = node_keys();
            let keys_b = node_keys();
            let keys_c = node_keys();

            // The hub knows both peers and which prefix each serves.
            let mut config_a = config(&operator, keys_a, peer_a.clone(), addr_a, None, None, None);
            config_a.peers = vec![
                PeerConfig {
                    peer_id: peer_b.clone(),
                    addr: Some(addr_b),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.88.0.0/24").unwrap()],
                },
                PeerConfig {
                    peer_id: peer_c.clone(),
                    addr: Some(addr_c),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.99.0.0/24").unwrap()],
                },
            ];
            // Both leaves accept only the hub, and do not dial.
            let mut config_b = config(&operator, keys_b, peer_b.clone(), addr_b, None, None, None);
            config_b.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];
            let mut config_c = config(&operator, keys_c, peer_c.clone(), addr_c, None, None, None);
            config_c.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (hub, _rx_a) = MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
            let (leaf_b, mut rx_b) = MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);
            let (leaf_c, mut rx_c) = MeshDaemon::with_socket(config_c, Arc::clone(&bus), socket_c);

            let mut tasks = Vec::new();
            for daemon in [Arc::clone(&hub), Arc::clone(&leaf_b), Arc::clone(&leaf_c)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }

            // The hub dials both peers from its configuration.
            let mut both = false;
            for _ in 0..100 {
                if hub.established_peers().len() == 2 {
                    both = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(
                both,
                "the hub must establish with both peers; stats {:?}",
                hub.stats()
            );
            assert!(leaf_b.is_peer_established(&peer_a));
            assert!(leaf_c.is_peer_established(&peer_a));

            // A packet for B's prefix goes to B, and only to B.
            hub.send_payload(&ipv4_packet([10, 88, 0, 5], 1))
                .await
                .unwrap();
            let to_b = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
                .await
                .expect("leaf B should receive")
                .expect("channel open");
            assert_eq!(to_b.payload.last(), Some(&1));
            assert_eq!(to_b.peer_id, peer_a);
            assert!(
                tokio::time::timeout(Duration::from_millis(300), rx_c.recv())
                    .await
                    .is_err(),
                "leaf C must not receive a packet for B's prefix"
            );

            // A packet for C's prefix goes to C, and only to C.
            hub.send_payload(&ipv4_packet([10, 99, 0, 7], 2))
                .await
                .unwrap();
            let to_c = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
                .await
                .expect("leaf C should receive")
                .expect("channel open");
            assert_eq!(to_c.payload.last(), Some(&2));
            assert_eq!(to_c.peer_id, peer_a);
            assert!(
                tokio::time::timeout(Duration::from_millis(300), rx_b.recv())
                    .await
                    .is_err(),
                "leaf B must not receive a packet for C's prefix"
            );

            // CONTROL: a destination no peer serves, with two peers to choose
            // from, must not be guessed at. Sending it to a peer with no route
            // to it would leak the packet to the wrong network.
            let unrouted = hub.send_payload(&ipv4_packet([10, 77, 0, 9], 3)).await;
            assert!(
                unrouted.is_err(),
                "an unserved destination must not be sent to an arbitrary peer: {unrouted:?}"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(300), rx_b.recv())
                    .await
                    .is_err(),
                "nothing may reach B"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(300), rx_c.recv())
                    .await
                    .is_err(),
                "nothing may reach C"
            );

            // An explicit per-peer send still works, and is how a caller with
            // its own routing knowledge would reach a peer directly.
            hub.send_payload_to(&peer_c, &ipv4_packet([10, 88, 0, 5], 4))
                .await
                .unwrap();
            let forced = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
                .await
                .expect("explicit send should reach C")
                .expect("channel open");
            assert_eq!(forced.payload.last(), Some(&4));

            for task in tasks {
                task.abort();
            }
        });
    });
}

/// Longest prefix wins when two peers both claim a destination.
#[test]
fn the_most_specific_route_decides_the_peer() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();
            let addr_c = socket_c.local_addr().unwrap();

            let peer_a = PeerId::new();
            let peer_b = PeerId::new();
            let peer_c = PeerId::new();

            let mut config_a = config(
                &operator,
                node_keys(),
                peer_a.clone(),
                addr_a,
                None,
                None,
                None,
            );
            // B claims the wide prefix, C the narrow one inside it.
            config_a.peers = vec![
                PeerConfig {
                    peer_id: peer_b.clone(),
                    addr: Some(addr_b),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.0.0.0/8").unwrap()],
                },
                PeerConfig {
                    peer_id: peer_c.clone(),
                    addr: Some(addr_c),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.88.0.0/16").unwrap()],
                },
            ];
            let mut config_b = config(
                &operator,
                node_keys(),
                peer_b.clone(),
                addr_b,
                None,
                None,
                None,
            );
            config_b.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];
            let mut config_c = config(
                &operator,
                node_keys(),
                peer_c.clone(),
                addr_c,
                None,
                None,
                None,
            );
            config_c.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (hub, _rx_a) = MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
            let (leaf_b, mut rx_b) = MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);
            let (leaf_c, mut rx_c) = MeshDaemon::with_socket(config_c, Arc::clone(&bus), socket_c);

            let mut tasks = Vec::new();
            for daemon in [Arc::clone(&hub), Arc::clone(&leaf_b), Arc::clone(&leaf_c)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }
            for _ in 0..100 {
                if hub.established_peers().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(hub.established_peers().len(), 2);

            // Inside C's /16: the narrower prefix wins, so C gets it.
            hub.send_payload(&ipv4_packet([10, 88, 4, 4], 9))
                .await
                .unwrap();
            let got = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
                .await
                .expect("C should get the more specific route")
                .expect("channel open");
            assert_eq!(got.payload.last(), Some(&9));
            assert!(
                tokio::time::timeout(Duration::from_millis(300), rx_b.recv())
                    .await
                    .is_err(),
                "B must not get a packet the narrower route claims"
            );

            // Elsewhere in B's /8: B gets it.
            hub.send_payload(&ipv4_packet([10, 20, 0, 1], 10))
                .await
                .unwrap();
            let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
                .await
                .expect("B should get the wider route")
                .expect("channel open");
            assert_eq!(got.payload.last(), Some(&10));

            for task in tasks {
                task.abort();
            }
        });
    });
}

/// A rebind from the SECOND peer must work, not just the first.
///
/// With several peers, the address of an unmatched datagram could belong to any
/// of them. Trying only one arbitrary candidate meant a datagram was tested
/// against the wrong peer's session, failed, and was dropped — so a peer whose
/// address had moved could never rebind while the node served more than one
/// peer. This asserts the rebind lands on the peer that actually sent it.
#[test]
fn a_rebind_from_the_second_peer_is_resolved() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();
            let addr_c = socket_c.local_addr().unwrap();

            let peer_a = PeerId::new();
            let peer_b = PeerId::new();
            let peer_c = PeerId::new();

            let mut config_a = config(
                &operator,
                node_keys(),
                peer_a.clone(),
                addr_a,
                None,
                None,
                None,
            );
            // B first, C second: the order matters, because the bug was trying
            // only the first candidate.
            config_a.peers = vec![
                PeerConfig {
                    peer_id: peer_b.clone(),
                    addr: Some(addr_b),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.88.0.0/24").unwrap()],
                },
                PeerConfig {
                    peer_id: peer_c.clone(),
                    addr: Some(addr_c),
                    pinned_identity_vk: None,
                    routes: vec![Destination::parse("10.99.0.0/24").unwrap()],
                },
            ];
            let mut config_b = config(
                &operator,
                node_keys(),
                peer_b.clone(),
                addr_b,
                None,
                None,
                None,
            );
            config_b.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];
            let mut config_c = config(
                &operator,
                node_keys(),
                peer_c.clone(),
                addr_c,
                None,
                None,
                None,
            );
            config_c.peers = vec![PeerConfig {
                peer_id: peer_a.clone(),
                addr: None,
                pinned_identity_vk: None,
                routes: Vec::new(),
            }];

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (hub, _rx_a) = MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
            let (leaf_b, _rx_b) = MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);
            let (leaf_c, _rx_c) = MeshDaemon::with_socket(config_c, Arc::clone(&bus), socket_c);

            let mut tasks = Vec::new();
            for daemon in [Arc::clone(&hub), Arc::clone(&leaf_b), Arc::clone(&leaf_c)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }
            for _ in 0..100 {
                if hub.established_peers().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(hub.established_peers().len(), 2);

            // C's address moves. The frame is sealed for the hub correctly, but
            // arrives from somewhere the hub has no session for.
            let moved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            assert_ne!(moved.local_addr().unwrap(), addr_c);

            let before = hub.stats();
            let frame = leaf_c
                .seal_for_peer(&peer_a, b"from-c-new-address")
                .await
                .unwrap();
            moved.send_to(&frame, addr_a).await.unwrap();

            let mut delivered = false;
            for _ in 0..40 {
                if hub.stats().nat_rebinds > before.nat_rebinds {
                    delivered = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(
                delivered,
                "a rebind from the second peer must be resolved: {:?}",
                hub.stats()
            );

            // It rebound to C and not to B: both links survive, and the next
            // frame from C's new address takes the fast path with no further
            // rebind, which is only possible if the address is now C's.
            assert_eq!(hub.established_peers().len(), 2, "both links must survive");
            let rebinds = hub.stats().nat_rebinds;
            let frame = leaf_c
                .seal_for_peer(&peer_a, b"second-from-c")
                .await
                .unwrap();
            moved.send_to(&frame, addr_a).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                hub.stats().nat_rebinds,
                rebinds,
                "the new address is now C's, so no second rebind is needed"
            );

            for task in tasks {
                task.abort();
            }
        });
    });
}

/// Mutual dial must settle on ONE handshake and carry traffic.
///
/// Found by the NAT adversarial review (2026-09-26, domain-dissolver C1). Both
/// nodes dialling each other was a silent black hole: each side adopted the
/// session the OTHER created, both links reported Established, and nothing could
/// be decrypted. The fix is a deterministic tie-break on the peer ids — the
/// lower id keeps initiating and ignores the incoming Hello, the higher defers
/// and adopts — so exactly one handshake survives and both sides agree on it.
///
/// This asserts the fix. It FAILS if the tie-break is removed.
#[test]
fn mutual_dial_settles_on_one_handshake_and_carries_traffic() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = socket_a.local_addr().unwrap();
            let addr_b = socket_b.local_addr().unwrap();

            let peer_a = PeerId::new();
            let peer_b = PeerId::new();
            let keys_a = node_keys();
            let keys_b = node_keys();
            let vk_b = keys_b.verifying.clone();
            let vk_a = keys_a.verifying.clone();

            // A dials B, B dials A. Both are initiators.
            let config_a = config(
                &operator,
                keys_a,
                peer_a.clone(),
                addr_a,
                Some(addr_b),
                Some(peer_b.clone()),
                Some(vk_b),
            );
            let config_b = config(
                &operator,
                keys_b,
                peer_b.clone(),
                addr_b,
                Some(addr_a),
                Some(peer_a.clone()),
                Some(vk_a),
            );

            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon_a, mut rx_a) =
                MeshDaemon::with_socket(config_a, Arc::clone(&bus), socket_a);
            let (daemon_b, mut rx_b) =
                MeshDaemon::with_socket(config_b, Arc::clone(&bus), socket_b);

            let mut tasks = Vec::new();
            for daemon in [Arc::clone(&daemon_a), Arc::clone(&daemon_b)] {
                let shutdown = Arc::new(Notify::new());
                tasks.push(tokio::spawn(async move {
                    let _ = daemon.run(shutdown).await;
                }));
            }

            // Give both sides far longer than a normal handshake needs.
            tokio::time::sleep(Duration::from_secs(3)).await;

            let established_a = daemon_a.is_established();
            let established_b = daemon_b.is_established();

            // Deliverable traffic: A sends a packet routed to B's prefix.
            let delivered = if established_a {
                let _ = daemon_a.send_payload(&ipv4_packet([10, 88, 0, 5], 7)).await;
                tokio::time::timeout(Duration::from_millis(800), rx_b.recv())
                    .await
                    .is_ok()
            } else {
                false
            };

            eprintln!(
                "mutual dial: a_established={established_a} b_established={established_b} \
                 delivered={delivered} | a={:?} b={:?}",
                daemon_a.stats(),
                daemon_b.stats()
            );

            assert!(
                established_a && established_b,
                "both sides must end up established \
                 (a_est={established_a} b_est={established_b})"
            );
            assert!(
                delivered,
                "mutual dial must carry traffic, not black-hole it \
                 (a_est={established_a} b_est={established_b} delivered={delivered})"
            );
            // Both sides converged on ONE session, rather than each holding the
            // other's — the tell that made the old failure silent.
            let session_a = daemon_a.linked_peer().expect("a established").0;
            let session_b = daemon_b.linked_peer().expect("b established").0;
            assert_eq!(
                session_a, session_b,
                "both sides must agree on the same session"
            );
            let _ = &mut rx_a;

            for task in tasks {
                task.abort();
            }
        });
    });
}

/// A forged gate MAC must never reach the verification.
///
/// This is the test that was missing. `mac_valid_for_source` is the only thing
/// between an arbitrary `GatedHello` and a full hybrid Ed25519 + ML-DSA-65
/// verification, and no test ever presented it a bad MAC — so it could be
/// stubbed to `true` and every suite stayed green while an attacker got an
/// ungated post-quantum verification from a spoofed source.
#[test]
fn a_forged_gate_mac_never_reaches_verification() {
    with_big_stack(|| {
        runtime().block_on(async {
            let operator = operator();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let cfg = config(
                &operator,
                node_keys(),
                PeerId::new(),
                addr,
                None,
                None,
                None,
            );
            let bus = Arc::new(spiderweb::Bus::open().publisher());
            let (daemon, _rx) = MeshDaemon::with_socket(cfg, Arc::clone(&bus), socket);
            let shutdown = Arc::new(Notify::new());
            let runner = Arc::clone(&daemon);
            let task = tokio::spawn(async move {
                let _ = runner.run(shutdown).await;
            });
            tokio::time::sleep(Duration::from_millis(150)).await;

            let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // A structurally perfect GatedHello carrying a MAC that was never
            // minted for this source.
            let hello = MeshHello {
                peer_id: PeerId::new(),
                endpoint: "127.0.0.1:9".parse().unwrap(),
                classical_pubkey: vec![0u8; 32],
                pqc_pubkey: vec![0u8; 1184],
                session_id: SessionId::new(),
                identity_vk: vec![0u8; 64],
                identity_grant: vec![0u8; 200],
                handshake_signature: vec![0u8; 64],
            };
            let plain = encode_hello(&hello).unwrap();
            let forged = imperium_net_mesh::wire::encode_gated_hello(&plain, &[0xAB; 32])
                .expect("gated hello encodes");

            for _ in 0..3 {
                attacker.send_to(&forged, addr).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(400)).await;

            let stats = daemon.stats();
            assert_eq!(
                stats.handshake_verifications, 0,
                "a forged gate MAC must never reach verification: {stats:?}"
            );
            assert!(
                stats.handshake_failures >= 1,
                "it must be counted as a gate failure: {stats:?}"
            );
            assert_eq!(stats.handshakes_completed, 0);
            assert!(!daemon.is_established());

            task.abort();
        });
    });
}
