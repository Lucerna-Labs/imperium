//! Real UDP mesh receive/send through the supervised passive Lightcone bus lane.
//!
//! A responder daemon receives an ungated Hello and sends a cookie. The test
//! compares bus structure and receipt hashes with the exact socket datagrams. This
//! exercises daemon wiring rather than publishing test frames into the strand.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use imperium_net_crypto::HybridEd25519Mldsa;
use imperium_net_lightcone::{topics, FaultPolicy, LightconeService, LightconeStrand};
use imperium_net_mesh::{encode_hello, DaemonError, MeshDaemon, MeshNodeConfig, PeerConfig};
use imperium_net_observer::decode_mesh_datagram;
use imperium_net_world::{embedded, hash};
use imperium_protocol::{
    BusEvent, ClusterId, LightconeFrameFormat, LightconeReceipt, LightconeStructure, MeshHello,
    Message, PeerId, SessionId,
};
use rand::rngs::OsRng;
use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

const BIG_STACK: usize = 64 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(10);

fn with_big_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(BIG_STACK)
        .spawn(body)
        .expect("spawn large-stack test thread")
        .join()
        .expect("large-stack test thread panicked");
}

struct SupervisedBus {
    publisher: Arc<BusPublisher>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl SupervisedBus {
    fn start() -> (
        Self,
        Arc<LightconeService>,
        mpsc::Receiver<LightconeStructure>,
        mpsc::Receiver<LightconeReceipt>,
    ) {
        let mut bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let service = Arc::new(LightconeService::new().expect("embedded v4 world verifies"));
        let (structure_tx, structure_rx) = mpsc::channel(32);
        let (receipt_tx, receipt_rx) = mpsc::channel(32);

        publisher.subscribe_exact(
            topics::FRAME,
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    if let Message::LightconeStructure(structure) = event.message {
                        let _ = structure_tx.try_send(structure);
                    }
                }
            }),
        );
        publisher.subscribe_exact(
            topics::RECEIPT,
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    if let Message::LightconeReceipt(receipt) = event.message {
                        let _ = receipt_tx.try_send(receipt);
                    }
                }
            }),
        );

        bus.register_spec(LightconeStrand::spec(
            Arc::clone(&service),
            FaultPolicy::None,
        ));
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));
        let join = std::thread::Builder::new()
            .name("mesh-lightcone-bus-test".into())
            .spawn(move || bus.run_until(None))
            .expect("start Spiderweb run loop");
        (
            Self {
                publisher,
                join: Some(join),
            },
            service,
            structure_rx,
            receipt_rx,
        )
    }
}

impl Drop for SupervisedBus {
    fn drop(&mut self) {
        let _ = self.publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        if let Some(join) = self.join.take() {
            join.join().expect("Spiderweb run loop exits cleanly");
        }
    }
}

fn responder_config(bind_addr: SocketAddr) -> MeshNodeConfig {
    let mut random = OsRng;
    let (operator_signing_key, operator_verifying_key) =
        HybridEd25519Mldsa::generate_keypair(&mut random);
    let (identity_signing_key, identity_verifying_key) =
        HybridEd25519Mldsa::generate_keypair(&mut random);
    MeshNodeConfig {
        peer_id: PeerId::new(),
        cluster_id: ClusterId::new(),
        bind_addr,
        peers: Vec::new(),
        identity_signing_key,
        identity_verifying_key,
        operator_signing_key,
        operator_verifying_key,
        identity_ttl: chrono::Duration::hours(1),
        handshake_retry: Duration::from_millis(500),
        max_handshake_attempts: 2,
        session_idle_secs: 120,
        session_max_bytes: None,
    }
}

fn ungated_hello() -> Vec<u8> {
    encode_hello(&MeshHello {
        peer_id: PeerId::new(),
        endpoint: "127.0.0.1:9".parse().unwrap(),
        classical_pubkey: vec![0; 32],
        pqc_pubkey: vec![0; 1184],
        session_id: SessionId::new(),
        identity_vk: vec![0; 64],
        identity_grant: vec![0; 200],
        handshake_signature: vec![0; 64],
    })
    .expect("test Hello encodes")
}

fn digest_hex(bytes: &[u8]) -> String {
    hash(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn matching_structure(
    structures: &mut mpsc::Receiver<LightconeStructure>,
    direction: u8,
    datagram: &[u8],
) {
    for _ in 0..8 {
        let structure = tokio::time::timeout(WAIT, structures.recv())
            .await
            .expect("structure bus event timed out")
            .expect("structure bus subscription closed");
        if structure.direction == direction && structure.query_hash == hash(datagram) {
            assert_eq!(structure.format, LightconeFrameFormat::MeshDatagram);
            let expected = decode_mesh_datagram(datagram);
            assert_eq!(structure.observation_kind, expected.kind as u8);
            assert_eq!(structure.seeds, expected.seeds.to_vec());
            return;
        }
    }
    panic!("digest of datagram with direction {direction} did not reach the Lightcone bus");
}

async fn matching_receipt(
    receipts: &mut mpsc::Receiver<LightconeReceipt>,
    direction: u8,
    datagram: &[u8],
) -> LightconeReceipt {
    let query = digest_hex(datagram);
    for _ in 0..8 {
        let receipt = tokio::time::timeout(WAIT, receipts.recv())
            .await
            .expect("Lightcone receipt timed out")
            .expect("Lightcone receipt subscription closed");
        if receipt.direction == direction && receipt.query_sha256 == query {
            return receipt;
        }
    }
    panic!("receipt for exact datagram with direction {direction} was not published");
}

#[test]
fn real_daemon_udp_datagrams_reach_supervised_passive_receipts() {
    with_big_stack(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime");
        runtime.block_on(async {
            let (supervisor, service, mut structures, mut receipts) = SupervisedBus::start();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let daemon_addr = socket.local_addr().unwrap();
            let (daemon, _payloads) = MeshDaemon::with_socket(
                responder_config(daemon_addr),
                Arc::clone(&supervisor.publisher),
                socket,
            );
            // This public send path fails before a socket send. It must not
            // announce an outbound datagram that never existed.
            assert!(matches!(
                daemon.send_payload_to(&PeerId::new(), b"no session").await,
                Err(DaemonError::NoSession)
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(structures.try_recv().is_err());
            assert!(receipts.try_recv().is_err());
            let shutdown = Arc::new(Notify::new());
            let runner = Arc::clone(&daemon);
            let runner_shutdown = Arc::clone(&shutdown);
            let task = tokio::spawn(async move {
                runner.run(runner_shutdown).await.expect("daemon run");
            });

            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let hello = ungated_hello();
            sender.send_to(&hello, daemon_addr).await.unwrap();
            let mut buf = [0u8; 128];
            let (len, source) = tokio::time::timeout(WAIT, sender.recv_from(&mut buf))
                .await
                .expect("cookie response timed out")
                .expect("receive cookie response");
            assert_eq!(source, daemon_addr);
            let cookie = &buf[..len];
            assert_eq!(&cookie[..2], &[0x02, 0x03]);

            matching_structure(&mut structures, 0, &hello).await;
            matching_structure(&mut structures, 1, cookie).await;
            let inbound = matching_receipt(&mut receipts, 0, &hello).await;
            let outbound = matching_receipt(&mut receipts, 1, cookie).await;
            for receipt in [&inbound, &outbound] {
                assert_eq!(receipt.pack_sha256, digest_hex(embedded::PACK));
                assert_eq!(receipt.frame_format, LightconeFrameFormat::MeshDatagram);
                assert_eq!(receipt.observation_kind, 0, "recognized mesh datagram");
                assert!(receipt.seeds.iter().any(|word| *word != 0));
                assert!(receipt.nodes.iter().any(|word| *word != 0));
                assert!(receipt.passive);
                assert!(!receipt.holds_verdict);
            }
            assert_eq!(service.info().training_platform, "local_diagnostic");
            assert!(!service.info().sealed);
            assert_eq!(service.info().rx, 1);
            assert_eq!(service.info().tx, 1);
            assert_eq!(daemon.stats().handshake_cookies_sent, 1);
            // A named receipt callback can run just before the observer task
            // increments its post-publish counter. Wait for that accounting
            // edge, then require an exact two-event total with no losses.
            tokio::time::timeout(WAIT, async {
                while daemon.stats().lightcone_observations_published < 2 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("observer publish accounting timed out");
            let stats = daemon.stats();
            assert_eq!(stats.lightcone_observations_queued, 2, "{stats:?}");
            assert_eq!(stats.lightcone_observations_published, 2, "{stats:?}");
            assert_eq!(stats.lightcone_observations_dropped, 0, "{stats:?}");
            assert_eq!(stats.lightcone_publish_errors, 0, "{stats:?}");

            shutdown.notify_one();
            tokio::time::timeout(WAIT, task)
                .await
                .expect("daemon shutdown timed out")
                .expect("daemon task panicked");
            drop(supervisor);
        });
    });
}

#[test]
fn failed_udp_send_does_not_announce_a_wire_datagram() {
    with_big_stack(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime");
        runtime.block_on(async {
            let (supervisor, _service, mut structures, mut receipts) = SupervisedBus::start();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target: SocketAddr = "[::1]:9".parse().unwrap();
            // An IPv4-only socket cannot send to an IPv6 destination. Check
            // that syscall condition before using it to exercise the daemon.
            assert!(socket.send_to(b"probe", target).await.is_err());
            let mut config = responder_config(socket.local_addr().unwrap());
            let peer = PeerId::new();
            config.peers.push(PeerConfig {
                peer_id: peer.clone(),
                addr: Some(target),
                pinned_identity_vk: None,
                routes: Vec::new(),
            });
            let (daemon, _payloads) =
                MeshDaemon::with_socket(config, Arc::clone(&supervisor.publisher), socket);

            // initiate constructs and attempts to send a real hybrid Hello;
            // send_handshake logs the expected socket error and returns.
            daemon.initiate(&peer).await.expect("initiate Hello");
            assert!(daemon.stats().handshake_datagram_bytes > 0);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(daemon.stats().lightcone_observations_queued, 0);
            assert!(structures.try_recv().is_err());
            assert!(receipts.try_recv().is_err());
            drop(supervisor);
        });
    });
}
