//! Safe end-to-end exercise of the RTX world on Imperium's UDP mesh.
//!
//! Every datagram stays on 127.0.0.1. Adversarial fixtures are inert ASCII
//! labels only: no shell, SQL engine, browser, filesystem, or external host is
//! invoked.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use chrono::Utc;
use imperium_net_crypto::HybridX25519Mlkem;
use imperium_net_mesh::{MeshTransport, PeerManager, SessionManager, WireDirection};
use imperium_net_sensors::{
    adversarial_probe_burst, adversarial_scan_fanout, adversarial_session_probe,
    adversarial_volume_anomaly, synthetic_normal_windows, EnvelopeTrainer,
};
use imperium_net_strainer::{
    AuthShapeInnerStrainer, AuthShapeOuterStrainer, StrainerInput, StrainerOutput, StrainerStack,
};
use imperium_net_world::{bit, embedded as node};
use imperium_protocol::{Message, PeerId};
use rand::rngs::OsRng;
use spiderweb::BusPublisher;
use tokio::net::UdpSocket;

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn established_pair() -> (MeshTransport, MeshTransport, imperium_protocol::SessionId) {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let initiator = MeshTransport::new(
        Arc::clone(&bus),
        Arc::new(PeerManager::new()),
        Arc::new(SessionManager::new()),
        PeerId::new(),
    );
    let responder = MeshTransport::new(
        bus,
        Arc::new(PeerManager::new()),
        Arc::new(SessionManager::new()),
        PeerId::new(),
    );
    let remote_peer = PeerId::new();
    let session_id = initiator
        .session_manager()
        .create_session(remote_peer.clone(), loopback(9_000), true)
        .unwrap();
    responder
        .session_manager()
        .adopt_session(session_id.clone(), remote_peer, loopback(9_000), false)
        .unwrap();
    let mut random = OsRng;
    let (secret, public) = HybridX25519Mlkem::generate_keypair(&mut random);
    let (encapsulation, initiator_key) = HybridX25519Mlkem::encapsulate(&mut random, &public);
    let responder_key = HybridX25519Mlkem::decapsulate(secret, &encapsulation).unwrap();
    initiator
        .session_manager()
        .establish_session(&session_id, initiator_key, &[], &[])
        .unwrap();
    responder
        .session_manager()
        .establish_session(&session_id, responder_key, &[], &[])
        .unwrap();
    (initiator, responder, session_id)
}

fn inert_fixtures() -> Vec<Vec<u8>> {
    vec![
        b"PROBE SYN sweep marker; inert test only".to_vec(),
        b"GET /../../etc/passwd HTTP/1.1\r\nHost: test.invalid\r\n".to_vec(),
        b"'; DROP TABLE audit; -- inert string".to_vec(),
        b"<script>alert('inert')</script>".to_vec(),
        vec![b'A'; 256],
    ]
}

fn strainer_input(data: Vec<u8>) -> StrainerInput {
    StrainerInput {
        data,
        source: Some("192.0.2.10:40000".parse().unwrap()),
        context: HashMap::from([("fixture".to_string(), "inert-local-only".to_string())]),
        timestamp: Utc::now(),
    }
}

#[tokio::test]
async fn rtx_world_observes_and_imperium_rejects_safe_probes() {
    let (initiator, responder, session_id) = established_pair();
    assert_eq!(initiator.network_world_hash(), node::HASH);
    assert_eq!(responder.network_world_hash(), node::HASH);

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let mut buffer = [0u8; 2_048];

    let benign = b"authenticated benign mesh control";
    let (counter, ciphertext) = initiator
        .session_manager()
        .seal_for_session(&session_id, benign, None)
        .unwrap();
    let valid = initiator.harden_payload_for_send(counter, ciphertext);
    sender.send_to(&valid.bytes, receiver_addr).await.unwrap();
    let (length, source) = receiver.recv_from(&mut buffer).await.unwrap();
    assert_eq!(source, sender.local_addr().unwrap());
    let recovered = responder
        .process_incoming(&session_id, &buffer[..length])
        .unwrap();
    assert_eq!(recovered.payload, benign);

    assert!(
        responder
            .process_incoming(&session_id, &buffer[..length])
            .is_err(),
        "replay must be rejected"
    );

    // NOTE (Item 10 decrypt-then-track): open() now authenticates BEFORE
    // touching the replay bitmap, so this tampered copy of an already-seen
    // counter fails AEAD open rather than replay check. Either way it is
    // rejected — fail-closed either path.
    let mut tampered = valid.bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    sender.send_to(&tampered, receiver_addr).await.unwrap();
    let (length, _) = receiver.recv_from(&mut buffer).await.unwrap();
    assert!(
        responder
            .process_incoming(&session_id, &buffer[..length])
            .is_err(),
        "tampered AEAD frame must be rejected"
    );

    let fixtures = inert_fixtures();
    for fixture in &fixtures {
        sender.send_to(fixture, receiver_addr).await.unwrap();
        let (length, _) = receiver.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], fixture);
        assert!(
            responder
                .process_incoming(&session_id, &buffer[..length])
                .is_err(),
            "unauthenticated probe-shaped datagram must be rejected"
        );
    }

    let outbound = initiator.network_world_snapshot();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].direction, WireDirection::Outbound);
    assert!(!bit(&outbound[0].receipt.seeds, node::FOREIGN));
    assert_eq!(outbound[0].receipt.world, node::HASH);

    let inbound = responder.network_world_snapshot();
    assert_eq!(inbound.len(), 3 + fixtures.len());
    assert!(inbound.iter().all(|observation| {
        observation.direction == WireDirection::Inbound
            && observation.receipt.world == node::HASH
            && bit(&observation.receipt.seeds, node::FRAME)
            && bit(&observation.receipt.seeds, node::UDP)
            && bit(&observation.receipt.seeds, node::OPAQUE)
            && bit(&observation.receipt.seeds, node::FOREIGN)
    }));

    // One kernel, two handles: the shared `Arc` for this test's own assertions
    // and a second `BusPublisher` for the strainer stack (the type is not
    // `Clone`, so a second handle is minted from the same kernel instead).
    let kernel = spiderweb::Bus::open();
    let bus = Arc::new(kernel.publisher());
    let mut rejection_events = subscribe_queue(&bus, "net.strainer.rejection", 64);
    let mut stack =
        StrainerStack::new("vpn-ingress", "imperium-mesh-v3").with_bus(kernel.publisher());
    stack.add_stage(Arc::new(AuthShapeOuterStrainer::new(64)));
    stack.add_stage(Arc::new(
        AuthShapeInnerStrainer::new("imperium-safe-auth-v1")
            .with_required_field(0, 0x01)
            .with_required_field(1, 0x02),
    ));
    let mut valid_shape = vec![0u8; 64];
    valid_shape[0] = 0x01;
    valid_shape[1] = 0x02;
    assert!(matches!(
        stack.apply(strainer_input(valid_shape)),
        StrainerOutput::Passed(_)
    ));
    for fixture in fixtures {
        assert!(stack.apply(strainer_input(fixture)).is_rejected());
        let event =
            tokio::time::timeout(std::time::Duration::from_secs(1), rejection_events.recv())
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(event.message, Message::StrainerRejection(_)));
    }

    let model = EnvelopeTrainer::fit(
        &synthetic_normal_windows(0xC0FFEE, 400),
        vec![64, 256, 768, 1200],
    )
    .unwrap();
    assert!(synthetic_normal_windows(0x51A7, 16)
        .iter()
        .all(|window| !model.outside_cone(window)));
    assert!(model.outside_cone(&adversarial_probe_burst(11)));
    assert!(model.outside_cone(&adversarial_scan_fanout(12)));
    assert!(model.outside_cone(&adversarial_volume_anomaly(13)));
    assert!(model.outside_cone(&adversarial_session_probe(14)));
}

/// A named subscription feeding an owned bounded queue — the shape an async
/// consumer outside a strand must have now that delivery is push-based.
fn subscribe_queue(
    publisher: &BusPublisher,
    prefix: &'static str,
    capacity: usize,
) -> tokio::sync::mpsc::Receiver<imperium_protocol::BusEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    publisher.subscribe_prefix(
        prefix,
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<imperium_protocol::BusEvent>() {
                let _ = tx.try_send(*event);
            }
        }),
    );
    rx
}
