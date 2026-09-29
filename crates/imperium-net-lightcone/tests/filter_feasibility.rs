//! Matched traffic probes for the current, unsealed v4 world. These tests do
//! not install a forwarding filter: they measure the information available to
//! one before any release rule can be justified.

use imperium_net_observer::{decode_raw_ip, ObservationKind};
use imperium_net_world::{embedded, hash, Policy, World};

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_packet(protocol: u8, destination: [u8; 4], transport: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    let total_length = (packet.len() + transport.len()) as u16;
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[10, 77, 0, 1]);
    packet[16..20].copy_from_slice(&destination);
    let header_checksum = checksum(&packet);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet.extend_from_slice(transport);
    packet
}

fn udp_packet(destination: [u8; 4], destination_port: u16) -> Vec<u8> {
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());
    // IPv4 UDP permits zero checksum. Both probes use the same supported form.
    ipv4_packet(17, destination, &udp)
}

fn tcp_ack_packet(sequence: u32, acknowledgement: u32) -> Vec<u8> {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x10;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
    let mut pseudo = Vec::from([10, 77, 0, 1, 10, 77, 0, 2, 0, 6, 0, 20]);
    pseudo.extend_from_slice(&tcp);
    let transport_checksum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&transport_checksum.to_be_bytes());
    ipv4_packet(6, [10, 77, 0, 2], &tcp)
}

fn admitted(packet: &[u8]) -> imperium_net_world::Receipt {
    let observation = decode_raw_ip(packet);
    assert_eq!(
        observation.kind,
        ObservationKind::Decoded,
        "{}",
        observation.reason
    );
    let world = World::load(
        imperium_net_world::embedded::PACK,
        imperium_net_world::embedded::HASH,
    )
    .expect("embedded world integrity");
    world
        .admit(observation.seeds, Policy::NETWORK, hash(packet))
        .expect("v4 admission")
}

#[test]
fn matched_udp_endpoints_have_indistinguishable_v4_causal_neighborhoods() {
    let approved_fixture = udp_packet([10, 77, 0, 2], 5353);
    let forbidden_fixture = udp_packet([10, 77, 0, 99], 9999);
    let approved = admitted(&approved_fixture);
    let forbidden = admitted(&forbidden_fixture);

    assert_ne!(approved.query, forbidden.query);
    assert_eq!(approved.seeds, forbidden.seeds);
    assert_eq!(approved.nodes, forbidden.nodes);
    assert_eq!(approved.edges, forbidden.edges);
    assert_eq!(approved.excluded, forbidden.excluded);
    assert_eq!(approved.hop_frontier, forbidden.hop_frontier);
}

#[test]
fn different_tcp_ack_progressions_have_indistinguishable_v4_causal_neighborhoods() {
    // The first is plausible after a handshake; the second could be an orphan
    // or out-of-window ACK. No flow history is given to the world, so neither
    // receives an in-window label here.
    let first_fixture = tcp_ack_packet(100, 200);
    let second_fixture = tcp_ack_packet(4_000_000, 9_000_000);
    let first = admitted(&first_fixture);
    let second = admitted(&second_fixture);

    assert_ne!(first.query, second.query);
    assert_eq!(first.seeds, second.seeds);
    assert_eq!(first.nodes, second.nodes);
    assert_eq!(first.edges, second.edges);
    assert_eq!(first.excluded, second.excluded);
    assert_eq!(first.hop_frontier, second.hop_frontier);
}

#[test]
fn packet_structure_has_no_positive_graph_path_to_authorized_flow() {
    let world = World::load(embedded::PACK, embedded::HASH).expect("embedded world integrity");
    let mut reachable = vec![false; world.node_count()];
    for seed in [
        embedded::IPV4,
        embedded::UDP,
        embedded::TCP,
        embedded::ENDPOINT_ADDRESSES,
    ] {
        reachable[seed] = true;
    }
    // This searches the entire v4 positive graph, beyond the production
    // three-hop/32-node receipt. A positive route absent here cannot be made
    // present by increasing receipt capacity.
    loop {
        let before = reachable.clone();
        for index in 0..world.edge_count() {
            let edge = world.edge(index).expect("validated edge index");
            if edge.polarity == 1
                && (reachable[edge.source as usize] || reachable[edge.target as usize])
            {
                reachable[edge.source as usize] = true;
                reachable[edge.target as usize] = true;
            }
        }
        if reachable == before {
            break;
        }
    }
    assert!(!reachable[embedded::AUTHORIZED_FLOW]);
    assert!(!reachable[embedded::APPROVED_SERVICE]);
}
