//! Bounded IPv6 parser -> flow-fact checks for an unsealed world expansion.
//! No peer authentication, host policy, Lightcone release, or delivery occurs.

use std::net::{IpAddr, Ipv6Addr};

use imperium_net_mesh::flow_behavior::{
    AcknowledgmentRelation, FlowBehaviorConfig, FlowBehaviorTracker, FlowFact, FlowOutcome,
    FlowSide, FlowUnsupported, SequenceRelation,
};
use imperium_net_mesh::WireDirection;
use imperium_net_observer::{parse_raw_ip_flow, FlowParseError, Fragmentation, TransportProtocol};
use imperium_protocol::{PeerId, SessionId};

fn endpoints(reverse: bool) -> (Ipv6Addr, Ipv6Addr) {
    let first: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let second: Ipv6Addr = "2001:db8:2::2".parse().unwrap();
    if reverse {
        (second, first)
    } else {
        (first, second)
    }
}

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

fn ipv6(next_header: u8, payload: &[u8], reverse: bool) -> Vec<u8> {
    let (source, destination) = endpoints(reverse);
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    packet
}

fn transport_checksum(packet: &mut [u8], offset: usize, protocol: u8, checksum_at: usize) {
    packet[offset + checksum_at..offset + checksum_at + 2].fill(0);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&packet[8..40]);
    pseudo.extend_from_slice(&((packet.len() - offset) as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    pseudo.extend_from_slice(&packet[offset..]);
    let mut value = checksum(&pseudo);
    if protocol == 17 && value == 0 {
        value = 0xffff;
    }
    packet[offset + checksum_at..offset + checksum_at + 2].copy_from_slice(&value.to_be_bytes());
}

fn udp(reverse: bool, extension: bool) -> Vec<u8> {
    let mut datagram = [0u8; 8];
    let (source_port, destination_port) = if reverse {
        (5353u16, 40_000u16)
    } else {
        (40_000, 5353)
    };
    datagram[0..2].copy_from_slice(&source_port.to_be_bytes());
    datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
    datagram[4..6].copy_from_slice(&8u16.to_be_bytes());
    if extension {
        let mut payload = [0u8; 16];
        payload[0] = 17; // Destination Options -> UDP.
        payload[8..].copy_from_slice(&datagram);
        let mut packet = ipv6(60, &payload, reverse);
        transport_checksum(&mut packet, 48, 17, 6);
        packet
    } else {
        let mut packet = ipv6(17, &datagram, reverse);
        transport_checksum(&mut packet, 40, 17, 6);
        packet
    }
}

fn tcp(reverse: bool, sequence: u32, acknowledgement: u32, flags: u8) -> Vec<u8> {
    let mut segment = [0u8; 20];
    let (source_port, destination_port) = if reverse {
        (443u16, 40_001u16)
    } else {
        (40_001, 443)
    };
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&4096u16.to_be_bytes());
    let mut packet = ipv6(6, &segment, reverse);
    transport_checksum(&mut packet, 40, 6, 16);
    packet
}

fn echo_request() -> Vec<u8> {
    let message = [128, 0, 0, 0, 0, 7, 0, 9];
    let mut packet = ipv6(58, &message, false);
    transport_checksum(&mut packet, 40, 58, 2);
    packet
}

#[test]
fn udp_extension_and_reverse_tuple_are_factual_not_authorization() {
    let peer = PeerId::new();
    let session = SessionId::new();
    let other_session = SessionId::new();
    let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
    let outbound = parse_raw_ip_flow(&udp(false, true)).unwrap();
    assert_eq!(outbound.protocol, TransportProtocol::Udp);
    assert_eq!(outbound.source, IpAddr::V6(endpoints(false).0));
    assert_eq!(outbound.destination, IpAddr::V6(endpoints(false).1));
    assert_eq!(
        (outbound.source_port, outbound.destination_port),
        (Some(40_000), Some(5353))
    );
    assert_eq!(outbound.fragmentation, Fragmentation::None);
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Outbound, &outbound),
        FlowOutcome::Fact(FlowFact::UdpTupleObserved)
    );
    let returned = parse_raw_ip_flow(&udp(true, false)).unwrap();
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Inbound, &returned),
        FlowOutcome::Fact(FlowFact::UdpReverseTupleObserved)
    );
    assert_eq!(
        tracker.observe(&peer, &other_session, WireDirection::Inbound, &returned),
        FlowOutcome::Fact(FlowFact::UdpTupleObserved)
    );
}

#[test]
fn tcp_opening_requires_same_session_history() {
    let peer = PeerId::new();
    let session = SessionId::new();
    let orphan_session = SessionId::new();
    let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
    let syn = parse_raw_ip_flow(&tcp(false, 1000, 0, 0x02)).unwrap();
    let synack = parse_raw_ip_flow(&tcp(true, 2000, 1001, 0x12)).unwrap();
    let ack_bytes = tcp(false, 1001, 2001, 0x10);
    let ack = parse_raw_ip_flow(&ack_bytes).unwrap();
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Outbound, &syn),
        FlowOutcome::Fact(FlowFact::TcpSynObserved)
    );
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Inbound, &synack),
        FlowOutcome::Fact(FlowFact::TcpSynAckCorrelated)
    );
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Outbound, &ack),
        FlowOutcome::Fact(FlowFact::TcpHandshakeCorrelated)
    );
    assert_eq!(
        tracker.observe(&peer, &orphan_session, WireDirection::Outbound, &ack),
        FlowOutcome::Unsupported(FlowUnsupported::TcpMidstream)
    );
    let ahead = parse_raw_ip_flow(&tcp(false, 9000, 9000, 0x10)).unwrap();
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Outbound, &ahead),
        FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
            side: FlowSide::Opening,
            sequence: SequenceRelation::AheadOfExpected,
            acknowledgement: AcknowledgmentRelation::AheadOfObserved,
            flags: 0x10,
            payload_len: 0,
        })
    );
}

#[test]
fn fragments_bad_checksums_and_unrepresented_echo_do_not_become_flow_facts() {
    let mut fragment = [0u8; 8];
    fragment[0] = 17; // UDP next header after reassembly.
    fragment[3] = 1; // offset zero, more fragments.
    fragment[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    let fragment = parse_raw_ip_flow(&ipv6(44, &fragment, false)).unwrap();
    assert_eq!(fragment.source_port, None);
    assert_eq!(fragment.destination_port, None);
    assert_eq!(
        fragment.fragmentation,
        Fragmentation::Fragment {
            identification: 0x1234_5678,
            offset_bytes: 0,
            more_fragments: true,
        }
    );
    let peer = PeerId::new();
    let session = SessionId::new();
    let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
    assert_eq!(
        tracker.observe(&peer, &session, WireDirection::Outbound, &fragment),
        FlowOutcome::Unsupported(FlowUnsupported::FragmentedPacket)
    );
    let mut invalid_udp = udp(false, false);
    invalid_udp[46] ^= 1;
    assert!(matches!(
        parse_raw_ip_flow(&invalid_udp),
        Err(FlowParseError::Malformed(_))
    ));
    assert_eq!(
        parse_raw_ip_flow(&echo_request()),
        Err(FlowParseError::Unsupported("unrepresented_icmp_type"))
    );
}
