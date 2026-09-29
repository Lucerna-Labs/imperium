//! Structural wire observations for the passive network Lightcone.
#![cfg_attr(not(any(test, feature = "std")), no_std)]

use imperium_net_world::{embedded as node, set, NODE_WORDS};

mod flow;
pub use flow::{
    parse_raw_ip_flow, FlowMetadata, FlowParseError, Fragmentation, IcmpEchoMetadata, IcmpMetadata,
    TcpMetadata, TransportProtocol,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationKind {
    Decoded,
    Unknown,
    Malformed,
    Fragment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub kind: ObservationKind,
    pub seeds: [u64; NODE_WORDS],
    /// Stable diagnostic reason for this exact structural observation.
    pub reason: &'static str,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    sum
}

fn folded(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn valid_checksum(bytes: &[u8]) -> bool {
    folded(add_words(0, bytes)) == 0xffff
}

fn valid_ipv4_transport(ip: &[u8], data: &[u8], protocol: u8) -> bool {
    let mut sum = protocol as u32 + data.len() as u32;
    sum = add_words(sum, &ip[12..20]);
    folded(add_words(sum, data)) == 0xffff
}

fn valid_ipv6_transport(ip: &[u8], data: &[u8], protocol: u8) -> bool {
    let length = data.len() as u32;
    let mut sum = add_words(0, &ip[8..40]);
    sum += (length >> 16) + (length & 0xffff) + protocol as u32;
    folded(add_words(sum, data)) == 0xffff
}

fn malformed(reason: &'static str) -> Observation {
    Observation {
        kind: ObservationKind::Malformed,
        seeds: [0; NODE_WORDS],
        reason,
    }
}

fn decode_udp(
    out: &mut Observation,
    ip: &[u8],
    data: &[u8],
    ipv6: bool,
) -> Result<(), &'static str> {
    if data.len() < 8 {
        return Err("udp_short_header");
    }
    let length = word(data, 4) as usize;
    if length < 8 || length != data.len() {
        return Err("udp_length_mismatch");
    }
    let checksum = word(data, 6);
    if ipv6 {
        if checksum == 0 {
            return Err("udp_ipv6_zero_checksum");
        }
        if !valid_ipv6_transport(ip, data, 17) {
            return Err("udp_ipv6_bad_checksum");
        }
    } else if checksum != 0 && !valid_ipv4_transport(ip, data, 17) {
        return Err("udp_ipv4_bad_checksum");
    }
    set(&mut out.seeds, node::UDP);
    set(&mut out.seeds, node::UDP_LENGTH);
    set(&mut out.seeds, node::UDP_PORTS);
    if word(data, 0) == 0 {
        set(&mut out.seeds, node::UDP_SOURCE_ZERO);
    }
    if checksum == 0 {
        set(&mut out.seeds, node::UDP_NO_CHECKSUM);
        out.reason = "ipv4_udp_no_checksum";
    } else {
        set(&mut out.seeds, node::UDP_CHECKSUM);
        set(&mut out.seeds, node::UDP_INTEGRITY);
        out.reason = if ipv6 {
            "ipv6_udp_valid"
        } else {
            "ipv4_udp_valid"
        };
    }
    Ok(())
}

fn decode_tcp(
    out: &mut Observation,
    ip: &[u8],
    data: &[u8],
    ipv6: bool,
) -> Result<(), &'static str> {
    if data.len() < 20 {
        return Err("tcp_short_header");
    }
    let header = (data[12] >> 4) as usize * 4;
    if header < 20 || header > data.len() {
        return Err("tcp_header_length_invalid");
    }
    let valid = if ipv6 {
        valid_ipv6_transport(ip, data, 6)
    } else {
        valid_ipv4_transport(ip, data, 6)
    };
    if !valid {
        return Err("tcp_bad_checksum");
    }
    set(&mut out.seeds, node::TCP);
    set(&mut out.seeds, node::TCP_PORTS);
    set(&mut out.seeds, node::TCP_CHECKSUM);
    if data.len() > header {
        set(&mut out.seeds, node::TCP_PAYLOAD);
    }
    for (flag, symbol) in [
        (0x02, node::TCP_SYN),
        (0x10, node::TCP_ACK),
        (0x01, node::TCP_FIN),
        (0x04, node::TCP_RST),
    ] {
        if data[13] & flag != 0 {
            set(&mut out.seeds, symbol);
        }
    }
    out.reason = if ipv6 {
        "ipv6_tcp_valid"
    } else {
        "ipv4_tcp_valid"
    };
    Ok(())
}

fn decode_icmpv4(out: &mut Observation, data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 8 {
        return Err("icmpv4_short_message");
    }
    if !valid_checksum(data) {
        return Err("icmpv4_bad_checksum");
    }
    set(&mut out.seeds, node::ICMP_CHECKSUM);
    match (data[0], data[1]) {
        (8, 0) => set(&mut out.seeds, node::ICMP_REQUEST),
        (0, 0) => set(&mut out.seeds, node::ICMP_REPLY),
        (3, 0..=15) => set(&mut out.seeds, node::ICMP_UNREACHABLE),
        (11, 0..=1) => set(&mut out.seeds, node::ICMP_EXPIRED),
        (12, _) => set(&mut out.seeds, node::ICMP_PARAMETER_PROBLEM),
        (5, _) => set(&mut out.seeds, node::ICMP_REDIRECT),
        _ => {
            out.reason = "icmpv4_unrepresented_type";
            return Ok(());
        }
    }
    out.reason = "icmpv4_valid";
    Ok(())
}

fn ndp_has_source_link_option(data: &[u8], mut offset: usize) -> Result<bool, &'static str> {
    let mut found = false;
    while offset < data.len() {
        if offset + 2 > data.len() {
            return Err("ndp_option_length_invalid");
        }
        let length = data[offset + 1] as usize * 8;
        if length == 0 || offset + length > data.len() {
            return Err("ndp_option_length_invalid");
        }
        found |= data[offset] == 1;
        offset += length;
    }
    Ok(found)
}

fn unspecified_ipv6(address: &[u8]) -> bool {
    address.iter().all(|&byte| byte == 0)
}

fn solicited_node_multicast(address: &[u8]) -> bool {
    address[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
}

fn link_local_ipv6(address: &[u8]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

fn decode_icmpv6(out: &mut Observation, ip: &[u8], data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 8 {
        return Err("icmpv6_short_message");
    }
    if !valid_ipv6_transport(ip, data, 58) {
        return Err("icmpv6_bad_checksum");
    }
    // Neighbor Discovery has stricter wire validity than generic ICMPv6.
    // Validate it before any IPv6 or NDP seed can reach the Lightcone.
    if (133..=136).contains(&data[0]) {
        if ip[7] != 255 {
            return Err("ndp_hop_limit_invalid");
        }
        if data[1] != 0 {
            return Err("ndp_code_invalid");
        }
        let minimum_length = if data[0] == 133 {
            8
        } else if data[0] == 134 {
            16
        } else {
            24
        };
        if data.len() < minimum_length {
            return Err("ndp_short_message");
        }
        let source = &ip[8..24];
        let destination = &ip[24..40];
        let source_link_option = ndp_has_source_link_option(data, minimum_length)?;
        match data[0] {
            133 if unspecified_ipv6(source) && source_link_option => {
                return Err("ndp_unspecified_source_link_option");
            }
            134 if !link_local_ipv6(source) => {
                return Err("ndp_router_source_not_link_local");
            }
            135 => {
                if data[8] == 0xff {
                    return Err("ndp_multicast_target");
                }
                if unspecified_ipv6(source) {
                    if !solicited_node_multicast(destination) {
                        return Err("ndp_unspecified_source_destination_invalid");
                    }
                    if source_link_option {
                        return Err("ndp_unspecified_source_link_option");
                    }
                }
            }
            136 => {
                if data[8] == 0xff {
                    return Err("ndp_multicast_target");
                }
                if destination[0] == 0xff && data[4] & 0x40 != 0 {
                    return Err("ndp_solicited_multicast_advertisement");
                }
            }
            _ => {}
        }
    }
    set(&mut out.seeds, node::ICMPV6);
    set(&mut out.seeds, node::ICMPV6_CHECKSUM);
    match data[0] {
        1..=4 => set(&mut out.seeds, node::ICMPV6_ERROR),
        133 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::ROUTER_SOLICITATION);
        }
        134 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::ROUTER_ADVERTISEMENT);
        }
        135 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::NEIGHBOR_SOLICITATION);
        }
        136 => {
            set(&mut out.seeds, node::NDP);
            set(&mut out.seeds, node::NEIGHBOR_ADVERTISEMENT);
        }
        _ => {
            out.reason = "icmpv6_unrepresented_type";
            return Ok(());
        }
    }
    out.reason = "icmpv6_valid";
    Ok(())
}

fn decode_ipv4(out: &mut Observation, packet: &[u8]) -> Result<(), &'static str> {
    if packet.len() < 20 {
        return Err("ipv4_short_header");
    }
    if packet[0] >> 4 != 4 {
        return Err("ipv4_bad_version");
    }
    let header = (packet[0] & 0x0f) as usize * 4;
    let total = word(packet, 2) as usize;
    if header < 20 || header > packet.len() {
        return Err("ipv4_header_length_invalid");
    }
    if total < header || total > packet.len() {
        return Err("ipv4_total_length_invalid");
    }
    if !valid_checksum(&packet[..header]) {
        return Err("ipv4_bad_header_checksum");
    }
    set(&mut out.seeds, node::IPV4);
    set(&mut out.seeds, node::IP_HEADER);
    set(&mut out.seeds, node::IP_LENGTH);
    set(&mut out.seeds, node::IP_CHECKSUM);
    set(&mut out.seeds, node::IP_PROTOCOL);
    set(&mut out.seeds, node::ENDPOINT_ADDRESSES);
    if packet[8] > 0 {
        set(&mut out.seeds, node::IP_TTL);
    }
    if word(packet, 6) & 0x3fff != 0 {
        set(&mut out.seeds, node::IP_FRAGMENT);
        out.kind = ObservationKind::Fragment;
        out.reason = "ipv4_fragment_requires_reassembly";
        return Ok(());
    }
    let data = &packet[header..total];
    match packet[9] {
        17 => decode_udp(out, packet, data, false),
        6 => decode_tcp(out, packet, data, false),
        1 => decode_icmpv4(out, data),
        _ => {
            out.reason = "ipv4_header_only_unrepresented_transport";
            Ok(())
        }
    }
}

fn decode_ipv6(out: &mut Observation, packet: &[u8]) -> Result<(), &'static str> {
    if packet.len() < 40 {
        return Err("ipv6_short_header");
    }
    if packet[0] >> 4 != 6 {
        return Err("ipv6_bad_version");
    }
    let payload = word(packet, 4) as usize;
    if 40 + payload > packet.len() {
        return Err("ipv6_payload_length_invalid");
    }
    set(&mut out.seeds, node::IPV6);
    set(&mut out.seeds, node::IPV6_PAYLOAD_LENGTH);
    set(&mut out.seeds, node::IPV6_NEXT_HEADER);
    set(&mut out.seeds, node::IPV6_HOP_LIMIT);
    set(&mut out.seeds, node::IPV6_SOURCE);
    set(&mut out.seeds, node::IPV6_DESTINATION);
    let mut next = packet[6];
    let mut offset = 40usize;
    let end = 40 + payload;
    // Each recognized extension consumes at least eight bytes, so the
    // declared payload bounds this walk without an arbitrary header count.
    loop {
        match next {
            0 | 43 | 60 => {
                if next == 0 && offset != 40 {
                    return Err("ipv6_hop_by_hop_not_first");
                }
                if offset + 2 > end {
                    return Err("ipv6_extension_short_header");
                }
                set(&mut out.seeds, node::IPV6_EXTENSION);
                let length = (packet[offset + 1] as usize + 1) * 8;
                if length < 8 || offset + length > end {
                    return Err("ipv6_extension_length_invalid");
                }
                next = packet[offset];
                offset += length;
            }
            44 => {
                if offset + 8 > end {
                    return Err("ipv6_fragment_short_header");
                }
                set(&mut out.seeds, node::IPV6_FRAGMENT);
                out.kind = ObservationKind::Fragment;
                out.reason = "ipv6_fragment_requires_reassembly";
                return Ok(());
            }
            _ => break,
        }
    }
    let data = &packet[offset..end];
    match next {
        17 => decode_udp(out, packet, data, true),
        6 => decode_tcp(out, packet, data, true),
        58 => decode_icmpv6(out, packet, data),
        _ => {
            out.reason = "ipv6_header_only_unrepresented_transport";
            Ok(())
        }
    }
}

/// Decode only bounded wire structure. Payload text cannot select node IDs.
pub fn decode(frame: &[u8]) -> Observation {
    let mut out = Observation {
        kind: ObservationKind::Unknown,
        seeds: [0; NODE_WORDS],
        reason: "unparsed",
    };
    if frame.len() < 14 {
        return malformed("ethernet_short_frame");
    }
    let ether_type = word(frame, 12);
    let packet = &frame[14..];
    let result = match ether_type {
        0x0806 => {
            if packet.len() < 28
                || word(packet, 0) != 1
                || word(packet, 2) != 0x0800
                || packet[4] != 6
                || packet[5] != 4
            {
                Err("arp_structure_invalid")
            } else {
                match word(packet, 6) {
                    1 => {
                        set(&mut out.seeds, node::ARP_REQUEST);
                        out.reason = "arp_request_valid";
                    }
                    2 => {
                        set(&mut out.seeds, node::ARP_REPLY);
                        out.reason = "arp_reply_valid";
                    }
                    _ => {
                        out.reason = "arp_unrepresented_operation";
                        return out;
                    }
                }
                Ok(())
            }
        }
        0x0800 => decode_ipv4(&mut out, packet),
        0x86dd => decode_ipv6(&mut out, packet),
        _ => {
            out.reason = "ethernet_unrepresented_ethertype";
            return out;
        }
    };
    if let Err(reason) = result {
        return malformed(reason);
    }
    if out.kind != ObservationKind::Fragment {
        out.kind = ObservationKind::Decoded;
    }
    out
}

/// Decode a packet from a Linux TUN device. TUN yields layer-3 IP bytes,
/// without an Ethernet header; no synthetic link header is inserted.
pub fn decode_raw_ip(packet: &[u8]) -> Observation {
    let mut out = Observation {
        kind: ObservationKind::Unknown,
        seeds: [0; NODE_WORDS],
        reason: "ip_unparsed",
    };
    let result = match packet.first().map(|byte| byte >> 4) {
        Some(4) => decode_ipv4(&mut out, packet),
        Some(6) => decode_ipv6(&mut out, packet),
        _ => return malformed("ip_version_unrecognized"),
    };
    if let Err(reason) = result {
        return malformed(reason);
    }
    if out.kind != ObservationKind::Fragment {
        out.kind = ObservationKind::Decoded;
    }
    out
}

/// Decode only Imperium's outer UDP datagram shape. The encrypted payload and
/// handshake body remain opaque; this is not a claim about their contents or
/// whether a received datagram was authenticated later in the mesh pipeline.
pub fn decode_mesh_datagram(datagram: &[u8]) -> Observation {
    let mut out = Observation {
        kind: ObservationKind::Unknown,
        seeds: [0; NODE_WORDS],
        reason: "mesh_unknown_datagram",
    };
    match datagram {
        [0x03, _, _, _, _, _, _, _, _, _, _, ..] => {
            out.kind = ObservationKind::Decoded;
            out.reason = "mesh_encrypted_frame_shape";
        }
        [0x02, 1..=4, _, ..] => {
            out.kind = ObservationKind::Decoded;
            out.reason = "mesh_handshake_shape";
        }
        [0x02, 5, _, _, _, _, _, _, _, _, _, ..] => {
            out.kind = ObservationKind::Fragment;
            out.reason = "mesh_handshake_fragment_shape";
        }
        [0x02 | 0x03, ..] => return malformed("mesh_datagram_truncated_or_invalid"),
        [] => return malformed("mesh_datagram_empty"),
        _ => return out,
    }
    set(&mut out.seeds, node::FRAME);
    set(&mut out.seeds, node::UDP);
    set(&mut out.seeds, node::OPAQUE);
    out
}

/// Add context only after a trusted host parser validates that symbol.
/// Raw packet payloads must never call this boundary directly.
pub fn add_host_validated_symbol(observation: &mut Observation, symbol: usize) -> bool {
    if symbol >= imperium_net_world::MAX_NODES {
        return false;
    }
    set(&mut observation.seeds, symbol);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_world::bit;

    fn finish_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset + 1] = 0;
        let value = !folded(add_words(0, bytes));
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn finish_icmpv6_checksum(packet: &mut [u8]) {
        let length = word(packet, 4) as usize;
        packet[42..44].fill(0);
        let mut sum = add_words(0, &packet[8..40]);
        sum += length as u32 + 58;
        let checksum = !folded(add_words(sum, &packet[40..40 + length]));
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    }

    fn udp_frame(payload: &[u8]) -> ([u8; 256], usize) {
        let mut frame = [0u8; 256];
        let length = 14 + 20 + 8 + payload.len();
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..length];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        finish_checksum(&mut ip[..20], 10);
        let udp = &mut ip[20..];
        udp[0..2].copy_from_slice(&12000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp[8..8 + payload.len()].copy_from_slice(payload);
        (frame, length)
    }

    #[test]
    fn tun_ip_is_decoded_without_inventing_an_ethernet_header() {
        let (frame, length) = udp_frame(b"payload");
        let observation = decode_raw_ip(&frame[14..length]);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert!(bit(&observation.seeds, node::IPV4));
        assert!(bit(&observation.seeds, node::UDP));
        assert_eq!(decode_raw_ip(b"not an IP packet").seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn mesh_datagram_decoding_is_structural_and_payload_blind() {
        let mut ordinary = vec![0x03, 0];
        ordinary.extend_from_slice(&7u64.to_le_bytes());
        ordinary.push(0);
        let mut hostile = ordinary.clone();
        hostile.extend_from_slice(b"authorize=true node=export");
        let a = decode_mesh_datagram(&ordinary);
        let b = decode_mesh_datagram(&hostile);
        assert_eq!(a.kind, ObservationKind::Decoded);
        assert_eq!(a.seeds, b.seeds);
        assert!(bit(&a.seeds, node::FRAME));
        assert!(bit(&a.seeds, node::OPAQUE));
        assert_eq!(decode_mesh_datagram(&[0x03, 0]).seeds, [0; NODE_WORDS]);
        assert_eq!(decode_mesh_datagram(&[0xff]).seeds, [0; NODE_WORDS]);
    }

    fn ipv6_neighbor_solicitation() -> ([u8; 128], usize) {
        let mut frame = [0u8; 128];
        let length = 14 + 40 + 24;
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&24u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 255;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 2]);
        packet[40] = 135;
        packet[41] = 0;
        packet[48..64].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        finish_icmpv6_checksum(packet);
        (frame, length)
    }

    #[test]
    fn malformed_and_unknown_observations_have_no_seeds() {
        for length in 0..14 {
            let observation = decode(&[0u8; 14][..length]);
            assert_eq!(observation.kind, ObservationKind::Malformed);
            assert_eq!(observation.seeds, [0; NODE_WORDS]);
            assert_eq!(observation.reason, "ethernet_short_frame");
        }
        let mut frame = [0u8; 14];
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Unknown);
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
        assert_eq!(observation.reason, "ethernet_unrepresented_ethertype");
    }

    #[test]
    fn payload_text_cannot_select_nodes() {
        let (ordinary, ordinary_len) = udp_frame(b"ordinary");
        let (text, text_len) = udp_frame(b"node=export;authorize=true;probe");
        assert_eq!(
            decode(&ordinary[..ordinary_len]).seeds,
            decode(&text[..text_len]).seeds
        );
    }

    #[test]
    fn structurally_valid_udp_seeds_only_protocol_context() {
        let (frame, length) = udp_frame(b"context");
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert_eq!(observation.reason, "ipv4_udp_no_checksum");
        assert!(bit(&observation.seeds, node::IPV4));
        assert!(bit(&observation.seeds, node::UDP));
        assert!(bit(&observation.seeds, node::UDP_PORTS));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
        assert!(!bit(&observation.seeds, node::POLICY_DECISION));
    }

    #[test]
    fn shared_protocol_symbol_can_enter_without_host_authority() {
        let (frame, length) = udp_frame(b"context");
        let mut observation = decode(&frame[..length]);
        assert!(add_host_validated_symbol(&mut observation, node::DNS_QUERY));
        assert!(bit(&observation.seeds, node::DNS_QUERY));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
    }

    #[test]
    fn ipv6_neighbor_discovery_is_structurally_seeded() {
        let (frame, length) = ipv6_neighbor_solicitation();
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert_eq!(observation.reason, "icmpv6_valid");
        assert!(bit(&observation.seeds, node::IPV6));
        assert!(bit(&observation.seeds, node::ICMPV6));
        assert!(bit(&observation.seeds, node::NDP));
        assert!(bit(&observation.seeds, node::NEIGHBOR_SOLICITATION));
        assert!(!bit(&observation.seeds, node::AUTHORIZED_FLOW));
    }

    #[test]
    fn neighbor_discovery_requires_hop_limit_255() {
        let (mut frame, length) = ipv6_neighbor_solicitation();
        frame[14 + 7] = 64;
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_hop_limit_invalid");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn neighbor_discovery_requires_code_zero_and_complete_message() {
        let (mut frame, length) = ipv6_neighbor_solicitation();
        let packet = &mut frame[14..length];
        packet[41] = 1;
        finish_icmpv6_checksum(packet);
        let observation = decode(&frame[..length]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_code_invalid");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);

        let (mut frame, _) = ipv6_neighbor_solicitation();
        let packet = &mut frame[14..14 + 40 + 8];
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        finish_icmpv6_checksum(packet);
        let observation = decode(&frame[..14 + 40 + 8]);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ndp_short_message");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn unresolved_ipv6_extension_chain_has_no_context() {
        let mut frame = [0u8; 14 + 40 + 64];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&64u16.to_be_bytes());
        packet[6] = 60;
        for extension in packet[40..].chunks_exact_mut(8) {
            extension[0] = 60;
        }
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ipv6_extension_short_header");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn complete_ipv6_extension_chain_can_exceed_eight_headers() {
        let mut frame = [0u8; 14 + 40 + 72];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&72u16.to_be_bytes());
        packet[6] = 60;
        for extension in packet[40..].chunks_exact_mut(8) {
            extension[0] = 60;
        }
        packet[40 + 64] = 59;
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Decoded);
        assert_eq!(
            observation.reason,
            "ipv6_header_only_unrepresented_transport"
        );
        assert!(bit(&observation.seeds, node::IPV6));
        assert!(bit(&observation.seeds, node::IPV6_EXTENSION));
    }

    #[test]
    fn hop_by_hop_extension_must_be_first() {
        let mut frame = [0u8; 14 + 40 + 16];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let packet = &mut frame[14..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 60;
        packet[40] = 0;
        packet[48] = 59;
        let observation = decode(&frame);
        assert_eq!(observation.kind, ObservationKind::Malformed);
        assert_eq!(observation.reason, "ipv6_hop_by_hop_not_first");
        assert_eq!(observation.seeds, [0; NODE_WORDS]);
    }

    #[test]
    fn deterministic_wire_stress_keeps_unrecognized_inputs_empty() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        let mut frame = [0u8; 300];
        for trial in 0..20_000usize {
            let length = 14 + trial % (frame.len() - 13);
            for byte in &mut frame[..length] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            frame[12..14].copy_from_slice(
                &match trial % 3 {
                    0 => 0x86ddu16,
                    1 => 0x0800u16,
                    _ => 0x0806u16,
                }
                .to_be_bytes(),
            );
            if trial % 3 == 0 && length >= 54 {
                frame[14] = 0x60;
                frame[18..20].copy_from_slice(&((length - 54) as u16).to_be_bytes());
                frame[20] = [0, 43, 44, 60, 58, 17, 6, 59][trial % 8];
            }
            let observation = decode(&frame[..length]);
            if matches!(
                observation.kind,
                ObservationKind::Malformed | ObservationKind::Unknown
            ) {
                assert_eq!(observation.seeds, [0; NODE_WORDS], "trial {trial}");
            }
        }
    }
}
