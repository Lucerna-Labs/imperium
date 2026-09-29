use imperium_net_observer::{
    parse_raw_ip_flow, FlowParseError, IcmpEchoMetadata, IcmpMetadata, TransportProtocol,
};

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let (pairs, tail) = bytes.as_chunks::<2>();
    for pair in pairs {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = tail.first() {
        sum += (last as u32) << 8;
    }
    sum
}

fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_icmp(message_type: u8, code: u8, reverse: bool) -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    let (source, destination) = if reverse {
        ([10, 0, 0, 2], [10, 0, 0, 1])
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2])
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let header_checksum = checksum(add_words(0, &packet[..20]));
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20] = message_type;
    packet[21] = code;
    packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[26..28].copy_from_slice(&7u16.to_be_bytes());
    let icmp_checksum = checksum(add_words(0, &packet[20..]));
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

fn ipv6_icmp(message_type: u8, code: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    packet[24..40].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    packet[40] = message_type;
    packet[41] = code;
    packet[44..46].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[46..48].copy_from_slice(&7u16.to_be_bytes());
    let mut sum = add_words(0, &packet[8..40]);
    sum += 8 + 58;
    let icmp_checksum = checksum(add_words(sum, &packet[40..]));
    packet[42..44].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

#[test]
fn ipv4_echo_request_reply_metadata_is_factual_and_correlatable() {
    let request = parse_raw_ip_flow(&ipv4_icmp(8, 0, false)).unwrap();
    let reply = parse_raw_ip_flow(&ipv4_icmp(0, 0, true)).unwrap();
    assert_eq!(request.protocol, TransportProtocol::Icmpv4);
    assert_eq!(request.source, reply.destination);
    assert_eq!(request.destination, reply.source);
    assert_eq!(request.source_port, None);
    assert_eq!(request.destination_port, None);
    assert_eq!(
        request.icmp,
        Some(IcmpMetadata {
            message_type: 8,
            code: 0,
            echo: Some(IcmpEchoMetadata {
                identifier: 0x1234,
                sequence: 7,
            }),
        })
    );
    assert_eq!(reply.icmp.unwrap().message_type, 0);
    assert_eq!(reply.icmp.unwrap().echo, request.icmp.unwrap().echo);
}

#[test]
fn represented_ipv6_error_has_type_code_but_ipv6_echo_is_unsupported() {
    let error = parse_raw_ip_flow(&ipv6_icmp(1, 4)).unwrap();
    assert_eq!(error.protocol, TransportProtocol::Icmpv6);
    assert_eq!(error.icmp.unwrap().message_type, 1);
    assert_eq!(error.icmp.unwrap().code, 4);
    assert_eq!(error.icmp.unwrap().echo, None);
    assert_eq!(
        parse_raw_ip_flow(&ipv6_icmp(128, 0)),
        Err(FlowParseError::Unsupported("unrepresented_icmp_type"))
    );
}

#[test]
fn unsupported_icmpv4_type_and_corrupt_checksum_are_rejected() {
    assert_eq!(
        parse_raw_ip_flow(&ipv4_icmp(13, 0, false)),
        Err(FlowParseError::Unsupported("unrepresented_icmp_type"))
    );
    let mut corrupt = ipv4_icmp(8, 0, false);
    corrupt[22] ^= 1;
    assert!(matches!(
        parse_raw_ip_flow(&corrupt),
        Err(FlowParseError::Malformed(_))
    ));
}
