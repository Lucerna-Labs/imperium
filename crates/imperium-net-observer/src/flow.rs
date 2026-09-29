//! Payload-blind metadata from a validated Linux TUN RawIp packet.
//!
//! This parser retains no packet bytes and makes no authorization decision.
//! A fragment has no attributable transport header until another owner
//! reassembles it.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{decode_raw_ip, ObservationKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fragmentation {
    None,
    Fragment {
        identification: u32,
        offset_bytes: u16,
        more_fragments: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpMetadata {
    /// Raw fields; sequence and ACK validity require external flow state.
    pub sequence: u32,
    pub acknowledgement: u32,
    /// NS in bit 8; the TCP flag octet in bits 7..0.
    pub flags: u16,
    pub window: u16,
    pub header_len: u8,
    pub payload_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEchoMetadata {
    pub identifier: u16,
    pub sequence: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpMetadata {
    pub message_type: u8,
    pub code: u8,
    /// Present only on represented echo request/reply messages.
    pub echo: Option<IcmpEchoMetadata>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowMetadata {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp: Option<TcpMetadata>,
    pub icmp: Option<IcmpMetadata>,
    pub fragmentation: Fragmentation,
    /// Declared IP packet size; no payload bytes are retained.
    pub packet_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowParseError {
    Malformed(&'static str),
    Unsupported(&'static str),
}

fn bytes<const N: usize>(packet: &[u8], offset: usize) -> Result<[u8; N], FlowParseError> {
    packet
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(FlowParseError::Malformed("flow_header_truncated"))
}

fn u16_at(packet: &[u8], offset: usize) -> Result<u16, FlowParseError> {
    Ok(u16::from_be_bytes(bytes::<2>(packet, offset)?))
}

fn u32_at(packet: &[u8], offset: usize) -> Result<u32, FlowParseError> {
    Ok(u32::from_be_bytes(bytes::<4>(packet, offset)?))
}

fn protocol(number: u8, ipv6: bool) -> Result<TransportProtocol, FlowParseError> {
    match (number, ipv6) {
        (6, _) => Ok(TransportProtocol::Tcp),
        (17, _) => Ok(TransportProtocol::Udp),
        (1, false) => Ok(TransportProtocol::Icmpv4),
        (58, true) => Ok(TransportProtocol::Icmpv6),
        _ => Err(FlowParseError::Unsupported("unrepresented_transport")),
    }
}

fn transport_fields(
    metadata: &mut FlowMetadata,
    packet: &[u8],
    offset: usize,
) -> Result<(), FlowParseError> {
    match metadata.protocol {
        TransportProtocol::Tcp => {
            let header = packet
                .get(offset..)
                .ok_or(FlowParseError::Malformed("tcp_header_truncated"))?;
            if header.len() < 20 {
                return Err(FlowParseError::Malformed("tcp_header_truncated"));
            }
            let header_len = usize::from(header[12] >> 4) * 4;
            let payload_len = header
                .len()
                .checked_sub(header_len)
                .ok_or(FlowParseError::Malformed("tcp_header_length_invalid"))?;
            metadata.source_port = Some(u16_at(header, 0)?);
            metadata.destination_port = Some(u16_at(header, 2)?);
            metadata.tcp = Some(TcpMetadata {
                sequence: u32_at(header, 4)?,
                acknowledgement: u32_at(header, 8)?,
                flags: (u16::from(header[12] & 1) << 8) | u16::from(header[13]),
                window: u16_at(header, 14)?,
                header_len: header_len as u8,
                payload_len: payload_len as u32,
            });
        }
        TransportProtocol::Udp => {
            let header = packet
                .get(offset..)
                .ok_or(FlowParseError::Malformed("udp_header_truncated"))?;
            if header.len() < 8 {
                return Err(FlowParseError::Malformed("udp_header_truncated"));
            }
            metadata.source_port = Some(u16_at(header, 0)?);
            metadata.destination_port = Some(u16_at(header, 2)?);
        }
        TransportProtocol::Icmpv4 | TransportProtocol::Icmpv6 => {
            let header = packet
                .get(offset..)
                .ok_or(FlowParseError::Malformed("icmp_header_truncated"))?;
            if header.len() < 8 {
                return Err(FlowParseError::Malformed("icmp_header_truncated"));
            }
            let message_type = header[0];
            let code = header[1];
            let echo = match (metadata.protocol, message_type, code) {
                (TransportProtocol::Icmpv4, 0 | 8, 0) => Some(IcmpEchoMetadata {
                    identifier: u16_at(header, 4)?,
                    sequence: u16_at(header, 6)?,
                }),
                (TransportProtocol::Icmpv4, 3, 0..=15)
                | (TransportProtocol::Icmpv4, 11, 0..=1)
                | (TransportProtocol::Icmpv4, 12 | 5, _)
                | (TransportProtocol::Icmpv6, 1..=4, _)
                | (TransportProtocol::Icmpv6, 133..=136, 0) => None,
                _ => return Err(FlowParseError::Unsupported("unrepresented_icmp_type")),
            };
            metadata.icmp = Some(IcmpMetadata {
                message_type,
                code,
                echo,
            });
        }
    }
    Ok(())
}

fn ipv4(packet: &[u8]) -> Result<FlowMetadata, FlowParseError> {
    let declared = usize::from(u16_at(packet, 2)?);
    if packet.len() != declared {
        return Err(FlowParseError::Malformed("ipv4_length_not_exact"));
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let flags_offset = u16_at(packet, 6)?;
    if flags_offset & 0x8000 != 0 || (flags_offset & 0x4000 != 0 && flags_offset & 0x3fff != 0) {
        return Err(FlowParseError::Malformed("ipv4_fragment_flags_invalid"));
    }
    let fragmentation = if flags_offset & 0x3fff == 0 {
        Fragmentation::None
    } else {
        Fragmentation::Fragment {
            identification: u32::from(u16_at(packet, 4)?),
            offset_bytes: (flags_offset & 0x1fff) * 8,
            more_fragments: flags_offset & 0x2000 != 0,
        }
    };
    let mut metadata = FlowMetadata {
        source: IpAddr::V4(Ipv4Addr::from(bytes::<4>(packet, 12)?)),
        destination: IpAddr::V4(Ipv4Addr::from(bytes::<4>(packet, 16)?)),
        protocol: protocol(packet[9], false)?,
        source_port: None,
        destination_port: None,
        tcp: None,
        icmp: None,
        fragmentation,
        packet_len: declared as u32,
    };
    if metadata.fragmentation == Fragmentation::None {
        transport_fields(&mut metadata, packet, header)?;
    }
    Ok(metadata)
}

fn ipv6(packet: &[u8]) -> Result<FlowMetadata, FlowParseError> {
    let declared = 40 + usize::from(u16_at(packet, 4)?);
    if packet.len() != declared {
        return Err(FlowParseError::Malformed("ipv6_length_not_exact"));
    }
    let source = IpAddr::V6(Ipv6Addr::from(bytes::<16>(packet, 8)?));
    let destination = IpAddr::V6(Ipv6Addr::from(bytes::<16>(packet, 24)?));
    let mut next = packet[6];
    let mut offset = 40usize;
    let mut fragmentation = Fragmentation::None;
    loop {
        match next {
            0 | 43 | 60 => {
                let next_header = *packet
                    .get(offset)
                    .ok_or(FlowParseError::Malformed("ipv6_extension_truncated"))?;
                let length_byte = *packet
                    .get(offset + 1)
                    .ok_or(FlowParseError::Malformed("ipv6_extension_truncated"))?;
                offset += (usize::from(length_byte) + 1) * 8;
                next = next_header;
            }
            44 => {
                let fragment_next = *packet
                    .get(offset)
                    .ok_or(FlowParseError::Malformed("ipv6_fragment_truncated"))?;
                let field = u16_at(packet, offset + 2)?;
                if field & 0x0006 != 0 {
                    return Err(FlowParseError::Malformed("ipv6_fragment_reserved_bits"));
                }
                fragmentation = Fragmentation::Fragment {
                    identification: u32_at(packet, offset + 4)?,
                    offset_bytes: field & 0xfff8,
                    more_fragments: field & 1 != 0,
                };
                next = fragment_next;
                break;
            }
            _ => break,
        }
    }
    let mut metadata = FlowMetadata {
        source,
        destination,
        protocol: protocol(next, true)?,
        source_port: None,
        destination_port: None,
        tcp: None,
        icmp: None,
        fragmentation,
        packet_len: declared as u32,
    };
    if metadata.fragmentation == Fragmentation::None {
        transport_fields(&mut metadata, packet, offset)?;
    }
    Ok(metadata)
}

/// Extract bounded wire fields only. No payload content or policy enters this
/// result; a caller must not treat successful parsing as authorization.
pub fn parse_raw_ip_flow(packet: &[u8]) -> Result<FlowMetadata, FlowParseError> {
    let observation = decode_raw_ip(packet);
    if observation.kind == ObservationKind::Malformed {
        return Err(FlowParseError::Malformed(observation.reason));
    }
    if observation.kind == ObservationKind::Unknown {
        return Err(FlowParseError::Unsupported(observation.reason));
    }
    match packet[0] >> 4 {
        4 => ipv4(packet),
        6 => ipv6(packet),
        _ => Err(FlowParseError::Unsupported("unrepresented_ip_version")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{add_words, folded};

    fn checksum(bytes: &[u8]) -> u16 {
        !folded(add_words(0, bytes))
    }

    fn ipv4_header(protocol: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        finish_ipv4_header(&mut packet);
        packet
    }

    fn finish_ipv4_header(packet: &mut [u8]) {
        packet[10..12].fill(0);
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }

    fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let mut packet = ipv4_header(17, 8 + payload.len());
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn ipv4_tcp() -> Vec<u8> {
        let mut packet = ipv4_header(6, 20);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        packet[28..32].copy_from_slice(&0x1112_1314u32.to_be_bytes());
        packet[32] = 0x51; // 20-byte header and NS
        packet[33] = 0x12; // SYN + ACK
        packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
        let mut sum = 6 + 20;
        sum = add_words(sum, &packet[12..20]);
        let value = !folded(add_words(sum, &packet[20..40]));
        packet[36..38].copy_from_slice(&value.to_be_bytes());
        packet
    }

    fn ipv6_header(next: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = next;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    fn finish_ipv6_transport(packet: &mut [u8], offset: usize, proto: u8, checksum_offset: usize) {
        packet[offset + checksum_offset..offset + checksum_offset + 2].fill(0);
        let length = packet.len() - offset;
        let mut sum = add_words(0, &packet[8..40]);
        sum += length as u32 + proto as u32;
        let value = !folded(add_words(sum, &packet[offset..]));
        packet[offset + checksum_offset..offset + checksum_offset + 2]
            .copy_from_slice(&value.to_be_bytes());
    }

    fn ipv6_udp_with_destination_options() -> Vec<u8> {
        let mut packet = ipv6_header(60, 8 + 8);
        packet[40] = 17; // destination options -> UDP
        packet[41] = 0; // one 8-byte extension
        packet[48..50].copy_from_slice(&12345u16.to_be_bytes());
        packet[50..52].copy_from_slice(&53u16.to_be_bytes());
        packet[52..54].copy_from_slice(&8u16.to_be_bytes());
        finish_ipv6_transport(&mut packet, 48, 17, 6);
        packet
    }

    fn ipv6_tcp() -> Vec<u8> {
        let mut packet = ipv6_header(6, 20);
        packet[40..42].copy_from_slice(&1234u16.to_be_bytes());
        packet[42..44].copy_from_slice(&8443u16.to_be_bytes());
        packet[44..48].copy_from_slice(&99u32.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x02; // SYN
        packet[54..56].copy_from_slice(&8192u16.to_be_bytes());
        finish_ipv6_transport(&mut packet, 40, 6, 16);
        packet
    }

    #[test]
    fn ipv4_udp_metadata_is_payload_blind() {
        let a = parse_raw_ip_flow(&ipv4_udp(b"ordinary")).unwrap();
        let b = parse_raw_ip_flow(&ipv4_udp(b"hostile!")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.source, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(a.destination, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(a.protocol, TransportProtocol::Udp);
        assert_eq!((a.source_port, a.destination_port), (Some(12345), Some(53)));
        assert_eq!(a.tcp, None);
        assert_eq!(a.fragmentation, Fragmentation::None);
    }

    #[test]
    fn ipv4_tcp_exposes_raw_fields_without_claiming_valid_flow_state() {
        let tcp = parse_raw_ip_flow(&ipv4_tcp()).unwrap();
        assert_eq!(tcp.protocol, TransportProtocol::Tcp);
        assert_eq!(
            (tcp.source_port, tcp.destination_port),
            (Some(40000), Some(443))
        );
        assert_eq!(
            tcp.tcp,
            Some(TcpMetadata {
                sequence: 0x0102_0304,
                acknowledgement: 0x1112_1314,
                flags: 0x112,
                window: 4096,
                header_len: 20,
                payload_len: 0,
            })
        );
    }

    #[test]
    fn tcp_payload_length_uses_validated_transport_header_boundary() {
        let mut packet = ipv4_tcp();
        packet.extend_from_slice(b"abc");
        packet[2..4].copy_from_slice(&43u16.to_be_bytes());
        finish_ipv4_header(&mut packet);
        packet[36..38].fill(0);
        let mut sum = 6 + 23;
        sum = add_words(sum, &packet[12..20]);
        let value = !folded(add_words(sum, &packet[20..]));
        packet[36..38].copy_from_slice(&value.to_be_bytes());

        let metadata = parse_raw_ip_flow(&packet).unwrap();
        let tcp = metadata.tcp.unwrap();
        assert_eq!(tcp.header_len, 20);
        assert_eq!(tcp.payload_len, 3);
    }

    #[test]
    fn ipv6_udp_and_tcp_fields_follow_extension_headers() {
        let udp = parse_raw_ip_flow(&ipv6_udp_with_destination_options()).unwrap();
        assert_eq!(udp.protocol, TransportProtocol::Udp);
        assert_eq!(udp.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(udp.destination, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(
            (udp.source_port, udp.destination_port),
            (Some(12345), Some(53))
        );

        let tcp = parse_raw_ip_flow(&ipv6_tcp()).unwrap();
        assert_eq!(tcp.protocol, TransportProtocol::Tcp);
        assert_eq!(
            (tcp.source_port, tcp.destination_port),
            (Some(1234), Some(8443))
        );
        assert_eq!(tcp.tcp.unwrap().sequence, 99);
        assert_eq!(tcp.tcp.unwrap().flags, 0x02);
        assert_eq!(tcp.tcp.unwrap().window, 8192);
    }

    #[test]
    fn fragments_report_identity_without_inventing_ports() {
        let mut ipv4 = ipv4_udp(b"data");
        ipv4[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
        ipv4[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        finish_ipv4_header(&mut ipv4);
        let first = parse_raw_ip_flow(&ipv4).unwrap();
        assert_eq!(
            first.fragmentation,
            Fragmentation::Fragment {
                identification: 0x4321,
                offset_bytes: 0,
                more_fragments: true,
            }
        );
        assert_eq!(first.source_port, None);
        assert_eq!(first.tcp, None);

        ipv4[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        finish_ipv4_header(&mut ipv4);
        let later = parse_raw_ip_flow(&ipv4).unwrap();
        assert_eq!(
            later.fragmentation,
            Fragmentation::Fragment {
                identification: 0x4321,
                offset_bytes: 8,
                more_fragments: false,
            }
        );
        assert_eq!(later.source_port, None);

        let mut ipv6 = ipv6_header(44, 8);
        ipv6[40] = 17; // UDP after reassembly
        ipv6[42..44].copy_from_slice(&0x0009u16.to_be_bytes());
        ipv6[44..48].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        let fragment = parse_raw_ip_flow(&ipv6).unwrap();
        assert_eq!(
            fragment.fragmentation,
            Fragmentation::Fragment {
                identification: 0xdead_beef,
                offset_bytes: 8,
                more_fragments: true,
            }
        );
        assert_eq!(fragment.source_port, None);
    }

    #[test]
    fn rejects_malformed_truncated_and_unsupported_forms() {
        for len in 0..40 {
            assert!(parse_raw_ip_flow(&vec![0u8; len]).is_err());
        }
        let mut bad_checksum = ipv4_udp(b"data");
        bad_checksum[10] ^= 1;
        assert!(matches!(
            parse_raw_ip_flow(&bad_checksum),
            Err(FlowParseError::Malformed(_))
        ));

        let mut trailing = ipv4_udp(b"data");
        trailing.push(0);
        assert_eq!(
            parse_raw_ip_flow(&trailing),
            Err(FlowParseError::Malformed("ipv4_length_not_exact"))
        );

        let mut unknown = ipv4_header(132, 0);
        finish_ipv4_header(&mut unknown);
        assert_eq!(
            parse_raw_ip_flow(&unknown),
            Err(FlowParseError::Unsupported("unrepresented_transport"))
        );

        let mut bad_flags = ipv4_udp(b"data");
        bad_flags[6..8].copy_from_slice(&0x6000u16.to_be_bytes());
        finish_ipv4_header(&mut bad_flags);
        assert_eq!(
            parse_raw_ip_flow(&bad_flags),
            Err(FlowParseError::Malformed("ipv4_fragment_flags_invalid"))
        );

        let mut ipv6_unknown = ipv6_header(51, 0);
        assert_eq!(
            parse_raw_ip_flow(&ipv6_unknown),
            Err(FlowParseError::Unsupported("unrepresented_transport"))
        );
        ipv6_unknown[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            parse_raw_ip_flow(&ipv6_unknown),
            Err(FlowParseError::Malformed(_))
        ));
    }
}
