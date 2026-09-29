//! Bounded facts about packet sequences within an authenticated mesh session.
//!
//! The caller supplies the authenticated peer/session identity and metadata
//! parsed by `imperium-net-observer`. This tracker never sees payload bytes,
//! reads a Lightcone world, or returns a forwarding decision. A matching tuple
//! is an observed relationship, not proof that a remote application authorized
//! the traffic. Unsupported and evicted state must remain visible to callers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use imperium_net_observer::{FlowMetadata, Fragmentation, TransportProtocol};
use imperium_protocol::{PeerId, SessionId};

use crate::WireDirection;

pub const MAX_TRACKED_FLOWS: usize = 4_096;
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

const TCP_FIN: u16 = 0x01;
const TCP_SYN: u16 = 0x02;
const TCP_ACK: u16 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowBehaviorConfig {
    pub capacity: usize,
    pub idle_timeout: Duration,
}

impl Default for FlowBehaviorConfig {
    fn default() -> Self {
        Self {
            capacity: 1_024,
            idle_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowBehaviorConfigError {
    InvalidCapacity,
    InvalidIdleTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowSide {
    Opening,
    Returning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceRelation {
    AtExpected,
    BehindExpected,
    AheadOfExpected,
    AmbiguousWrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgmentRelation {
    Absent,
    AtObserved,
    BehindObserved,
    AheadOfObserved,
    AmbiguousWrap,
}

/// A recorded packet relationship. Every variant, including TCP segment facts
/// with ahead/behind sequence or acknowledgement values, is diagnostic only.
/// A caller must never treat `FlowOutcome::Fact` as permission to forward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowFact {
    TcpSynObserved,
    TcpRepeatedSynObserved,
    TcpSynAckCorrelated,
    TcpRepeatedSynAckObserved,
    TcpHandshakeCorrelated,
    TcpSegmentObserved {
        side: FlowSide,
        sequence: SequenceRelation,
        acknowledgement: AcknowledgmentRelation,
        flags: u16,
        payload_len: u32,
    },
    UdpTupleObserved,
    UdpSameDirectionObserved,
    UdpReverseTupleObserved,
    IcmpEchoRequestObserved,
    IcmpEchoRequestRepeated,
    IcmpEchoReplyCorrelated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowUnsupported {
    FragmentedPacket,
    MissingTransportMetadata,
    UnrepresentedIcmp,
    UnmatchedIcmpReply,
    DirectionMismatch,
    TcpMidstream,
    TcpSimultaneousOpen,
    TcpHandshakeMismatch,
    TcpUnexpectedSyn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowOutcome {
    Fact(FlowFact),
    Unsupported(FlowUnsupported),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowBehaviorStats {
    pub tracked: usize,
    pub expired: u64,
    pub evicted: u64,
    pub unsupported: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum KeyKind {
    Tcp,
    Udp,
    IcmpEcho { identifier: u16, sequence: u16 },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    peer_id: PeerId,
    session_id: SessionId,
    kind: KeyKind,
    lower: Endpoint,
    upper: Endpoint,
}

#[derive(Clone, Copy, Debug)]
enum TcpState {
    Syn {
        opening_syn: u32,
        opening_next: u32,
    },
    SynAck {
        opening_next: u32,
        returning_syn: u32,
        returning_next: u32,
    },
    Correlated {
        opening_next: u32,
        returning_next: u32,
    },
}

#[derive(Clone, Copy, Debug)]
enum FlowState {
    Tcp(TcpState),
    Udp,
    IcmpEcho,
}

struct Entry {
    opening_source: Endpoint,
    opening_destination: Endpoint,
    opening_direction: WireDirection,
    last_seen: Instant,
    state: FlowState,
}

pub struct FlowBehaviorTracker {
    config: FlowBehaviorConfig,
    entries: HashMap<FlowKey, Entry>,
    stats: FlowBehaviorStats,
    observations: u64,
}

impl FlowBehaviorTracker {
    pub fn new(config: FlowBehaviorConfig) -> Result<Self, FlowBehaviorConfigError> {
        if config.capacity == 0 || config.capacity > MAX_TRACKED_FLOWS {
            return Err(FlowBehaviorConfigError::InvalidCapacity);
        }
        if config.idle_timeout.is_zero() || config.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(FlowBehaviorConfigError::InvalidIdleTimeout);
        }
        Ok(Self {
            config,
            entries: HashMap::new(),
            stats: FlowBehaviorStats::default(),
            observations: 0,
        })
    }

    pub fn stats(&self) -> FlowBehaviorStats {
        FlowBehaviorStats {
            tracked: self.entries.len(),
            ..self.stats
        }
    }

    /// Remove facts from a rotated or closed authenticated session.
    pub fn remove_session(&mut self, peer_id: &PeerId, session_id: &SessionId) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|key, _| &key.peer_id != peer_id || &key.session_id != session_id);
        before - self.entries.len()
    }

    pub fn observe(
        &mut self,
        peer_id: &PeerId,
        session_id: &SessionId,
        direction: WireDirection,
        flow: &FlowMetadata,
    ) -> FlowOutcome {
        self.observe_at(peer_id, session_id, direction, flow, Instant::now())
    }

    /// Explicit time supports deterministic expiry tests and host-owned clocks.
    pub fn observe_at(
        &mut self,
        peer_id: &PeerId,
        session_id: &SessionId,
        direction: WireDirection,
        flow: &FlowMetadata,
        now: Instant,
    ) -> FlowOutcome {
        self.observations = self.observations.wrapping_add(1);
        if self.observations % 64 == 0 {
            self.expire(now);
        }
        let (kind, source, destination) = match describe(flow) {
            Ok(description) => description,
            Err(reason) => return self.unsupported(reason),
        };
        let (lower, upper) = if endpoint_order(source) <= endpoint_order(destination) {
            (source, destination)
        } else {
            (destination, source)
        };
        let key = FlowKey {
            peer_id: peer_id.clone(),
            session_id: session_id.clone(),
            kind,
            lower,
            upper,
        };
        if self.entries.get(&key).is_some_and(|entry| {
            now.saturating_duration_since(entry.last_seen) >= self.config.idle_timeout
        }) {
            self.entries.remove(&key);
            self.stats.expired = self.stats.expired.saturating_add(1);
        }
        if let Some(entry) = self.entries.get_mut(&key) {
            let outcome = observe_existing(entry, direction, source, destination, flow);
            if matches!(outcome, FlowOutcome::Fact(_)) {
                if now > entry.last_seen {
                    entry.last_seen = now;
                }
            }
            if matches!(
                outcome,
                FlowOutcome::Fact(FlowFact::IcmpEchoReplyCorrelated)
            ) {
                self.entries.remove(&key);
            }
            if matches!(outcome, FlowOutcome::Unsupported(_)) {
                self.stats.unsupported = self.stats.unsupported.saturating_add(1);
            }
            return outcome;
        }
        let state = match (kind, initial_state(flow)) {
            (KeyKind::IcmpEcho { .. }, Ok(FlowState::IcmpEcho)) => FlowState::IcmpEcho,
            (KeyKind::Udp, Ok(FlowState::Udp)) => FlowState::Udp,
            (KeyKind::Tcp, Ok(FlowState::Tcp(state))) => FlowState::Tcp(state),
            (_, Err(reason)) => return self.unsupported(reason),
            _ => return self.unsupported(FlowUnsupported::MissingTransportMetadata),
        };
        if self.entries.len() >= self.config.capacity {
            self.expire(now);
        }
        if self.entries.len() >= self.config.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
                self.stats.evicted = self.stats.evicted.saturating_add(1);
            }
        }
        self.entries.insert(
            key,
            Entry {
                opening_source: source,
                opening_destination: destination,
                opening_direction: direction,
                last_seen: now,
                state,
            },
        );
        FlowOutcome::Fact(match kind {
            KeyKind::Tcp => FlowFact::TcpSynObserved,
            KeyKind::Udp => FlowFact::UdpTupleObserved,
            KeyKind::IcmpEcho { .. } => FlowFact::IcmpEchoRequestObserved,
        })
    }

    fn unsupported(&mut self, reason: FlowUnsupported) -> FlowOutcome {
        self.stats.unsupported = self.stats.unsupported.saturating_add(1);
        FlowOutcome::Unsupported(reason)
    }

    fn expire(&mut self, now: Instant) {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.last_seen) < self.config.idle_timeout
        });
        self.stats.expired = self
            .stats
            .expired
            .saturating_add((before - self.entries.len()) as u64);
    }
}

fn endpoint_order(endpoint: Endpoint) -> (IpAddr, u16) {
    (endpoint.ip, endpoint.port)
}

fn describe(flow: &FlowMetadata) -> Result<(KeyKind, Endpoint, Endpoint), FlowUnsupported> {
    if flow.fragmentation != Fragmentation::None {
        return Err(FlowUnsupported::FragmentedPacket);
    }
    let (kind, source_port, destination_port) = match flow.protocol {
        TransportProtocol::Tcp | TransportProtocol::Udp => {
            let source = flow
                .source_port
                .ok_or(FlowUnsupported::MissingTransportMetadata)?;
            let destination = flow
                .destination_port
                .ok_or(FlowUnsupported::MissingTransportMetadata)?;
            (
                if flow.protocol == TransportProtocol::Tcp {
                    KeyKind::Tcp
                } else {
                    KeyKind::Udp
                },
                source,
                destination,
            )
        }
        TransportProtocol::Icmpv4 => {
            let icmp = flow.icmp.ok_or(FlowUnsupported::MissingTransportMetadata)?;
            let echo = icmp.echo.ok_or(FlowUnsupported::UnrepresentedIcmp)?;
            (
                KeyKind::IcmpEcho {
                    identifier: echo.identifier,
                    sequence: echo.sequence,
                },
                0,
                0,
            )
        }
        TransportProtocol::Icmpv6 => return Err(FlowUnsupported::UnrepresentedIcmp),
    };
    Ok((
        kind,
        Endpoint {
            ip: flow.source,
            port: source_port,
        },
        Endpoint {
            ip: flow.destination,
            port: destination_port,
        },
    ))
}

fn initial_state(flow: &FlowMetadata) -> Result<FlowState, FlowUnsupported> {
    match flow.protocol {
        TransportProtocol::Tcp => {
            let tcp = flow.tcp.ok_or(FlowUnsupported::MissingTransportMetadata)?;
            if tcp.flags & TCP_SYN == 0 || tcp.flags & TCP_ACK != 0 {
                return Err(FlowUnsupported::TcpMidstream);
            }
            Ok(FlowState::Tcp(TcpState::Syn {
                opening_syn: tcp.sequence,
                opening_next: tcp.sequence.wrapping_add(1).wrapping_add(tcp.payload_len),
            }))
        }
        TransportProtocol::Udp => Ok(FlowState::Udp),
        TransportProtocol::Icmpv4 => {
            let icmp = flow.icmp.ok_or(FlowUnsupported::MissingTransportMetadata)?;
            if icmp.message_type == 8 && icmp.code == 0 {
                Ok(FlowState::IcmpEcho)
            } else if icmp.message_type == 0 && icmp.code == 0 {
                Err(FlowUnsupported::UnmatchedIcmpReply)
            } else {
                Err(FlowUnsupported::UnrepresentedIcmp)
            }
        }
        TransportProtocol::Icmpv6 => Err(FlowUnsupported::UnrepresentedIcmp),
    }
}

fn observe_existing(
    entry: &mut Entry,
    direction: WireDirection,
    source: Endpoint,
    destination: Endpoint,
    flow: &FlowMetadata,
) -> FlowOutcome {
    let side = if source == entry.opening_source
        && destination == entry.opening_destination
        && direction == entry.opening_direction
    {
        FlowSide::Opening
    } else if source == entry.opening_destination
        && destination == entry.opening_source
        && direction != entry.opening_direction
    {
        FlowSide::Returning
    } else {
        return FlowOutcome::Unsupported(FlowUnsupported::DirectionMismatch);
    };
    match &mut entry.state {
        FlowState::Udp => FlowOutcome::Fact(match side {
            FlowSide::Opening => FlowFact::UdpSameDirectionObserved,
            FlowSide::Returning => FlowFact::UdpReverseTupleObserved,
        }),
        FlowState::IcmpEcho => {
            let Some(icmp) = flow.icmp else {
                return FlowOutcome::Unsupported(FlowUnsupported::MissingTransportMetadata);
            };
            match (side, icmp.message_type, icmp.code) {
                (FlowSide::Opening, 8, 0) => FlowOutcome::Fact(FlowFact::IcmpEchoRequestRepeated),
                (FlowSide::Returning, 0, 0) => FlowOutcome::Fact(FlowFact::IcmpEchoReplyCorrelated),
                _ => FlowOutcome::Unsupported(FlowUnsupported::UnrepresentedIcmp),
            }
        }
        FlowState::Tcp(state) => observe_tcp(state, side, flow),
    }
}

fn observe_tcp(state: &mut TcpState, side: FlowSide, flow: &FlowMetadata) -> FlowOutcome {
    let Some(tcp) = flow.tcp else {
        return FlowOutcome::Unsupported(FlowUnsupported::MissingTransportMetadata);
    };
    let syn = tcp.flags & TCP_SYN != 0;
    let ack = tcp.flags & TCP_ACK != 0;
    match *state {
        TcpState::Syn {
            opening_syn,
            opening_next,
        } => match side {
            FlowSide::Opening if syn && !ack && tcp.sequence == opening_syn => {
                FlowOutcome::Fact(FlowFact::TcpRepeatedSynObserved)
            }
            FlowSide::Opening => FlowOutcome::Unsupported(FlowUnsupported::TcpHandshakeMismatch),
            FlowSide::Returning if syn && ack && tcp.acknowledgement == opening_next => {
                *state = TcpState::SynAck {
                    opening_next,
                    returning_syn: tcp.sequence,
                    returning_next: tcp.sequence.wrapping_add(1).wrapping_add(tcp.payload_len),
                };
                FlowOutcome::Fact(FlowFact::TcpSynAckCorrelated)
            }
            FlowSide::Returning if syn && !ack => {
                FlowOutcome::Unsupported(FlowUnsupported::TcpSimultaneousOpen)
            }
            FlowSide::Returning => FlowOutcome::Unsupported(FlowUnsupported::TcpHandshakeMismatch),
        },
        TcpState::SynAck {
            opening_next,
            returning_syn,
            returning_next,
        } => match side {
            FlowSide::Returning
                if syn
                    && ack
                    && tcp.sequence == returning_syn
                    && tcp.acknowledgement == opening_next =>
            {
                FlowOutcome::Fact(FlowFact::TcpRepeatedSynAckObserved)
            }
            FlowSide::Opening
                if !syn
                    && ack
                    && tcp.sequence == opening_next
                    && tcp.acknowledgement == returning_next =>
            {
                *state = TcpState::Correlated {
                    opening_next: opening_next
                        .wrapping_add(tcp.payload_len)
                        .wrapping_add(u32::from(tcp.flags & TCP_FIN != 0)),
                    returning_next,
                };
                FlowOutcome::Fact(FlowFact::TcpHandshakeCorrelated)
            }
            _ => FlowOutcome::Unsupported(FlowUnsupported::TcpHandshakeMismatch),
        },
        TcpState::Correlated {
            mut opening_next,
            mut returning_next,
        } => {
            if syn {
                return FlowOutcome::Unsupported(FlowUnsupported::TcpUnexpectedSyn);
            }
            let (expected, other_expected) = match side {
                FlowSide::Opening => (&mut opening_next, returning_next),
                FlowSide::Returning => (&mut returning_next, opening_next),
            };
            let sequence = sequence_relation(tcp.sequence, *expected);
            if sequence == SequenceRelation::AtExpected {
                *expected = expected
                    .wrapping_add(tcp.payload_len)
                    .wrapping_add(u32::from(tcp.flags & TCP_FIN != 0));
            }
            let acknowledgement = if !ack {
                AcknowledgmentRelation::Absent
            } else {
                match sequence_relation(tcp.acknowledgement, other_expected) {
                    SequenceRelation::AtExpected => AcknowledgmentRelation::AtObserved,
                    SequenceRelation::BehindExpected => AcknowledgmentRelation::BehindObserved,
                    SequenceRelation::AheadOfExpected => AcknowledgmentRelation::AheadOfObserved,
                    SequenceRelation::AmbiguousWrap => AcknowledgmentRelation::AmbiguousWrap,
                }
            };
            *state = TcpState::Correlated {
                opening_next,
                returning_next,
            };
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side,
                sequence,
                acknowledgement,
                flags: tcp.flags,
                payload_len: tcp.payload_len,
            })
        }
    }
}

fn sequence_relation(sequence: u32, expected: u32) -> SequenceRelation {
    let difference = sequence.wrapping_sub(expected);
    if difference == 0 {
        SequenceRelation::AtExpected
    } else if difference == 0x8000_0000 {
        SequenceRelation::AmbiguousWrap
    } else if difference < 0x8000_0000 {
        SequenceRelation::AheadOfExpected
    } else {
        SequenceRelation::BehindExpected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use imperium_net_observer::{parse_raw_ip_flow, IcmpEchoMetadata, IcmpMetadata, TcpMetadata};

    fn addresses() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        )
    }

    fn tcp(
        reverse: bool,
        sequence: u32,
        acknowledgement: u32,
        flags: u16,
        payload_len: u32,
    ) -> FlowMetadata {
        let (a, b) = addresses();
        FlowMetadata {
            source: if reverse { b } else { a },
            destination: if reverse { a } else { b },
            protocol: TransportProtocol::Tcp,
            source_port: Some(if reverse { 443 } else { 40_000 }),
            destination_port: Some(if reverse { 40_000 } else { 443 }),
            tcp: Some(TcpMetadata {
                sequence,
                acknowledgement,
                flags,
                window: 4_096,
                header_len: 20,
                payload_len,
            }),
            icmp: None,
            fragmentation: Fragmentation::None,
            packet_len: 40 + payload_len,
        }
    }

    fn udp(reverse: bool, source_port: u16) -> FlowMetadata {
        let (a, b) = addresses();
        FlowMetadata {
            source: if reverse { b } else { a },
            destination: if reverse { a } else { b },
            protocol: TransportProtocol::Udp,
            source_port: Some(if reverse { 53 } else { source_port }),
            destination_port: Some(if reverse { source_port } else { 53 }),
            tcp: None,
            icmp: None,
            fragmentation: Fragmentation::None,
            packet_len: 28,
        }
    }

    fn echo(reverse: bool, identifier: u16, sequence: u16) -> FlowMetadata {
        let (a, b) = addresses();
        FlowMetadata {
            source: if reverse { b } else { a },
            destination: if reverse { a } else { b },
            protocol: TransportProtocol::Icmpv4,
            source_port: None,
            destination_port: None,
            tcp: None,
            icmp: Some(IcmpMetadata {
                message_type: if reverse { 0 } else { 8 },
                code: 0,
                echo: Some(IcmpEchoMetadata {
                    identifier,
                    sequence,
                }),
            }),
            fragmentation: Fragmentation::None,
            packet_len: 28,
        }
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for word in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn raw_ipv4(reverse: bool, protocol: u8, mut transport: Vec<u8>) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + transport.len()];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(if reverse {
            &[10, 0, 0, 2]
        } else {
            &[10, 0, 0, 1]
        });
        packet[16..20].copy_from_slice(if reverse {
            &[10, 0, 0, 1]
        } else {
            &[10, 0, 0, 2]
        });
        match protocol {
            1 => {
                let value = checksum(&transport);
                transport[2..4].copy_from_slice(&value.to_be_bytes());
            }
            6 => {
                let mut pseudo = Vec::from(&packet[12..20]);
                pseudo.extend_from_slice(&[0, 6]);
                pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
                pseudo.extend_from_slice(&transport);
                transport[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
            }
            _ => unreachable!(),
        }
        packet[20..].copy_from_slice(&transport);
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
        packet
    }

    #[test]
    fn actual_observer_raw_ip_metadata_feeds_echo_and_tcp_opening_facts() {
        let peer = PeerId::new();
        let session = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();

        let mut request = vec![0u8; 8];
        request[0] = 8;
        request[4..6].copy_from_slice(&7u16.to_be_bytes());
        request[6..8].copy_from_slice(&10u16.to_be_bytes());
        let request = parse_raw_ip_flow(&raw_ipv4(false, 1, request)).unwrap();
        let mut reply = vec![0u8; 8];
        reply[4..6].copy_from_slice(&7u16.to_be_bytes());
        reply[6..8].copy_from_slice(&10u16.to_be_bytes());
        let reply = parse_raw_ip_flow(&raw_ipv4(true, 1, reply)).unwrap();
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Outbound, &request),
            FlowOutcome::Fact(FlowFact::IcmpEchoRequestObserved)
        );
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Inbound, &reply),
            FlowOutcome::Fact(FlowFact::IcmpEchoReplyCorrelated)
        );

        let mut syn = vec![0u8; 20];
        syn[0..2].copy_from_slice(&40_000u16.to_be_bytes());
        syn[2..4].copy_from_slice(&443u16.to_be_bytes());
        syn[4..8].copy_from_slice(&100u32.to_be_bytes());
        syn[12] = 0x50;
        syn[13] = TCP_SYN as u8;
        syn[14..16].copy_from_slice(&4_096u16.to_be_bytes());
        let syn = parse_raw_ip_flow(&raw_ipv4(false, 6, syn)).unwrap();
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Outbound, &syn),
            FlowOutcome::Fact(FlowFact::TcpSynObserved)
        );
        assert_eq!(tracker.stats().tracked, 1);
    }

    #[test]
    fn tcp_handshake_and_sequence_facts_require_matching_session_and_direction() {
        let peer = PeerId::new();
        let session = SessionId::new();
        let other_session = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
        let now = Instant::now();
        let observe = |tracker: &mut FlowBehaviorTracker,
                       session: &SessionId,
                       direction,
                       flow: FlowMetadata| {
            tracker.observe_at(&peer, session, direction, &flow, now)
        };

        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 100, 0, TCP_SYN, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpSynObserved)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 100, 0, TCP_SYN, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpRepeatedSynObserved)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &other_session,
                WireDirection::Inbound,
                tcp(true, 500, 101, TCP_SYN | TCP_ACK, 0)
            ),
            FlowOutcome::Unsupported(FlowUnsupported::TcpMidstream)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Inbound,
                tcp(true, 500, 102, TCP_SYN | TCP_ACK, 0)
            ),
            FlowOutcome::Unsupported(FlowUnsupported::TcpHandshakeMismatch)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Inbound,
                tcp(true, 500, 101, TCP_SYN | TCP_ACK, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpSynAckCorrelated)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 101, 501, TCP_ACK, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpHandshakeCorrelated)
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 101, 501, TCP_ACK, 10)
            ),
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side: FlowSide::Opening,
                sequence: SequenceRelation::AtExpected,
                acknowledgement: AcknowledgmentRelation::AtObserved,
                flags: TCP_ACK,
                payload_len: 10,
            })
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 101, 501, TCP_ACK, 10)
            ),
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side: FlowSide::Opening,
                sequence: SequenceRelation::BehindExpected,
                acknowledgement: AcknowledgmentRelation::AtObserved,
                flags: TCP_ACK,
                payload_len: 10,
            })
        );
        // Ahead-of-observed sequence and ACK values are facts about this
        // packet, never a pass result; neither advances our observed cursor.
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 200, 600, TCP_ACK, 5)
            ),
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side: FlowSide::Opening,
                sequence: SequenceRelation::AheadOfExpected,
                acknowledgement: AcknowledgmentRelation::AheadOfObserved,
                flags: TCP_ACK,
                payload_len: 5,
            })
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Outbound,
                tcp(false, 111, 501, TCP_ACK, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side: FlowSide::Opening,
                sequence: SequenceRelation::AtExpected,
                acknowledgement: AcknowledgmentRelation::AtObserved,
                flags: TCP_ACK,
                payload_len: 0,
            })
        );
        assert_eq!(
            observe(
                &mut tracker,
                &session,
                WireDirection::Inbound,
                tcp(true, 501, 111, TCP_ACK, 0)
            ),
            FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
                side: FlowSide::Returning,
                sequence: SequenceRelation::AtExpected,
                acknowledgement: AcknowledgmentRelation::AtObserved,
                flags: TCP_ACK,
                payload_len: 0,
            })
        );
        assert_eq!(tracker.stats().tracked, 1);
        assert_eq!(tracker.remove_session(&peer, &session), 1);
        assert_eq!(tracker.stats().tracked, 0);
    }

    #[test]
    fn udp_reverse_tuple_is_scoped_and_capacity_and_expiry_are_visible() {
        let peer = PeerId::new();
        let session = SessionId::new();
        let other = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig {
            capacity: 2,
            idle_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let now = Instant::now();
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Outbound,
                &udp(false, 40_000),
                now
            ),
            FlowOutcome::Fact(FlowFact::UdpTupleObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Inbound,
                &udp(true, 40_000),
                now
            ),
            FlowOutcome::Fact(FlowFact::UdpReverseTupleObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &other,
                WireDirection::Inbound,
                &udp(true, 40_000),
                now
            ),
            FlowOutcome::Fact(FlowFact::UdpTupleObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Outbound,
                &udp(false, 40_001),
                now + Duration::from_secs(1)
            ),
            FlowOutcome::Fact(FlowFact::UdpTupleObserved)
        );
        assert_eq!(tracker.stats().tracked, 2);
        assert_eq!(tracker.stats().evicted, 1);
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Inbound,
                &udp(true, 40_001),
                now + Duration::from_secs(7)
            ),
            FlowOutcome::Fact(FlowFact::UdpTupleObserved)
        );
        assert!(tracker.stats().expired >= 1);
    }

    #[test]
    fn icmp_echo_reply_requires_same_id_sequence_and_reversed_direction() {
        let peer = PeerId::new();
        let session = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
        assert_eq!(
            tracker.observe(
                &peer,
                &session,
                WireDirection::Outbound,
                &echo(false, 7, 10)
            ),
            FlowOutcome::Fact(FlowFact::IcmpEchoRequestObserved)
        );
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Inbound, &echo(true, 7, 11)),
            FlowOutcome::Unsupported(FlowUnsupported::UnmatchedIcmpReply)
        );
        assert_eq!(
            tracker.observe(
                &peer,
                &session,
                WireDirection::Outbound,
                &echo(false, 7, 10)
            ),
            FlowOutcome::Fact(FlowFact::IcmpEchoRequestRepeated)
        );
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Inbound, &echo(true, 7, 10)),
            FlowOutcome::Fact(FlowFact::IcmpEchoReplyCorrelated)
        );
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Inbound, &echo(true, 7, 10)),
            FlowOutcome::Unsupported(FlowUnsupported::UnmatchedIcmpReply)
        );
    }

    #[test]
    fn earlier_caller_time_cannot_move_last_seen_backward() {
        let peer = PeerId::new();
        let session = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig {
            capacity: 1,
            idle_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let now = Instant::now();
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Outbound,
                &udp(false, 40_000),
                now
            ),
            FlowOutcome::Fact(FlowFact::UdpTupleObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Outbound,
                &udp(false, 40_000),
                now + Duration::from_secs(4)
            ),
            FlowOutcome::Fact(FlowFact::UdpSameDirectionObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Outbound,
                &udp(false, 40_000),
                now + Duration::from_secs(2)
            ),
            FlowOutcome::Fact(FlowFact::UdpSameDirectionObserved)
        );
        assert_eq!(
            tracker.observe_at(
                &peer,
                &session,
                WireDirection::Inbound,
                &udp(true, 40_000),
                now + Duration::from_secs(8)
            ),
            FlowOutcome::Fact(FlowFact::UdpReverseTupleObserved)
        );
        assert_eq!(tracker.stats().expired, 0);
    }

    #[test]
    fn unsupported_metadata_and_config_never_create_state() {
        assert!(matches!(
            FlowBehaviorTracker::new(FlowBehaviorConfig {
                capacity: 0,
                ..Default::default()
            }),
            Err(FlowBehaviorConfigError::InvalidCapacity)
        ));
        assert!(matches!(
            FlowBehaviorTracker::new(FlowBehaviorConfig {
                idle_timeout: Duration::ZERO,
                ..Default::default()
            }),
            Err(FlowBehaviorConfigError::InvalidIdleTimeout)
        ));
        let peer = PeerId::new();
        let session = SessionId::new();
        let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig::default()).unwrap();
        let mut fragmented = udp(false, 40_000);
        fragmented.fragmentation = Fragmentation::Fragment {
            identification: 1,
            offset_bytes: 8,
            more_fragments: false,
        };
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Outbound, &fragmented),
            FlowOutcome::Unsupported(FlowUnsupported::FragmentedPacket)
        );
        let mut icmpv6 = echo(false, 7, 10);
        icmpv6.protocol = TransportProtocol::Icmpv6;
        assert_eq!(
            tracker.observe(&peer, &session, WireDirection::Outbound, &icmpv6),
            FlowOutcome::Unsupported(FlowUnsupported::UnrepresentedIcmp)
        );
        assert_eq!(tracker.stats().tracked, 0);
        assert_eq!(tracker.stats().unsupported, 2);
    }
}
