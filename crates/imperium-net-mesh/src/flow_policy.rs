//! Versioned host-owned flow policy for a future network forwarding gate.
//!
//! This module has no forwarding call site. It does not ask a Lightcone to
//! decide, and it cannot inspect payload bytes. A future host boundary may
//! supply authenticated peer identity, host-assigned zones, parsed headers and
//! a verified v5 world digest. Until that boundary exists, compiling a policy
//! does not filter traffic.

use std::collections::HashSet;
use std::net::IpAddr;

use imperium_net_world::World;
use imperium_protocol::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u16 = 1;
pub const REQUIRED_WORLD_VERSION: u16 = 5;
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowPolicyDocument {
    pub schema_version: u16,
    pub world_version: u16,
    pub world_sha256: String,
    pub rules: Vec<FlowRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRule {
    pub rule_id: String,
    pub peer_id: PeerId,
    pub direction: FlowDirection,
    pub source_zone: String,
    pub destination_zone: String,
    pub source_cidr: String,
    pub destination_cidr: String,
    pub protocol: FlowProtocol,
    pub service: FlowService,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProtocol {
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowService {
    Port { port: u16 },
    Icmp { icmp_type: u8, icmp_code: u8 },
}

/// Host-parsed packet headers. Payload bytes are absent by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowPacket {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: FlowProtocol,
    pub transport: PacketTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketTransport {
    Ports {
        source_port: u16,
        destination_port: u16,
    },
    Icmp {
        icmp_type: u8,
        icmp_code: u8,
    },
}

/// Captures the canonical service from one observed opening tuple. For TCP/UDP,
/// a reverse packet must match reversed addresses and ports. This does not
/// validate TCP state/sequence, UDP activity lifetime, or ICMP echo identity.
/// A future forwarding gate must combine this tuple match with independent
/// flow-behavior facts before permitting traffic.
#[derive(Clone, Copy, Debug)]
pub struct ObservedFlowTuple {
    opening: FlowPacket,
    service: FlowService,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowContextError {
    #[error("packet protocol and transport fields disagree")]
    InvalidTransport,
    #[error("packet does not match the observed opening or return tuple")]
    TupleMismatch,
    #[error("host zone label is invalid")]
    InvalidZone,
}

/// World identity is captured only after `World::load` verifies the pack hash.
/// The host must pin the expected digest from an accepted v5 artifact. This
/// type is immutable with private fields; callers cannot supply a digest in a
/// per-packet context or mutate a `World` before a decision.
pub struct VerifiedWorldContext {
    version: u16,
    digest: [u8; 32],
}

/// Construct this only from authenticated session identity, host-assigned
/// zones, a packet parsed by the host, and its observed tuple. No payload
/// field, caller-supplied world digest or raw packet input exists here.
#[derive(Clone, Debug)]
pub struct FlowMetadata {
    peer_id: Option<PeerId>,
    direction: FlowDirection,
    source_zone: String,
    destination_zone: String,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: FlowProtocol,
    service: FlowService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowDecision {
    Allow { rule_id: String },
    Deny { reason: DenyReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    WrongWorld,
    MissingPeer,
    InvalidService,
    NoMatchingRule,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowPolicyError {
    #[error("flow policy JSON invalid: {0}")]
    Json(String),
    #[error("flow policy exceeds 1 MiB")]
    TooLarge,
    #[error("unsupported flow policy schema version {0}")]
    SchemaVersion(u16),
    #[error("flow policy requires trained world v5, got {0}")]
    WorldVersion(u16),
    #[error("flow policy world digest is invalid or does not match the supplied world")]
    WorldDigest,
    #[error("verified world failed to load: {0:?}")]
    WorldLoad(imperium_net_world::Error),
    #[error("flow policy has too many rules")]
    TooManyRules,
    #[error("duplicate rule id {0}")]
    DuplicateRuleId(String),
    #[error("invalid flow rule: {0}")]
    InvalidRule(String),
    #[error("invalid canonical CIDR {0}")]
    InvalidCidr(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

struct CompiledRule {
    id: String,
    peer_id: PeerId,
    direction: FlowDirection,
    source_zone: String,
    destination_zone: String,
    source: IpCidr,
    destination: IpCidr,
    protocol: FlowProtocol,
    service: FlowService,
}

/// Validated, immutable allow rules bound to one exact world digest. Empty or
/// unmatched policies deny by construction. No default allow, wildcard peer,
/// payload matcher or content-dependent fallback exists.
pub struct FlowPolicy {
    world_sha256: String,
    rules: Vec<CompiledRule>,
}

impl VerifiedWorldContext {
    pub fn from_verified_pack(
        pack: &[u8],
        pinned_digest: [u8; 32],
    ) -> Result<Self, FlowPolicyError> {
        let world = World::load(pack, pinned_digest).map_err(FlowPolicyError::WorldLoad)?;
        if world.id != REQUIRED_WORLD_VERSION {
            return Err(FlowPolicyError::WorldVersion(world.id));
        }
        Ok(Self {
            version: world.id,
            digest: world.digest,
        })
    }

    fn sha256(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl ObservedFlowTuple {
    pub fn from_opening_tuple(opening: FlowPacket) -> Result<Self, FlowContextError> {
        let service = match (opening.protocol, opening.transport) {
            (
                FlowProtocol::Tcp | FlowProtocol::Udp,
                PacketTransport::Ports {
                    source_port,
                    destination_port,
                },
            ) if source_port != 0 && destination_port != 0 => FlowService::Port {
                port: destination_port,
            },
            (
                FlowProtocol::IcmpV4 | FlowProtocol::IcmpV6,
                PacketTransport::Icmp {
                    icmp_type,
                    icmp_code,
                },
            ) => FlowService::Icmp {
                icmp_type,
                icmp_code,
            },
            _ => return Err(FlowContextError::InvalidTransport),
        };
        if opening.source_ip.is_ipv4() != opening.destination_ip.is_ipv4() {
            return Err(FlowContextError::InvalidTransport);
        }
        Ok(Self { opening, service })
    }

    fn contains(&self, packet: FlowPacket) -> bool {
        if packet == self.opening {
            return true;
        }
        if packet.source_ip != self.opening.destination_ip
            || packet.destination_ip != self.opening.source_ip
            || packet.protocol != self.opening.protocol
        {
            return false;
        }
        match (
            self.opening.protocol,
            self.opening.transport,
            packet.transport,
        ) {
            (
                FlowProtocol::Tcp | FlowProtocol::Udp,
                PacketTransport::Ports {
                    source_port: opening_source,
                    destination_port: opening_destination,
                },
                PacketTransport::Ports {
                    source_port: return_source,
                    destination_port: return_destination,
                },
            ) => return_source == opening_destination && return_destination == opening_source,
            // ICMP return packets are deliberately not accepted here: type/code
            // alone cannot correlate echo ID/sequence or error quotations.
            _ => false,
        }
    }
}

impl FlowMetadata {
    pub fn from_matching_tuple(
        state: &ObservedFlowTuple,
        packet: FlowPacket,
        authenticated_peer: Option<PeerId>,
        direction: FlowDirection,
        source_zone: impl Into<String>,
        destination_zone: impl Into<String>,
    ) -> Result<Self, FlowContextError> {
        if !state.contains(packet) {
            return Err(FlowContextError::TupleMismatch);
        }
        let source_zone = source_zone.into();
        let destination_zone = destination_zone.into();
        if !valid_label(&source_zone) || !valid_label(&destination_zone) {
            return Err(FlowContextError::InvalidZone);
        }
        Ok(Self {
            peer_id: authenticated_peer,
            direction,
            source_zone,
            destination_zone,
            source_ip: packet.source_ip,
            destination_ip: packet.destination_ip,
            protocol: packet.protocol,
            service: state.service,
        })
    }
}

impl FlowPolicy {
    pub fn from_json(
        bytes: &[u8],
        verified_world: &VerifiedWorldContext,
    ) -> Result<Self, FlowPolicyError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(FlowPolicyError::TooLarge);
        }
        let document: FlowPolicyDocument = serde_json::from_slice(bytes)
            .map_err(|error| FlowPolicyError::Json(error.to_string()))?;
        Self::compile(document, verified_world)
    }

    pub fn compile(
        document: FlowPolicyDocument,
        verified_world: &VerifiedWorldContext,
    ) -> Result<Self, FlowPolicyError> {
        if document.schema_version != SCHEMA_VERSION {
            return Err(FlowPolicyError::SchemaVersion(document.schema_version));
        }
        if document.world_version != REQUIRED_WORLD_VERSION
            || verified_world.version != REQUIRED_WORLD_VERSION
        {
            return Err(FlowPolicyError::WorldVersion(document.world_version));
        }
        if !valid_digest(&document.world_sha256) || document.world_sha256 != verified_world.sha256()
        {
            return Err(FlowPolicyError::WorldDigest);
        }
        if document.rules.len() > MAX_RULES {
            return Err(FlowPolicyError::TooManyRules);
        }
        let mut ids = HashSet::new();
        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            if !valid_label(&rule.rule_id) {
                return Err(FlowPolicyError::InvalidRule("bad rule_id".into()));
            }
            if !ids.insert(rule.rule_id.clone()) {
                return Err(FlowPolicyError::DuplicateRuleId(rule.rule_id));
            }
            if !valid_label(&rule.source_zone) || !valid_label(&rule.destination_zone) {
                return Err(FlowPolicyError::InvalidRule(format!(
                    "{} has an invalid zone label",
                    rule.rule_id
                )));
            }
            if !service_matches_protocol(rule.protocol, rule.service) {
                return Err(FlowPolicyError::InvalidRule(format!(
                    "{} service does not match protocol",
                    rule.rule_id
                )));
            }
            let source = IpCidr::parse(&rule.source_cidr)?;
            let destination = IpCidr::parse(&rule.destination_cidr)?;
            if source.is_v4() != destination.is_v4() {
                return Err(FlowPolicyError::InvalidRule(format!(
                    "{} mixes IPv4 and IPv6 CIDRs",
                    rule.rule_id
                )));
            }
            rules.push(CompiledRule {
                id: rule.rule_id,
                peer_id: rule.peer_id,
                direction: rule.direction,
                source_zone: rule.source_zone,
                destination_zone: rule.destination_zone,
                source,
                destination,
                protocol: rule.protocol,
                service: rule.service,
            });
        }
        Ok(Self {
            world_sha256: document.world_sha256,
            rules,
        })
    }

    pub fn decision(
        &self,
        verified_world: &VerifiedWorldContext,
        flow: &FlowMetadata,
    ) -> FlowDecision {
        if verified_world.version != REQUIRED_WORLD_VERSION
            || verified_world.sha256() != self.world_sha256
        {
            return FlowDecision::Deny {
                reason: DenyReason::WrongWorld,
            };
        }
        let Some(peer_id) = flow.peer_id.as_ref() else {
            return FlowDecision::Deny {
                reason: DenyReason::MissingPeer,
            };
        };
        if !service_matches_protocol(flow.protocol, flow.service) {
            return FlowDecision::Deny {
                reason: DenyReason::InvalidService,
            };
        }
        for rule in &self.rules {
            if &rule.peer_id == peer_id
                && rule.direction == flow.direction
                && rule.source_zone == flow.source_zone
                && rule.destination_zone == flow.destination_zone
                && rule.source.contains(flow.source_ip)
                && rule.destination.contains(flow.destination_ip)
                && rule.protocol == flow.protocol
                && rule.service == flow.service
            {
                return FlowDecision::Allow {
                    rule_id: rule.id.clone(),
                };
            }
        }
        FlowDecision::Deny {
            reason: DenyReason::NoMatchingRule,
        }
    }

    pub fn allows(&self, verified_world: &VerifiedWorldContext, flow: &FlowMetadata) -> bool {
        matches!(
            self.decision(verified_world, flow),
            FlowDecision::Allow { .. }
        )
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl IpCidr {
    fn parse(text: &str) -> Result<Self, FlowPolicyError> {
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| FlowPolicyError::InvalidCidr(text.into()))?;
        let address: IpAddr = address
            .parse()
            .map_err(|_| FlowPolicyError::InvalidCidr(text.into()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| FlowPolicyError::InvalidCidr(text.into()))?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let bits = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                if bits & mask != bits {
                    return Err(FlowPolicyError::InvalidCidr(text.into()));
                }
                Ok(Self::V4 {
                    network: bits,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let bits = u128::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                if bits & mask != bits {
                    return Err(FlowPolicyError::InvalidCidr(text.into()));
                }
                Ok(Self::V6 {
                    network: bits,
                    prefix,
                })
            }
            _ => Err(FlowPolicyError::InvalidCidr(text.into())),
        }
    }

    fn is_v4(self) -> bool {
        matches!(self, Self::V4 { .. })
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(address) & mask == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

fn service_matches_protocol(protocol: FlowProtocol, service: FlowService) -> bool {
    match (protocol, service) {
        (FlowProtocol::Tcp | FlowProtocol::Udp, FlowService::Port { port }) => port != 0,
        (FlowProtocol::IcmpV4 | FlowProtocol::IcmpV6, FlowService::Icmp { .. }) => true,
        _ => false,
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const WORLD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn verified_world() -> VerifiedWorldContext {
        let mut digest = [0u8; 32];
        for (index, pair) in WORLD.as_bytes().chunks_exact(2).enumerate() {
            digest[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        // Synthetic identity exists only inside this unit module. Production
        // obtains the context through World::load and a pinned pack digest.
        VerifiedWorldContext { version: 5, digest }
    }

    fn peer() -> PeerId {
        PeerId(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap())
    }

    fn rule() -> FlowRule {
        FlowRule {
            rule_id: "branch-https".into(),
            peer_id: peer(),
            direction: FlowDirection::Outbound,
            source_zone: "branch".into(),
            destination_zone: "service".into(),
            source_cidr: "10.10.0.0/16".into(),
            destination_cidr: "192.0.2.0/24".into(),
            protocol: FlowProtocol::Tcp,
            service: FlowService::Port { port: 443 },
        }
    }

    fn document(rules: Vec<FlowRule>) -> FlowPolicyDocument {
        FlowPolicyDocument {
            schema_version: SCHEMA_VERSION,
            world_version: REQUIRED_WORLD_VERSION,
            world_sha256: WORLD.into(),
            rules,
        }
    }

    fn opening() -> FlowPacket {
        FlowPacket {
            source_ip: "10.10.7.3".parse().unwrap(),
            destination_ip: "192.0.2.80".parse().unwrap(),
            protocol: FlowProtocol::Tcp,
            transport: PacketTransport::Ports {
                source_port: 53000,
                destination_port: 443,
            },
        }
    }

    fn flow() -> FlowMetadata {
        let opening = opening();
        let state = ObservedFlowTuple::from_opening_tuple(opening).unwrap();
        FlowMetadata::from_matching_tuple(
            &state,
            opening,
            Some(peer()),
            FlowDirection::Outbound,
            "branch",
            "service",
        )
        .unwrap()
    }

    #[test]
    fn exact_metadata_allows_only_the_named_rule() {
        let encoded = serde_json::to_vec(&document(vec![rule()])).unwrap();
        let policy = FlowPolicy::from_json(&encoded, &verified_world()).unwrap();
        assert_eq!(
            policy.decision(&verified_world(), &flow()),
            FlowDecision::Allow {
                rule_id: "branch-https".into()
            }
        );
        let mut changed = flow();
        changed.service = FlowService::Port { port: 80 };
        assert!(!policy.allows(&verified_world(), &changed));
        changed = flow();
        changed.peer_id = Some(PeerId(Uuid::new_v4()));
        assert!(!policy.allows(&verified_world(), &changed));
        changed = flow();
        changed.source_zone = "untrusted".into();
        assert!(!policy.allows(&verified_world(), &changed));
        changed = flow();
        changed.direction = FlowDirection::Inbound;
        assert!(!policy.allows(&verified_world(), &changed));
        changed = flow();
        changed.destination_ip = "198.51.100.1".parse().unwrap();
        assert!(!policy.allows(&verified_world(), &changed));
    }

    #[test]
    fn no_rule_missing_peer_and_wrong_world_deny() {
        let empty = FlowPolicy::compile(document(Vec::new()), &verified_world()).unwrap();
        assert_eq!(empty.rule_count(), 0);
        assert_eq!(
            empty.decision(&verified_world(), &flow()),
            FlowDecision::Deny {
                reason: DenyReason::NoMatchingRule
            }
        );
        let policy = FlowPolicy::compile(document(vec![rule()]), &verified_world()).unwrap();
        let mut missing_peer = flow();
        missing_peer.peer_id = None;
        assert_eq!(
            policy.decision(&verified_world(), &missing_peer),
            FlowDecision::Deny {
                reason: DenyReason::MissingPeer
            }
        );
        let wrong_world = VerifiedWorldContext {
            version: 5,
            digest: [0xff; 32],
        };
        assert_eq!(
            policy.decision(&wrong_world, &flow()),
            FlowDecision::Deny {
                reason: DenyReason::WrongWorld
            }
        );
    }

    #[test]
    fn version_digest_and_canonical_cidr_are_required() {
        assert_eq!(
            VerifiedWorldContext::from_verified_pack(
                imperium_net_world::embedded::PACK,
                imperium_net_world::embedded::HASH,
            )
            .err(),
            Some(FlowPolicyError::WorldVersion(4))
        );
        let mut spec = document(vec![rule()]);
        spec.world_version = 4;
        assert_eq!(
            FlowPolicy::compile(spec, &verified_world()).err(),
            Some(FlowPolicyError::WorldVersion(4))
        );
        let mut spec = document(vec![rule()]);
        spec.world_sha256 = "f".repeat(64);
        assert_eq!(
            FlowPolicy::compile(spec, &verified_world()).err(),
            Some(FlowPolicyError::WorldDigest)
        );
        let mut spec = document(vec![rule()]);
        spec.rules[0].source_cidr = "10.10.7.3/16".into();
        assert!(matches!(
            FlowPolicy::compile(spec, &verified_world()),
            Err(FlowPolicyError::InvalidCidr(_))
        ));
        let mut spec = document(vec![rule()]);
        spec.rules[0].source_cidr = "10.10.0.0/33".into();
        assert!(matches!(
            FlowPolicy::compile(spec, &verified_world()),
            Err(FlowPolicyError::InvalidCidr(_))
        ));
    }

    #[test]
    fn icmp_kind_and_ipv6_cidr_match_exactly() {
        let mut spec = rule();
        spec.rule_id = "v6-echo".into();
        spec.source_cidr = "2001:db8:1::/48".into();
        spec.destination_cidr = "2001:db8:2::/48".into();
        spec.protocol = FlowProtocol::IcmpV6;
        spec.service = FlowService::Icmp {
            icmp_type: 128,
            icmp_code: 0,
        };
        let policy = FlowPolicy::compile(document(vec![spec]), &verified_world()).unwrap();
        let packet = FlowPacket {
            source_ip: "2001:db8:1::7".parse().unwrap(),
            destination_ip: "2001:db8:2::9".parse().unwrap(),
            protocol: FlowProtocol::IcmpV6,
            transport: PacketTransport::Icmp {
                icmp_type: 128,
                icmp_code: 0,
            },
        };
        let state = ObservedFlowTuple::from_opening_tuple(packet).unwrap();
        let metadata = FlowMetadata::from_matching_tuple(
            &state,
            packet,
            Some(peer()),
            FlowDirection::Outbound,
            "branch",
            "service",
        )
        .unwrap();
        assert!(policy.allows(&verified_world(), &metadata));
        let wrong_type = FlowPacket {
            transport: PacketTransport::Icmp {
                icmp_type: 129,
                icmp_code: 0,
            },
            ..packet
        };
        assert!(matches!(
            FlowMetadata::from_matching_tuple(
                &state,
                wrong_type,
                Some(peer()),
                FlowDirection::Outbound,
                "branch",
                "service"
            ),
            Err(FlowContextError::TupleMismatch)
        ));
        // Echo reply type/code alone cannot prove the same request: this
        // tuple-only module has no ICMP ID/sequence, so it refuses the reply.
        let unproven_reply = FlowPacket {
            source_ip: packet.destination_ip,
            destination_ip: packet.source_ip,
            transport: PacketTransport::Icmp {
                icmp_type: 129,
                icmp_code: 0,
            },
            ..packet
        };
        assert!(matches!(
            FlowMetadata::from_matching_tuple(
                &state,
                unproven_reply,
                Some(peer()),
                FlowDirection::Inbound,
                "service",
                "branch"
            ),
            Err(FlowContextError::TupleMismatch)
        ));
        assert_eq!(
            ObservedFlowTuple::from_opening_tuple(FlowPacket {
                transport: PacketTransport::Ports {
                    source_port: 1,
                    destination_port: 443
                },
                ..packet
            })
            .err(),
            Some(FlowContextError::InvalidTransport)
        );
    }

    #[test]
    fn udp_return_flow_uses_canonical_service_not_ephemeral_destination() {
        let opening = FlowPacket {
            source_ip: "10.10.7.3".parse().unwrap(),
            destination_ip: "192.0.2.80".parse().unwrap(),
            protocol: FlowProtocol::Udp,
            transport: PacketTransport::Ports {
                source_port: 53000,
                destination_port: 53,
            },
        };
        let state = ObservedFlowTuple::from_opening_tuple(opening).unwrap();
        let reply = FlowPacket {
            source_ip: opening.destination_ip,
            destination_ip: opening.source_ip,
            protocol: FlowProtocol::Udp,
            transport: PacketTransport::Ports {
                source_port: 53,
                destination_port: 53000,
            },
        };
        let metadata = FlowMetadata::from_matching_tuple(
            &state,
            reply,
            Some(peer()),
            FlowDirection::Inbound,
            "service",
            "branch",
        )
        .unwrap();
        assert_eq!(metadata.service, FlowService::Port { port: 53 });
        let mut return_rule = rule();
        return_rule.rule_id = "dns-reply".into();
        return_rule.direction = FlowDirection::Inbound;
        return_rule.source_zone = "service".into();
        return_rule.destination_zone = "branch".into();
        return_rule.source_cidr = "192.0.2.0/24".into();
        return_rule.destination_cidr = "10.10.0.0/16".into();
        return_rule.protocol = FlowProtocol::Udp;
        return_rule.service = FlowService::Port { port: 53 };
        let policy = FlowPolicy::compile(document(vec![return_rule]), &verified_world()).unwrap();
        assert!(policy.allows(&verified_world(), &metadata));
        let forged_reply = FlowPacket {
            transport: PacketTransport::Ports {
                source_port: 99,
                destination_port: 53000,
            },
            ..reply
        };
        assert!(matches!(
            FlowMetadata::from_matching_tuple(
                &state,
                forged_reply,
                Some(peer()),
                FlowDirection::Inbound,
                "service",
                "branch"
            ),
            Err(FlowContextError::TupleMismatch)
        ));
    }

    #[test]
    fn json_rejects_payload_matchers_and_protocol_service_mismatch() {
        let mut value = serde_json::to_value(document(vec![rule()])).unwrap();
        value["rules"][0]["payload_pattern"] = serde_json::json!("secret");
        assert!(
            FlowPolicy::from_json(&serde_json::to_vec(&value).unwrap(), &verified_world()).is_err()
        );
        let mut spec = document(vec![rule()]);
        spec.rules[0].protocol = FlowProtocol::Udp;
        spec.rules[0].service = FlowService::Icmp {
            icmp_type: 8,
            icmp_code: 0,
        };
        assert!(matches!(
            FlowPolicy::compile(spec, &verified_world()),
            Err(FlowPolicyError::InvalidRule(_))
        ));
    }
}
