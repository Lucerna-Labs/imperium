//! Replay the revision-5 corpus through current packet and flow fact producers.
//!
//! Fixture UUIDs scope a tracker history; they are not authenticated-session
//! evidence. This test supplies no host service policy or forwarding verdict.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use imperium_net_mesh::flow_behavior::{
    FlowBehaviorConfig, FlowBehaviorTracker, FlowFact, FlowOutcome, FlowUnsupported,
    SequenceRelation,
};
use imperium_net_mesh::WireDirection;
use imperium_net_observer::{parse_raw_ip_flow, FlowParseError, Fragmentation, TransportProtocol};
use imperium_protocol::{PeerId, SessionId};
use serde_json::{json, Value};
use uuid::Uuid;

fn revision() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../imperium-net-world/v5/revision-5")
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid UTF-8 hex"), 16)
                .expect("valid fixture hex")
        })
        .collect()
}

fn observed_event(outcome: FlowOutcome) -> &'static str {
    match outcome {
        FlowOutcome::Fact(FlowFact::TcpSynObserved) => "tcp_syn_observed",
        FlowOutcome::Fact(FlowFact::TcpSynAckCorrelated) => "tcp_synack_correlated",
        FlowOutcome::Fact(FlowFact::TcpHandshakeCorrelated) => "tcp_handshake_correlated",
        FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
            sequence: SequenceRelation::AtExpected,
            ..
        }) => "tcp_segment_at_expected",
        FlowOutcome::Fact(FlowFact::TcpSegmentObserved {
            sequence: SequenceRelation::AheadOfExpected,
            ..
        }) => "tcp_segment_ahead",
        FlowOutcome::Fact(FlowFact::UdpTupleObserved) => "udp_tuple_observed",
        FlowOutcome::Fact(FlowFact::UdpReverseTupleObserved) => "udp_reverse_tuple_observed",
        FlowOutcome::Fact(FlowFact::IcmpEchoRequestObserved) => "icmp_echo_request_observed",
        FlowOutcome::Fact(FlowFact::IcmpEchoReplyCorrelated) => "icmp_echo_reply_correlated",
        FlowOutcome::Unsupported(FlowUnsupported::TcpMidstream) => "tcp_midstream_unsupported",
        FlowOutcome::Unsupported(FlowUnsupported::UnmatchedIcmpReply) => {
            "icmp_unmatched_reply_unsupported"
        }
        FlowOutcome::Unsupported(FlowUnsupported::FragmentedPacket) => "fragmented_unsupported",
        other => panic!("unrepresented revision-5 fact: {other:?}"),
    }
}

#[test]
fn corpus_facts_match_real_observer_and_tracker() {
    let directory = revision();
    let manifest: Value = serde_json::from_slice(
        &fs::read(directory.join("corpus.json")).expect("frozen corpus manifest"),
    )
    .expect("corpus manifest JSON");
    let cases = manifest["cases"].as_array().expect("case references");
    assert_eq!(cases.len(), 15);

    let mut tracker = FlowBehaviorTracker::new(FlowBehaviorConfig {
        capacity: 64,
        idle_timeout: Duration::from_secs(120),
    })
    .expect("bounded flow tracker");
    let start = Instant::now();
    for reference in cases {
        let identifier = reference["id"].as_str().expect("case ID");
        let relative = reference["file"].as_str().expect("case path");
        assert_eq!(relative, format!("cases/{identifier}.json"));
        let case: Value =
            serde_json::from_slice(&fs::read(directory.join(relative)).expect("frozen case file"))
                .expect("case JSON");
        let packet = bytes(case["packet_hex"].as_str().expect("packet hex"));
        let mut actual = BTreeMap::<String, Value>::new();
        match parse_raw_ip_flow(&packet) {
            Ok(flow) => {
                let fragmented = flow.fragmentation != Fragmentation::None;
                actual.insert(
                    "packet.validation".into(),
                    json!(if fragmented { "fragment" } else { "parsed" }),
                );
                actual.insert(
                    "packet.ip_version".into(),
                    json!(if flow.source.is_ipv4() {
                        "ipv4"
                    } else {
                        "ipv6"
                    }),
                );
                let protocol = match flow.protocol {
                    TransportProtocol::Tcp => "tcp",
                    TransportProtocol::Udp => "udp",
                    TransportProtocol::Icmpv4 => "icmpv4",
                    TransportProtocol::Icmpv6 => "icmpv6",
                };
                actual.insert("packet.next_protocol".into(), json!(protocol));
                actual.insert("packet.fragmented".into(), json!(fragmented));
                actual.insert("packet.transport_complete".into(), json!(!fragmented));
                if let Some(port) = flow.source_port {
                    actual.insert("packet.source_port".into(), json!(port));
                }
                if let Some(port) = flow.destination_port {
                    actual.insert("packet.destination_port".into(), json!(port));
                }
                let peer = PeerId(
                    Uuid::parse_str(case["peer_id"].as_str().expect("peer ID"))
                        .expect("fixture peer UUID"),
                );
                let session = SessionId(
                    Uuid::parse_str(case["session_id"].as_str().expect("session ID"))
                        .expect("fixture session UUID"),
                );
                let direction = match case["direction"].as_str().expect("direction") {
                    "inbound" => WireDirection::Inbound,
                    "outbound" => WireDirection::Outbound,
                    other => panic!("unknown fixture direction: {other}"),
                };
                let when =
                    start + Duration::from_millis(case["at_ms"].as_u64().expect("fixture time"));
                let event =
                    observed_event(tracker.observe_at(&peer, &session, direction, &flow, when));
                actual.insert("flow.event".into(), json!(event));
            }
            Err(FlowParseError::Unsupported(_)) => {
                actual.insert("packet.validation".into(), json!("unsupported"));
            }
            Err(FlowParseError::Malformed(_)) => {
                actual.insert("packet.validation".into(), json!("malformed"));
            }
        }
        let expected = case["facts"].as_array().expect("expected facts");
        let expected = expected
            .iter()
            .map(|fact| {
                (
                    fact["id"].as_str().expect("fact id").to_string(),
                    fact["value"].clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, expected, "producer mismatch for {identifier}");
    }
}
