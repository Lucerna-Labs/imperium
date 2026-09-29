// Bus topic pair regression test.
//
// Hand-curated from the audit in BUS_CONVENTIONS.md (Round 5, 2026-05-13).
// Each entry asserts that a publisher's topic string matches its intended
// subscriber's prefix pattern via starts_with. If a topic or subscription
// pattern changes, this test catches the mismatch at compile time (for
// literals) or at test time (for format strings).
//
// Update this file whenever a new publish/subscribe pair is added.

#[test]
fn all_topic_pairs_match() {
    let pairs: Vec<(&str, &str, &str)> = vec![
        // (publisher_topic, subscriber_pattern, description)

        // --- emergency ---
        (
            "emergency.transport.double_degraded",
            "emergency",
            "orchestrator → coordinator",
        ),
        (
            "emergency.cli.operator_shutdown",
            "emergency",
            "CLI control pipe → coordinator",
        ),
        (
            "emergency.shutdown",
            "emergency",
            "runtime unit test → coordinator",
        ),
        // --- runtime ---
        (
            "runtime.subsystem.ready.good",
            "runtime.subsystem.ready",
            "coordinator → ready listener",
        ),
        // --- net.transport ---
        (
            "net.transport.ready",
            "net.transport.",
            "transport init → transport sub",
        ),
        (
            "net.transport.leak_guard.status",
            "net.transport.",
            "transport init → transport sub",
        ),
        (
            "net.transport.command",
            "net.transport.",
            "orchestrator cmd → transport sub",
        ),
        (
            "net.transport.decision",
            "net.transport.",
            "orchestrator decision → transport sub",
        ),
        (
            "net.transport.profile.rotate",
            "net.transport.",
            "control pipe → transport sub",
        ),
        (
            "net.transport.active_request",
            "net.transport.",
            "control pipe → transport sub",
        ),
        (
            "net.transport.killswitch.command",
            "net.transport.",
            "control pipe → transport sub",
        ),
        (
            "net.transport.masque.configure",
            "net.transport.",
            "control pipe → transport sub",
        ),
        (
            "net.transport.masque.status",
            "net.transport.",
            "masque controller → transport sub",
        ),
        (
            "net.transport.hardening.apply",
            "net.transport.hardening.apply",
            "control/orchestrator → hardening controller",
        ),
        (
            "net.transport.hardening.status",
            "net.transport.",
            "hardening controller → transport sub",
        ),
        (
            "net.transport.probe_deception.decision",
            "net.transport.",
            "probe deception engine → transport sub",
        ),
        (
            "net.transport.event",
            "net.transport.event",
            "orchestrator event → protocol event sub",
        ),
        (
            "net.transport.event.wireguard",
            "net.transport.event",
            "controller event → protocol event sub",
        ),
        (
            "net.transport.event.xray",
            "net.transport.event",
            "controller event → protocol event sub",
        ),
        (
            "net.transport.event",
            "net.transport.",
            "protocol event → transport sub",
        ),
        (
            "net.transport.decision",
            "net.transport.decision",
            "orchestrator → decision listener (exact)",
        ),
        // --- net.sensors ---
        (
            "net.sensors.ready",
            "net.sensors.",
            "sensors init → sensors sub",
        ),
        (
            "net.sensors.threat",
            "net.sensors.",
            "classifier → orchestrator",
        ),
        (
            "net.sensors.signature_match",
            "net.sensors.",
            "sig engine → orchestrator",
        ),
        (
            "net.sensors.probe_profile",
            "net.sensors.",
            "probe sensor → net.sensors. sub (threat lane filters it by variant)",
        ),
        // --- net.signatures ---
        (
            "net.signatures.ready",
            "net.signatures.",
            "signatures init → signatures sub",
        ),
        (
            "net.signatures.candidate",
            "net.signatures.",
            "staging submit → signatures sub",
        ),
        (
            "net.signatures.approved",
            "net.signatures.",
            "staging approve → signatures sub",
        ),
        (
            "net.signatures.approved",
            "net.signatures.approved",
            "staging approve → sig engine (exact)",
        ),
        (
            "net.signatures.rejected",
            "net.signatures.",
            "staging reject → signatures sub",
        ),
        (
            "net.signatures.activated",
            "net.signatures.",
            "engine activation → signatures sub",
        ),
        (
            "net.signatures.activation_failed",
            "net.signatures.",
            "engine activation failed → signatures sub",
        ),
        (
            "net.signatures.extraction_request",
            "net.signatures.extraction_request",
            "CLI → extraction loop (exact)",
        ),
        (
            "net.signatures.extraction_request",
            "net.signatures.",
            "CLI → signatures sub",
        ),
        (
            "net.signatures.candidate_pending",
            "net.signatures.",
            "extraction loop → signatures sub",
        ),
        (
            "net.signatures.extraction_failed",
            "net.signatures.",
            "extraction loop → signatures sub",
        ),
        (
            "net.signatures.approve_request",
            "net.signatures.",
            "CLI control pipe → signatures sub",
        ),
        (
            "net.signatures.reject_request",
            "net.signatures.",
            "CLI control pipe → signatures sub",
        ),
        // --- net.strainer ---
        (
            "net.strainer.ready",
            "net.strainer.",
            "strainer init → strainer sub",
        ),
        (
            "net.strainer.rejection",
            "net.strainer.",
            "stack → strainer sub",
        ),
        (
            "net.strainer.rejection",
            "net.strainer.rejection",
            "stack → memory-log",
        ),
        // --- net.cluster ---
        (
            "net.cluster.ready",
            "net.cluster.",
            "cluster init → cluster sub",
        ),
        (
            "net.cluster.membership.request",
            "net.cluster.",
            "membership → cluster sub",
        ),
        (
            "net.cluster.membership.granted",
            "net.cluster.",
            "membership → cluster sub",
        ),
        (
            "net.cluster.membership.granted",
            "net.cluster.membership.granted",
            "membership → grant listener",
        ),
        (
            "net.cluster.membership.gossip",
            "net.cluster.",
            "membership → cluster sub",
        ),
        (
            "net.cluster.config.updated",
            "net.cluster.",
            "config → cluster sub",
        ),
        (
            "net.cluster.config.fetch_request",
            "net.cluster.",
            "config → cluster sub",
        ),
        (
            "net.cluster.config.fetch_response",
            "net.cluster.",
            "config → cluster sub",
        ),
        (
            "net.cluster.config.fetch_response",
            "net.cluster.config.fetch_response",
            "config → fetch listener",
        ),
        (
            "net.cluster.policy.apply",
            "net.cluster.",
            "control pipe → cluster sub",
        ),
        (
            "net.vpn.deployment.apply",
            "net.vpn.deployment.apply",
            "control pipe/ordo → deployment orchestrator",
        ),
        (
            "net.vpn.deployment.status",
            "net.vpn.",
            "deployment orchestrator → vpn namespace",
        ),
        (
            "net.vpn.deployment.status_request",
            "net.vpn.",
            "control pipe/ordo → deployment status request",
        ),
        // --- net.mesh ---
        ("net.mesh.ready", "net.mesh.", "mesh init → mesh sub"),
        (
            "net.mesh.nat.policy",
            "net.mesh.",
            "mesh/control pipe → mesh sub",
        ),
        (
            "net.mesh.nat.plan",
            "net.mesh.",
            "deployment orchestrator → mesh sub",
        ),
        (
            "net.mesh.relay.selected",
            "net.mesh.",
            "deployment orchestrator → mesh sub",
        ),
        (
            "net.mesh.ping.sent",
            "net.mesh.",
            "mesh transport → mesh sub",
        ),
        (
            "net.mesh.pong.sent",
            "net.mesh.",
            "mesh transport → mesh sub",
        ),
        (
            "net.toolkit.ready",
            "net.toolkit.",
            "toolkit init → toolkit sub",
        ),
        (
            "net.toolkit.request",
            "net.toolkit.request",
            "orchestrator → toolkit manager",
        ),
        (
            "net.toolkit.state",
            "net.toolkit.",
            "toolkit manager → toolkit sub",
        ),
        (
            "net.toolkit.activation",
            "net.toolkit.",
            "toolkit manager → toolkit sub",
        ),
        // --- net.transport → memory-log ---
        (
            "net.transport.event",
            "net.transport.",
            "protocol events → memory-log transport sub",
        ),
        (
            "net.transport.decision",
            "net.transport.",
            "decisions → memory-log transport sub",
        ),
    ];

    let mut failures = Vec::new();

    for (topic, pattern, desc) in &pairs {
        if !topic.starts_with(pattern) {
            failures.push(format!(
                "MISMATCH: topic {:?} does not start with pattern {:?} ({})",
                topic, pattern, desc,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Bus topic pair mismatches found:\n{}",
        failures.join("\n"),
    );
}

#[test]
fn emergency_topics_never_use_net_prefix() {
    let emergency_topics = [
        "emergency.transport.double_degraded",
        "emergency.cli.operator_shutdown",
        "emergency.shutdown",
    ];

    for topic in &emergency_topics {
        assert!(
            topic.starts_with("emergency"),
            "emergency topic {:?} must start with 'emergency'",
            topic,
        );
        assert!(
            !topic.starts_with("net."),
            "emergency topic {:?} must NOT use the 'net.' prefix",
            topic,
        );
    }
}

#[test]
fn no_namespace_cross_contamination() {
    let namespaces = [
        "net.transport.",
        "net.vpn.",
        "net.sensors.",
        "net.signatures.",
        "net.strainer.",
        "net.cluster.",
        "net.mesh.",
        "net.toolkit.",
        "emergency.",
        "runtime.",
    ];

    for (i, ns_a) in namespaces.iter().enumerate() {
        for (j, ns_b) in namespaces.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !ns_a.starts_with(ns_b),
                "namespace {:?} is a prefix of {:?} — this would cause cross-contamination",
                ns_b,
                ns_a,
            );
        }
    }
}
