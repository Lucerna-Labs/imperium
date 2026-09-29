//! E26's G5 gate, applied to the guard: is there a bit an attacker can aim at?
//!
//! E26 scanned every single-bit flip of an emergent field's whole state and
//! counted the flips that produced the ATTACKER'S CHOSEN output — 0 of 4096 —
//! against a rule-system control where exactly 1 of 65 flips granted bypass.
//! The move that matters is counting CHOSEN admission, not mere change: random
//! noise passes "did it change". That measurement belongs on the guard.
//!
//! Method note: one perturbation per FRESH guard, as E26 cloned the field per
//! flip — so each flip is evaluated against identical clean state and the
//! counts mean what they say.
//!
//! Scan results, and which way each one landed:
//!
//!   - presented bytes  : 0 of 2048 flips move the verdict  (payload is opaque)
//!   - attempt token    : 0 of 224 flips admit              (no adjacent token)
//!   - source tag       : MANY of 70 flips admit            <-- see the ignored
//!                                                              probe at the end
//!
//! The first two are earned claims. The third is a live finding: the budget is
//! keyed on a field the knocker supplies.

use imperium_net_guard::{Guard, GuardConfig, GuardVerdict, Knock};

const SOURCE: &str = "peer-alpha";

fn fresh_guard() -> Guard {
    Guard::new(GuardConfig::default()).expect("default config is valid")
}

/// Issue enough tokens that no scan can run out.
fn stock(guard: &Guard, n: usize) {
    for i in 0..n {
        guard.issue_token(&format!("tok-{i:04}"));
    }
}

fn knock(source: &str, token: &str, payload_len: usize) -> Knock {
    Knock {
        source: source.to_string(),
        attempt_token: token.to_string(),
        presented: vec![0u8; payload_len],
    }
}

/// Every single-bit flip of a byte string that keeps it valid ASCII. Bit 7 is
/// excluded because flipping it on an ASCII byte yields a lone byte >= 0x80,
/// which is not valid UTF-8 and so is not a string an attacker could present.
fn ascii_bit_flips(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for idx in 0..bytes.len() {
        for bit in 0..7u8 {
            let mut mutated = bytes.to_vec();
            mutated[idx] ^= 1 << bit;
            if let Ok(candidate) = String::from_utf8(mutated) {
                out.push(candidate);
            }
        }
    }
    out
}

// --- scan 1: the presented payload must be INERT -------------------------
//
// The shape check is length-only, so no flip of the CONTENT may move the
// verdict in either direction. This is the property that makes the payload
// opaque rather than merely unread.

#[test]
fn presented_bytes_are_inert_to_every_single_bit_flip() {
    let admitted = vec![0x00u8; 64];
    let mut verdict_moves = 0usize;
    let mut flips = 0usize;

    for idx in 0..admitted.len() {
        for bit in 0..8u8 {
            let guard = fresh_guard();
            stock(&guard, 4);
            let mut payload = admitted.clone();
            payload[idx] ^= 1 << bit;
            let verdict = guard.knock(
                &Knock {
                    source: SOURCE.to_string(),
                    attempt_token: "tok-0000".to_string(),
                    presented: payload,
                },
                0,
            );
            flips += 1;
            if verdict != GuardVerdict::Admit {
                verdict_moves += 1;
            }
        }
    }

    assert_eq!(
        verdict_moves, 0,
        "{verdict_moves} of {flips} payload-content flips changed the verdict — \
         the payload is not opaque, it is being read"
    );
    assert_eq!(flips, 512, "scan coverage");
}

// --- scan 2: an unissued token admits on ZERO single-bit flips -----------
//
// The issued set is chosen far from the presented token, so restoring a valid
// token by flipping one bit would be a guess, not an accident of the scan.

#[test]
fn unissued_token_admits_on_zero_single_bit_flips() {
    let presented = "attempt-gggg";
    let mut admitted_flips = 0usize;

    let candidates = ascii_bit_flips(presented);
    for candidate in &candidates {
        let guard = fresh_guard();
        // Issued tokens share no neighbourhood with `presented`.
        for i in 0..8 {
            guard.issue_token(&format!("unrelated-{i}"));
        }
        if guard.knock(&knock(SOURCE, candidate, 16), 0) == GuardVerdict::Admit {
            admitted_flips += 1;
        }
    }

    assert_eq!(
        admitted_flips,
        0,
        "{admitted_flips} of {} flips of an unissued token bought admission",
        candidates.len()
    );
    assert!(
        candidates.len() >= 70,
        "scan coverage: {}",
        candidates.len()
    );
}

// --- the E26 control: a rule system has exactly one bypass bit -----------
//
// Kept so the guard's numbers are read against the same baseline E26 used. Its
// point is that a flag is a bit, and a bit is a thing to aim at.

#[test]
fn rule_system_control_has_exactly_one_bypass_bit() {
    #[derive(Clone)]
    struct RuleState {
        authorized: bool,
        key: u64,
    }

    let rule = RuleState {
        authorized: false,
        key: 0xABCD,
    };
    let mut bypasses = 0usize;
    for bit in 0..65usize {
        let mut patched = rule.clone();
        if bit < 64 {
            patched.key ^= 1 << bit;
        } else {
            patched.authorized = !patched.authorized;
        }
        if patched.authorized {
            bypasses += 1;
        }
    }
    assert_eq!(bypasses, 1, "the rule system's bypass count");
}

// --- the earned claims hold; the budget key does not --------------------

#[test]
fn a_valid_token_under_a_fresh_source_is_admitted_before_exhaustion() {
    let guard = fresh_guard();
    stock(&guard, 4);
    assert_eq!(
        guard.knock(&knock(SOURCE, "tok-0000", 16), 0),
        GuardVerdict::Admit,
        "the honest path must admit, or the scans below prove nothing"
    );
}

#[test]
fn an_exhausted_source_is_avalanched_and_rejected() {
    let guard = fresh_guard();
    stock(&guard, 32);
    let budget = GuardConfig::default().budget as usize;
    for i in 0..budget {
        let _ = guard.knock(&knock(SOURCE, &format!("tok-{i:04}"), 16), i as i64);
    }
    assert!(
        guard.is_avalanched(SOURCE),
        "budget exhaustion must avalanche"
    );
    assert!(
        guard.face_of(SOURCE).is_some(),
        "an avalanched source is given a face"
    );
    // And a further knock with a perfectly good token still fails.
    assert_eq!(
        guard.knock(&knock(SOURCE, &format!("tok-{budget:04}"), 16), 99),
        GuardVerdict::SilentReject,
        "an avalanched source must not admit, however valid the token"
    );
}

/// DELIBERATELY FAILING PROBE — kept, not deleted, as the acceptance test for
/// the fix (same house pattern as the atom-cognitive-engine's documented
/// failing `hop1_under_hops_load`, and E27's N-gates before their fix).
///
/// THE FINDING: the per-source budget is keyed on [`Knock::source`], a field
/// the knocker supplies, while the issued-token set is GLOBAL and the burn
/// record is per-source. So a knocker who has exhausted its budget under
/// "peer-alpha" presents the SAME valid token under a source tag one bit away
/// and gets a full fresh budget. Every such flip admits.
///
/// This is not a guess about a secret — the token is legitimately issued and
/// the source tag is free — so it is a genuine single-bit admission bypass, and
/// it is exactly what P3's "no free admission" conjunction is supposed to
/// exclude. A rotating source tag defeats windowed conservation entirely.
///
/// Run it with: `cargo test -- --ignored source_tag_flip`
///
/// Fix candidates (DESIGN DECISION, not applied):
///   1. Key the budget on something not attacker-declared — verify the source
///      tag against a peer identity before it reaches the ledger, so a knob
///      the knocker cannot rotate is the budget key.
///   2. Key the budget on the TOKEN rather than the source, if tokens are
///      minted per engagement; then one token buys one attempt in total.
///   3. Keep per-source budgets but make the source a closed set the operator
///      populates (like `issued`), so an unissued source is refused outright —
///      costs the ability to absorb a new peer without operator action.
#[test]
#[ignore = "FAILS by design: documents a live single-bit bypass (source tag buys a fresh budget). Run explicitly; this is the acceptance test for the fix."]
fn source_tag_flip_buys_a_fresh_budget() {
    let flips = ascii_bit_flips(SOURCE);
    let mut admitted = 0usize;
    let budget = GuardConfig::default().budget as usize;

    for (n, rotated) in flips.iter().enumerate() {
        let guard = fresh_guard();
        stock(&guard, 128);
        // Exhaust the real source.
        for i in 0..budget {
            let _ = guard.knock(&knock(SOURCE, &format!("tok-{i:04}"), 16), i as i64);
        }
        assert!(guard.is_avalanched(SOURCE), "precondition: exhausted");
        // The SAME token, under a source tag one bit away.
        let token = format!("tok-{:04}", budget + n);
        if guard.knock(&knock(rotated, &token, 16), 99) == GuardVerdict::Admit {
            admitted += 1;
        }
    }

    assert_eq!(
        admitted,
        0,
        "{admitted} of {} single-bit source-tag flips bought a fresh budget after \
         exhaustion — a one-bit rotation defeats windowed conservation (P1)",
        flips.len()
    );
}
