//! End-to-end supervision proof for the signature-engine strand conversion.
//!
//! `imperium-net-sensors`' approval loop used to be a `tokio::spawn`ed recv
//! loop over `net.signatures.approved`; it is now a Spiderweb **strand**
//! ([`SignatureEngineStrand`](imperium_net_sensors::SignatureEngineStrand)),
//! registered as a spec through
//! [`register_strands`](imperium_net_sensors::register_strands) /
//! [`SignatureEngineSensor::register_strand`](imperium_net_sensors::SignatureEngineSensor::register_strand).
//! The unit tests in `src/signature_engine.rs` cover the *service*; these
//! integration tests cover what only a real kernel can prove:
//!
//! 1. [`strand_serves_approvals_and_publishes_outcomes_to_shim_subscribers`] —
//!    behaviour preservation. Same topic in, same topics out, same payloads,
//!    same fail-closed semantics, and the outcome reaches the *same*
//!    `Bus::subscribe` subscribers the old loop's `Bus::publish` reached (plus a
//!    peer strand, proving strand → strand delivery).
//! 2. [`crashed_strand_is_restarted_three_times_then_quarantined`] — the crash
//!    policy, driven through the real strand with its injected fault: registered
//!    as a **spec**, every crash is a `LifecycleEvent::Crashed`, the spider
//!    restarts it three times, and the fourth crash quarantines it.
//! 3. [`replayed_approval_is_deduped_and_activated_state_survives_a_restart`] —
//!    the kernel replays its pending tail (32 messages per type) to a restarted
//!    generation; activation is *not* idempotent, so the strand dedupes on
//!    `BusEvent::id` through a set shared by every generation. One published
//!    approval therefore produces exactly one activation and exactly one loaded
//!    rule, however many times the restart replays it — while the shared engine
//!    keeps the state that generation one built.
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `Bus::register_strand(spec)`, real `Bus::engage_supervision()` (kernel run
//! loop and `spider` orchestrator on their own OS threads), real strand workers,
//! and the real `SignatureEngineStrand`. Nothing is simulated, nothing is
//! stubbed.
//!
//! # The instruments: recorder strands
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle`. The
//! recipe's answer (and the pilot's) is to register another strand whose input
//! is `LifecycleEvent` and let it record what it feels. That is
//! [`LifecycleRecorder`], and it doubles as proof that a *second* strand on the
//! same web keeps running while this one crashes and is restarted.
//! [`ActivationRecorder`] does the same for the engine's own output.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_net_sensors::{
    topics, FaultPolicy, SignatureEngineSensor, SignatureEngineStrand, NAME as STRAND_NAME,
};
use imperium_net_signatures::SignatureDatabase;
use imperium_protocol::{
    BusEvent, EventId, ExtractedSignatureActivated, Message, PeerId, SignatureActivationFailed,
    SignatureApproved, SignatureCandidate,
};
use imperium_store::Store;
use rand::rngs::OsRng;
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};
use spiderweb::{
    BusHandle, LifecycleEvent, Socket, Strand, StrandError, StrandSpec, SYS_LIFECYCLE,
};
use uuid::Uuid;

const CANDIDATE_RULE: &str = r#"rule drill_hit { strings: $a = { CA FE } condition: $a }"#;

// ---------------------------------------------------------------------------
// Recorder strands — the supervision instruments
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;

/// Shared, test-owned record of the engine's own outcomes.
type ActivationLog = Arc<Mutex<Vec<Outcome>>>;

/// What the engine published, in arrival order.
#[derive(Clone, Debug)]
enum Outcome {
    Activated(ExtractedSignatureActivated),
    Failed(SignatureActivationFailed),
}

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_activation_log() -> ActivationLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn outcome_snapshot(log: &ActivationLog) -> Vec<Outcome> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Count lifecycle events matching `pred`.
fn count(log: &LifecycleLog, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
    lifecycle_snapshot(log).iter().filter(|e| pred(e)).count()
}

/// Count this strand's own lifecycle events (the kernel emits unrelated
/// `Buffered`/`ThreadFormed`/`IntersectionEmerged` events continuously, so
/// assertions must never count the whole stream).
fn strand_events(log: &LifecycleLog) -> usize {
    count(log, |e| match e {
        LifecycleEvent::Registered { name, .. }
        | LifecycleEvent::Crashed { name, .. }
        | LifecycleEvent::Restarted { name, .. }
        | LifecycleEvent::Quarantined { name, .. }
        | LifecycleEvent::Detached { name } => name == STRAND_NAME,
        _ => false,
    })
}

/// Block (with a hard deadline) until `pred` holds, so a supervision bug fails
/// the test instead of hanging it.
fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !pred() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A strand that records the kernel's lifecycle stream — who registered, who
/// crashed, who was restarted, who was quarantined.
///
/// Registered as a **spec**, exactly like a converted subsystem, so it starts
/// with the run loop and survives the crash of its neighbour.
struct LifecycleRecorder {
    log: LifecycleLog,
}

impl Strand for LifecycleRecorder {
    fn name(&self) -> &str {
        "test.sensors-lifecycle-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        // Routing is by `TypeId`, so this strand feels every `LifecycleEvent`
        // on the web rather than one named socket.
        const SOCKS: [Socket; 1] = [Socket::new::<LifecycleEvent>(SYS_LIFECYCLE)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        for (_socket, event) in bus.recv_all::<LifecycleEvent>()? {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        }
        Ok(())
    }
}

/// A strand that records the engine's activation outcomes.
///
/// Its input type is [`BusEvent`] — the same type the engine's strand declares —
/// because strand routing is by `TypeId`; the topic prefix here *is* the old
/// `bus.subscribe("net.signatures.activated")` filter, moved into the consumer.
/// It therefore also proves the second half of the contract: one strand's
/// publish reaches another strand.
struct ActivationRecorder {
    log: ActivationLog,
}

impl Strand for ActivationRecorder {
    fn name(&self) -> &str {
        "test.sensors-activation-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>("net.signatures")];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // `recv_all`, not `recv(name)`: the inbox is a mailbox, not a filter.
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if !socket.starts_with("net.signatures.") {
                continue;
            }
            let outcome = match event.message {
                Message::SignatureActivated(activated) => Some(Outcome::Activated(activated)),
                Message::SignatureActivationFailed(failed) => Some(Outcome::Failed(failed)),
                _ => None,
            };
            if let Some(outcome) = outcome {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(outcome);
            }
        }
        Ok(())
    }
}

fn lifecycle_recorder_spec(log: LifecycleLog) -> StrandSpec {
    StrandSpec::new(
        "test.sensors-lifecycle-recorder",
        move || -> Box<dyn Strand> {
            Box::new(LifecycleRecorder {
                log: Arc::clone(&log),
            })
        },
    )
}

fn activation_recorder_spec(log: ActivationLog) -> StrandSpec {
    StrandSpec::new(
        "test.sensors-activation-recorder",
        move || -> Box<dyn Strand> {
            Box::new(ActivationRecorder {
                log: Arc::clone(&log),
            })
        },
    )
}

// ---------------------------------------------------------------------------
// Engine fixture
// ---------------------------------------------------------------------------

/// The engine plus the operator material needed to sign approvals for it.
struct Fixture {
    engine: Arc<SignatureEngineSensor>,
    database: Arc<SignatureDatabase>,
    /// Shared, because the key is `ZeroizeOnDrop` (deliberately not `Clone`) and
    /// a drill may sign several approvals.
    signing_key: Arc<HybridSigningKey>,
    operator: PeerId,
    candidate_id: Uuid,
}

/// How the engine under test is wired, so a drill can choose which refusal path
/// an approval takes without changing anything else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wiring {
    /// A store holding the candidate: approvals activate a real rule. (An
    /// approval for a *missing* candidate — the other refusal path — is covered
    /// by the behaviour-preservation test, which has a store.)
    WithCandidate,
    /// No store at all: every approval is refused (the fail-closed default).
    NoStore,
}

/// Build an engine with a real operator keypair and a real database, optionally
/// with a store holding one candidate (a rule that compiles and matches
/// `CA FE`) — the exact state the two-phase activation path expects.
///
/// Key generation runs on a 64 MiB-stack thread: ML-DSA-65 keygen is
/// stack-heavy and two keypairs in one test overflow a default test-thread
/// stack (the service's own unit tests do the same).
fn fixture(bus: Arc<BusPublisher>, wiring: Wiring) -> Fixture {
    let candidate_id = Uuid::new_v4();
    let store = Store::in_memory();
    let candidate = SignatureCandidate {
        id: candidate_id,
        rule_text: CANDIDATE_RULE.to_string(),
        description: "strand drill candidate".into(),
        source_events: vec![EventId::new()],
        extracted_at: chrono::Utc::now(),
        confidence: 0.9,
    };
    if wiring == Wiring::WithCandidate {
        store
            .put(
                &format!("signature_candidate:{}", candidate_id),
                serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
    }

    let (signing_key, verify_key) = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let mut rng = OsRng;
            HybridEd25519Mldsa::generate_keypair(&mut rng)
        })
        .unwrap()
        .join()
        .unwrap();

    let database = Arc::new(SignatureDatabase::new());
    let mut sensor = SignatureEngineSensor::new(Arc::clone(&bus))
        .with_operator_verify_key(Arc::new(verify_key))
        .with_database(Arc::clone(&database));
    if wiring != Wiring::NoStore {
        sensor = sensor.with_store(store);
    }
    let engine = Arc::new(sensor);

    Fixture {
        engine,
        database,
        signing_key: Arc::new(signing_key),
        operator: PeerId::new(),
        candidate_id,
    }
}

/// Sign an approval over `rule_text` on a big-stack thread (ML-DSA signing is
/// stack-heavy too).
fn sign_approval(
    signing_key: Arc<HybridSigningKey>,
    operator: PeerId,
    candidate_id: Uuid,
    rule_text: &str,
) -> SignatureApproved {
    let rule_text = rule_text.to_string();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || SignatureApproved {
            candidate_id,
            approved_by: operator,
            approved_at: chrono::Utc::now(),
            signature: HybridEd25519Mldsa::sign(&signing_key, rule_text.as_bytes()).to_bytes(),
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Offer one approval to the strand, exactly as the operator console does:
/// publish `net.signatures.approved` on the bus.
fn offer_approval(bus: &BusPublisher, approved: SignatureApproved) {
    BusEvent::publish(&bus, topics::APPROVED, Message::SignatureApproved(approved))
        .expect("publish is fire-and-forget and never fails on an idle topic");
}

// ---------------------------------------------------------------------------
// Behaviour preservation
// ---------------------------------------------------------------------------

/// The strand serves the same topic pair with the same payloads and the same
/// fail-closed semantics the `tokio::spawn`ed loop had, and its outcomes reach
/// the same `Bus::subscribe` subscribers the old loop fed — proving the strand's
/// publish path (`Bus::publish` through the shared engine) is equivalent to the
/// old loop's.
#[tokio::test]
async fn strand_serves_approvals_and_publishes_outcomes_to_shim_subscribers() {
    // The topics are literally the ones the old loop used, so a re-wired
    // subscriber cannot be silently listening to something else.
    assert_eq!(topics::APPROVED, "net.signatures.approved");
    assert_eq!(topics::ACTIVATED, "net.signatures.activated");
    assert_eq!(
        topics::ACTIVATION_FAILED,
        "net.signatures.activation_failed"
    );

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let fixture = fixture(Arc::clone(&publisher), Wiring::WithCandidate);
    let outcomes = new_activation_log();

    // A second strand on the same web, consuming the engine's output by TypeId.
    bus.register_spec(activation_recorder_spec(Arc::clone(&outcomes)));

    // The engine's loop, as a spec — the production registration path, which
    // reads the drill policy from the environment (unarmed here).
    imperium_net_sensors::register_strands(&mut bus, &fixture.engine);

    // The shim's own subscriber surface: the path every existing consumer of
    // these topics uses, and the path the pre-conversion loop's `Bus::publish`
    // reached.
    let mut activated_sub = subscribe_queue(&publisher, topics::ACTIVATED, 64);
    let mut failed_sub = subscribe_queue(&publisher, topics::ACTIVATION_FAILED, 64);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // 1. A validly signed approval for the stored candidate activates the rule.
    let approval = sign_approval(
        Arc::clone(&fixture.signing_key),
        fixture.operator.clone(),
        fixture.candidate_id,
        CANDIDATE_RULE,
    );
    offer_approval(&publisher, approval);

    let event = tokio::time::timeout(Duration::from_secs(5), activated_sub.recv())
        .await
        .expect("the activation must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    assert_eq!(&*event.topic, topics::ACTIVATED);
    match event.message {
        Message::SignatureActivated(activated) => {
            assert_eq!(activated.candidate_id, fixture.candidate_id);
            assert!(
                !activated.signature_id.is_nil(),
                "the activated payload must carry the rule's fresh id"
            );
        }
        other => panic!("expected SignatureActivated, got {other:?}"),
    }

    // The verdict of the service is unchanged: the rule is loaded in the engine
    // vec, mirrored in the auditable database, and it matches.
    assert_eq!(fixture.engine.extracted_count(), 1);
    assert_eq!(fixture.database.extracted_count(), 1);
    let matches = fixture.engine.scan(&[0xCA, 0xFE]).unwrap();
    assert_eq!(matches.len(), 1, "the activated rule must scan");

    // 2. A forged approval (signed over different bytes) is refused, and the
    //    refusal names the reason — the verify-before-activate invariant.
    let forged = sign_approval(
        Arc::clone(&fixture.signing_key),
        fixture.operator.clone(),
        fixture.candidate_id,
        "rule something_else { strings: $a = { BE EF } condition: $a }",
    );
    offer_approval(&publisher, forged);
    let event = tokio::time::timeout(Duration::from_secs(5), failed_sub.recv())
        .await
        .expect("the refusal must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    match event.message {
        Message::SignatureActivationFailed(failed) => {
            assert_eq!(failed.candidate_id, fixture.candidate_id);
            assert!(
                failed.compile_error.contains("verification failed"),
                "the refusal must say verification failed: {}",
                failed.compile_error
            );
        }
        other => panic!("expected SignatureActivationFailed, got {other:?}"),
    }

    // 3. An approval whose candidate is not in the store is refused too.
    let unknown = Uuid::new_v4();
    let orphan = sign_approval(
        Arc::clone(&fixture.signing_key),
        fixture.operator.clone(),
        unknown,
        CANDIDATE_RULE,
    );
    offer_approval(&publisher, orphan);
    let event = tokio::time::timeout(Duration::from_secs(5), failed_sub.recv())
        .await
        .expect("the second refusal must arrive")
        .expect("subscription must not lag or close");
    match event.message {
        Message::SignatureActivationFailed(failed) => {
            assert_eq!(failed.candidate_id, unknown);
            assert!(
                failed.compile_error.contains("store fetch failed"),
                "the refusal must name the store lookup: {}",
                failed.compile_error
            );
        }
        other => panic!("expected SignatureActivationFailed, got {other:?}"),
    }

    // The peer strand saw all three outcomes, in order: strand → strand delivery.
    wait_until("the outcome recorder to see all three outcomes", || {
        outcome_snapshot(&outcomes).len() >= 3
    });
    supervision.shutdown();

    let seen = outcome_snapshot(&outcomes);
    match &seen[0] {
        Outcome::Activated(activated) => {
            assert_eq!(activated.candidate_id, fixture.candidate_id);
        }
        other => panic!("the peer strand must see the activation first: {other:?}"),
    }
    match &seen[1] {
        Outcome::Failed(failed) => {
            assert_eq!(failed.candidate_id, fixture.candidate_id);
            assert!(failed.compile_error.contains("verification failed"));
        }
        other => panic!("the peer strand must see the refusal second: {other:?}"),
    }
    match &seen[2] {
        Outcome::Failed(failed) => {
            assert_eq!(failed.candidate_id, unknown);
            assert!(failed.compile_error.contains("store fetch failed"));
        }
        other => panic!("the peer strand must see the store refusal third: {other:?}"),
    }
    // Fail-closed: no refusal loaded anything.
    assert_eq!(fixture.engine.extracted_count(), 1);
    assert_eq!(fixture.database.extracted_count(), 1);
}

// ---------------------------------------------------------------------------
// The crash-restart proof
// ---------------------------------------------------------------------------

/// The strand's full crash policy, driven through the real strand with an
/// injected fault: it is installed as a **spec** (so the spider can restart it),
/// each crash is a `LifecycleEvent::Crashed` carrying the injected reason, the
/// spider restarts it three times, and the fourth crash quarantines it.
///
/// Approvals are offered continuously so a restarted instance always has work;
/// the replayed pending tail would also do it, but publishing keeps the drill
/// independent of buffer timing.
#[test]
fn crashed_strand_is_restarted_three_times_then_quarantined() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let outcomes = new_activation_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(activation_recorder_spec(Arc::clone(&outcomes)));

    // An engine with no store configured: every approval is refused (fail
    // closed), which is real work for the strand and leaves no rule loaded, so
    // the drill cannot inflate engine state.
    let fixture = fixture(Arc::clone(&publisher), Wiring::NoStore);

    // Armed to crash after the first approval each instance observes. The fault
    // is per instance, so every restart crashes again — which is what drives the
    // whole restart-then-quarantine sequence.
    bus.register_spec(SignatureEngineStrand::spec(
        Arc::clone(&fixture.engine),
        FaultPolicy::CrashAfterApprovals(1),
    ));

    // Nothing has started yet: a spec is queued, not installed.
    // A spec is queued, not started: `register_spec` only appends.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == STRAND_NAME
        )),
        0,
        "registering the spec must not start the strand"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the strand to be installed and register itself", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Registered { name, .. } if name == STRAND_NAME
            )
        }) == 1
    });

    // Feed approvals until the fourth crash has been quarantined by the spider.
    // The same signed approval is re-published: every publish mints a fresh
    // `BusEvent` id, so each one is new work for the strand (and fresh evidence
    // that a restarted instance is really running).
    let approval = sign_approval(
        Arc::clone(&fixture.signing_key),
        fixture.operator.clone(),
        fixture.candidate_id,
        CANDIDATE_RULE,
    );
    wait_until(
        "the strand to be quarantined after its fourth crash",
        || {
            offer_approval(&publisher, approval.clone());
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Quarantined { name, .. } if name == STRAND_NAME
                )
            }) >= 1
        },
    );

    // The run loop was genuinely live for the whole drill (not a stall).
    assert!(supervision.is_running());
    supervision.shutdown();

    // (a) Installed from the queued spec — and only a spec can be restarted:
    // `Bus::register` installs a *live* strand with no factory, and the kernel
    // refuses the spider's `ControlMsg::Restart` for it. The three `Restarted`
    // events below are therefore themselves proof this strand arrived as a
    // `StrandSpec`.
    //
    // `Registered` fires once per *generation* (each restart builds a fresh slot
    // whose generation counter starts at 0), so one install plus three restarts
    // produce four.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == STRAND_NAME
        )),
        4,
        "`Registered` fires once per generation (initial + 3 restarts): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == STRAND_NAME
        )
    });
    let restarted = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Restarted { name, .. } if name == STRAND_NAME
        )
    });
    let quarantined = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Quarantined { name, .. } if name == STRAND_NAME
        )
    });
    assert_eq!(
        crashed,
        4,
        "every crash must be visible as a lifecycle event: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted,
        3,
        "the spider restarts three times: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined,
        1,
        "the fourth crash quarantines the strand: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The injected fault names itself in every reason: a real forensic signal,
    // not a bare marker.
    let reasons: Vec<String> = lifecycle_snapshot(&lifecycle)
        .into_iter()
        .filter_map(|e| match e {
            LifecycleEvent::Crashed { name, reason } if name == STRAND_NAME => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .all(|r| r.contains("injected fault") && r.contains("1 approval")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // The strand was doing its job right up to (and including) the tick it
    // crashed on: the engine refused the approval (no store) and said so.
    assert!(
        outcome_snapshot(&outcomes)
            .iter()
            .any(|o| matches!(o, Outcome::Failed(f) if f.compile_error.contains("no store"))),
        "the refused approval must have been published before the crash"
    );
    assert_eq!(
        fixture.engine.extracted_count(),
        0,
        "a fail-closed engine must not load anything"
    );

    // After quarantine it is gone for good: further approvals cannot revive it.
    // (Unrelated `Buffered` events are expected — a topic with no subscriber
    // buffers its messages — so this counts the strand's own events.)
    let before = strand_events(&lifecycle);
    for _ in 0..5 {
        offer_approval(&publisher, approval.clone());
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        strand_events(&lifecycle),
        before,
        "a quarantined strand must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// Replay dedupe + state continuity
// ---------------------------------------------------------------------------

/// A restarted generation is a late subscriber: the kernel replays its bounded
/// pending tail (32 messages per `TypeId`) to it, and activation is **not**
/// idempotent. This test proves the conversion handles that the recipe's way —
/// dedupe on `BusEvent::id` through a set shared by every generation — and that
/// the restarted strand resumes the *same* engine.
///
/// Exactly one approval is published, ever. The first generation activates it
/// and crashes (armed policy); every later generation is replayed the same
/// (still pending) event, skips it as already acted on, and crashes on it again.
/// So: at least two crashes prove the replay reached a later generation, while
/// exactly one activation proves the replay was deduped — and the loaded rule
/// that generation one created is still there, because the spec's factory shares
/// one `Arc<SignatureEngineSensor>`.
#[test]
fn replayed_approval_is_deduped_and_activated_state_survives_a_restart() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let outcomes = new_activation_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(activation_recorder_spec(Arc::clone(&outcomes)));

    let fixture = fixture(Arc::clone(&publisher), Wiring::WithCandidate);
    bus.register_spec(SignatureEngineStrand::spec(
        Arc::clone(&fixture.engine),
        FaultPolicy::CrashAfterApprovals(1),
    ));

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // One approval, published once. Everything after this is a *replay*.
    offer_approval(
        &publisher,
        sign_approval(
            Arc::clone(&fixture.signing_key),
            fixture.operator.clone(),
            fixture.candidate_id,
            CANDIDATE_RULE,
        ),
    );

    // Generation one activates it and crashes; a later generation is replayed
    // the same pending event and crashes on *that* — which is the replay proof.
    wait_until(
        "a replayed approval to reach a restarted generation",
        || {
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Crashed { name, .. } if name == STRAND_NAME
                )
            }) >= 2
        },
    );
    // Let the restarted generation finish its tick (and any further replay)
    // before the final counts are taken.
    std::thread::sleep(Duration::from_millis(300));
    supervision.shutdown();

    let activations = outcome_snapshot(&outcomes)
        .into_iter()
        .filter(|o| matches!(o, Outcome::Activated(_)))
        .count();
    assert_eq!(
        activations, 1,
        "a replayed approval must be deduped on its event id, never re-activated"
    );

    // State continuity: the rule generation one loaded is still loaded, exactly
    // once, in the engine (and its auditable database) every generation shares.
    assert_eq!(
        fixture.engine.extracted_count(),
        1,
        "the restarted strand must resume the same engine, not reload a fresh one"
    );
    assert_eq!(
        fixture.database.extracted_count(),
        1,
        "the auditable database is shared too, and holds exactly the one rule"
    );
    assert_eq!(
        fixture.engine.scan(&[0xCA, 0xFE]).unwrap().len(),
        1,
        "the rule loaded across the restart still scans"
    );

    // At least two crashes: generation 1 did the work, a later generation was
    // replayed the same pending event (and skipped it, hence the single
    // activation asserted above). The drill's armed policy keeps crashing on
    // every replay, so the spider's full budget (4 crashes → quarantine) is
    // reached too — but the property under test is the replay itself, so the
    // assertion is a floor, not an exact count.
    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == STRAND_NAME
        )
    });
    assert!(
        crashed >= 2,
        "a replayed approval must reach a restarted generation: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// Clears the liveness flag when the run-loop thread exits, whether `run_until`
/// returned normally or unwound (`panic = "unwind"` runs the `Drop`).
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind.
struct Supervision {
    publisher: Arc<BusPublisher>,
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(spiderweb::StrandSpec::new("spider", || {
            Box::new(spider::Spider::new())
        }));

        let running = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&running);
        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                thread_flag.store(true, Ordering::SeqCst);
                let _running = RunningGuard(Arc::clone(&thread_flag));
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            running,
            join: Some(join),
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn shutdown(&mut self) {
        let _ = self.publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Supervision {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A named subscription feeding an owned bounded queue — the shape an async
/// consumer outside a strand must have now that delivery is push-based. The
/// callback runs on the publisher's thread and only does a non-blocking send.
fn subscribe_queue(
    publisher: &BusPublisher,
    prefix: &'static str,
    capacity: usize,
) -> tokio::sync::mpsc::Receiver<BusEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    publisher.subscribe_prefix(
        prefix,
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<BusEvent>() {
                let _ = tx.try_send(*event);
            }
        }),
    );
    rx
}
