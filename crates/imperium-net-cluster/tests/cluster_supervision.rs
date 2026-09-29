//! End-to-end supervision proof for the cluster strand conversion.
//!
//! `imperium-net-cluster`'s two standing recv loops — the
//! `net.cluster.membership.granted` loop that applies an operator-signed
//! [`MembershipGrant`], and the `net.cluster.config.fetch_response` loop that
//! applies a fetched configuration — used to be `tokio::spawn`ed tasks. They are
//! supervised Spiderweb **strands** now
//! ([`MembershipGrantStrand`](imperium_net_cluster::MembershipGrantStrand),
//! [`ConfigResponseStrand`](imperium_net_cluster::ConfigResponseStrand); see
//! the pilot (`imperium-net-lightcone`)). The unit tests in `src/` cover
//! the *managers*; these integration tests cover the part only a real kernel can
//! prove:
//!
//! 1. [`strands_apply_verified_cluster_traffic_and_reject_forgeries`] — behaviour
//!    preservation. Same topic in, same signature-verified state change out, and
//!    both fail-closed paths (forged grant, forged config) still reject.
//! 2. [`crashed_membership_strand_is_restarted_three_times_then_quarantined`] —
//!    the crash policy, driven through the real strand with its injected fault:
//!    registered as a **spec**, crashes become `LifecycleEvent::Crashed`, the
//!    spider sends `ControlMsg::Restart` three times, and the fourth crash
//!    quarantines the strand. The config strand is an independent failure domain
//!    and keeps running throughout.
//! 3. [`replayed_grant_is_not_applied_twice_across_a_restart`] — the replay
//!    hazard. A restarted generation is replayed the kernel's pending tail, which
//!    the previous generation already applied; the durable `SeenIds` guard
//!    refuses the repeat, so a replayed **grant** is not applied a second time.
//! 4. [`replayed_config_response_is_not_applied_twice_across_a_restart`] — the
//!    same proof for the config loop, with the version gate named as the second
//!    line of defence.
//!
//! Everything here runs the production path: a real `Bus`, real `register_strand`
//! / `attach_*` wiring, real `Bus::engage_supervision` (which installs the
//! kernel's run loop and the `spider` orchestrator on their own OS threads), real
//! strand workers, real operators signing real payloads. Nothing is simulated and
//! nothing is stubbed — the injected fault is the only concession, and it is the
//! same `FaultPolicy` production exposes.
//!
//! # The instruments
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle`. The
//! recipe's answer is a second strand whose input is `LifecycleEvent` and which
//! records what it feels: [`LifecycleRecorder`]. The state-change counters on the
//! managers (`applied_grants`, `applied_configs`) are the other instrument: they
//! are what makes "the replayed event was *not* applied again" an assertion
//! rather than a hope.
//!
//! # Why every key operation runs on a worker thread
//!
//! `HybridVerifyingKey` is 43 KB **by value** and `HybridSigningKey` is 109 KB:
//! every `verifying_key()` call, every manager construction and every ML-DSA sign
//! expands that material on the stack. A test frame that does several of those (a
//! keypair, two managers, a couple of signatures) exhausts libtest's default
//! test-thread stack, so all of it happens inside [`with_big_stack`], and what
//! crosses a frame boundary is an `Arc` or a plain-data message.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_net_cluster::{
    attach_config, attach_membership, links_for, register_strands_with, topics, ConfigManager,
    FaultPolicy, MembershipManager, CONFIG_STRAND, MEMBERSHIP_STRAND,
};
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey, HybridVerifyingKey};
use imperium_protocol::BusEvent;
use imperium_protocol::{ClusterId, ConfigurationFetchResponse, MembershipGrant, Message, PeerId};
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};
use spiderweb::{
    BusHandle, LifecycleEvent, Socket, Strand, StrandError, StrandSpec, SYS_LIFECYCLE,
};

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind — the
/// one shareable handle, and (since the composition root mints exactly one per
/// node) the bus's identity in the wiring registry.
struct Supervision {
    publisher: Arc<BusPublisher>,
    /// True while the run-loop thread is inside `run_until`; cleared by
    /// [`RunningGuard`] on any exit, so a panic inside the kernel cannot leave a
    /// stale `true` behind.
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// Clears the liveness flag when the run-loop thread exits, whether `run_until`
/// returned normally or unwound (`panic = "unwind"` runs the `Drop`).
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));

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

    /// Whether the run loop is currently executing.
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

// ---------------------------------------------------------------------------
// Instruments
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Count the lifecycle events of `strand` matching `pred`.
fn count(log: &LifecycleLog, strand: &str, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
    lifecycle_snapshot(log)
        .iter()
        .filter(|event| match event {
            LifecycleEvent::Registered { name, .. }
            | LifecycleEvent::Crashed { name, .. }
            | LifecycleEvent::Restarted { name, .. }
            | LifecycleEvent::Quarantined { name, .. }
            | LifecycleEvent::Detached { name } => name == strand && pred(event),
            _ => false,
        })
        .count()
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
/// with the run loop and survives the crash of its neighbours.
struct LifecycleRecorder {
    log: LifecycleLog,
}

impl Strand for LifecycleRecorder {
    fn name(&self) -> &str {
        "test.cluster-lifecycle-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        // Routing is by `TypeId`, so this strand feels every `LifecycleEvent` on
        // the web rather than one named socket.
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

fn lifecycle_recorder_spec(log: LifecycleLog) -> StrandSpec {
    StrandSpec::new(
        "test.cluster-lifecycle-recorder",
        move || -> Box<dyn Strand> {
            Box::new(LifecycleRecorder {
                log: Arc::clone(&log),
            })
        },
    )
}

// ---------------------------------------------------------------------------
// Operator key material, and the helpers that touch it
// ---------------------------------------------------------------------------

/// Run `f` on a thread with a large stack and return its result.
///
/// See the module docs: the hybrid keys are tens of kilobytes *by value*, and
/// libtest's default test-thread stack cannot hold the temporaries of a frame
/// that derives keys, builds managers and signs payloads. Every such operation is
/// confined to this worker; the return value must stay small (a handle, a
/// message, a count) — which is why keys travel as `Arc`s here.
fn with_big_stack<T: Send, F: FnOnce() -> T + Send>(what: &str, f: F) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(format!("cluster-test-{what}"))
            .stack_size(32 * 1024 * 1024)
            .spawn_scoped(scope, f)
            .expect("the crypto worker spawns")
            .join()
            .expect("the crypto worker does not panic")
    })
}

/// An operator's signing material, heap-boxed so it never appears in a test
/// frame's stack.
struct Operator {
    signing: Arc<HybridSigningKey>,
    verifying: Arc<HybridVerifyingKey>,
}

/// The operator keypair, with the verifying key derived exactly once.
fn operator_keypair() -> Operator {
    with_big_stack("keypair", || {
        let mut rng = rand::rngs::OsRng;
        let (signing, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let verifying = HybridEd25519Mldsa::verifying_key(&signing);
        Operator {
            signing: Arc::new(signing),
            verifying: Arc::new(verifying),
        }
    })
}

/// A membership manager for `peer`, trusting `vk`.
fn membership_manager(
    cluster_id: &ClusterId,
    peer: PeerId,
    vk: &HybridVerifyingKey,
) -> Arc<MembershipManager> {
    with_big_stack("membership-manager", || {
        Arc::new(MembershipManager::new(
            cluster_id.clone(),
            peer,
            (*vk).clone(),
        ))
    })
}

/// A config manager for `peer`, trusting `vk`.
fn config_manager(
    cluster_id: &ClusterId,
    peer: PeerId,
    vk: &HybridVerifyingKey,
) -> Arc<ConfigManager> {
    with_big_stack("config-manager", || {
        Arc::new(ConfigManager::new(cluster_id.clone(), peer, (*vk).clone()))
    })
}

/// Mint genuine operator-signed grants for `peers`, on a **separate** bus.
///
/// The grants have to be genuine (the strands verify them), but the test must
/// control exactly when each one reaches the bus under test — otherwise a
/// pre-minted grant would sit in that bus's pending tail and be replayed into the
/// strand at install time. Minting elsewhere, and up front, keeps the tested
/// bus's traffic entirely under the test's control.
fn mint_grants(
    operator: &Operator,
    cluster_id: &ClusterId,
    peers: Vec<PeerId>,
) -> Vec<MembershipGrant> {
    with_big_stack("grants", || {
        let operator_id = PeerId::new();
        let bus = Arc::new(Bus::open().publisher());
        let manager = Arc::new(MembershipManager::new(
            cluster_id.clone(),
            operator_id.clone(),
            (*operator.verifying).clone(),
        ));
        peers
            .into_iter()
            .map(|peer| {
                manager
                    .request_membership(peer.clone(), &bus)
                    .expect("a fresh peer is not a member yet");
                manager
                    .approve_membership(&peer, &operator_id, &operator.signing, &bus)
                    .expect("the operator can approve a pending peer")
            })
            .collect()
    })
}

/// One genuine grant, for the tests that need a single one.
fn mint_grant(operator: &Operator, cluster_id: &ClusterId, peer: PeerId) -> MembershipGrant {
    mint_grants(operator, cluster_id, vec![peer])
        .pop()
        .expect("one peer yields one grant")
}

/// An operator-signed fetch response.
fn signed_response(
    operator: &Operator,
    cluster_id: &ClusterId,
    version: u64,
    data: &[u8],
) -> ConfigurationFetchResponse {
    with_big_stack("config", || ConfigurationFetchResponse {
        cluster_id: cluster_id.clone(),
        version,
        config_data: data.to_vec(),
        signature: ConfigManager::sign_config(data, version, &operator.signing).to_bytes(),
    })
}

fn publish_grant(publisher: &BusPublisher, grant: MembershipGrant) {
    BusEvent::publish(
        publisher,
        topics::MEMBERSHIP_GRANTED,
        Message::MembershipGrant(grant),
    )
    .expect("publish is fire-and-forget and never fails");
}

fn publish_response(publisher: &BusPublisher, resp: ConfigurationFetchResponse) {
    BusEvent::publish(
        publisher,
        topics::CONFIG_FETCH_RESPONSE,
        Message::ConfigFetchResp(resp),
    )
    .expect("publish is fire-and-forget and never fails");
}

/// A simulated node's two managers, wired to `bus`'s supervised strands.
struct Node {
    membership: Arc<MembershipManager>,
    config: Arc<ConfigManager>,
}

fn node_on(publisher: &Arc<BusPublisher>, cluster_id: &ClusterId, vk: &HybridVerifyingKey) -> Node {
    let peer = PeerId::new();
    let membership = membership_manager(cluster_id, peer.clone(), vk);
    let config = config_manager(cluster_id, peer, vk);
    assert!(attach_membership(publisher, &membership), "fresh wiring");
    assert!(attach_config(publisher, &config), "fresh wiring");
    Node { membership, config }
}

// ---------------------------------------------------------------------------
// Behaviour preservation
// ---------------------------------------------------------------------------

/// The two loops serve the same topics and produce the same signature-verified
/// state changes through the strands, and both fail-closed paths survive the
/// conversion.
///
/// The forged messages are published *first*, and a genuine message of the same
/// kind follows as a control: only then does "the forged one was rejected" mean
/// anything, because the control proves the loops are live and applying.
///
/// This test drives the canonical wiring — `attach_membership` /
/// `attach_config` plus `register_strands_with` — which is what the composition
/// root calls (the old `subscribe_*` shims those methods replaced are gone).
#[tokio::test]
async fn strands_apply_verified_cluster_traffic_and_reject_forgeries() {
    let cluster_id = ClusterId::new();
    let operator = operator_keypair();
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    let peer = PeerId::new();
    let membership = membership_manager(&cluster_id, peer.clone(), &operator.verifying);
    let config = config_manager(&cluster_id, peer, &operator.verifying);

    // The wiring the deleted `subscribe_*` shims performed, written out: attach
    // both managers to the bus's links registry, then queue the crate's strands.
    attach_membership(&publisher, &membership);
    attach_config(&publisher, &config);
    register_strands_with(&mut bus, &publisher, FaultPolicy::None);

    // A spec is queued, not started: nothing runs until the run loop starts.
    // (`register_spec` only appends; `run_until` consumes the bus.)
    let links = links_for(&publisher);
    assert_eq!(
        links.membership_len(),
        1,
        "the wiring registers its manager"
    );
    assert_eq!(links.config_len(), 1, "the wiring registers its manager");

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // 1. Forgeries, published first. Neither may reach the managers' state.
    let forged_peer = PeerId::new();
    publish_grant(
        &publisher,
        MembershipGrant {
            cluster_id: cluster_id.clone(),
            peer_id: forged_peer.clone(),
            granted_by: PeerId::new(),
            granted_at: chrono::Utc::now(),
            signature: vec![1, 2, 3],
        },
    );
    let forged_config = b"forged-config".to_vec();
    publish_response(
        &publisher,
        ConfigurationFetchResponse {
            cluster_id: cluster_id.clone(),
            // Same version as the genuine response below: if the forgery were
            // applied, the genuine one would then be rejected as stale, and the
            // data assertion at the end would catch it.
            version: 1,
            config_data: forged_config,
            signature: vec![1, 2, 3],
        },
    );

    // 2. The controls: genuine, operator-signed traffic.
    let verified_peer = PeerId::new();
    publish_grant(
        &publisher,
        mint_grant(&operator, &cluster_id, verified_peer.clone()),
    );
    let verified_config = b"operator-config-1".to_vec();
    publish_response(
        &publisher,
        signed_response(&operator, &cluster_id, 1, &verified_config),
    );

    wait_until(
        "both supervised loops to apply their verified message",
        || membership.is_member(&verified_peer) && config.current_version() == 1,
    );
    // Give the strands a few more ticks: a forgery applied late would land here.
    std::thread::sleep(Duration::from_millis(100));

    // Membership: exactly the verified grant was applied, the forgery was not.
    assert!(
        !membership.is_member(&forged_peer),
        "a forged grant must never be applied"
    );
    assert_eq!(
        membership.applied_grants(),
        1,
        "only the operator-signed grant may be applied"
    );
    assert_eq!(membership.member_count(), 2);

    // Config: same shape. The applied data is the signed one, and there was
    // exactly one application — so the forgery was rejected before any state
    // change, and did not merely look rejected.
    assert_eq!(
        config.applied_configs(),
        1,
        "only the operator-signed response may be applied"
    );
    assert_eq!(config.current_version(), 1);
    assert_eq!(
        config.current_config().expect("a config is current").data,
        verified_config,
        "the forged config must never have been applied"
    );

    assert!(supervision.is_running());
    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// The crash-restart proof
// ---------------------------------------------------------------------------

/// The membership strand's full crash policy, driven through the real strand with
/// an injected fault: it is installed as a **spec** (so the spider can restart
/// it), each crash is a `LifecycleEvent::Crashed` carrying the injected reason,
/// the spider restarts it three times, and the fourth crash quarantines it.
///
/// The config strand shares the fault policy but never receives a config response
/// here, so it must run through the whole drill untouched: the two loops are
/// independent failure domains, which is the point of supervision.
#[test]
fn crashed_membership_strand_is_restarted_three_times_then_quarantined() {
    let cluster_id = ClusterId::new();
    let operator = operator_keypair();
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    // Arm the drill *before* wiring: every instance crashes after applying its
    // first message, and the first policy queued is the one that stays in force.
    register_strands_with(&mut bus, &publisher, FaultPolicy::CrashAfterMessages(1));
    let node = node_on(&publisher, &cluster_id, &operator.verifying);

    // Genuine grants, minted off-bus: the drill publishes one per attempt so a
    // restarted generation always has fresh work.
    let peers: Vec<PeerId> = (0..6).map(|_| PeerId::new()).collect();
    let grants = mint_grants(&operator, &cluster_id, peers);

    // A spec is queued, not installed.
    // A spec is queued, not started: nothing runs until the run loop starts.
    // (`register_spec` only appends; `run_until` consumes the bus.)
    assert_eq!(
        count(&lifecycle, MEMBERSHIP_STRAND, |_| true),
        0,
        "registering the spec must not start the strand"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the membership strand to be installed", || {
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Registered { .. })
        }) == 1
    });

    // Drive the drill: a fresh grant every poll iteration, until the fourth crash
    // has been quarantined.
    let mut published = 0usize;
    wait_until("the membership strand to be quarantined", || {
        if published < grants.len() {
            publish_grant(&publisher, grants[published].clone());
            published += 1;
        }
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Quarantined { .. })
        }) >= 1
    });

    assert!(
        supervision.is_running(),
        "the run loop was live for the whole drill"
    );
    supervision.shutdown();

    // (a) Installed from the queued spec. `Registered` fires once per
    // *generation* (each restart builds a fresh slot), so one initial install
    // plus three restarts produce four — and restarts are impossible without a
    // factory, so the three `Restarted` events below are themselves proof the
    // strand arrived as a `StrandSpec`.
    assert_eq!(
        count(&lifecycle, MEMBERSHIP_STRAND, |event| matches!(
            event,
            LifecycleEvent::Registered { .. }
        )),
        4,
        "{:#?}",
        lifecycle_snapshot(&lifecycle)
    );

    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    let crashed = count(&lifecycle, MEMBERSHIP_STRAND, |event| {
        matches!(event, LifecycleEvent::Crashed { .. })
    });
    let restarted = count(&lifecycle, MEMBERSHIP_STRAND, |event| {
        matches!(event, LifecycleEvent::Restarted { .. })
    });
    let quarantined = count(&lifecycle, MEMBERSHIP_STRAND, |event| {
        matches!(event, LifecycleEvent::Quarantined { .. })
    });
    assert_eq!(crashed, 4, "{:#?}", lifecycle_snapshot(&lifecycle));
    assert_eq!(restarted, 3, "{:#?}", lifecycle_snapshot(&lifecycle));
    assert_eq!(quarantined, 1, "{:#?}", lifecycle_snapshot(&lifecycle));

    // The injected fault's reason is a real forensic signal, not a bare marker.
    let reasons: Vec<String> = lifecycle_snapshot(&lifecycle)
        .into_iter()
        .filter_map(|event| match event {
            LifecycleEvent::Crashed { name, reason } if name == MEMBERSHIP_STRAND => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("injected fault") && reason.contains("1 message")),
        "every Crashed reason must name the injected fault: {reasons:?}"
    );

    // Exactly four applications: one per generation, and none of the replayed
    // tail events was applied a second time.
    assert_eq!(
        node.membership.applied_grants(),
        4,
        "four crashes, four applications — the replay must not have re-applied anything"
    );
    // State continuity: the manager survived the crashes, so four distinct peers
    // are approved alongside the node itself.
    assert_eq!(node.membership.member_count(), 5);
    assert_eq!(node.membership.approved_members().len(), 5);

    // The config strand is an independent failure domain: it registered with the
    // same drill armed and never crashed.
    assert_eq!(
        count(&lifecycle, CONFIG_STRAND, |event| matches!(
            event,
            LifecycleEvent::Crashed { .. }
        )),
        0,
        "the config strand never received a message, so the drill must not touch it"
    );
    assert_eq!(
        count(&lifecycle, CONFIG_STRAND, |event| matches!(
            event,
            LifecycleEvent::Registered { .. }
        )),
        1
    );

    // After quarantine it is gone for good: further grants cannot revive it, so
    // no new lifecycle event *about this strand* appears.
    let before = count(&lifecycle, MEMBERSHIP_STRAND, |_| true);
    for grant in grants.iter().skip(published) {
        publish_grant(&publisher, grant.clone());
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        count(&lifecycle, MEMBERSHIP_STRAND, |_| true),
        before,
        "a quarantined strand must stay quarantined"
    );
}

// ---------------------------------------------------------------------------
// The replay proof
// ---------------------------------------------------------------------------

/// A replayed **grant** is not applied twice.
///
/// This is the hazard the recipe's §5.4 warns about, in its sharpest form: the
/// effect of this loop is a signature-verified state change, and a restarted
/// generation is replayed the kernel's recent tail — which the previous
/// generation already applied. The durable `SeenIds` guard must refuse it.
///
/// Three independent observables prove it:
///
/// * `applied_grants()` stays at 1 — the replay never reached a manager.
/// * `Crashed` stays at 1 — the fault is armed per *instance* after one *applied*
///   message, so a re-applied replay would have crashed the restarted generation
///   too, giving a second crash and a second restart.
/// * the state survives: the peer is still approved after the restart, because the
///   manager is shared through the spec's factory.
///
/// A fresh grant is then published as the control: it *is* applied, crashes the
/// second generation, and moves the counter — so "1" is a refusal, not a strand
/// that stopped working.
#[test]
fn replayed_grant_is_not_applied_twice_across_a_restart() {
    let cluster_id = ClusterId::new();
    let operator = operator_keypair();
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    register_strands_with(&mut bus, &publisher, FaultPolicy::CrashAfterMessages(1));
    let node = node_on(&publisher, &cluster_id, &operator.verifying);

    let grants = mint_grants(&operator, &cluster_id, vec![PeerId::new(), PeerId::new()]);
    let first = grants[0].clone();
    let second = grants[1].clone();

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the membership strand to be installed", || {
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Registered { .. })
        }) == 1
    });

    // One grant reaches the strand: it is applied, then this instance crashes.
    publish_grant(&publisher, first.clone());
    wait_until("the first crash", || {
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Crashed { .. })
        }) >= 1
    });
    wait_until("the restart", || {
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Restarted { .. })
        }) >= 1
    });

    // The restarted generation is now replayed the pending tail — which contains
    // the grant its predecessor already applied. Give it ample time to (wrongly)
    // re-apply it: the replay is refused, so nothing happens at all.
    std::thread::sleep(Duration::from_millis(400));

    assert!(
        node.membership.is_member(&first.peer_id),
        "the applied grant survives the restart (shared manager)"
    );
    assert_eq!(
        node.membership.applied_grants(),
        1,
        "the replayed grant must not be applied a second time"
    );
    assert_eq!(
        count(&lifecycle, MEMBERSHIP_STRAND, |event| matches!(
            event,
            LifecycleEvent::Crashed { .. }
        )),
        1,
        "a re-applied replay would have crashed the restarted generation too"
    );
    assert_eq!(
        count(&lifecycle, MEMBERSHIP_STRAND, |event| matches!(
            event,
            LifecycleEvent::Restarted { .. }
        )),
        1
    );
    // The durable guard holds exactly the one id it applied, and it is shared
    // across the generations.
    assert_eq!(links_for(&publisher).seen_membership().len(), 1);

    // Control: a genuinely new grant is still applied (and crashes generation 2,
    // which proves the counter can move).
    publish_grant(&publisher, second.clone());
    wait_until("the second grant to be applied", || {
        node.membership.is_member(&second.peer_id)
    });
    wait_until("the second crash", || {
        count(&lifecycle, MEMBERSHIP_STRAND, |event| {
            matches!(event, LifecycleEvent::Crashed { .. })
        }) >= 2
    });
    assert_eq!(
        node.membership.applied_grants(),
        2,
        "a new event is applied normally; only the replay is refused"
    );

    supervision.shutdown();
}

/// A replayed **config fetch response** is not applied twice.
///
/// Same shape as the grant proof, and the config loop needs it for the same
/// reason: a replayed response re-applies a fetched configuration, which is a
/// state change a node did not ask for. `apply_fetched_config`'s version gate
/// (`resp.version <= current_version` → reject) is a second, independent line of
/// defence, but it only protects state a manager has already reached; the durable
/// guard refuses the replay before any manager sees it.
#[test]
fn replayed_config_response_is_not_applied_twice_across_a_restart() {
    let cluster_id = ClusterId::new();
    let operator = operator_keypair();
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    register_strands_with(&mut bus, &publisher, FaultPolicy::CrashAfterMessages(1));
    let node = node_on(&publisher, &cluster_id, &operator.verifying);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the config strand to be installed", || {
        count(&lifecycle, CONFIG_STRAND, |event| {
            matches!(event, LifecycleEvent::Registered { .. })
        }) == 1
    });

    let first = b"config-v1".to_vec();
    publish_response(
        &publisher,
        signed_response(&operator, &cluster_id, 1, &first),
    );
    wait_until("the fetched config to be applied", || {
        node.config.current_version() == 1
    });
    wait_until("the crash", || {
        count(&lifecycle, CONFIG_STRAND, |event| {
            matches!(event, LifecycleEvent::Crashed { .. })
        }) >= 1
    });
    wait_until("the restart", || {
        count(&lifecycle, CONFIG_STRAND, |event| {
            matches!(event, LifecycleEvent::Restarted { .. })
        }) >= 1
    });

    // The replay of the response this generation already applied arrives here.
    std::thread::sleep(Duration::from_millis(400));

    assert_eq!(node.config.current_version(), 1);
    assert_eq!(
        node.config
            .current_config()
            .expect("a config is current")
            .data,
        first,
        "the applied configuration survives the restart"
    );
    assert_eq!(
        node.config.applied_configs(),
        1,
        "the replayed response must not be applied a second time"
    );
    assert_eq!(
        count(&lifecycle, CONFIG_STRAND, |event| matches!(
            event,
            LifecycleEvent::Crashed { .. }
        )),
        1,
        "handing the replay to a manager would have crashed the restarted generation too"
    );
    assert_eq!(links_for(&publisher).seen_config().len(), 1);

    // Control: a genuinely newer configuration is still applied.
    let second = b"config-v2".to_vec();
    publish_response(
        &publisher,
        signed_response(&operator, &cluster_id, 2, &second),
    );
    wait_until("the newer config to be applied", || {
        node.config.current_version() == 2
    });
    wait_until("the second crash", || {
        count(&lifecycle, CONFIG_STRAND, |event| {
            matches!(event, LifecycleEvent::Crashed { .. })
        }) >= 2
    });
    assert_eq!(node.config.applied_configs(), 2);
    assert_eq!(
        node.config
            .current_config()
            .expect("a config is current")
            .data,
        second
    );

    supervision.shutdown();
}
