//! Process-level proof that `Active` means a **real running process**.
//!
//! The unit tests in `src/lib.rs` cover the dormancy state machine; these tests
//! cover the seam that used to be a stub — [`ToolManager::activate`] now spawns
//! the tool's declared program through `imperium-managed-process`, the manifest's
//! `idle_timeout` stops it, and a process that ends is reconciled out of `Active`.
//!
//! Everything here drives a **real binary** (`/bin/sleep`, `/bin/sh`) with real
//! arguments. Nothing is stubbed, and every "the process is gone" assertion
//! reads the process table (`/proc/<pid>`) rather than the tool's state — a state
//! change alone would prove only that a flag moved.
//!
//! Two properties make this suite possible and are worth stating, because they
//! are the point of the design in `src/proc.rs`:
//!
//! * These tests are plain `#[test]` — **no tokio runtime in the test thread**.
//!   The manager spawns a supervisor thread with its own runtime to await
//!   `ManagedProcess`, so synchronous callers (tests, the CLI's composition root,
//!   any non-async caller) can run real processes without an ambient runtime.
//! * The strand drives reconciliation through `ToolManager::tick`, which the
//!   tests call in their poll loops — the same call the strand makes every ~10 ms.
//!   The last test proves that path end-to-end through a real `Bus`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_managed_process::ResourceBudget;
use imperium_net_toolkit::{StopCause, ToolManager, ToolManifest, ToolProgram, TriggerCondition};
use imperium_protocol::{BusEvent, Message, ToolActivationRequest, ToolState, ToolStateChange};
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};

// ---------------------------------------------------------------------------
// Helpers: a real binary, a real manifest, and process-table assertions
// ---------------------------------------------------------------------------

/// `/bin/sleep` and `/bin/sh` are the two binaries this suite drives: both are
/// present on every system the workspace can build on, both can be made to live
/// until they are stopped, and one of them exits on demand with a chosen code.
const SLEEP: &str = "/bin/sleep";
const SH: &str = "/bin/sh";

/// A program that runs `script` under `/bin/sh`.
fn sh(script: &str) -> ToolProgram {
    ToolProgram::new(SH).with_args(["-c", script])
}

fn manifest(name: &str) -> ToolManifest {
    ToolManifest {
        name: name.to_string(),
        description: format!("{name} test tool"),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(300),
        cooldown_duration: Duration::from_secs(60),
        max_activations_per_hour: 5,
    }
}

fn activation(name: &str) -> ToolActivationRequest {
    ToolActivationRequest {
        tool_name: name.to_string(),
        trigger: "test trigger".to_string(),
        context: HashMap::new(),
        timestamp: Utc::now(),
    }
}

/// Whether the pid is still in the process table. A stopped child is reaped by
/// `ManagedProcess::stop`, so "not present" means *gone*, not zombie.
fn present(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// What a live pid is really executing, straight from the kernel.
fn running_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// The live pid's command line, NUL separators flattened to spaces.
fn cmdline(pid: u32) -> Option<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
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

/// Wait for the supervisor to report a live pid for an already-activated tool,
/// returning it. `ToolManager::tick` runs in the poll loop — the same
/// reconciliation call the strand makes on every tick.
fn wait_for_pid(manager: &ToolManager, name: &str) -> u32 {
    let mut pid = None;
    wait_until("the tool's process to have a pid", || {
        manager.tick();
        pid = manager.pid(name);
        pid.is_some()
    });
    pid.expect("a pid was observed")
}

/// Activate a tool and wait for its process to be live.
fn activate_and_wait_for_pid(manager: &ToolManager, name: &str) -> u32 {
    manager
        .activate(&activation(name))
        .expect("activation accepted");
    wait_for_pid(manager, name)
}

/// Wait until the process table no longer holds `pid`, reconciling as we go.
fn wait_until_gone(manager: &ToolManager, pid: u32) {
    wait_until("the tool's process to leave the process table", || {
        manager.tick();
        !present(pid)
    })
}

/// Wait (bounded) until `pid` really *is* the named binary, and return its path.
///
/// A program written as `/bin/sh -c 'exec …'` becomes the exec'd binary a moment
/// after the spawn, so "this pid is the declared program" is a wait, not a guess.
fn wait_for_exe(pid: u32, name: &str) -> PathBuf {
    let mut exe = None;
    wait_until(&format!("process {pid} to exec {name}"), || {
        exe = running_exe(pid).filter(|path| {
            path.file_name()
                .map(|file| file.to_string_lossy().as_ref() == name)
                .unwrap_or(false)
        });
        exe.is_some()
    });
    exe.expect("the process is the declared binary")
}

/// `manifest` + `program` in one registration.
fn register(manager: &ToolManager, manifest: ToolManifest, program: ToolProgram) {
    manager.register(manifest.with_program(program));
}

// ---------------------------------------------------------------------------
// Activation really spawns; deactivation really stops
// ---------------------------------------------------------------------------

/// The headline requirement: `Active` is a live process, not a flag. The argv
/// template is proved end-to-end here too — the declared argument is
/// `{{context.seconds}}`, so the running binary is holding the *substituted*
/// value in its own command line. (A template that had not been rendered would
/// make `sleep` fail immediately, and there would be no pid at all.)
#[test]
fn activation_spawns_a_real_process_with_a_live_pid() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    register(
        &manager,
        manifest("dormant.sleep"),
        ToolProgram::new(SLEEP).with_args(["{{context.seconds}}"]),
    );
    manager.arm("dormant.sleep").unwrap();

    let mut request = activation("dormant.sleep");
    request
        .context
        .insert("seconds".to_string(), "3600".to_string());
    manager.activate(&request).unwrap();

    // The state machine reports Active immediately: the state *is* the admission
    // record, and the spawn completes on the supervisor thread.
    assert_eq!(
        manager.get_state("dormant.sleep"),
        Some(ToolState::Active),
        "an accepted activation must be Active"
    );

    let pid = wait_for_pid(&manager, "dormant.sleep");

    // A real process, running the declared binary, with the rendered argv.
    let exe = running_exe(pid).expect("a live /proc entry");
    assert_eq!(
        exe.file_name().and_then(|name| name.to_str()),
        Some("sleep"),
        "the running process must be the declared binary, got {exe:?}"
    );
    assert!(
        cmdline(pid).unwrap_or_default().contains("3600"),
        "the argv template must be rendered from the activation context: {:?}",
        cmdline(pid)
    );
    assert!(manager
        .process_report("dormant.sleep")
        .unwrap()
        .is_running());

    // Deactivation stops it — and the assertion is that the process is gone.
    manager.deactivate("dormant.sleep").unwrap();
    assert_eq!(
        manager.get_state("dormant.sleep"),
        Some(ToolState::Cooldown)
    );
    wait_until_gone(&manager, pid);
    assert!(!present(pid), "the deactivated process must be gone");
    assert_eq!(
        manager.process_report("dormant.sleep").unwrap().outcome,
        Some(StopCause::Requested)
    );

    manager.shutdown();
}

/// The manifest's `idle_timeout` stops the process — asserted against the
/// process table, not against the state — and the tool cools down exactly as a
/// deactivation would leave it.
#[test]
fn idle_timeout_stops_the_process_and_cools_the_tool_down() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.capture");
    tool.idle_timeout = Duration::from_secs(1);
    tool.cooldown_duration = Duration::from_secs(30);
    tool.max_activations_per_hour = 3;
    register(&manager, tool, sh("exec sleep 600"));
    manager.arm("dormant.capture").unwrap();

    let pid = activate_and_wait_for_pid(&manager, "dormant.capture");
    assert!(present(pid), "precondition: the process is running");

    wait_until("the idle timeout to cool the tool down", || {
        manager.tick();
        manager.get_state("dormant.capture") == Some(ToolState::Cooldown)
    });
    wait_until_gone(&manager, pid);

    assert!(
        !present(pid),
        "the idle timeout must stop the process, not just move the state"
    );
    let report = manager.process_report("dormant.capture").unwrap();
    assert_eq!(report.outcome, Some(StopCause::IdleTimeout));
    assert!(!report.is_running());
    assert!(manager.pid("dormant.capture").is_none());

    // The dormancy machine is unchanged afterwards: cooldown completes, the
    // tool re-arms, and the activation spent one unit of the hourly budget.
    assert_eq!(
        manager
            .get_budget("dormant.capture")
            .unwrap()
            .remaining_activations,
        2
    );
    manager.complete_cooldown("dormant.capture").unwrap();
    assert_eq!(
        manager.get_state("dormant.capture"),
        Some(ToolState::Dormant)
    );
    manager.arm("dormant.capture").unwrap();

    manager.shutdown();
}

/// The declared `ResourceBudget::max_runtime` is enforced too: a process that
/// outlives its budget is stopped and the tool cools down.
#[test]
fn max_runtime_budget_stops_a_long_lived_process() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.scan");
    // The idle timeout is deliberately far away: only the budget can stop this.
    tool.idle_timeout = Duration::from_secs(300);
    tool.cooldown_duration = Duration::from_secs(30);
    register(
        &manager,
        tool,
        sh("exec sleep 600").with_budget(ResourceBudget {
            memory_bytes: None,
            cpu_percent: None,
            max_runtime: Some(Duration::from_secs(1)),
        }),
    );
    manager.arm("dormant.scan").unwrap();

    let pid = activate_and_wait_for_pid(&manager, "dormant.scan");

    wait_until("the runtime budget to stop the process", || {
        manager.tick();
        manager.get_state("dormant.scan") == Some(ToolState::Cooldown)
    });
    wait_until_gone(&manager, pid);

    assert!(!present(pid), "the budget overrun must stop the process");
    assert_eq!(
        manager.process_report("dormant.scan").unwrap().outcome,
        Some(StopCause::MaxRuntime)
    );

    manager.shutdown();
}

/// A process that ends on its own is **observed**: the tool does not sit in
/// `Active` forever over a dead process, it cools down with the exit recorded.
#[test]
fn a_process_that_ends_on_its_own_is_observed_and_cools_the_tool_down() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.oneshot");
    tool.idle_timeout = Duration::from_secs(300); // only the exit can end this
    tool.cooldown_duration = Duration::from_secs(30);
    tool.max_activations_per_hour = 2;
    // Exits immediately, with a code of its own choosing.
    register(&manager, tool, sh("exit 7"));
    manager.arm("dormant.oneshot").unwrap();

    manager.activate(&activation("dormant.oneshot")).unwrap();
    assert_eq!(
        manager.get_state("dormant.oneshot"),
        Some(ToolState::Active)
    );

    let mut outcome = None;
    wait_until("the supervisor to see the process end", || {
        manager.tick();
        outcome = manager
            .process_report("dormant.oneshot")
            .and_then(|r| r.outcome);
        outcome.is_some()
    });

    assert_eq!(outcome, Some(StopCause::Exited));
    let report = manager.process_report("dormant.oneshot").unwrap();
    assert!(
        report.detail.as_deref().unwrap_or_default().contains('7'),
        "the exit must be recorded with the primitive's own words: {:?}",
        report.detail
    );

    wait_until("the ended process to leave Active", || {
        manager.tick();
        manager.get_state("dormant.oneshot") == Some(ToolState::Cooldown)
    });
    assert!(manager.pid("dormant.oneshot").is_none());
    assert_eq!(
        manager.get_state("dormant.oneshot"),
        Some(ToolState::Cooldown),
        "a tool whose process ended must not sit in Active forever"
    );

    // Ending on its own does not refund the activation.
    assert_eq!(
        manager
            .get_budget("dormant.oneshot")
            .unwrap()
            .remaining_activations,
        1
    );

    manager.shutdown();
}

/// A new activation must never be reconciled against the **previous**
/// activation's terminal report: the first activation here ends by itself, and
/// the second — long-lived — must stay `Active` with a live pid even though its
/// predecessor's exit was the last thing the supervisor observed.
///
/// The window is made provable rather than probable. Commands reach the
/// supervisor far faster than this test can call `tick`, so the test first
/// occupies the supervisor with a *slow graceful stop of another tool* (one that
/// ignores SIGTERM, so the stop really does hold the supervisor for its full
/// escalation window). Commands are handled one at a time in FIFO order, so the
/// new activation's `Spawn` cannot have been processed while that stop is still
/// running — meaning the manager's own report reset at activation is the only
/// thing standing between the new activation and its predecessor's corpse.
#[test]
fn a_new_activation_is_not_cooled_down_by_the_previous_activations_exit() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    // "reused": exits at once, or sleeps, depending on the activation context.
    // The rendered `{{context.mode}}` becomes the shell's `$0`.
    let mut reused = manifest("dormant.reused");
    reused.idle_timeout = Duration::from_secs(300);
    reused.cooldown_duration = Duration::from_secs(0);
    register(
        &manager,
        reused,
        sh("if [ \"$0\" = quick ]; then exit 0; fi; exec sleep 600").with_arg("{{context.mode}}"),
    );

    // "stubborn": ignores SIGTERM, so stopping it costs the supervisor a full
    // escalation window — the window this test runs inside.
    let mut stubborn = manifest("dormant.busy");
    stubborn.idle_timeout = Duration::from_secs(300);
    stubborn.cooldown_duration = Duration::from_secs(30);
    register(
        &manager,
        stubborn,
        sh("trap \"\" TERM; exec sleep 600").with_graceful_stop_timeout(Duration::from_secs(1)),
    );

    manager.arm("dormant.reused").unwrap();
    manager.arm("dormant.busy").unwrap();

    // 1. The first activation ends on its own and cools the tool down.
    let mut quick = activation("dormant.reused");
    quick
        .context
        .insert("mode".to_string(), "quick".to_string());
    manager.activate(&quick).unwrap();
    wait_until("the first activation to end and cool down", || {
        manager.tick();
        manager.get_state("dormant.reused") == Some(ToolState::Cooldown)
    });
    assert_eq!(
        manager.process_report("dormant.reused").unwrap().outcome,
        Some(StopCause::Exited),
        "precondition: the first activation ended by itself"
    );

    manager.complete_cooldown("dormant.reused").unwrap();
    manager.arm("dormant.reused").unwrap();

    // 2. Occupy the supervisor with a slow stop.
    let busy_pid = activate_and_wait_for_pid(&manager, "dormant.busy");
    manager.deactivate("dormant.busy").unwrap();
    assert!(
        present(busy_pid),
        "precondition: the SIGTERM-ignoring tool is still alive, so the supervisor is still inside its stop"
    );

    // 3. The second activation of "reused", queued behind that stop.
    let mut slow = activation("dormant.reused");
    slow.context.insert("mode".to_string(), "slow".to_string());
    manager.activate(&slow).unwrap();
    manager.tick();

    assert!(
        !manager
            .process_report("dormant.reused")
            .unwrap()
            .is_terminal(),
        "an accepted activation must not inherit the previous activation's outcome"
    );
    assert_eq!(
        manager.get_state("dormant.reused"),
        Some(ToolState::Active),
        "the live second activation must not be cooled down by the first one's exit"
    );

    // 4. Once the supervisor is free it really starts the second process.
    let pid = wait_for_pid(&manager, "dormant.reused");
    manager.tick();
    assert_eq!(manager.get_state("dormant.reused"), Some(ToolState::Active));
    assert!(present(pid), "the second activation's process must be real");

    manager.deactivate("dormant.reused").unwrap();
    wait_until_gone(&manager, pid);
    wait_until_gone(&manager, busy_pid);
    manager.shutdown();
}

/// A spawn that cannot happen is observed too: the tool cools down with the
/// failure as the reason instead of sitting in `Active` over nothing.
#[test]
fn a_process_that_cannot_start_cools_the_tool_down() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.missing");
    tool.idle_timeout = Duration::from_secs(300);
    tool.cooldown_duration = Duration::from_secs(30);
    register(
        &manager,
        tool,
        ToolProgram::new("/nonexistent/imperium-toolkit-test-binary"),
    );
    manager.arm("dormant.missing").unwrap();

    manager.activate(&activation("dormant.missing")).unwrap();

    wait_until("the failed spawn to be reconciled", || {
        manager.tick();
        manager.get_state("dormant.missing") == Some(ToolState::Cooldown)
    });

    let report = manager.process_report("dormant.missing").unwrap();
    assert_eq!(report.outcome, Some(StopCause::SpawnFailed));
    assert!(report.detail.is_some(), "the spawn error must be recorded");
    assert!(manager.pid("dormant.missing").is_none());

    manager.shutdown();
}

// ---------------------------------------------------------------------------
// The existing gates still refuse, and a refusal spawns nothing
// ---------------------------------------------------------------------------

/// `max_activations_per_hour` still refuses, and a refused activation reaches
/// neither the process table nor the supervisor: the tool's report is still the
/// terminal one left by the *first* activation, with no new pid.
#[test]
fn over_budget_activations_are_refused_and_spawn_nothing() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.scarce");
    tool.max_activations_per_hour = 1;
    tool.cooldown_duration = Duration::from_secs(0); // so re-arming is allowed
    register(&manager, tool, sh("exec sleep 600"));
    manager.arm("dormant.scarce").unwrap();

    let pid = activate_and_wait_for_pid(&manager, "dormant.scarce");
    manager.deactivate("dormant.scarce").unwrap();
    wait_until_gone(&manager, pid);
    manager.complete_cooldown("dormant.scarce").unwrap();
    manager.arm("dormant.scarce").unwrap();

    let refused = manager.activate(&activation("dormant.scarce"));
    assert!(
        matches!(
            refused,
            Err(imperium_net_toolkit::ToolkitError::BudgetExhausted(_))
        ),
        "the hourly budget must still refuse: {refused:?}"
    );

    // Nothing was spawned: no pid, and the supervisor's report is untouched —
    // still the terminal record of the first activation's deactivation.
    assert!(manager.pid("dormant.scarce").is_none());
    let report = manager.process_report("dormant.scarce").unwrap();
    assert_eq!(report.outcome, Some(StopCause::Requested));
    assert!(!report.is_running());
    assert_eq!(
        manager.get_state("dormant.scarce"),
        Some(ToolState::Armed),
        "a refused activation must not move the state"
    );

    manager.shutdown();
}

/// Cooldown is enforced through the state machine (a cooling tool is not
/// `Armed`), and the attempt spawns nothing.
#[test]
fn an_activation_during_cooldown_is_refused_and_spawns_nothing() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.cooling");
    tool.cooldown_duration = Duration::from_secs(60);
    register(&manager, tool, sh("exec sleep 600"));
    manager.arm("dormant.cooling").unwrap();

    let pid = activate_and_wait_for_pid(&manager, "dormant.cooling");
    manager.deactivate("dormant.cooling").unwrap();
    wait_until_gone(&manager, pid);

    let refused = manager.activate(&activation("dormant.cooling"));
    assert!(
        refused.is_err(),
        "a tool in cooldown must not be activatable: {refused:?}"
    );
    assert!(
        manager.pid("dormant.cooling").is_none(),
        "a refused activation must spawn nothing"
    );
    assert_eq!(
        manager.get_state("dormant.cooling"),
        Some(ToolState::Cooldown)
    );

    manager.shutdown();
}

// ---------------------------------------------------------------------------
// Graceful stop, escalation, and no orphans
// ---------------------------------------------------------------------------

/// The stop is the primitive's graceful one, and its escalation works: this
/// process *ignores SIGTERM* (`trap "" TERM` then `exec`, so the ignored
/// disposition survives into `sleep`), so the only way it can leave the process
/// table is the `kill()` that follows `graceful_stop_timeout`. No orphan is
/// left behind — the assertion is the process table, after the stop returned.
#[test]
fn graceful_stop_escalates_sigterm_to_sigkill_without_orphans() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    let mut tool = manifest("dormant.stubborn");
    tool.idle_timeout = Duration::from_secs(300);
    tool.cooldown_duration = Duration::from_secs(30);
    register(
        &manager,
        tool,
        sh("trap \"\" TERM; exec sleep 600").with_graceful_stop_timeout(Duration::from_millis(500)),
    );
    manager.arm("dormant.stubborn").unwrap();

    let pid = activate_and_wait_for_pid(&manager, "dormant.stubborn");
    assert!(present(pid));

    // The shell execs `sleep` itself, so the pid this tool owns ends up being
    // the declared binary — which is also what makes the stop below a stop of
    // the real process and not of a wrapper that could orphan a child.
    let exe = wait_for_exe(pid, "sleep");
    assert_eq!(
        exe.file_name().and_then(|name| name.to_str()),
        Some("sleep"),
        "the exec'd process is the declared one"
    );

    // The deactivation window is the declared 500 ms plus the supervisor's
    // SIGTERM → kill() escalation; give it room and then prove the outcome.
    manager.deactivate("dormant.stubborn").unwrap();
    wait_until_gone(&manager, pid);

    assert!(
        !present(pid),
        "a SIGTERM-ignoring tool must still be gone after the escalation"
    );
    assert_eq!(
        manager.process_report("dormant.stubborn").unwrap().outcome,
        Some(StopCause::Requested)
    );

    manager.shutdown();
}

/// Shutting the manager down stops every live tool and leaves no orphans — the
/// pids are gone the moment `shutdown()` returns, because it joins the
/// supervisor thread only after each process has been stopped and reaped.
#[test]
fn shutdown_stops_every_live_tool_and_leaves_no_orphans() {
    let bus = Arc::new(spiderweb::Bus::open().publisher());
    let manager = ToolManager::new(bus);

    for name in ["dormant.one", "dormant.two"] {
        register(&manager, manifest(name), sh("exec sleep 600"));
        manager.arm(name).unwrap();
    }

    let first = activate_and_wait_for_pid(&manager, "dormant.one");
    let second = activate_and_wait_for_pid(&manager, "dormant.two");
    assert_ne!(first, second, "two tools are two processes");

    manager.shutdown();

    // No waiting: shutdown() returns only once every stop has completed.
    assert!(
        !present(first) && !present(second),
        "shutdown must leave no orphan processes (first={first}, second={second})"
    );
    for name in ["dormant.one", "dormant.two"] {
        assert_eq!(
            manager.process_report(name).unwrap().outcome,
            Some(StopCause::Requested)
        );
    }

    // Dropping the manager afterwards must not panic or re-join anything.
    drop(manager);
    assert!(!present(first) && !present(second));
}

// ---------------------------------------------------------------------------
// The production path: a real bus, a real strand, real processes
// ---------------------------------------------------------------------------

/// End-to-end through the supervised strand: a request on `net.toolkit.request`
/// activates a real process, that process exits on its own, and the **strand's
/// tick** — not a manual call — reconciles the tool to `Cooldown`, publishing
/// the `net.toolkit.state` change with the exit in its reason.
#[tokio::test]
async fn the_strand_reconciles_an_ended_process_and_publishes_the_state_change() {
    // ONE kernel: the strand is queued on it and the request is published on it.
    // (Two `Bus::open()` calls would be two unrelated kernels, and the request
    // would never reach the strand.)
    let mut kernel = Bus::open();
    let bus = Arc::new(kernel.publisher());
    let manager = Arc::new(ToolManager::new(Arc::clone(&bus)));

    let mut tool = manifest("dormant.stranded");
    tool.idle_timeout = Duration::from_secs(300);
    tool.cooldown_duration = Duration::from_secs(30);
    // Exits immediately: only the strand's reconciliation can move the state on.
    register(&manager, tool, sh("exit 7"));
    manager.arm("dormant.stranded").unwrap();

    let mut states = subscribe_queue(&bus, "net.toolkit.state", 64);
    // The activation lane is queued on the kernel; the run loop installs it and
    // the strand's tick is what reconciles the ended process.
    imperium_net_toolkit::register_strands(&mut kernel, &bus, &manager);
    let mut supervision = Supervision::engage_with(kernel, Arc::clone(&bus));

    BusEvent::publish(
        &bus,
        "net.toolkit.request",
        Message::ToolActivationReq(activation("dormant.stranded")),
    )
    .unwrap();

    let mut changes: Vec<ToolStateChange> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !changes
        .iter()
        .any(|change| change.to == ToolState::Cooldown)
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            remaining > Duration::ZERO,
            "timed out waiting for the state changes to settle; saw {changes:?}"
        );
        let event = tokio::time::timeout(remaining, states.recv())
            .await
            .expect("a state change arrives")
            .expect("the subscription is alive");
        if let Message::ToolStateChange(change) = event.message {
            assert_eq!(change.tool_name, "dormant.stranded");
            changes.push(change);
        }
    }

    assert_eq!(
        changes.first().map(|change| change.to.clone()),
        Some(ToolState::Active)
    );
    let cooled = changes.last().unwrap();
    assert_eq!(cooled.from, ToolState::Active);
    assert_eq!(cooled.to, ToolState::Cooldown);
    assert!(
        cooled.reason.contains("ended on its own") && cooled.reason.contains('7'),
        "the published reason must carry the observed exit: {}",
        cooled.reason
    );

    assert_eq!(
        manager.get_state("dormant.stranded"),
        Some(ToolState::Cooldown),
        "the strand's own tick must reconcile the table"
    );
    assert!(manager.pid("dormant.stranded").is_none());

    // The strand never touched a process: the supervisor owns them, and the
    // manager stops them on the way out.
    supervision.shutdown();
    manager.shutdown();
}

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind.
struct Supervision {
    publisher: Arc<BusPublisher>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(spiderweb::StrandSpec::new("spider", || {
            Box::new(spider::Spider::new())
        }));

        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            join: Some(join),
        }
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
) -> tokio::sync::mpsc::Receiver<imperium_protocol::BusEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    publisher.subscribe_prefix(
        prefix,
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<imperium_protocol::BusEvent>() {
                let _ = tx.try_send(*event);
            }
        }),
    );
    rx
}
