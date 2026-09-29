//! The process supervisor: the helper thread that owns every activated tool's
//! [`ManagedProcess`](imperium_managed_process::ManagedProcess), so that
//! [`ToolState::Active`](imperium_protocol::ToolState::Active) means a real,
//! running process rather than a flag.
//!
//! # The mismatch, and the decision
//!
//! `ManagedProcess` is built on `tokio::process`; its start, health check,
//! graceful stop and restart are `async` and it spawns its stdout/stderr drain
//! tasks with `tokio::spawn`. A Spiderweb strand's
//! [`run`](spiderweb::Strand::run) is **synchronous** and is called
//! on a plain `std::thread` (`strand-<name>`) every ~10 ms — there is no
//! `await` to spend, and the kernel's shutdown join deadline is 5 s
//! (the pilot (`imperium-net-lightcone`)).
//!
//! Three ways out were available, and this module takes the third:
//!
//! 1. **A `std::process::Command` path for strand-driven tools.** Rejected: it
//!    would have to re-implement SIGTERM → SIGKILL escalation, child reaping,
//!    `kill_on_drop` and the stdout/stderr drains that
//!    [`ManagedProcess::stop`](imperium_managed_process::ManagedProcess::stop)
//!    already provides — exactly the duplication the managed-process primitive
//!    exists to prevent.
//! 2. **`Handle::block_on` on the strand thread.** Rejected on three counts.
//!    `ManagedProcess::stop` awaits the child for up to
//!    `graceful_stop_timeout` (escalating to `kill()`), so a strand-driven
//!    deactivation would block a tick for the whole escalation window — and the
//!    tick budget is 10 ms, with a 5 s join deadline at shutdown. It also
//!    requires an ambient runtime `Handle`, which would make every
//!    `ToolManager::new` caller (including synchronous unit tests, and any
//!    caller that is not on a runtime) responsible for one, and it panics
//!    outright when called from inside a runtime — a trap this crate's callers
//!    cannot be trusted to avoid.
//! 3. **A dedicated supervisor thread** (taken). One `std::thread` with its own
//!    single-threaded tokio runtime owns every `ManagedProcess`; the strand
//!    hands it work over an unbounded `tokio::sync::mpsc` channel and reads
//!    observations back from a shared, lock-guarded report map. Both directions
//!    are O(1) and non-blocking: `activate`/`deactivate` *send a command* and
//!    return, and the strand's reconciliation (`ToolManager::tick`) *clones a
//!    snapshot*. Every `await` — spawn, health check, graceful stop, the
//!    escalation deadline — happens on the supervisor thread, never on a tick.
//!
//! The trade-off is explicit and accepted: activation becomes *eventually
//! consistent*. `activate` returns with the tool `Active` and its process still
//! `Starting`; the pid appears a few milliseconds later, readable through
//! [`ToolManager::pid`](crate::ToolManager::pid). Nothing in the dormancy state
//! machine depends on the spawn having already completed — the state itself is
//! the admission record — so this costs no policy, only immediacy, and it buys a
//! strand whose `run` never blocks on a subprocess.
//!
//! The supervisor is owned by the [`ToolManager`](crate::ToolManager), **not**
//! by the strand: a crashed and restarted strand generation drives the same
//! supervisor, so tool processes survive strand restarts (and are stopped when
//! the manager is dropped, so the node leaves no orphans).
//!
//! # Division of labour
//!
//! The supervisor holds **mechanism** only: spawn, watch, stop, and report what
//! it observed. All **policy** stays in the manager — the `Armed`/`Active`/
//! `Cooldown` gates, the hourly budget, the cooldown clock, and the idle
//! deadline, which the manager computes from the manifest and hands over at
//! spawn time. The supervisor never writes tool state; the manager reads the
//! reports in [`ToolManager::tick`](crate::ToolManager::tick) and reconciles.
//! One writer, one direction of authority — the reports are observations.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use imperium_managed_process::{ManagedProcess, ProcessState};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

use crate::ToolProgram;

/// How often the supervisor thread sweeps the tools it supervises: it enforces
/// idle and runtime deadlines and asks each live process whether it is still
/// running. 50 ms bounds how long a tool can sit in `Active` after its process
/// ended, and costs one timer wake-up per tick on the supervisor thread only
/// (the strand is not involved).
pub const SUPERVISOR_TICK: Duration = Duration::from_millis(50);

/// The supervisor thread's name, so `ps`/debuggers attribute it.
const THREAD_NAME: &str = "toolkit-proc-supervisor";

/// Why an activation's process is no longer running.
///
/// Recorded once per activation, by the sweep or the stop path that ended it;
/// [`ToolManager::tick`](crate::ToolManager::tick) turns it into the reason text
/// of the `net.toolkit.state` change that cools the tool down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// No activity within the manifest's `idle_timeout`.
    IdleTimeout,
    /// The manifest's declared `ResourceBudget::max_runtime` elapsed.
    MaxRuntime,
    /// An operator deactivated the tool, or the manager shut down.
    Requested,
    /// The process ended on its own (exited, crashed, or was killed by
    /// something else).
    Exited,
    /// The process could not be spawned at all.
    SpawnFailed,
}

impl StopCause {
    /// The `reason` of the state change the manager publishes for this outcome.
    /// The human-readable detail the supervisor recorded is appended when there
    /// is one, so the bus carries the primitive's own words ("exited with code
    /// 3") rather than a paraphrase.
    pub fn reason(self, detail: Option<&str>) -> String {
        let head = match self {
            StopCause::IdleTimeout => "idle timeout elapsed; process stopped",
            StopCause::MaxRuntime => {
                "declared ResourceBudget::max_runtime elapsed; process stopped"
            }
            StopCause::Requested => "deactivated; process stopped",
            StopCause::Exited => "process ended on its own",
            StopCause::SpawnFailed => "process failed to start",
        };
        match detail {
            Some(detail) if !detail.is_empty() => format!("{head}: {detail}"),
            _ => head.to_string(),
        }
    }
}

/// Where an activation's process is, as the supervisor last observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessPhase {
    /// The spawn is in flight on the supervisor thread.
    Starting,
    /// Spawned and not yet observed to have ended.
    Running,
    /// No process: it ended, was stopped, or never started.
    Stopped,
}

/// What the supervisor observed about one tool's activation.
///
/// A report exists only once the supervisor has been told to spawn that tool —
/// a refused activation (state, cooldown or budget gate) produces no report at
/// all, which is how "a refused activation spawns nothing" is observable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolProcessReport {
    /// Where the process is now.
    pub phase: ProcessPhase,
    /// The live pid while there is a child, `None` once it is stopped.
    pub pid: Option<u32>,
    /// When the supervisor started the process.
    pub started_at: Option<DateTime<Utc>>,
    /// Set exactly once, when this activation's process is no longer running.
    pub outcome: Option<StopCause>,
    /// The primitive's own words about the end (e.g. `exited with code 3`).
    pub detail: Option<String>,
}

impl ToolProcessReport {
    fn starting() -> Self {
        Self {
            phase: ProcessPhase::Starting,
            pid: None,
            started_at: None,
            outcome: None,
            detail: None,
        }
    }

    fn running(pid: Option<u32>) -> Self {
        Self {
            phase: ProcessPhase::Running,
            pid,
            started_at: Some(Utc::now()),
            outcome: None,
            detail: None,
        }
    }

    fn stopped(outcome: StopCause, detail: Option<String>) -> Self {
        Self {
            phase: ProcessPhase::Stopped,
            pid: None,
            started_at: None,
            outcome: Some(outcome),
            detail,
        }
    }

    /// Whether the supervisor last saw a live child.
    pub fn is_running(&self) -> bool {
        self.phase == ProcessPhase::Running
    }

    /// Whether this activation is over (the process is gone, for good).
    pub fn is_terminal(&self) -> bool {
        self.outcome.is_some()
    }
}

/// A tool whose process the supervisor is responsible for.
struct Live {
    process: ManagedProcess,
    /// When the manifest's `idle_timeout` runs out. Chosen by the manager from
    /// the manifest at activation and enforced here.
    idle_deadline: Instant,
}

/// Work handed to the supervisor thread. Sent over an unbounded channel, so
/// sending is not an `await` and cannot block a strand tick.
enum Command {
    Spawn {
        name: String,
        program: ToolProgram,
        idle_timeout: Duration,
    },
    Stop {
        name: String,
        cause: StopCause,
        detail: String,
    },
    Shutdown,
}

/// Reports shared with the manager: the supervisor writes, the manager reads.
type Reports = Arc<RwLock<HashMap<String, ToolProcessReport>>>;

/// Handle to the supervisor thread.
///
/// Cheap to use from synchronous code: [`ProcessSupervisor::spawn_tool`] and
/// [`ProcessSupervisor::stop_tool`] are non-blocking sends, and
/// [`ProcessSupervisor::report`] / [`ProcessSupervisor::snapshot`] are bounded
/// reads of the report map. Only [`ProcessSupervisor::shutdown`] blocks, and
/// only for as long as the declared graceful-stop escalation of each live tool
/// takes.
pub struct ProcessSupervisor {
    commands: mpsc::UnboundedSender<Command>,
    reports: Reports,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ProcessSupervisor {
    /// Start the supervisor thread (and, with it, the private tokio runtime it
    /// awaits on). Called lazily by the manager the first time a tool declares a
    /// program, so a manager whose tools declare none costs no thread.
    pub fn start() -> Self {
        let (commands, receiver) = mpsc::unbounded_channel::<Command>();
        let reports: Reports = Arc::new(RwLock::new(HashMap::new()));

        let spawned = {
            let reports = Arc::clone(&reports);
            std::thread::Builder::new()
                .name(THREAD_NAME.to_string())
                .spawn(move || run(receiver, reports))
        };
        let thread = match spawned {
            Ok(handle) => Some(handle),
            Err(error) => {
                // Degraded, not fatal: the receiver is dropped with the failed
                // spawn, so every later command send fails and the manager logs
                // it. The node keeps running with tools that cannot activate.
                tracing::error!(
                    %error,
                    "could not spawn the toolkit process supervisor thread; tool activations will not start processes"
                );
                None
            }
        };

        Self {
            commands,
            reports,
            thread: Mutex::new(thread),
        }
    }

    /// Ask the supervisor to start `name`'s process under the manifest's idle
    /// deadline. Returns whether the command reached the supervisor thread (a
    /// `false` means the supervisor is gone — the tool is left `Active` with no
    /// process, exactly the pre-existing behaviour, and the caller logs it).
    ///
    /// The report is reset to [`ProcessPhase::Starting`] **before** the command
    /// is queued, on the caller's thread. That ordering is load-bearing: the
    /// previous activation's terminal report (an exit, a stop) must never be
    /// read as if it belonged to *this* activation — a manager ticking right
    /// after an accepted activation would otherwise cool the tool straight back
    /// down over its predecessor's corpse. Every write the supervisor makes
    /// happens after this one, because it happens after the send, so the
    /// supervisor's observations always win.
    pub fn spawn_tool(&self, name: &str, program: ToolProgram, idle_timeout: Duration) -> bool {
        publish(&self.reports, name, ToolProcessReport::starting());
        self.commands
            .send(Command::Spawn {
                name: name.to_string(),
                program,
                idle_timeout,
            })
            .is_ok()
    }

    /// Ask the supervisor to stop `name`'s process gracefully (the primitive's
    /// SIGTERM → `kill()` escalation, bounded by the program's declared
    /// `graceful_stop_timeout`). Non-blocking: the stop happens on the
    /// supervisor thread.
    pub fn stop_tool(&self, name: &str, cause: StopCause, detail: impl Into<String>) -> bool {
        self.commands
            .send(Command::Stop {
                name: name.to_string(),
                cause,
                detail: detail.into(),
            })
            .is_ok()
    }

    /// The last observation for one tool, if the supervisor was ever asked to
    /// spawn it.
    pub fn report(&self, name: &str) -> Option<ToolProcessReport> {
        self.reports.read().get(name).cloned()
    }

    /// A consistent copy of every observation, for one reconciliation pass.
    ///
    /// Cloned out under the lock and released immediately: the supervisor never
    /// holds this lock across an `await`, and the manager never holds the tool
    /// table while taking it, so neither side can wedge the other.
    pub fn snapshot(&self) -> HashMap<String, ToolProcessReport> {
        self.reports.read().clone()
    }

    /// Stop every supervised process and join the supervisor thread.
    ///
    /// Idempotent, and bounded: the thread stops each live process through
    /// [`ManagedProcess::stop`](imperium_managed_process::ManagedProcess::stop),
    /// which waits at most that program's declared `graceful_stop_timeout`
    /// before escalating to `kill()`. Blocking by design — it is the "no
    /// orphans" guarantee — and it is only reached when the manager is
    /// explicitly shut down or dropped.
    pub fn shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown);
        let handle = self.thread.lock().take();
        if let Some(handle) = handle {
            if handle.join().is_err() {
                tracing::error!("the toolkit process supervisor thread panicked");
            }
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        // The safety net: dropping the manager must not leave a tool process
        // behind. `shutdown` is idempotent, so an explicit shutdown first is a
        // no-op here.
        self.shutdown();
    }
}

/// The supervisor thread body: one private runtime, one command loop.
fn run(mut receiver: mpsc::UnboundedReceiver<Command>, reports: Reports) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "toolkit process supervisor could not build its runtime");
            return;
        }
    };

    // `block_on` here is the *supervisor's* await point, not the strand's: this
    // thread exists precisely so that no strand tick ever has to block on a
    // subprocess. `ManagedProcess::start`'s `tokio::spawn` for the stdout/stderr
    // drains lands on this runtime, as it must.
    runtime.block_on(async move {
        let mut live: HashMap<String, Live> = HashMap::new();
        let mut ticker = tokio::time::interval(SUPERVISOR_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                command = receiver.recv() => match command {
                    Some(Command::Spawn { name, program, idle_timeout }) => {
                        spawn_tool(&name, &program, idle_timeout, &mut live, &reports).await;
                    }
                    Some(Command::Stop { name, cause, detail }) => {
                        stop_tool(&name, cause, &detail, &mut live, &reports).await;
                    }
                    Some(Command::Shutdown) | None => {
                        for name in live.keys().cloned().collect::<Vec<String>>() {
                            stop_tool(
                                &name,
                                StopCause::Requested,
                                "node shutdown",
                                &mut live,
                                &reports,
                            )
                            .await;
                        }
                        break;
                    }
                },
                _ = ticker.tick() => sweep(&mut live, &reports).await,
            }
        }
    });
}

/// Spawn one tool's process and record what happened.
///
/// A single task owns the map: commands are handled one at a time in the order
/// they were sent, so a `Stop` for a tool always runs after the `Spawn` that
/// preceded it, and a tool never has two processes (the state machine admits
/// only one activation at a time, and `live` is keyed by tool name).
async fn spawn_tool(
    name: &str,
    program: &ToolProgram,
    idle_timeout: Duration,
    live: &mut HashMap<String, Live>,
    reports: &Reports,
) {
    // The caller already reset the report to `Starting` before queuing this
    // command; re-stating it here keeps the invariant local to the spawn path
    // (see `ProcessSupervisor::spawn_tool`).
    publish(reports, name, ToolProcessReport::starting());

    let mut process = ManagedProcess::new(program.process_config());
    let started = match program.working_dir.as_deref() {
        Some(working_dir) => process.start_in(working_dir).await,
        None => process.start().await,
    };

    match started {
        Ok(()) => {
            tracing::info!(
                tool = %name,
                binary = %program.binary.display(),
                pid = ?process.pid(),
                "tool process started"
            );
            publish(reports, name, ToolProcessReport::running(process.pid()));
            live.insert(
                name.to_string(),
                Live {
                    process,
                    idle_deadline: Instant::now() + idle_timeout,
                },
            );
        }
        Err(error) => {
            tracing::error!(
                tool = %name,
                binary = %program.binary.display(),
                %error,
                "tool process failed to start"
            );
            // No child exists, so there is nothing to supervise: the terminal
            // report is the whole record of this activation, and the manager's
            // next tick cools the tool down with the failure as the reason.
            publish(
                reports,
                name,
                ToolProcessReport::stopped(StopCause::SpawnFailed, Some(error.to_string())),
            );
        }
    }
}

/// Stop one live tool through the primitive's own graceful path.
///
/// A `Stop` for a tool with no live entry is a no-op: it must not overwrite the
/// terminal report that already recorded why that activation ended (a spawn
/// failure, or an end the sweep saw first).
async fn stop_tool(
    name: &str,
    cause: StopCause,
    detail: &str,
    live: &mut HashMap<String, Live>,
    reports: &Reports,
) {
    let Some(mut entry) = live.remove(name) else {
        return;
    };

    let pid = entry.process.pid();
    tracing::info!(tool = %name, cause = ?cause, pid = ?pid, "stopping tool process");

    let recorded = match entry.process.stop().await {
        // `stop` is the primitive's: SIGTERM, then `kill()` after the declared
        // graceful_stop_timeout, then the child is reaped — which is why the pid
        // is gone (not a zombie) when this returns.
        Ok(()) => detail.to_string(),
        Err(error) => format!("{detail} (stop reported {error})"),
    };
    publish(
        reports,
        name,
        ToolProcessReport::stopped(cause, Some(recorded)),
    );
}

/// One supervision pass: enforce the declared deadlines, then ask the primitive
/// whether each live process is still there.
///
/// Nothing here assumes a process is alive because a state says `Active`: the
/// deadline is compared against a monotonic clock, the runtime budget is asked
/// of the process itself (`runtime_exceeded`), and liveness is
/// `is_running()` + `check_health()`, which observes the child.
async fn sweep(live: &mut HashMap<String, Live>, reports: &Reports) {
    // Names first: the body mutates the map (a stop or an end removes an entry).
    for name in live.keys().cloned().collect::<Vec<String>>() {
        let idle_expired = live
            .get(&name)
            .map(|entry| Instant::now() >= entry.idle_deadline)
            .unwrap_or(false);
        if idle_expired {
            stop_tool(
                &name,
                StopCause::IdleTimeout,
                "no activation activity within the manifest's idle_timeout",
                live,
                reports,
            )
            .await;
            continue;
        }

        let over_budget = live
            .get(&name)
            .map(|entry| entry.process.runtime_exceeded())
            .unwrap_or(false);
        if over_budget {
            stop_tool(
                &name,
                StopCause::MaxRuntime,
                "the manifest's ResourceBudget::max_runtime elapsed",
                live,
                reports,
            )
            .await;
            continue;
        }

        let ended = match live.get_mut(&name) {
            // `is_running` is the cheap guard (state `Running` and a child in
            // hand); `check_health` is what actually observes the child with
            // `try_wait`, and clears it when the process is gone.
            Some(entry) if entry.process.is_running() => !entry.process.check_health().await,
            _ => false,
        };
        if ended {
            let detail = live.get(&name).map(|entry| match entry.process.state() {
                ProcessState::Failed { reason } => reason,
                other => format!("{other:?}"),
            });
            live.remove(&name);
            tracing::warn!(
                tool = %name,
                detail = ?detail,
                "tool process ended on its own; cooling the tool down"
            );
            publish(
                reports,
                &name,
                ToolProcessReport::stopped(StopCause::Exited, detail),
            );
        }
    }
}

/// Record an observation. Called between awaits, never with a lock held across
/// one, so a strand's `snapshot` can never wait on a subprocess.
fn publish(reports: &Reports, name: &str, report: ToolProcessReport) {
    reports.write().insert(name.to_string(), report);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_cause_reasons_carry_the_recorded_detail() {
        assert_eq!(
            StopCause::Requested.reason(None),
            "deactivated; process stopped"
        );
        assert_eq!(
            StopCause::Exited.reason(Some("exited with code 3")),
            "process ended on its own: exited with code 3",
        );
        assert_eq!(
            StopCause::SpawnFailed.reason(Some("No such file".to_string()).as_deref()),
            "process failed to start: No such file"
        );
        // An empty detail must not produce a dangling colon.
        assert_eq!(
            StopCause::IdleTimeout.reason(Some("")),
            "idle timeout elapsed; process stopped"
        );
    }

    #[test]
    fn a_store_without_a_thread_reports_nothing_and_does_not_panic() {
        // The handle's contract with a manager that was shut down: commands are
        // dropped (`false`), reads see an empty map.
        let supervisor = ProcessSupervisor::start();
        assert!(supervisor.snapshot().is_empty());
        assert!(supervisor.report("nothing").is_none());
        assert!(supervisor.spawn_tool(
            "nothing",
            ToolProgram::new("/bin/sh").with_args(["-c", "exit 0"]),
            Duration::from_secs(1),
        ));
        supervisor.shutdown();
        // Idempotent, as `Drop` relies on.
        supervisor.shutdown();
    }
}
