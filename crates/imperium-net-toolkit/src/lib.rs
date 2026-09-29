//! The dormant toolkit: tools that cost nothing until a trigger fires, run
//! under a declared budget, and go back to sleep.
//!
//! A tool is declared as a [`ToolManifest`] — when it may run, how often, and
//! for how long — plus an optional [`ToolProgram`]: what to run (binary, argv
//! template, environment, working directory, resource budget). [`ToolManager`]
//! owns the dormancy state machine (`Dormant → Armed → Active → Cooldown →
//! Dormant`, with the per-hour activation budget and the cooldown clock), and
//! the supervised strand in [`strand`] drives it from `net.toolkit.request`.
//!
//! # `Active` means a real process
//!
//! A tool that declares a [`ToolProgram`] really runs one:
//!
//! * [`ToolManager::activate`] passes every gate it passed before (state,
//!   cooldown, `max_activations_per_hour`) and then **spawns the declared
//!   binary** through [`imperium_managed_process::ManagedProcess`].
//! * The manifest's `idle_timeout` **stops** it — the tool cools down exactly
//!   as an operator deactivation would leave it, and the stop is the
//!   primitive's graceful one (SIGTERM, then `kill()` after the declared
//!   `graceful_stop_timeout`).
//! * A process that ends on its own, or one whose declared
//!   `ResourceBudget::max_runtime` runs out, is observed and the tool is moved
//!   out of `Active` — it can never sit there forever over a dead process.
//! * Every transition still publishes [`ToolStateChange`] on
//!   `net.toolkit.state`, and an accepted activation still publishes the
//!   request on `net.toolkit.activation`.
//!
//! A tool that declares **no** program keeps the original behaviour: activation
//! is a state transition only. That is deliberate — a manifest with no
//! declaration of what to run has nothing to spawn, and the toolkit stays
//! usable as a pure state machine for callers that drive their own work.
//!
//! # The sync-strand / tokio-process seam
//!
//! `ManagedProcess` is `tokio`-based and awaits; a strand's
//! [`run`](spiderweb::Strand::run) is synchronous and is called on a
//! plain 10 ms tick. The seam is closed by a **dedicated supervisor thread**
//! with its own single-threaded tokio runtime, which owns every process: the
//! strand's calls only *send a command* (an unbounded channel send) or *read a
//! snapshot* (a lock-guarded clone), so no tick ever blocks on a subprocess, and
//! every await — spawn, health check, graceful stop — happens off the tick.
//! The trade-off is that activation is eventually consistent: `activate`
//! returns with the tool `Active` and the process still starting, and the pid
//! appears a few milliseconds later in [`ToolManager::pid`]. The alternatives
//! (`Handle::block_on` on the tick, or a second `std::process` lifecycle) and
//! why each was rejected are argued in the supervisor module's docs
//! (`src/proc.rs`).
//!
//! The supervisor lives on the [`ToolManager`], **not** on the strand, so a
//! restarted strand generation drives the same processes, and dropping the
//! manager stops them (no orphans).

mod proc;
mod strand;

#[cfg(test)]
mod test_supervision;

pub use proc::{ProcessPhase, StopCause, ToolProcessReport, SUPERVISOR_TICK};
pub use strand::{
    topics, FaultPolicy, SeenIds, ToolkitStrand, CRASH_AFTER_REQUESTS_ENV, NAME, SEEN_CAPACITY,
};
// The crate-level registration entry point for the composition root, plus the
// idempotent queue it and the legacy shim both go through.
pub use strand::{queue_strand, register_strands};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use imperium_managed_process::{ProcessConfig, ResourceBudget, RestartPolicy};
use imperium_protocol::BusEvent;
use imperium_protocol::{Message, ToolActivationRequest, ToolBudget, ToolState, ToolStateChange};
use parking_lot::RwLock;
use proc::ProcessSupervisor;
use spiderweb::{Bus, BusPublisher};
use thiserror::Error;

/// Announce readiness. Publishes only; the supervised activation loop is queued
/// separately by [`register_strands`].
pub async fn init(publisher: &BusPublisher) -> Result<(), spiderweb::BusError> {
    BusEvent::publish(
        publisher,
        "net.toolkit.ready",
        Message::SubsystemReady {
            name: "imperium-net-toolkit".to_string(),
        },
    )?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum ToolkitError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("tool not in required state: expected {expected:?}, got {actual:?}")]
    InvalidState {
        expected: ToolState,
        actual: ToolState,
    },
    #[error("activation budget exhausted for: {0}")]
    BudgetExhausted(String),
    #[error("tool in cooldown until {0}")]
    InCooldown(DateTime<Utc>),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

#[derive(Clone, Debug)]
pub struct TriggerCondition {
    pub event_topic: String,
    pub min_confidence: f64,
}

#[derive(Clone, Debug)]
pub struct ToolManifest {
    pub name: String,
    pub description: String,
    pub trigger_conditions: Vec<TriggerCondition>,
    pub idle_timeout: Duration,
    pub cooldown_duration: Duration,
    pub max_activations_per_hour: u32,
}

/// How long a tool process gets to exit on SIGTERM before `kill()` — the
/// primitive's escalation, declared per tool, defaulting to five seconds.
pub const DEFAULT_GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the process is asked about its health, passed through to the
/// managed-process configuration. Defaults to five seconds.
pub const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

impl ToolManifest {
    /// Attach the declaration of **what to run** to this manifest.
    ///
    /// The program is not a `ToolManifest` field because a new field would be a
    /// compile break for the exhaustive `ToolManifest` literals outside this
    /// crate (`imperium-cli`'s composition root and `imperium-runtime`'s
    /// simulation test both construct one field by field). Attaching it here
    /// keeps the two halves of a tool's declaration — *when* it may run and
    /// *what* it runs — in one registration call:
    ///
    /// ```ignore
    /// manager.register(ToolManifest { /* … */ }.with_program(ToolProgram::new("/usr/sbin/suricata")));
    /// ```
    pub fn with_program(self, program: ToolProgram) -> ToolDeclaration {
        ToolDeclaration {
            manifest: self,
            program: Some(program),
        }
    }
}

/// What a tool runs when it is activated: the declarative half of the Phase 7
/// tool declaration ("each tool declares binary, args template, trigger
/// conditions"), kept tool-generic and free of any tool-specific knowledge.
///
/// The `args` are an **argv template**: the placeholders are filled in from the
/// activation request when the tool is activated, so one declaration serves
/// every trigger.
///
/// # Template placeholders
///
/// * `{{tool}}` — the activated tool's name (`ToolActivationRequest::tool_name`)
/// * `{{trigger}}` — the trigger string that fired
/// * `{{context.KEY}}` — one entry of `ToolActivationRequest::context`
///
/// Anything else, including an unknown `{{context.…}}` key, is left in the
/// argument verbatim rather than silently dropped, so a mis-declared template
/// is visible in the process's argv instead of hidden (the same rule
/// `ProtocolController::render_config` uses for its config template).
#[derive(Clone, Debug)]
pub struct ToolProgram {
    /// The program to run. Absolute by convention: the supervisor spawns it
    /// directly, with no shell and no `PATH` search of its own.
    pub binary: PathBuf,
    /// The argv **template**, rendered from the activation request at
    /// activation time. It is passed to the binary verbatim — no shell is
    /// inserted — so a tool that needs shell semantics declares
    /// `/bin/sh -c <script>` as its program.
    pub args: Vec<String>,
    /// Working directory for the process, if it needs one. `ProcessConfig` has
    /// no such field (adding one would break its existing literals), so it is
    /// carried here and passed to `ManagedProcess::start_in`.
    pub working_dir: Option<PathBuf>,
    /// Extra environment variables for the process.
    pub env: HashMap<String, String>,
    /// The declared resource budget. `max_runtime` is enforced: a process that
    /// outlives it is stopped. (`memory_bytes`/`cpu_percent` are carried into
    /// the managed-process configuration unchanged.)
    pub budget: ResourceBudget,
    /// SIGTERM → `kill()` escalation window for a graceful stop.
    pub graceful_stop_timeout: Duration,
    /// Passed through to the managed-process configuration.
    pub health_check_interval: Duration,
}

impl ToolProgram {
    /// A program with no arguments, no environment, no working directory and no
    /// budget — add what the tool needs with the `with_*` methods.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            args: Vec::new(),
            working_dir: None,
            env: HashMap::new(),
            budget: ResourceBudget::default(),
            graceful_stop_timeout: DEFAULT_GRACEFUL_STOP_TIMEOUT,
            health_check_interval: DEFAULT_HEALTH_CHECK_INTERVAL,
        }
    }

    /// Replace the argv template.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Append one argv template element.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add one environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set the process's working directory.
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Declare the resource budget (in particular `max_runtime`).
    pub fn with_budget(mut self, budget: ResourceBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Set the SIGTERM → `kill()` escalation window.
    pub fn with_graceful_stop_timeout(mut self, timeout: Duration) -> Self {
        self.graceful_stop_timeout = timeout;
        self
    }

    /// Set the health-check interval passed through to the process config.
    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    /// The argv for one activation: the declared template with
    /// `{{tool}}`/`{{trigger}}`/`{{context.KEY}}` filled in from `request`.
    pub fn render_argv(&self, request: &ToolActivationRequest) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| {
                let rendered = arg
                    .replace("{{tool}}", &request.tool_name)
                    .replace("{{trigger}}", &request.trigger);
                request
                    .context
                    .iter()
                    .fold(rendered, |rendered, (key, value)| {
                        rendered.replace(&format!("{{{{context.{key}}}}}"), value)
                    })
            })
            .collect()
    }

    /// This program with its template resolved against `request` — what the
    /// process supervisor is handed (it has no activation request to render
    /// against, and must not have to guess one).
    fn resolved_for(&self, request: &ToolActivationRequest) -> Self {
        let mut resolved = self.clone();
        resolved.args = self.render_argv(request);
        resolved
    }

    /// The managed-process configuration this program describes.
    ///
    /// `restart_policy` is pinned to `Never`, deliberately: re-activation is the
    /// dormancy state machine's business, and it is the state machine that
    /// spends the per-hour activation budget and starts the cooldown clock. An
    /// automatic respawn inside one activation would run the tool without the
    /// budget ever seeing it, so the toolkit does not declare one. If a tool
    /// genuinely needs in-activation restarts, that is a policy decision for the
    /// manifest and its author, not a default smuggled in here;
    /// `ManagedProcess::restart` already provides the mechanism.
    fn process_config(&self) -> ProcessConfig {
        ProcessConfig {
            binary: self.binary.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
            health_check_interval: self.health_check_interval,
            restart_policy: RestartPolicy::Never,
            budget: self.budget.clone(),
            graceful_stop_timeout: self.graceful_stop_timeout,
        }
    }
}

/// A tool's full declaration: the dormancy/policy [`ToolManifest`] plus, when
/// the tool runs a process, its [`ToolProgram`].
///
/// [`ToolManager::register`] accepts either a bare [`ToolManifest`] (a
/// state-only tool) or a manifest with a program attached
/// ([`ToolManifest::with_program`]), so a registration always says, in one
/// call, both when the tool may run and what it runs.
#[derive(Clone, Debug)]
pub struct ToolDeclaration {
    pub manifest: ToolManifest,
    pub program: Option<ToolProgram>,
}

impl From<ToolManifest> for ToolDeclaration {
    fn from(manifest: ToolManifest) -> Self {
        Self {
            manifest,
            program: None,
        }
    }
}

struct ManagedTool {
    manifest: ToolManifest,
    /// What this tool runs. `None` is a state-only tool: activation moves the
    /// state machine and spawns nothing (the toolkit's historical behaviour).
    program: Option<ToolProgram>,
    state: ToolState,
    activation_count: u32,
    hour_window_start: DateTime<Utc>,
    last_activity: Option<DateTime<Utc>>,
    cooldown_until: Option<DateTime<Utc>>,
}

impl ManagedTool {
    fn new(manifest: ToolManifest, program: Option<ToolProgram>) -> Self {
        Self {
            manifest,
            program,
            state: ToolState::Dormant,
            activation_count: 0,
            hour_window_start: Utc::now(),
            last_activity: None,
            cooldown_until: None,
        }
    }

    fn reset_hour_window_if_needed(&mut self) {
        let elapsed = Utc::now() - self.hour_window_start;
        if elapsed.num_seconds() >= 3600 {
            self.hour_window_start = Utc::now();
            self.activation_count = 0;
        }
    }

    fn budget_remaining(&mut self) -> u32 {
        self.reset_hour_window_if_needed();
        self.manifest
            .max_activations_per_hour
            .saturating_sub(self.activation_count)
    }

    fn is_in_cooldown(&self) -> bool {
        if let Some(until) = self.cooldown_until {
            Utc::now() < until
        } else {
            false
        }
    }
}

pub struct ToolManager {
    tools: Arc<RwLock<HashMap<String, ManagedTool>>>,
    bus: Arc<BusPublisher>,
    /// The process supervisor, started lazily the first time a tool declares a
    /// [`ToolProgram`] and owned by the manager for its whole life — not by the
    /// strand, so a restarted strand generation drives the same processes.
    supervisor: OnceLock<ProcessSupervisor>,
}

impl ToolManager {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            bus,
            supervisor: OnceLock::new(),
        }
    }

    /// The process supervisor, if a tool has already declared a program.
    fn supervisor(&self) -> Option<&ProcessSupervisor> {
        self.supervisor.get()
    }

    /// The process supervisor, starting its thread on first use.
    fn supervisor_or_start(&self) -> &ProcessSupervisor {
        self.supervisor.get_or_init(ProcessSupervisor::start)
    }

    /// Register a tool: a bare [`ToolManifest`] for a state-only tool, or
    /// `ToolManifest::with_program(program)` ([`ToolDeclaration`]) for a tool
    /// that runs a process.
    pub fn register(&self, tool: impl Into<ToolDeclaration>) {
        let ToolDeclaration { manifest, program } = tool.into();
        let name = manifest.name.clone();

        if program.is_some() {
            // Only a manager whose tools actually run something pays for the
            // supervisor thread; a state-only table costs none.
            self.supervisor_or_start();
        } else {
            // Loud enough to be actionable at boot: this tool's activation will
            // move the state machine and start nothing, because nothing was
            // declared to run.
            tracing::info!(
                tool = %name,
                "tool registered without a program: activation is state-only"
            );
        }

        self.tools
            .write()
            .insert(name, ManagedTool::new(manifest, program));
    }

    pub fn arm(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Dormant {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Dormant,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Armed;

        self.emit_state_change(tool_name, from, ToolState::Armed, "armed by operator");
        Ok(())
    }

    /// Activate a tool: pass the gates, then **start its process**.
    ///
    /// The gates are exactly the ones this method has always applied, in the
    /// same order — the tool must be `Armed`, must not be cooling down, and must
    /// have budget left in the current hour — and they run *before* anything is
    /// spawned, so a refused activation starts nothing at all.
    ///
    /// Once they pass, a tool that declares a [`ToolProgram`] has that program's
    /// argv rendered from this request (see [`ToolProgram::render_argv`]) and
    /// handed to the process supervisor, and the tool becomes `Active`. The
    /// spawn itself completes on the supervisor thread a few milliseconds later;
    /// the pid is readable through [`ToolManager::pid`]. A tool that declares no
    /// program keeps the historical behaviour (state only).
    pub fn activate(&self, request: &ToolActivationRequest) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(&request.tool_name)
            .ok_or_else(|| ToolkitError::NotFound(request.tool_name.clone()))?;

        if tool.state != ToolState::Armed {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Armed,
                actual: tool.state.clone(),
            });
        }

        if tool.is_in_cooldown() {
            return Err(ToolkitError::InCooldown(tool.cooldown_until.unwrap()));
        }

        tool.reset_hour_window_if_needed();
        if tool.activation_count >= tool.manifest.max_activations_per_hour {
            return Err(ToolkitError::BudgetExhausted(request.tool_name.clone()));
        }

        let from = tool.state.clone();
        tool.state = ToolState::Active;
        tool.activation_count += 1;
        tool.last_activity = Some(Utc::now());

        // Resolve the argv template while the activation's context is in hand;
        // the supervisor is handed a concrete program.
        let program = tool
            .program
            .as_ref()
            .map(|program| program.resolved_for(request));
        let idle_timeout = tool.manifest.idle_timeout;

        drop(tools);

        if let Some(program) = program {
            let started = self
                .supervisor()
                .map(|supervisor| supervisor.spawn_tool(&request.tool_name, program, idle_timeout))
                .unwrap_or(false);
            if !started {
                tracing::error!(
                    tool = %request.tool_name,
                    "the process supervisor is not accepting commands; the tool is Active with no process"
                );
            }
        }

        self.emit_state_change(
            &request.tool_name,
            from,
            ToolState::Active,
            &format!("triggered by: {}", request.trigger),
        );

        let _ = BusEvent::publish(
            &self.bus,
            "net.toolkit.activation",
            Message::ToolActivationReq(request.clone()),
        );

        Ok(())
    }

    /// Deactivate a tool: enter cooldown **and stop its process**.
    ///
    /// The stop is the managed-process primitive's graceful one — SIGTERM, then
    /// `kill()` after the program's declared `graceful_stop_timeout`, then the
    /// child is reaped — and it runs on the supervisor thread, so this call
    /// returns immediately and does not block the caller for the escalation
    /// window. The tool is in `Cooldown` as before; the process is gone
    /// milliseconds later, observable through [`ToolManager::pid`].
    pub fn deactivate(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Active {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Active,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Cooldown;
        tool.cooldown_until =
            Some(Utc::now() + chrono::Duration::from_std(tool.manifest.cooldown_duration).unwrap());
        let has_program = tool.program.is_some();

        drop(tools);

        if has_program {
            if let Some(supervisor) = self.supervisor() {
                supervisor.stop_tool(tool_name, StopCause::Requested, "deactivated by operator");
            }
        }

        self.emit_state_change(
            tool_name,
            from,
            ToolState::Cooldown,
            "deactivated, entering cooldown",
        );
        Ok(())
    }

    /// Reconcile the tool table with the processes that are actually running.
    ///
    /// This is the state machine's observation step, and the strand calls it on
    /// every tick (the tick is ~10 ms). It asks the supervisor what it last
    /// observed and, for every `Active` tool whose process is **gone**, moves the
    /// tool to `Cooldown` exactly as a deactivation would — same state, same
    /// cooldown clock, same published `net.toolkit.state` change — with the
    /// observed cause in the reason: an idle timeout, an exhausted runtime
    /// budget, a process that ended on its own, or a spawn that failed. So a tool
    /// can never sit in `Active` over a dead process, and the state the rest of
    /// the node reads is the state of the world.
    ///
    /// It is idempotent and cheap: one snapshot of the report map, and one
    /// transition per tool whose activation has ended. Calling it more often
    /// than the strand does is harmless.
    pub fn tick(&self) {
        let Some(supervisor) = self.supervisor() else {
            return;
        };
        let reports = supervisor.snapshot();
        if reports.is_empty() {
            return;
        }

        // Lock discipline, as in every other method here: decide under the tool
        // table's lock, but publish only after releasing it.
        let mut transitions: Vec<(String, ToolState, String)> = Vec::new();
        {
            let mut tools = self.tools.write();
            for (name, tool) in tools.iter_mut() {
                if tool.state != ToolState::Active || tool.program.is_none() {
                    continue;
                }
                let Some(report) = reports.get(name) else {
                    continue;
                };
                let Some(cause) = report.outcome else {
                    continue; // still running (or still starting)
                };

                let reason = cause.reason(report.detail.as_deref());
                let from = tool.state.clone();
                tool.state = ToolState::Cooldown;
                tool.cooldown_until = Some(
                    Utc::now()
                        + chrono::Duration::from_std(tool.manifest.cooldown_duration).unwrap(),
                );
                transitions.push((name.clone(), from, reason));
            }
        }

        for (name, from, reason) in transitions {
            self.emit_state_change(&name, from, ToolState::Cooldown, &reason);
        }
    }

    pub fn complete_cooldown(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Cooldown {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Cooldown,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Dormant;
        tool.cooldown_until = None;

        drop(tools);

        self.emit_state_change(tool_name, from, ToolState::Dormant, "cooldown complete");
        Ok(())
    }

    pub fn disarm(&self, tool_name: &str) -> Result<(), ToolkitError> {
        let mut tools = self.tools.write();
        let tool = tools
            .get_mut(tool_name)
            .ok_or_else(|| ToolkitError::NotFound(tool_name.to_string()))?;

        if tool.state != ToolState::Armed {
            return Err(ToolkitError::InvalidState {
                expected: ToolState::Armed,
                actual: tool.state.clone(),
            });
        }

        let from = tool.state.clone();
        tool.state = ToolState::Dormant;

        drop(tools);

        self.emit_state_change(tool_name, from, ToolState::Dormant, "disarmed by operator");
        Ok(())
    }

    pub fn get_state(&self, tool_name: &str) -> Option<ToolState> {
        self.tools.read().get(tool_name).map(|t| t.state.clone())
    }

    pub fn get_budget(&self, tool_name: &str) -> Option<ToolBudget> {
        let mut tools = self.tools.write();
        let tool = tools.get_mut(tool_name)?;
        tool.reset_hour_window_if_needed();

        Some(ToolBudget {
            tool_name: tool_name.to_string(),
            max_activations_per_hour: tool.manifest.max_activations_per_hour,
            cooldown_seconds: tool.manifest.cooldown_duration.as_secs(),
            remaining_activations: tool.budget_remaining(),
        })
    }

    pub fn list_tools(&self) -> Vec<(String, ToolState)> {
        self.tools
            .read()
            .iter()
            .map(|(name, tool)| (name.clone(), tool.state.clone()))
            .collect()
    }

    /// The live pid of a tool's process, if it has one right now.
    ///
    /// `None` covers every reason there is no live process: the tool declares no
    /// program, its activation is still starting on the supervisor thread, its
    /// process has ended, or it was never activated. The pid is what the
    /// supervisor last observed — not an assumption derived from the tool's
    /// state.
    pub fn pid(&self, tool_name: &str) -> Option<u32> {
        self.process_report(tool_name).and_then(|report| report.pid)
    }

    /// What the supervisor last observed about a tool's process, if it was ever
    /// asked to start one.
    pub fn process_report(&self, tool_name: &str) -> Option<ToolProcessReport> {
        self.supervisor()?.report(tool_name)
    }

    /// Stop every supervised process and join the supervisor thread.
    ///
    /// Bounded: each live process is stopped through the primitive's graceful
    /// path, waiting at most its declared `graceful_stop_timeout` for SIGTERM
    /// before `kill()`. Idempotent, and also run when the manager is dropped, so
    /// a node that exits — or a test that ends — leaves no tool processes
    /// behind.
    pub fn shutdown(&self) {
        if let Some(supervisor) = self.supervisor() {
            supervisor.shutdown();
        }
    }

    pub fn check_trigger(&self, event_topic: &str, confidence: f64) -> Vec<String> {
        self.tools
            .read()
            .iter()
            .filter(|(_, tool)| {
                tool.state == ToolState::Armed
                    && tool.trigger_conditions_match(event_topic, confidence)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// The restartable strand spec for this manager's activation loop, ready for
    /// [`Bus::register_strand`]. Prefer [`ToolManager::register_strand`], which
    /// is idempotent per bus.
    pub fn strand_spec(self: &Arc<Self>, faults: FaultPolicy) -> spiderweb::StrandSpec {
        ToolkitStrand::spec(Arc::clone(self), faults)
    }

    /// Read the fault policy from the environment and queue this manager's strand
    /// on `bus`, logging loudly when a drill is armed.
    ///
    /// This is one of the two equivalent ways the composition root queues the
    /// loop (the other is the crate-level
    /// [`register_strands`](crate::register_strands), which is the same call):
    /// it runs before [`Bus::engage_supervision`], and re-queueing —
    /// from the legacy shim, say — is a no-op instead of the kernel's
    /// duplicate-name panic.
    pub fn register_strand(self: &Arc<Self>, bus: &mut Bus, publisher: &Arc<BusPublisher>) {
        let faults = FaultPolicy::from_env();
        if faults.is_injected() {
            // A deliberately armed fault must never look like a real one in the
            // logs, and must be impossible to leave on by accident without a
            // trace.
            tracing::warn!(
                policy = ?faults,
                env = CRASH_AFTER_REQUESTS_ENV,
                "toolkit strand fault injection ARMED — the strand will crash on purpose"
            );
        }
        strand::queue_strand(bus, publisher, self, faults)
    }

    fn emit_state_change(&self, tool_name: &str, from: ToolState, to: ToolState, reason: &str) {
        let change = ToolStateChange {
            tool_name: tool_name.to_string(),
            from,
            to,
            reason: reason.to_string(),
            timestamp: Utc::now(),
        };
        // The envelope is what carries the fan-out registration; a bare
        // `Message` payload is not a registered clone type.
        let _ = BusEvent::publish(
            &self.bus,
            "net.toolkit.state",
            Message::ToolStateChange(change),
        );
    }
}

impl Drop for ToolManager {
    fn drop(&mut self) {
        // "Dormant" must not mean "leaked": dropping the manager stops every
        // process it started and joins the supervisor thread, which is bounded
        // by the live tools' declared graceful_stop_timeout values.
        self.shutdown();
    }
}

impl ManagedTool {
    fn trigger_conditions_match(&self, event_topic: &str, confidence: f64) -> bool {
        self.manifest.trigger_conditions.iter().any(|cond| {
            event_topic.starts_with(&cond.event_topic) && confidence >= cond.min_confidence
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::ToolActivationRequest;

    fn test_manifest(name: &str) -> ToolManifest {
        ToolManifest {
            name: name.to_string(),
            description: format!("{} tool", name),
            trigger_conditions: vec![TriggerCondition {
                event_topic: "net.sensors.threat".to_string(),
                min_confidence: 0.8,
            }],
            idle_timeout: Duration::from_secs(300),
            cooldown_duration: Duration::from_secs(60),
            max_activations_per_hour: 5,
        }
    }

    fn test_activation(name: &str) -> ToolActivationRequest {
        ToolActivationRequest {
            tool_name: name.to_string(),
            trigger: "high threat detected".to_string(),
            context: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn full_lifecycle() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);

        mgr.register(test_manifest("probe"));

        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));

        mgr.arm("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Armed));

        mgr.activate(&test_activation("probe")).unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Active));

        mgr.deactivate("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Cooldown));

        mgr.complete_cooldown("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));
    }

    #[test]
    fn cannot_activate_dormant() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);
        mgr.register(test_manifest("probe"));

        assert!(mgr.activate(&test_activation("probe")).is_err());
    }

    #[test]
    fn budget_tracking() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);

        let mut manifest = test_manifest("scanner");
        manifest.max_activations_per_hour = 2;
        manifest.cooldown_duration = Duration::from_secs(0);
        mgr.register(manifest);

        let budget = mgr.get_budget("scanner").unwrap();
        assert_eq!(budget.remaining_activations, 2);

        mgr.arm("scanner").unwrap();
        mgr.activate(&test_activation("scanner")).unwrap();
        mgr.deactivate("scanner").unwrap();
        mgr.complete_cooldown("scanner").unwrap();

        let budget = mgr.get_budget("scanner").unwrap();
        assert_eq!(budget.remaining_activations, 1);
    }

    #[test]
    fn trigger_matching() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);

        mgr.register(test_manifest("probe"));
        mgr.arm("probe").unwrap();

        let matches = mgr.check_trigger("net.sensors.threat.high", 0.9);
        assert_eq!(matches.len(), 1);

        let no_match = mgr.check_trigger("net.sensors.threat.high", 0.5);
        assert!(no_match.is_empty());

        let wrong_topic = mgr.check_trigger("net.mesh.peer", 0.9);
        assert!(wrong_topic.is_empty());
    }

    #[test]
    fn disarm_returns_to_dormant() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);
        mgr.register(test_manifest("probe"));

        mgr.arm("probe").unwrap();
        mgr.disarm("probe").unwrap();
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Dormant));
    }

    /// The argv template: one declaration serves every trigger, because the
    /// request's name, trigger and context are substituted at activation — and
    /// an unknown placeholder is left visible rather than dropped.
    #[test]
    fn argv_template_is_rendered_from_the_activation_request() {
        let program = ToolProgram::new("/usr/bin/example")
            .with_args([
                "--tool",
                "{{tool}}",
                "--why",
                "{{trigger}}",
                "--iface",
                "{{context.iface}}",
            ])
            .with_arg("{{context.missing}}")
            .with_arg("literal");

        let mut request = test_activation("probe");
        request.trigger = "burn signal".to_string();
        request
            .context
            .insert("iface".to_string(), "eth0".to_string());

        let expected: Vec<String> = [
            "--tool",
            "probe",
            "--why",
            "burn signal",
            "--iface",
            "eth0",
            "{{context.missing}}",
            "literal",
        ]
        .iter()
        .map(|part| part.to_string())
        .collect();

        assert_eq!(program.render_argv(&request), expected);
    }

    /// A manifest with no program is a state-only tool: activation moves the
    /// state machine and starts nothing, exactly as it did before the toolkit
    /// could run processes. (The tests that prove a *declared* program really
    /// runs a real binary live in `tests/tool_process.rs`.)
    #[test]
    fn a_manifest_without_a_program_keeps_the_state_only_behaviour() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);
        mgr.register(test_manifest("probe"));
        mgr.arm("probe").unwrap();

        mgr.activate(&test_activation("probe")).unwrap();
        mgr.tick();

        assert_eq!(mgr.get_state("probe"), Some(ToolState::Active));
        assert!(mgr.pid("probe").is_none());
        assert!(mgr.process_report("probe").is_none());
        assert!(mgr.supervisor().is_none(), "no program, no supervisor");
    }

    /// The cooldown guard still refuses, and a refused activation must not reach
    /// the supervisor at all — no process is started for it.
    ///
    /// The public state machine only ever sets the cooldown clock together with
    /// the `Cooldown` state (which `activate` refuses on state alone), so the
    /// guard itself is exercised here through the field it reads.
    #[test]
    fn activate_refuses_while_cooling_down_and_spawns_nothing() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mgr = ToolManager::new(bus);
        mgr.register(
            test_manifest("scanner")
                .with_program(ToolProgram::new("/bin/sh").with_args(["-c", "sleep 30"])),
        );
        mgr.arm("scanner").unwrap();

        {
            let mut tools = mgr.tools.write();
            let tool = tools.get_mut("scanner").unwrap();
            tool.cooldown_until = Some(Utc::now() + chrono::Duration::seconds(60));
        }

        let refused = mgr.activate(&test_activation("scanner"));

        assert!(
            matches!(refused, Err(ToolkitError::InCooldown(_))),
            "the cooldown guard must still refuse: {refused:?}"
        );
        assert_eq!(
            mgr.get_state("scanner"),
            Some(ToolState::Armed),
            "a refused activation must not move the state"
        );
        assert!(
            mgr.process_report("scanner").is_none(),
            "a refused activation must not even reach the supervisor"
        );
        assert!(mgr.pid("scanner").is_none());
        mgr.shutdown();
    }

    #[tokio::test]
    async fn activation_requests_are_budget_gated() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let mgr = Arc::new(ToolManager::new(Arc::clone(&publisher)));
        mgr.register(test_manifest("probe"));
        mgr.arm("probe").unwrap();

        let mut activation_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.toolkit.activation", 64);
        // The activation loop is a supervised strand now: queue its spec on the
        // kernel, then run the loop — the step the old `tokio::spawn` inside the
        // shim used to provide.
        register_strands(&mut bus, &publisher, &mgr);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        BusEvent::publish(
            &publisher,
            "net.toolkit.request",
            Message::ToolActivationReq(test_activation("probe")),
        )
        .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(10), activation_sub.recv())
            .await
            .expect("activation event")
            .unwrap();

        assert!(matches!(event.message, Message::ToolActivationReq(_)));
        assert_eq!(mgr.get_state("probe"), Some(ToolState::Active));
        supervision.shutdown();
    }
}
