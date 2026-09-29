//! The supervision composition, owned by the process root.
//!
//! Spiderweb's run loop **consumes** the bus — `Bus::run_until(&mut self, ..)` —
//! so a kernel cannot be shared as `Arc` *and* driven by a loop. That is the
//! whole ownership change of the cutover: exactly one `&mut spiderweb::Bus`,
//! moved onto the thread that runs the loop, and one `BusPublisher` left behind
//! as the shareable handle for everybody else.
//!
//! This module is where that composition lives, because the CLI is the process
//! owner. It is also where the rest of the Imperium policy that the old
//! old `imperium-bus` shim happened to carry lives, and which has no bus to belong
//! to any more:
//!
//! * [`SPIDER_STRAND_NAME`] — the name the `spider` orchestrator is registered
//!   under, so a test, an operator tool or a dashboard can recognise the
//!   spider's own `LifecycleEvent`s;
//! * the cognition gate and its two tuning overrides ([`COGNITION_ENV`],
//!   [`WARMUP_EVENTS_ENV`], [`HEARTBEAT_STALL_TICKS_ENV`]), and the parsing
//!   behind them ([`cognition_config_from`], [`cognition_config_from_env`]);
//! * the spider seeding, including the fail-safe that a configuration
//!   `validate()` rejects degrades to cognition OFF rather than arming a
//!   mis-tuned judge.
//!
//! None of that is compatibility scaffolding, which is why it is preserved here
//! exactly rather than dropped with the shim.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use spider::CognitiveConfig;
use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};

/// Strand name the spider is registered under on the Spiderweb kernel.
///
/// Fixed and `&'static str` because Spiderweb's [`StrandSpec`] requires it; the
/// name is what the kernel's slot table and lifecycle events use. Public
/// because it is how a test, an operator tool or a dashboard recognises the
/// spider's own `LifecycleEvent`s (and how it excludes the spider when it
/// reasons about *other* nodes — the spider watches others, never itself).
pub const SPIDER_STRAND_NAME: &str = "spider";

/// Environment variable that arms the spider's **cognitive engine**.
///
/// The recognised "on" tokens are `1`, `true`, `on`, `yes` and `enabled`
/// (case-insensitive, surrounding whitespace ignored). Everything else —
/// unset, empty, `0`, `false`, or a typo — means **OFF**, because an operator's
/// typo must never arm a judge. Arming is logged loudly at
/// [`engage_supervision_env`]; a value that is present but not recognised is
/// logged too, so silence-by-typo is visible rather than mysterious.
pub const COGNITION_ENV: &str = "IMPERIUM_SPIDER_COGNITION";

/// Optional override for the engine's `warmup_events` knob (observations
/// required before a node has a rhythm baseline), read only when cognition is
/// armed.
///
/// Unset/unparsable leaves the audited default in place. A value the
/// configuration's `validate()` rejects (e.g. `1`) disarms cognition entirely
/// and logs the error — deliberately fail-closed: a half-tuned judge is worse
/// than a silent one, and the alarm is additive (a false negative costs
/// detection, a mis-tuned judge costs trust).
pub const WARMUP_EVENTS_ENV: &str = "IMPERIUM_SPIDER_WARMUP_EVENTS";

/// Optional override for the engine's `heartbeat_stall_ticks` knob — how many
/// consecutive ticks without progress count as a node that is alive but stuck.
/// Same fail-safe rules as [`WARMUP_EVENTS_ENV`].
pub const HEARTBEAT_STALL_TICKS_ENV: &str = "IMPERIUM_SPIDER_HEARTBEAT_STALL_TICKS";

/// The tokens that arm cognition, compared case-insensitively after trimming.
const COGNITION_ON_TOKENS: [&str; 5] = ["1", "true", "on", "yes", "enabled"];

/// Resolve the spider's cognitive configuration from the process environment.
///
/// Returns cognition **OFF** ([`CognitiveConfig::default`]) unless
/// [`COGNITION_ENV`] carries a recognised arming token, in which case the
/// validated engine defaults are returned with the two documented overrides
/// applied. Called by [`engage_supervision_env`]; the parsing half is the pure
/// [`cognition_config_from`], so every value can be tested without racing the
/// process environment.
///
/// The only thing this function logs is a *present but unrecognised* master
/// value: the caller logs the arming decision itself (and any validation
/// failure), so that the armed/refused line appears exactly once, in the
/// caller's order.
pub fn cognition_config_from_env() -> CognitiveConfig {
    let master = std::env::var(COGNITION_ENV).ok();
    let warmup = std::env::var(WARMUP_EVENTS_ENV).ok();
    let stall = std::env::var(HEARTBEAT_STALL_TICKS_ENV).ok();
    let config = cognition_config_from(master.as_deref(), warmup.as_deref(), stall.as_deref());

    if !config.enabled {
        // A value that is *present* and unrecognised is far more likely to be a
        // typo than an operator asking for silence. Say so: OFF-by-typo must not
        // be indistinguishable from OFF-by-default.
        if let Some(value) = master.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            tracing::warn!(
                env = COGNITION_ENV,
                value,
                tokens = ?COGNITION_ON_TOKENS,
                "spider cognition: value is not a recognised arming token — cognition stays OFF"
            );
        }
    }
    config
}

/// The parsing half of [`cognition_config_from_env`]: no process-env access, no
/// logging, so it is exhaustively testable.
///
/// The overrides are applied *only* when cognition is armed (they cannot
/// accidentally switch it on), and are never silently clamped — an out-of-range
/// value is left in the configuration so that `CognitiveConfig::validate`
/// rejects it and the caller degrades to cognition OFF with an error, rather
/// than arming a judge with a knob the operator did not ask for.
pub fn cognition_config_from(
    master: Option<&str>,
    warmup_events: Option<&str>,
    heartbeat_stall_ticks: Option<&str>,
) -> CognitiveConfig {
    let mut config = CognitiveConfig::default();
    config.enabled = master
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .is_some_and(|token| COGNITION_ON_TOKENS.contains(&token.as_str()));

    if config.enabled {
        if let Some(events) = parse_positive_count(warmup_events) {
            config.warmup_events = events;
        }
        if let Some(ticks) = parse_positive_count(heartbeat_stall_ticks) {
            config.heartbeat_stall_ticks = ticks;
        }
    }
    config
}

/// Parse an optional positive integer knob. Absent, empty, zero, negative and
/// unparsable all mean "no override" — a typo must never re-tune the alarm.
fn parse_positive_count(raw: Option<&str>) -> Option<u64> {
    match raw?.trim().parse::<u64>() {
        Ok(n) if n > 0 => Some(n),
        _ => None,
    }
}

/// What the run loop will build for the `spider` slot.
///
/// Resolved **once, at engage time, on the caller's thread** — so a boot log
/// shows the arming decision in order, and so an invalid configuration is
/// reported once rather than once per spider generation. The factory the kernel
/// stores captures this, not the raw environment.
#[derive(Clone, Debug)]
enum SpiderSeed {
    /// The shipped spider: the deterministic crash policy, cognition OFF.
    CrashWallOnly,
    /// Cognition armed, carrying a configuration that has already passed
    /// `validate()`.
    Cognitive(Box<CognitiveConfig>),
}

impl SpiderSeed {
    /// Resolve a requested configuration into what will actually be built.
    ///
    /// Fail-safe in both directions: `enabled: false` (the default) leaves the
    /// shipped spider untouched, and a configuration `validate()` rejects
    /// degrades to that same spider with an error log — an out-of-range knob
    /// must not take the node down, and it must not arm a judge either.
    fn resolve(config: CognitiveConfig) -> Self {
        if !config.enabled {
            return SpiderSeed::CrashWallOnly;
        }
        match config.validate() {
            Ok(()) => SpiderSeed::Cognitive(Box::new(config)),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    env = COGNITION_ENV,
                    "spider cognition config is invalid — falling back to cognition OFF \
                     (the crash policy is unaffected)"
                );
                SpiderSeed::CrashWallOnly
            }
        }
    }

    /// The strand this seed builds. Called by the kernel's factory, once per
    /// spider generation (there should only ever be one).
    fn build(&self) -> Box<dyn spiderweb::Strand> {
        match self {
            SpiderSeed::CrashWallOnly => Box::new(spider::Spider::new()),
            SpiderSeed::Cognitive(config) => {
                Box::new(spider::Spider::with_cognition((**config).clone()))
            }
        }
    }
}

/// Clears the liveness flag when the run-loop thread exits, whether `run_until`
/// returned normally or unwound. The workspace keeps `panic = "unwind"`, so
/// this `Drop` always runs.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// A live kernel run loop, and the handles that observe and stop it.
///
/// This replaces the old shim's `SupervisionHandle`, and it is much
/// smaller for a reason: the kernel already owns the hard parts (it polls
/// `sys.control` every ~50 ms and joins its workers under a bounded deadline),
/// so "stop" is one publish plus one join.
pub struct Supervision {
    /// The shareable publish handle onto the running kernel. `BusPublisher` is
    /// **not** `Clone` in this revision of the vendored kernel, so a caller that
    /// needs its own handle mints one from the kernel before engaging (see
    /// `RuntimeCoordinator::bus`) rather than cloning this one.
    publisher: BusPublisher,
    running: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Supervision {
    /// Install `spider` on `bus` and run the kernel's loop on its own thread.
    ///
    /// Takes the bus **by value**: the loop consumes it, which is the ownership
    /// change this cutover is about. Every caller keeps the returned
    /// [`Supervision::publisher`] — or the one it minted before calling — for
    /// publishing and named subscriptions.
    ///
    /// `cognition` is resolved here, on the caller's thread, so the arming
    /// decision appears once, in boot order, and an invalid configuration is
    /// reported once rather than once per spider generation.
    pub fn engage(bus: Bus, cognition: CognitiveConfig) -> Self {
        let seed = SpiderSeed::resolve(cognition);
        if let SpiderSeed::Cognitive(config) = &seed {
            // Loud on purpose: this spider may now act on its own — restarting
            // or quarantining a strand — without a crash having happened.
            tracing::warn!(
                env = COGNITION_ENV,
                warmup_events = config.warmup_events,
                heartbeat_stall_ticks = config.heartbeat_stall_ticks,
                alert_budget = config.alert_budget,
                alert_window = config.alert_window,
                "spider cognition ARMED — the spider will learn each strand's rhythm and may \
                 publish Restart/Quarantine/SetTransfer on sys.control"
            );
        }

        let mut kernel = bus;
        let publisher = kernel.publisher();
        kernel.register_spider(StrandSpec::new(SPIDER_STRAND_NAME, move || seed.build()));

        let running = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&running);
        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                thread_flag.store(true, Ordering::SeqCst);
                let _running = RunningGuard(Arc::clone(&thread_flag));
                let mut kernel = kernel;
                kernel.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            running,
            join: Some(join),
        }
    }

    /// [`Supervision::engage`], reading cognition from the environment — what
    /// every deployment does, and the only difference between the two entry
    /// points.
    pub fn engage_from_env(bus: Bus) -> Self {
        Self::engage(bus, cognition_config_from_env())
    }

    /// Whether the run loop is currently executing.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Ask the kernel to stop over `sys.control`, then join the run-loop thread.
    ///
    /// Idempotent, and safe after the loop has already exited: the join handle
    /// is taken exactly once. The kernel bounds its own worker joins, so this
    /// returns rather than hanging on a wedged strand.
    pub fn shutdown(&mut self) {
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
