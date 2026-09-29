//! Operator-supplied, health-verified backend process control.
//!
//! Xray and AmneziaWG are protocol labels here, not inferred executables.
//! Every launch uses an explicit absolute executable, config file, arguments,
//! and profile-specific health command. A successful child spawn alone never
//! marks a profile ready. The caller's health command must verify the actual
//! backend path it intends to use; this crate cannot infer its semantics.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use imperium_protocol::{
    BusEvent, EventId, Message, ProtocolRole, TransportControlOperation, TransportControlOutcome,
    TransportControlStatus,
};
use serde::{Deserialize, Serialize};
use spiderweb::BusPublisher;
use thiserror::Error;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::controller::{ControllerError, VerifiedLaunch};
use crate::{ProtocolController, ProtocolControllerConfig, ProtocolKind};

const MAX_PROFILES: usize = 32;
const MAX_TIMEOUT_MS: u64 = 120_000;
const CONFIG_TOKEN: &str = "{config}";
const REQUEST_QUEUE: usize = 64;
const HEALTH_REPORT_INTERVAL: Duration = Duration::from_secs(5);
pub const CONTROL_STATUS_TOPIC: &str = "net.transport.control.status";
pub const PROFILE_ROTATION_TOPIC: &str = "net.transport.profile.rotate";
pub const ACTIVE_REQUEST_TOPIC: &str = "net.transport.active_request";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveHealthProbe {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

/// An explicit command supplied by the operator to change or verify the
/// backend's active traffic path. No implicit shell or backend flags are used.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivePathCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProtocolProfile {
    pub profile_id: String,
    pub kind: ProtocolKind,
    pub executable: PathBuf,
    pub config: PathBuf,
    pub args: Vec<String>,
    pub health_probe: LiveHealthProbe,
    pub activate: LivePathCommand,
    pub deactivate: LivePathCommand,
    pub active_path_probe: LivePathCommand,
    pub startup_timeout_ms: u64,
    pub graceful_stop_timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionAction {
    Started,
    ProfileRotated,
    ActiveSelected,
}

/// Returned only after the requested process and profile-specific probe pass.
#[derive(Clone, Debug, Serialize)]
pub struct TransitionReceipt {
    pub action: TransitionAction,
    pub active_protocol: String,
    pub active_profile_id: String,
    pub selected_protocol: String,
    pub selected_profile_id: String,
    pub previous_profile_id: Option<String>,
    pub changed: bool,
    pub verified: bool,
    pub active_path_verified: bool,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveTransportStatus {
    pub configured: bool,
    pub started: bool,
    pub ready: bool,
    pub active_protocol: Option<String>,
    pub active_profile_id: Option<String>,
    pub profiles: Vec<ProfileStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileStatus {
    pub profile_id: String,
    pub protocol: String,
    pub selected: bool,
    pub active: bool,
    pub running: bool,
}

#[derive(Debug, Error)]
pub enum LiveTransportError {
    #[error("invalid transport profile: {0}")]
    InvalidProfile(String),
    #[error("transport process: {0}")]
    Controller(#[from] ControllerError),
    #[error("transport runtime has not started")]
    NotStarted,
    #[error("transport runtime is already started")]
    AlreadyStarted,
    #[error("transport bus commands are already subscribed")]
    AlreadySubscribed,
    #[error("protocol {0} has no configured profile")]
    ProtocolUnavailable(String),
    #[error("protocol {0} has no alternate profile")]
    NoAlternateProfile(String),
    #[error("active backend is unhealthy")]
    ActiveUnhealthy,
    #[error("transport path command failed: {0}")]
    PathCommand(String),
    #[error("transport path rollback failed: {0}")]
    RollbackFailed(String),
}

#[derive(Clone)]
struct VerifiedPathCommand {
    executable: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

#[derive(Clone)]
struct VerifiedPathActions {
    activate: VerifiedPathCommand,
    deactivate: VerifiedPathCommand,
    active_probe: VerifiedPathCommand,
}

struct Slot {
    profile: LiveProtocolProfile,
    controller: ProtocolController,
    path: VerifiedPathActions,
}

struct Inner {
    slots: Vec<Slot>,
    selected: [Option<usize>; 2],
    active: usize,
    started: bool,
}

/// Serializes process transitions so concurrent socket and GUI requests cannot
/// both promote different candidates. An incumbent remains selected unless a
/// candidate process and its explicit probe pass.
pub struct LiveTransportRuntime {
    inner: Mutex<Inner>,
    bus: Arc<BusPublisher>,
    commands_subscribed: AtomicBool,
}

enum QueuedRequest {
    Rotate {
        event_id: EventId,
        protocol_name: Option<String>,
    },
    SetActive {
        event_id: EventId,
        protocol_name: String,
    },
}

impl LiveTransportRuntime {
    pub fn new(
        bus: Arc<BusPublisher>,
        profiles: Vec<LiveProtocolProfile>,
        initial_profile_id: &str,
    ) -> Result<Self, LiveTransportError> {
        if profiles.is_empty() || profiles.len() > MAX_PROFILES {
            return Err(LiveTransportError::InvalidProfile(format!(
                "expected 1..={MAX_PROFILES} explicit profiles"
            )));
        }
        let mut ids = HashSet::new();
        let mut slots = Vec::with_capacity(profiles.len());
        let mut selected = [None, None];
        let mut active = None;
        for profile in profiles {
            if !ids.insert(profile.profile_id.clone()) {
                return Err(LiveTransportError::InvalidProfile(format!(
                    "duplicate id {}",
                    profile.profile_id
                )));
            }
            let (executable, launch, stop_timeout, path) = profile.validate()?;
            let index = slots.len();
            selected[profile.kind.index()].get_or_insert(index);
            if profile.profile_id == initial_profile_id {
                active = Some(index);
            }
            let config = ProtocolControllerConfig {
                kind: profile.kind,
                binary_path: executable,
                config_template: String::new(),
                health_check_interval: Duration::from_secs(5),
                graceful_stop_timeout: stop_timeout,
            };
            let controller =
                ProtocolController::new(config, Arc::clone(&bus)).with_verified_launch(launch);
            slots.push(Slot {
                profile,
                controller,
                path,
            });
        }
        let active = active.ok_or_else(|| {
            LiveTransportError::InvalidProfile(format!(
                "initial profile {initial_profile_id} is not configured"
            ))
        })?;
        selected[slots[active].profile.kind.index()] = Some(active);
        Ok(Self {
            inner: Mutex::new(Inner {
                slots,
                selected,
                active,
                started: false,
            }),
            bus,
            commands_subscribed: AtomicBool::new(false),
        })
    }

    pub async fn start(&self) -> Result<TransitionReceipt, LiveTransportError> {
        let mut inner = self.inner.lock().await;
        if inner.started {
            return Err(LiveTransportError::AlreadyStarted);
        }
        let active = inner.active;
        inner.slots[active].controller.start().await?;
        let path = inner.slots[active].path.clone();
        if let Err(error) = path.activate.run("activate initial path").await {
            let _ = path.deactivate.run("undo initial activation").await;
            let _ = inner.slots[active].controller.stop().await;
            return Err(error);
        }
        if let Err(error) = path.active_probe.run("verify initial active path").await {
            let cleanup = path.deactivate.run("undo initial activation").await;
            let _ = inner.slots[active].controller.stop().await;
            if cleanup.is_err() {
                return Err(LiveTransportError::RollbackFailed(
                    "initial path could not be deactivated".into(),
                ));
            }
            return Err(error);
        }
        inner.slots[active]
            .controller
            .set_role(ProtocolRole::Active);
        inner.started = true;
        let receipt = inner.receipt(TransitionAction::Started, active, None, true);
        drop(inner);
        self.publish_status(TransportControlStatus {
            request_event_id: None,
            operation: TransportControlOperation::RuntimeReady,
            outcome: TransportControlOutcome::Applied,
            runtime_ready: true,
            active_protocol: Some(receipt.active_protocol.clone()),
            active_profile_id: Some(receipt.active_profile_id.clone()),
            target_protocol: Some(receipt.selected_protocol.clone()),
            target_profile_id: Some(receipt.selected_profile_id.clone()),
            reason: None,
            timestamp: Utc::now(),
        });
        Ok(receipt)
    }

    /// Select a configured backend, starting and probing its selected profile
    /// before changing the active role. The previous backend stays available
    /// as standby, matching the existing active/standby controller design.
    pub async fn set_active(
        &self,
        protocol_name: &str,
    ) -> Result<TransitionReceipt, LiveTransportError> {
        let kind = parse_kind(protocol_name)?;
        let mut inner = self.inner.lock().await;
        if !inner.started {
            return Err(LiveTransportError::NotStarted);
        }
        let target = inner.selected[kind.index()]
            .ok_or_else(|| LiveTransportError::ProtocolUnavailable(protocol_name.into()))?;
        let target_was_running = inner.slots[target].controller.pid().is_some();
        inner.slots[target]
            .controller
            .ensure_healthy_running()
            .await?;
        let previous = inner.active;
        if previous != target {
            let incumbent_path = inner.slots[previous].path.clone();
            let candidate_path = inner.slots[target].path.clone();
            if let Err(error) = switch_active_path(&incumbent_path, &candidate_path).await {
                if !target_was_running {
                    let _ = inner.slots[target].controller.stop().await;
                }
                return Err(error);
            }
            inner.slots[previous]
                .controller
                .set_role(ProtocolRole::Standby);
            inner.slots[target]
                .controller
                .set_role(ProtocolRole::Active);
            inner.active = target;
        } else {
            inner.slots[target]
                .path
                .active_probe
                .run("verify current active path")
                .await?;
        }
        Ok(inner.receipt(
            TransitionAction::ActiveSelected,
            target,
            Some(inner.slots[previous].profile.profile_id.clone()),
            previous != target,
        ))
    }

    /// Rotate the current active backend by default, or the named backend.
    /// A healthy candidate starts before the previous profile is stopped.
    /// A failed candidate leaves the incumbent selected and running.
    pub async fn rotate_profile(
        &self,
        protocol_name: Option<&str>,
    ) -> Result<TransitionReceipt, LiveTransportError> {
        let mut inner = self.inner.lock().await;
        if !inner.started {
            return Err(LiveTransportError::NotStarted);
        }
        let kind = match protocol_name {
            Some(name) => parse_kind(name)?,
            None => inner.slots[inner.active].profile.kind,
        };
        let current = inner.selected[kind.index()]
            .ok_or_else(|| LiveTransportError::ProtocolUnavailable(kind.name().into()))?;
        let alternatives: Vec<usize> = inner
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| (slot.profile.kind == kind).then_some(index))
            .collect();
        if alternatives.len() < 2 {
            return Err(LiveTransportError::NoAlternateProfile(kind.name().into()));
        }
        let current_position = alternatives
            .iter()
            .position(|index| *index == current)
            .ok_or_else(|| LiveTransportError::ProtocolUnavailable(kind.name().into()))?;
        let candidate = alternatives[(current_position + 1) % alternatives.len()];
        let candidate_was_running = inner.slots[candidate].controller.pid().is_some();
        inner.slots[candidate]
            .controller
            .ensure_healthy_running()
            .await?;

        let previous_role = inner.slots[current].controller.role();
        if inner.active == current {
            let incumbent_path = inner.slots[current].path.clone();
            let candidate_path = inner.slots[candidate].path.clone();
            if let Err(error) = switch_active_path(&incumbent_path, &candidate_path).await {
                if !candidate_was_running {
                    let _ = inner.slots[candidate].controller.stop().await;
                }
                return Err(error);
            }
        } else {
            let active = inner.active;
            if !inner.slots[active].controller.check_health().await
                || inner.slots[active]
                    .path
                    .active_probe
                    .run("verify unchanged active path")
                    .await
                    .is_err()
            {
                if !candidate_was_running {
                    let _ = inner.slots[candidate].controller.stop().await;
                }
                return Err(LiveTransportError::ActiveUnhealthy);
            }
            if let Err(error) = inner.slots[current].controller.stop().await {
                if !candidate_was_running {
                    let _ = inner.slots[candidate].controller.stop().await;
                }
                return Err(error.into());
            }
        }
        inner.slots[current]
            .controller
            .set_role(ProtocolRole::Standby);
        inner.slots[candidate].controller.set_role(previous_role);
        inner.selected[kind.index()] = Some(candidate);
        if inner.active == current {
            inner.active = candidate;
        }
        Ok(inner.receipt(
            TransitionAction::ProfileRotated,
            candidate,
            Some(inner.slots[current].profile.profile_id.clone()),
            true,
        ))
    }

    /// Rechecks the active child and its operator-provided health command.
    /// Paths, command arguments, and config contents are never returned.
    pub async fn status(&self) -> LiveTransportStatus {
        let mut inner = self.inner.lock().await;
        let ready = if inner.started {
            let active = inner.active;
            inner.slots[active].controller.check_health().await
                && inner.slots[active]
                    .path
                    .active_probe
                    .run("verify active traffic path")
                    .await
                    .is_ok()
        } else {
            false
        };
        let profiles = inner
            .slots
            .iter()
            .enumerate()
            .map(|(index, slot)| ProfileStatus {
                profile_id: slot.profile.profile_id.clone(),
                protocol: slot.profile.kind.name().into(),
                selected: inner.selected[slot.profile.kind.index()] == Some(index),
                active: inner.started && inner.active == index,
                running: slot.controller.is_running(),
            })
            .collect();
        let (active_protocol, active_profile_id) = if inner.started {
            let slot = &inner.slots[inner.active];
            (
                Some(slot.profile.kind.name().into()),
                Some(slot.profile.profile_id.clone()),
            )
        } else {
            (None, None)
        };
        LiveTransportStatus {
            configured: true,
            started: inner.started,
            ready,
            active_protocol,
            active_profile_id,
            profiles,
        }
    }

    pub async fn shutdown(&self) -> Result<(), LiveTransportError> {
        let mut inner = self.inner.lock().await;
        let mut error = if inner.started {
            inner.slots[inner.active]
                .path
                .deactivate
                .run("deactivate active path on shutdown")
                .await
                .err()
        } else {
            None
        };
        for slot in &mut inner.slots {
            if slot.controller.pid().is_some() {
                if let Err(stop_error) = slot.controller.stop().await {
                    if error.is_none() {
                        error = Some(stop_error.into());
                    }
                }
            }
        }
        inner.started = false;
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Publish the verified outcome of a direct control-socket request as well
    /// as bus requests, so an open console observes the transition promptly.
    pub async fn report_outcome(
        &self,
        request_event_id: Option<EventId>,
        operation: TransportControlOperation,
        target_protocol: Option<String>,
        result: &Result<TransitionReceipt, LiveTransportError>,
    ) {
        let current = self.status().await;
        self.publish_status(TransportControlStatus {
            request_event_id,
            operation,
            outcome: if result.is_ok() {
                TransportControlOutcome::Applied
            } else {
                TransportControlOutcome::Rejected
            },
            runtime_ready: current.ready,
            active_protocol: current.active_protocol,
            active_profile_id: current.active_profile_id,
            target_protocol,
            target_profile_id: result
                .as_ref()
                .ok()
                .map(|receipt| receipt.selected_profile_id.clone()),
            reason: result.as_ref().err().map(ToString::to_string),
            timestamp: Utc::now(),
        });
    }

    /// Consume GUI/operator bus requests in one bounded worker. Every request
    /// receives an applied or rejected outcome; queue overflow is rejected
    /// synchronously rather than silently losing a control command.
    pub fn subscribe_commands(
        self: &Arc<Self>,
        publisher: &BusPublisher,
    ) -> Result<JoinHandle<()>, LiveTransportError> {
        if self
            .commands_subscribed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(LiveTransportError::AlreadySubscribed);
        }
        let (tx, mut rx) = mpsc::channel::<QueuedRequest>(REQUEST_QUEUE);

        let rotate_tx = tx.clone();
        let rotate_bus = Arc::downgrade(&self.bus);
        publisher.subscribe_exact(
            PROFILE_ROTATION_TOPIC,
            Box::new(move |_socket, payload| {
                let Ok(event) = payload.downcast::<BusEvent>() else {
                    return;
                };
                let event = *event;
                if let Message::ProfileRotationRequest(request) = event.message {
                    let event_id = event.id;
                    let protocol_name = request.protocol_name;
                    if rotate_tx
                        .try_send(QueuedRequest::Rotate {
                            event_id: event_id.clone(),
                            protocol_name: protocol_name.clone(),
                        })
                        .is_err()
                    {
                        if let Some(bus) = rotate_bus.upgrade() {
                            publish_rejected_queue(
                                &bus,
                                event_id,
                                TransportControlOperation::RotateProfile,
                                protocol_name,
                            );
                        }
                    }
                }
            }),
        );

        let active_bus = Arc::downgrade(&self.bus);
        publisher.subscribe_exact(
            ACTIVE_REQUEST_TOPIC,
            Box::new(move |_socket, payload| {
                let Ok(event) = payload.downcast::<BusEvent>() else {
                    return;
                };
                let event = *event;
                if let Message::TransportActiveRequest(request) = event.message {
                    let event_id = event.id;
                    let protocol_name = request.protocol_name;
                    if tx
                        .try_send(QueuedRequest::SetActive {
                            event_id: event_id.clone(),
                            protocol_name: protocol_name.clone(),
                        })
                        .is_err()
                    {
                        if let Some(bus) = active_bus.upgrade() {
                            publish_rejected_queue(
                                &bus,
                                event_id,
                                TransportControlOperation::SetActive,
                                Some(protocol_name),
                            );
                        }
                    }
                }
            }),
        );

        let runtime = Arc::clone(self);
        Ok(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEALTH_REPORT_INTERVAL);
            ticker.tick().await; // first tick is immediate; readiness was published by start()
            loop {
                tokio::select! {
                    request = rx.recv() => {
                        let Some(request) = request else { break; };
                        let (event_id, operation, target_protocol, result) = match request {
                            QueuedRequest::Rotate { event_id, protocol_name } => {
                                let result = runtime.rotate_profile(protocol_name.as_deref()).await;
                                (event_id, TransportControlOperation::RotateProfile, protocol_name, result)
                            }
                            QueuedRequest::SetActive { event_id, protocol_name } => {
                                let result = runtime.set_active(&protocol_name).await;
                                (event_id, TransportControlOperation::SetActive, Some(protocol_name), result)
                            }
                        };
                        runtime.report_outcome(Some(event_id), operation, target_protocol, &result).await;
                    }
                    _ = ticker.tick() => {
                        let current = runtime.status().await;
                        runtime.publish_status(TransportControlStatus {
                            request_event_id: None,
                            operation: TransportControlOperation::HealthCheck,
                            outcome: if current.ready { TransportControlOutcome::Applied } else { TransportControlOutcome::Rejected },
                            runtime_ready: current.ready,
                            active_protocol: current.active_protocol,
                            active_profile_id: current.active_profile_id,
                            target_protocol: None,
                            target_profile_id: None,
                            reason: (!current.ready).then_some("active backend process or health probe is not healthy".into()),
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        }))
    }

    fn publish_status(&self, status: TransportControlStatus) {
        if let Err(error) = BusEvent::publish(
            &self.bus,
            CONTROL_STATUS_TOPIC,
            Message::TransportControlStatus(status),
        ) {
            tracing::warn!(%error, "transport control outcome publication failed");
        }
    }
}

fn publish_rejected_queue(
    bus: &BusPublisher,
    event_id: EventId,
    operation: TransportControlOperation,
    target_protocol: Option<String>,
) {
    let status = TransportControlStatus {
        request_event_id: Some(event_id),
        operation,
        outcome: TransportControlOutcome::Rejected,
        runtime_ready: false,
        active_protocol: None,
        active_profile_id: None,
        target_protocol,
        target_profile_id: None,
        reason: Some("transport control queue is full or closed; readiness not verified".into()),
        timestamp: Utc::now(),
    };
    if let Err(error) = BusEvent::publish(
        bus,
        CONTROL_STATUS_TOPIC,
        Message::TransportControlStatus(status),
    ) {
        tracing::warn!(%error, "transport control queue rejection publication failed");
    }
}

impl Inner {
    fn receipt(
        &self,
        action: TransitionAction,
        selected: usize,
        previous_profile_id: Option<String>,
        changed: bool,
    ) -> TransitionReceipt {
        let active = &self.slots[self.active];
        let selected = &self.slots[selected];
        TransitionReceipt {
            action,
            active_protocol: active.profile.kind.name().into(),
            active_profile_id: active.profile.profile_id.clone(),
            selected_protocol: selected.profile.kind.name().into(),
            selected_profile_id: selected.profile.profile_id.clone(),
            previous_profile_id,
            changed,
            verified: true,
            active_path_verified: true,
            pid: selected.controller.pid(),
        }
    }
}

impl LiveProtocolProfile {
    fn validate(
        &self,
    ) -> Result<(PathBuf, VerifiedLaunch, Duration, VerifiedPathActions), LiveTransportError> {
        if self.profile_id.is_empty()
            || self.profile_id.len() > 64
            || !self
                .profile_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(LiveTransportError::InvalidProfile(
                "profile_id must be 1..64 ASCII letters, digits, dot, underscore or hyphen".into(),
            ));
        }
        let backend_binary = executable(&self.executable)?;
        let config = regular_readable_file(&self.config, "config")?;
        let health_binary = executable(&self.health_probe.executable)?;
        if !self.args.iter().any(|arg| arg.contains(CONFIG_TOKEN)) {
            return Err(LiveTransportError::InvalidProfile(format!(
                "{} launch arguments must include {CONFIG_TOKEN}",
                self.profile_id
            )));
        }
        if !self
            .health_probe
            .args
            .iter()
            .any(|arg| arg.contains(CONFIG_TOKEN))
        {
            return Err(LiveTransportError::InvalidProfile(format!(
                "{} health probe must include {CONFIG_TOKEN} to identify the candidate",
                self.profile_id
            )));
        }
        let config_text = config
            .to_str()
            .ok_or_else(|| {
                LiveTransportError::InvalidProfile("config path is not valid UTF-8".into())
            })?
            .to_string();
        let timeout = duration(self.health_probe.timeout_ms, "health probe timeout")?;
        let startup_timeout = duration(self.startup_timeout_ms, "startup timeout")?;
        let stop_timeout = duration(self.graceful_stop_timeout_ms, "stop timeout")?;
        let launch = VerifiedLaunch {
            config_path: config,
            args: replace_config(&self.args, &config_text),
            health_binary,
            health_args: replace_config(&self.health_probe.args, &config_text),
            health_timeout: timeout,
            startup_timeout,
        };
        let path = VerifiedPathActions {
            activate: self.activate.validate(&config_text, "activate")?,
            deactivate: self.deactivate.validate(&config_text, "deactivate")?,
            active_probe: self
                .active_path_probe
                .validate(&config_text, "active_path_probe")?,
        };
        Ok((backend_binary, launch, stop_timeout, path))
    }
}

impl LivePathCommand {
    fn validate(
        &self,
        config: &str,
        label: &str,
    ) -> Result<VerifiedPathCommand, LiveTransportError> {
        if !self.args.iter().any(|arg| arg.contains(CONFIG_TOKEN)) {
            return Err(LiveTransportError::InvalidProfile(format!(
                "{label} arguments must include {CONFIG_TOKEN}"
            )));
        }
        Ok(VerifiedPathCommand {
            executable: executable(&self.executable)?,
            args: replace_config(&self.args, config),
            timeout: duration(self.timeout_ms, label)?,
        })
    }
}

impl VerifiedPathCommand {
    async fn run(&self, label: &str) -> Result<(), LiveTransportError> {
        let mut command = Command::new(&self.executable);
        command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let status = tokio::time::timeout(self.timeout, command.status())
            .await
            .map_err(|_| LiveTransportError::PathCommand(format!("{label} timed out")))?
            .map_err(|error| {
                LiveTransportError::PathCommand(format!("{label} could not run: {error}"))
            })?;
        if !status.success() {
            return Err(LiveTransportError::PathCommand(format!(
                "{label} returned unsuccessful status"
            )));
        }
        Ok(())
    }
}

async fn restore_incumbent(
    incumbent: &VerifiedPathActions,
    attempted: &VerifiedPathActions,
) -> Result<(), LiveTransportError> {
    let deactivate_result = attempted
        .deactivate
        .run("deactivate failed candidate")
        .await;
    let restore_result = incumbent.activate.run("restore incumbent path").await;
    let probe_result = if restore_result.is_ok() {
        incumbent
            .active_probe
            .run("verify restored incumbent path")
            .await
    } else {
        restore_result
    };
    if deactivate_result.is_err() || probe_result.is_err() {
        return Err(LiveTransportError::RollbackFailed(
            "candidate cleanup or incumbent path verification failed".into(),
        ));
    }
    Ok(())
}

async fn switch_active_path(
    incumbent: &VerifiedPathActions,
    candidate: &VerifiedPathActions,
) -> Result<(), LiveTransportError> {
    if let Err(error) = incumbent.deactivate.run("deactivate incumbent path").await {
        if incumbent
            .activate
            .run("restore incumbent path")
            .await
            .is_err()
            || incumbent
                .active_probe
                .run("verify restored incumbent path")
                .await
                .is_err()
        {
            return Err(LiveTransportError::RollbackFailed(
                "incumbent path could not be verified".into(),
            ));
        }
        return Err(error);
    }
    if let Err(error) = candidate.activate.run("activate candidate path").await {
        restore_incumbent(incumbent, candidate).await?;
        return Err(error);
    }
    if let Err(error) = candidate
        .active_probe
        .run("verify candidate active path")
        .await
    {
        restore_incumbent(incumbent, candidate).await?;
        return Err(error);
    }
    Ok(())
}

fn parse_kind(name: &str) -> Result<ProtocolKind, LiveTransportError> {
    match name {
        "xray" => Ok(ProtocolKind::Xray),
        "amneziawg" => Ok(ProtocolKind::AmneziaWg),
        _ => Err(LiveTransportError::ProtocolUnavailable(name.into())),
    }
}

fn duration(value: u64, label: &str) -> Result<Duration, LiveTransportError> {
    if value == 0 || value > MAX_TIMEOUT_MS {
        return Err(LiveTransportError::InvalidProfile(format!(
            "{label} must be 1..={MAX_TIMEOUT_MS} ms"
        )));
    }
    Ok(Duration::from_millis(value))
}

fn executable(path: &Path) -> Result<PathBuf, LiveTransportError> {
    let canonical = regular_readable_file(path, "executable")?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        LiveTransportError::InvalidProfile(format!("{}: {error}", canonical.display()))
    })?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(LiveTransportError::InvalidProfile(format!(
            "{} is not executable",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn regular_readable_file(path: &Path, label: &str) -> Result<PathBuf, LiveTransportError> {
    if !path.is_absolute() {
        return Err(LiveTransportError::InvalidProfile(format!(
            "{label} path must be absolute: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        LiveTransportError::InvalidProfile(format!("{}: {error}", path.display()))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        LiveTransportError::InvalidProfile(format!("{label} {}: {error}", canonical.display()))
    })?;
    if !metadata.is_file() || fs::File::open(&canonical).is_err() {
        return Err(LiveTransportError::InvalidProfile(format!(
            "{label} must be a readable regular file: {}",
            canonical.display()
        )));
    }
    // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
    let uid = unsafe { libc::geteuid() };
    let overflow_uid = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    let overflow_system_binary = label == "executable"
        && overflow_uid == Some(metadata.uid())
        && (canonical.starts_with("/usr/bin") || canonical.starts_with("/bin"));
    if metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != uid && metadata.uid() != 0 && !overflow_system_binary)
    {
        return Err(LiveTransportError::InvalidProfile(format!(
            "{label} is writable by another user or has an untrusted owner: {}",
            canonical.display()
        )));
    }
    if let Some(parent) = canonical.parent() {
        for ancestor in parent.ancestors() {
            let ancestor_meta = fs::symlink_metadata(ancestor).map_err(|error| {
                LiveTransportError::InvalidProfile(format!(
                    "{label} ancestor {}: {error}",
                    ancestor.display()
                ))
            })?;
            let mode = ancestor_meta.permissions().mode();
            let sticky_tmp = ancestor == Path::new("/tmp") && mode & 0o1777 == 0o1777;
            if !ancestor_meta.file_type().is_dir()
                || (mode & 0o022 != 0 && !sticky_tmp)
                || (ancestor_meta.uid() != uid
                    && ancestor_meta.uid() != 0
                    && overflow_uid != Some(ancestor_meta.uid()))
                || (overflow_uid == Some(ancestor_meta.uid())
                    && ancestor.starts_with("/tmp")
                    && ancestor != Path::new("/tmp"))
            {
                return Err(LiveTransportError::InvalidProfile(format!(
                    "{label} has an untrusted writable ancestor: {}",
                    ancestor.display()
                )));
            }
        }
    }
    Ok(canonical)
}

fn replace_config(args: &[String], config: &str) -> Vec<String> {
    args.iter()
        .map(|arg| arg.replace(CONFIG_TOKEN, config))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "imperium-live-transport-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn config(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            // This is a test-only controllable child, never presented as an
            // Xray or AmneziaWG implementation or a tunnel acceptance test.
            fs::write(
                &path,
                "touch \"${0}.ready\"\ntrap 'rm -f \"${0}.ready\"; exit 0' TERM\nwhile :; do sleep 0.05; done\n",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn profile(
        id: &str,
        kind: ProtocolKind,
        config: PathBuf,
        probe_passes: bool,
    ) -> LiveProtocolProfile {
        let path_command = |script: &str| LivePathCommand {
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), script.into(), "sh".into(), "{config}".into()],
            timeout_ms: 500,
        };
        LiveProtocolProfile {
            profile_id: id.into(),
            kind,
            executable: "/bin/sh".into(),
            config,
            args: vec!["{config}".into()],
            health_probe: LiveHealthProbe {
                executable: if probe_passes {
                    "/bin/sh"
                } else {
                    "/bin/false"
                }
                .into(),
                args: if probe_passes {
                    vec![
                        "-c".into(),
                        "test -f \"${1}.ready\"".into(),
                        "sh".into(),
                        "{config}".into(),
                    ]
                } else {
                    vec!["{config}".into()]
                },
                timeout_ms: 200,
            },
            // These test-only marker commands stand in for an operator's
            // traffic switch and path probe; they prove the transition order,
            // never Xray/AmneziaWG routing or tunnel health.
            activate: path_command("touch \"${1}.active\""),
            deactivate: path_command("rm -f \"${1}.active\""),
            active_path_probe: path_command("test -f \"${1}.active\""),
            startup_timeout_ms: 800,
            graceful_stop_timeout_ms: 2_000,
        }
    }

    #[test]
    fn json_profiles_require_exact_paths_and_config_binding() {
        let dir = TestDirectory::new();
        let config = dir.config("xray-a.conf");
        let mut valid = profile("xray-a", ProtocolKind::Xray, config, true);
        let json = serde_json::to_string(&valid).unwrap();
        let parsed: LiveProtocolProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.profile_id, "xray-a");
        assert_eq!(parsed.kind, ProtocolKind::Xray);

        let bus = Arc::new(spiderweb::Bus::open().publisher());
        valid.executable = "/absent/xray".into();
        assert!(
            LiveTransportRuntime::new(Arc::clone(&bus), vec![valid.clone()], "xray-a").is_err()
        );
        valid.executable = "/bin/sh".into();
        valid.args = vec!["run".into()];
        assert!(LiveTransportRuntime::new(Arc::clone(&bus), vec![valid], "xray-a").is_err());
    }

    #[test]
    fn writable_backend_config_and_executable_are_rejected() {
        let dir = TestDirectory::new();
        let config = dir.config("writable.conf");
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mut candidate = profile("xray-a", ProtocolKind::Xray, config.clone(), true);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            LiveTransportRuntime::new(Arc::clone(&bus), vec![candidate.clone()], "xray-a").is_err()
        );

        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let launcher = dir.0.join("launcher");
        fs::write(&launcher, b"#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o777)).unwrap();
        candidate.executable = launcher.clone();
        assert!(
            LiveTransportRuntime::new(Arc::clone(&bus), vec![candidate.clone()], "xray-a").is_err()
        );
        candidate.executable = "/bin/sh".into();
        candidate.health_probe.executable = launcher;
        assert!(LiveTransportRuntime::new(bus, vec![candidate], "xray-a").is_err());
    }

    #[tokio::test]
    async fn verified_rotation_and_active_selection_change_real_children() {
        let dir = TestDirectory::new();
        let profiles = vec![
            profile(
                "xray-a",
                ProtocolKind::Xray,
                dir.config("xray-a.conf"),
                true,
            ),
            profile(
                "xray-b",
                ProtocolKind::Xray,
                dir.config("xray-b.conf"),
                true,
            ),
            profile(
                "awg-a",
                ProtocolKind::AmneziaWg,
                dir.config("awg-a.conf"),
                true,
            ),
        ];
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let runtime = LiveTransportRuntime::new(bus, profiles, "xray-a").unwrap();

        let started = runtime.start().await.unwrap();
        assert_eq!(started.active_profile_id, "xray-a");
        assert!(started.pid.is_some());
        assert!(runtime.status().await.ready);

        let rotated = runtime.rotate_profile(None).await.unwrap();
        assert_eq!(rotated.previous_profile_id.as_deref(), Some("xray-a"));
        assert_eq!(rotated.active_profile_id, "xray-b");
        assert_ne!(rotated.pid, started.pid);
        assert!(runtime.status().await.ready);

        let selected = runtime.set_active("amneziawg").await.unwrap();
        assert_eq!(selected.active_protocol, "amneziawg");
        assert_eq!(selected.active_profile_id, "awg-a");
        let status = runtime.status().await;
        assert!(status.ready);
        assert_eq!(
            status
                .profiles
                .iter()
                .filter(|profile| profile.active)
                .count(),
            1
        );

        runtime.shutdown().await.unwrap();
        let stopped = runtime.status().await;
        assert!(!stopped.started);
        assert!(!stopped.ready);
    }

    #[tokio::test]
    async fn failed_candidate_probe_keeps_incumbent_selected_and_healthy() {
        let dir = TestDirectory::new();
        let profiles = vec![
            profile(
                "xray-a",
                ProtocolKind::Xray,
                dir.config("xray-a.conf"),
                true,
            ),
            profile(
                "xray-b",
                ProtocolKind::Xray,
                dir.config("xray-b.conf"),
                false,
            ),
        ];
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let runtime = LiveTransportRuntime::new(bus, profiles, "xray-a").unwrap();
        let started = runtime.start().await.unwrap();

        assert!(runtime.rotate_profile(None).await.is_err());
        let status = runtime.status().await;
        assert!(status.ready);
        assert_eq!(status.active_profile_id.as_deref(), Some("xray-a"));
        let still_active = runtime.set_active("xray").await.unwrap();
        assert_eq!(still_active.pid, started.pid);

        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn failed_active_path_probe_restores_incumbent_path() {
        let dir = TestDirectory::new();
        let old_config = dir.config("xray-a.conf");
        let new_config = dir.config("xray-b.conf");
        let old_path_marker = PathBuf::from(format!("{}.active", old_config.display()));
        let new_path_marker = PathBuf::from(format!("{}.active", new_config.display()));
        let mut candidate = profile("xray-b", ProtocolKind::Xray, new_config, true);
        candidate.active_path_probe = LivePathCommand {
            executable: "/bin/false".into(),
            args: vec!["{config}".into()],
            timeout_ms: 200,
        };
        let profiles = vec![
            profile("xray-a", ProtocolKind::Xray, old_config, true),
            candidate,
        ];
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let runtime = LiveTransportRuntime::new(bus, profiles, "xray-a").unwrap();
        runtime.start().await.unwrap();
        assert!(old_path_marker.exists());

        assert!(runtime.rotate_profile(None).await.is_err());
        assert!(old_path_marker.exists(), "incumbent path was not restored");
        assert!(
            !new_path_marker.exists(),
            "failed candidate path was not undone"
        );
        let status = runtime.status().await;
        assert!(status.ready);
        assert_eq!(status.active_profile_id.as_deref(), Some("xray-a"));

        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn bus_requests_report_applied_or_rejected_after_verified_transition() {
        let dir = TestDirectory::new();
        let profiles = vec![
            profile(
                "xray-a",
                ProtocolKind::Xray,
                dir.config("xray-a.conf"),
                true,
            ),
            profile(
                "xray-b",
                ProtocolKind::Xray,
                dir.config("xray-b.conf"),
                true,
            ),
            profile(
                "awg-a",
                ProtocolKind::AmneziaWg,
                dir.config("awg-a.conf"),
                true,
            ),
        ];
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let (status_tx, mut status_rx) = mpsc::unbounded_channel();
        bus.subscribe_exact(
            CONTROL_STATUS_TOPIC,
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    if let Message::TransportControlStatus(status) = event.message {
                        let _ = status_tx.send(status);
                    }
                }
            }),
        );
        let runtime =
            Arc::new(LiveTransportRuntime::new(Arc::clone(&bus), profiles, "xray-a").unwrap());
        let worker = runtime.subscribe_commands(&bus).unwrap();
        assert!(matches!(
            runtime.subscribe_commands(&bus),
            Err(LiveTransportError::AlreadySubscribed)
        ));
        runtime.start().await.unwrap();
        let ready = status_rx.recv().await.unwrap();
        assert_eq!(ready.operation, TransportControlOperation::RuntimeReady);
        assert_eq!(ready.outcome, TransportControlOutcome::Applied);
        assert!(ready.runtime_ready);

        let rotate = BusEvent::new(
            PROFILE_ROTATION_TOPIC,
            Message::ProfileRotationRequest(imperium_protocol::ProfileRotationRequest {
                protocol_name: None,
                reason: "operator test request".into(),
                requested_at: Utc::now(),
            }),
        );
        let rotate_id = rotate.id.clone();
        bus.publish(PROFILE_ROTATION_TOPIC, rotate).unwrap();
        let rotated = tokio::time::timeout(Duration::from_secs(3), status_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.request_event_id.as_ref().unwrap().0, rotate_id.0);
        assert_eq!(rotated.operation, TransportControlOperation::RotateProfile);
        assert_eq!(rotated.outcome, TransportControlOutcome::Applied);
        assert_eq!(rotated.active_profile_id.as_deref(), Some("xray-b"));
        assert_eq!(rotated.target_profile_id.as_deref(), Some("xray-b"));

        let activate = BusEvent::new(
            ACTIVE_REQUEST_TOPIC,
            Message::TransportActiveRequest(imperium_protocol::TransportActiveRequest {
                protocol_name: "amneziawg".into(),
                requested_at: Utc::now(),
            }),
        );
        bus.publish(ACTIVE_REQUEST_TOPIC, activate).unwrap();
        let activated = tokio::time::timeout(Duration::from_secs(3), status_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(activated.operation, TransportControlOperation::SetActive);
        assert_eq!(activated.outcome, TransportControlOutcome::Applied);
        assert_eq!(activated.active_protocol.as_deref(), Some("amneziawg"));

        let rejected = BusEvent::new(
            PROFILE_ROTATION_TOPIC,
            Message::ProfileRotationRequest(imperium_protocol::ProfileRotationRequest {
                protocol_name: Some("amneziawg".into()),
                reason: "no alternate".into(),
                requested_at: Utc::now(),
            }),
        );
        bus.publish(PROFILE_ROTATION_TOPIC, rejected).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(3), status_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.operation, TransportControlOperation::RotateProfile);
        assert_eq!(outcome.outcome, TransportControlOutcome::Rejected);
        assert_eq!(outcome.active_profile_id.as_deref(), Some("awg-a"));
        assert!(outcome.reason.as_deref().unwrap().contains("no alternate"));
        assert!(runtime.status().await.ready);

        worker.abort();
        runtime.shutdown().await.unwrap();
    }
}
