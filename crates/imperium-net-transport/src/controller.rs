use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_managed_process::{ManagedProcess, ProcessConfig, ResourceBudget, RestartPolicy};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    Message, PaddingDistribution, ProtocolCommand, ProtocolCommandKind, ProtocolEvent,
    ProtocolEventKind, ProtocolHardeningProfile, ProtocolRole, ProtocolStatus,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use spiderweb::BusPublisher;
use thiserror::Error;
use tokio::process::Command;

/// Depth of a consumer-owned subscription queue; parity with the depth the
/// deleted shim gave every subscription.
const SUBSCRIPTION_QUEUE: usize = 1024;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("process error: {0}")]
    Process(#[from] imperium_managed_process::ProcessError),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
    #[error("protocol not configured")]
    NotConfigured,
    #[error("protocol process is already running")]
    AlreadyRunning,
    #[error("protocol health check failed: {0}")]
    Unhealthy(String),
    #[error("protocol launch invalid: {0}")]
    InvalidLaunch(String),
}

/// A launch contract validated from an explicit operator profile. This is
/// intentionally separate from config rendering: no template output silently
/// becomes a backend command or a claim that traffic was routed.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedLaunch {
    pub config_path: PathBuf,
    pub args: Vec<String>,
    pub health_binary: PathBuf,
    pub health_args: Vec<String>,
    pub health_timeout: Duration,
    pub startup_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    Xray,
    AmneziaWg,
}

impl ProtocolKind {
    pub(crate) const fn index(self) -> usize {
        match self {
            ProtocolKind::Xray => 0,
            ProtocolKind::AmneziaWg => 1,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ProtocolKind::Xray => "xray",
            ProtocolKind::AmneziaWg => "amneziawg",
        }
    }

    /// The **static** Spiderweb routing socket this kind's protocol events go
    /// out on.
    ///
    /// Spiderweb routing keys are `&'static str`, while the envelope topic for
    /// this family is built at runtime (`net.transport.event.{kind}`). The set
    /// is closed — two variants, two sockets — so the socket is enumerated here
    /// rather than interned, and the envelope keeps its dynamic topic so a
    /// subscriber that filters on `event.topic` sees exactly what it saw before.
    pub const fn event_socket(&self) -> &'static str {
        match self {
            ProtocolKind::Xray => "net.transport.event.xray",
            ProtocolKind::AmneziaWg => "net.transport.event.amneziawg",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolControllerConfig {
    pub kind: ProtocolKind,
    pub binary_path: PathBuf,
    pub config_template: String,
    pub health_check_interval: Duration,
    pub graceful_stop_timeout: Duration,
}

pub struct ProtocolController {
    config: ProtocolControllerConfig,
    role: Arc<RwLock<ProtocolRole>>,
    status: Arc<RwLock<ProtocolStatus>>,
    hardening_profile: Arc<RwLock<Option<ProtocolHardeningProfile>>>,
    process: Option<ManagedProcess>,
    launch: Option<VerifiedLaunch>,
    bus: Arc<BusPublisher>,
}

impl ProtocolController {
    pub fn new(config: ProtocolControllerConfig, bus: Arc<BusPublisher>) -> Self {
        Self {
            config,
            role: Arc::new(RwLock::new(ProtocolRole::Standby)),
            status: Arc::new(RwLock::new(ProtocolStatus::Stopped)),
            hardening_profile: Arc::new(RwLock::new(None)),
            process: None,
            launch: None,
            bus,
        }
    }

    pub(crate) fn with_verified_launch(mut self, launch: VerifiedLaunch) -> Self {
        self.launch = Some(launch);
        self
    }

    pub fn protocol_name(&self) -> String {
        self.config.kind.name().to_string()
    }

    pub fn role(&self) -> ProtocolRole {
        self.role.read().clone()
    }

    pub fn status(&self) -> ProtocolStatus {
        self.status.read().clone()
    }

    pub fn set_role(&self, role: ProtocolRole) {
        *self.role.write() = role;
    }

    pub fn apply_hardening_profile(&self, profile: ProtocolHardeningProfile) {
        *self.hardening_profile.write() = Some(profile);
    }

    /// Consume applied hardening profiles from an owned bounded queue.
    ///
    /// The consumer owns the queue: native delivery is push-based and the kernel
    /// keeps no per-subscriber queue, so the callback (which runs on the
    /// publisher's thread) does one non-blocking send and nothing else. A full
    /// queue drops THIS event and counts it; the loop reports the count before
    /// the next event, so a slow consumer still observes its own gap. The loop
    /// ends when every sender is gone.
    pub fn subscribe_hardening_profiles(
        self: &Arc<Self>,
        publisher: &BusPublisher,
    ) -> tokio::task::JoinHandle<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(SUBSCRIPTION_QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let drops = Arc::clone(&dropped);
        publisher.subscribe_prefix(
            "net.transport.hardening.apply",
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    if tx.try_send(*event).is_err() {
                        drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }),
        );

        let controller = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let lagged = dropped.swap(0, Ordering::Relaxed);
                if lagged > 0 {
                    tracing::warn!(
                        lagged,
                        "hardening-profile subscription queue overflowed; events were dropped"
                    );
                }
                if let Message::ProtocolHardeningProfile(profile) = event.message {
                    let applies_to_this_controller = match profile.protocol_name.as_deref() {
                        None => true,
                        Some(name) => name == controller.protocol_name(),
                    };
                    if applies_to_this_controller {
                        controller.apply_hardening_profile(profile);
                    }
                }
            }
        })
    }

    pub async fn start(&mut self) -> Result<(), ControllerError> {
        if self.process.is_some() {
            return Err(ControllerError::AlreadyRunning);
        }
        let launch = self.launch.clone().ok_or(ControllerError::NotConfigured)?;
        std::fs::File::open(&launch.config_path).map_err(|error| {
            ControllerError::InvalidLaunch(format!(
                "config {} is not readable: {error}",
                launch.config_path.display()
            ))
        })?;
        let proc_config = ProcessConfig {
            binary: self.config.binary_path.clone(),
            args: launch.args.clone(),
            env: HashMap::new(),
            health_check_interval: self.config.health_check_interval,
            restart_policy: RestartPolicy::Never,
            budget: ResourceBudget::default(),
            graceful_stop_timeout: self.config.graceful_stop_timeout,
        };

        let mut managed = ManagedProcess::new(proc_config);
        managed.start().await?;

        let deadline = Instant::now() + launch.startup_timeout;
        loop {
            if !managed.check_health().await {
                *self.status.write() = ProtocolStatus::Failed;
                return Err(ControllerError::Unhealthy(
                    "backend process exited during startup".into(),
                ));
            }
            match run_health_probe(&launch).await {
                Ok(true) if managed.check_health().await => break,
                Ok(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok(_) => {
                    let _ = managed.stop().await;
                    *self.status.write() = ProtocolStatus::Failed;
                    return Err(ControllerError::Unhealthy(
                        "backend health probe did not pass before startup deadline".into(),
                    ));
                }
                Err(error) => {
                    let _ = managed.stop().await;
                    *self.status.write() = ProtocolStatus::Failed;
                    return Err(error);
                }
            }
        }

        self.process = Some(managed);

        *self.status.write() = ProtocolStatus::Running;
        self.emit_event(ProtocolEventKind::Started)?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ControllerError> {
        if let Some(ref mut proc) = self.process {
            if let Err(error) = proc.stop().await {
                if !matches!(error, imperium_managed_process::ProcessError::NotRunning) {
                    return Err(error.into());
                }
            }
        }
        self.process = None;
        *self.status.write() = ProtocolStatus::Stopped;
        self.emit_event(ProtocolEventKind::Stopped)?;
        Ok(())
    }

    /// Reuse a verified process or replace an unhealthy one. The caller keeps
    /// any incumbent transport active until this candidate returns success.
    pub(crate) async fn ensure_healthy_running(&mut self) -> Result<(), ControllerError> {
        if self.process.is_some() {
            if self.check_health().await {
                return Ok(());
            }
            self.stop().await?;
        }
        self.start().await
    }

    pub async fn check_health(&mut self) -> bool {
        if let Some(ref mut proc) = self.process {
            let process_healthy = proc.check_health().await;
            let probe_healthy = if process_healthy {
                match &self.launch {
                    Some(launch) => run_health_probe(launch).await.unwrap_or(false),
                    None => false,
                }
            } else {
                false
            };
            let healthy = process_healthy && probe_healthy;
            if !healthy {
                *self.status.write() = ProtocolStatus::Failed;
                let _ = self.emit_event(ProtocolEventKind::Crashed {
                    reason: "process exited unexpectedly".into(),
                });
            }
            healthy
        } else {
            false
        }
    }

    pub fn handle_command(&mut self, cmd: &ProtocolCommand) {
        if cmd.protocol_name != self.protocol_name() {
            return;
        }

        match cmd.command {
            ProtocolCommandKind::PromoteToActive => {
                self.set_role(ProtocolRole::Active);
            }
            ProtocolCommandKind::DemoteToStandby => {
                self.set_role(ProtocolRole::Standby);
            }
            ProtocolCommandKind::Quarantine => {
                self.set_role(ProtocolRole::Quarantined);
            }
            _ => {}
        }
    }

    pub fn render_config(&self, params: &HashMap<String, String>) -> String {
        let mut rendered = self.config.config_template.clone();
        let mut merged = params.clone();

        if let Some(profile) = self.hardening_profile.read().clone() {
            merged.extend(hardening_template_params(&profile));
        }

        for (key, value) in merged {
            rendered = rendered.replace(&format!("{{{{{}}}}}", key), &value);
        }

        rendered
    }

    pub fn parse_status(&self, _output: &str) -> ProtocolStatus {
        self.status()
    }

    fn emit_event(&self, event: ProtocolEventKind) -> Result<(), ControllerError> {
        let protocol_event = ProtocolEvent {
            protocol_name: self.protocol_name(),
            role: self.role(),
            status: self.status(),
            event,
            timestamp: Utc::now(),
        };

        // Static socket, dynamic topic: see `ProtocolKind::event_socket`.
        let socket = self.config.kind.event_socket();
        let topic = format!("net.transport.event.{}", self.config.kind.name());
        self.bus.publish(
            socket,
            BusEvent::new(topic, Message::ProtocolEvt(protocol_event)),
        )?;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.status() == ProtocolStatus::Running
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.process.as_ref().and_then(ManagedProcess::pid)
    }
}

async fn run_health_probe(launch: &VerifiedLaunch) -> Result<bool, ControllerError> {
    let mut command = Command::new(&launch.health_binary);
    command
        .args(&launch.health_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(launch.health_timeout, command.status())
        .await
        .map_err(|_| ControllerError::Unhealthy("health probe timed out".into()))?
        .map_err(|error| {
            ControllerError::Unhealthy(format!("health probe failed to start: {error}"))
        })?;
    Ok(status.success())
}

fn hardening_template_params(profile: &ProtocolHardeningProfile) -> HashMap<String, String> {
    let mut params = HashMap::new();
    params.insert(
        "hardening.profile_id".to_string(),
        profile.profile_id.clone(),
    );
    params.insert(
        "hardening.protocol_name".to_string(),
        profile.protocol_name.clone().unwrap_or_default(),
    );
    params.insert(
        "hardening.padding.mode".to_string(),
        match &profile.traffic_morph.padding {
            PaddingDistribution::None => "none".to_string(),
            PaddingDistribution::Fixed { .. } => "fixed".to_string(),
            PaddingDistribution::Bucketed { .. } => "bucketed".to_string(),
            PaddingDistribution::Envelope { .. } => "envelope".to_string(),
        },
    );
    params.insert(
        "hardening.padding.max_overhead_ppm".to_string(),
        profile.traffic_morph.max_padding_overhead_ppm.to_string(),
    );
    params.insert(
        "hardening.jitter.floor_ms".to_string(),
        profile.traffic_morph.jitter_floor_ms.to_string(),
    );
    params.insert(
        "hardening.jitter.ceiling_ms".to_string(),
        profile.traffic_morph.jitter_ceiling_ms.to_string(),
    );
    params.insert(
        "hardening.cover_traffic_ppm".to_string(),
        profile.traffic_morph.cover_traffic_ppm.to_string(),
    );
    params.insert(
        "hardening.rekey.max_age_seconds".to_string(),
        profile.rekey.max_key_age_seconds.to_string(),
    );
    params.insert(
        "hardening.rekey.max_key_bytes".to_string(),
        profile.rekey.max_key_bytes.to_string(),
    );
    params.insert(
        "hardening.probe.auth_first_packet".to_string(),
        profile
            .probe_resistance
            .authenticated_first_packet_required
            .to_string(),
    );
    params.insert(
        "hardening.deception.enabled".to_string(),
        profile.probe_deception.enabled.to_string(),
    );
    params.insert(
        "hardening.deception.mode".to_string(),
        format!("{:?}", profile.probe_deception.mode),
    );
    params.insert(
        "hardening.deception.min_confidence".to_string(),
        format!("{:.3}", profile.probe_deception.min_confidence),
    );
    params.insert(
        "hardening.deception.max_transcript_bytes".to_string(),
        profile.probe_deception.max_transcript_bytes.to_string(),
    );
    params.insert(
        "hardening.path_hopping.enabled".to_string(),
        profile.path_hopping.enabled.to_string(),
    );
    params.insert(
        "hardening.fec.enabled".to_string(),
        profile.fec.enabled.to_string(),
    );
    params.insert(
        "hardening.fec.data_shards".to_string(),
        profile.fec.data_shards.to_string(),
    );
    params.insert(
        "hardening.fec.parity_shards".to_string(),
        profile.fec.parity_shards.to_string(),
    );

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(kind: ProtocolKind) -> ProtocolControllerConfig {
        ProtocolControllerConfig {
            kind,
            binary_path: PathBuf::from("echo"),
            config_template: String::new(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn controller_role_management() {
        let (_bus, publisher) = crate::test_supervision::open();
        let ctrl = ProtocolController::new(test_config(ProtocolKind::Xray), Arc::clone(&publisher));

        assert_eq!(ctrl.role(), ProtocolRole::Standby);
        ctrl.set_role(ProtocolRole::Active);
        assert_eq!(ctrl.role(), ProtocolRole::Active);
    }

    #[test]
    fn protocol_names() {
        let (_bus, publisher) = crate::test_supervision::open();
        let xray = ProtocolController::new(test_config(ProtocolKind::Xray), Arc::clone(&publisher));
        let awg =
            ProtocolController::new(test_config(ProtocolKind::AmneziaWg), Arc::clone(&publisher));

        assert_eq!(xray.protocol_name(), "xray");
        assert_eq!(awg.protocol_name(), "amneziawg");
    }

    #[test]
    fn render_config_includes_hardening_params() {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = ProtocolControllerConfig {
            kind: ProtocolKind::Xray,
            binary_path: PathBuf::from("echo"),
            config_template: concat!(
                "profile={{hardening.profile_id}}\n",
                "padding={{hardening.padding.mode}}\n",
                "jitter={{hardening.jitter.floor_ms}}-{{hardening.jitter.ceiling_ms}}\n",
                "deception={{hardening.deception.mode}}\n",
                "fec={{hardening.fec.data_shards}}/{{hardening.fec.parity_shards}}\n",
                "custom={{operator.value}}\n"
            )
            .to_string(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        };
        let ctrl = ProtocolController::new(config, Arc::clone(&publisher));
        ctrl.apply_hardening_profile(crate::HardeningController::resilience_profile(Some(
            "xray".to_string(),
        )));

        let mut params = HashMap::new();
        params.insert("operator.value".to_string(), "enabled".to_string());
        let rendered = ctrl.render_config(&params);

        assert!(rendered.contains("profile=resilience-rf-inspired"));
        assert!(rendered.contains("padding=envelope"));
        assert!(rendered.contains("jitter=5-50"));
        assert!(rendered.contains("deception=ShadowEndpoint"));
        assert!(rendered.contains("fec=10/4"));
        assert!(rendered.contains("custom=enabled"));
    }

    #[tokio::test]
    async fn hardening_subscription_updates_config_rendering() {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = ProtocolControllerConfig {
            kind: ProtocolKind::Xray,
            binary_path: PathBuf::from("echo"),
            config_template: "profile={{hardening.profile_id}}".to_string(),
            health_check_interval: Duration::from_secs(5),
            graceful_stop_timeout: Duration::from_secs(5),
        };
        let ctrl = Arc::new(ProtocolController::new(config, Arc::clone(&publisher)));
        let _sub = ctrl.subscribe_hardening_profiles(&publisher);

        assert_eq!(
            ctrl.render_config(&HashMap::new()),
            "profile={{hardening.profile_id}}"
        );

        BusEvent::publish(
            &publisher,
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(crate::HardeningController::resilience_profile(
                Some("xray".to_string()),
            )),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            ctrl.render_config(&HashMap::new()),
            "profile=resilience-rf-inspired"
        );
    }
}
