use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};
use std::time::Duration;

use imperium_net_host::{HostGuardMode, HostKillSwitch};
use imperium_net_lightcone::LightconeService;
use imperium_net_mesh::MeshDaemon;
use imperium_net_signatures::{CandidateStatus, StagingArea};
use imperium_net_transport::LiveTransportRuntime;
use imperium_protocol::{
    BusEvent, KillSwitchCommand, KillSwitchState, MasqueTunnelConfig, Message, PolicyApplyRequest,
    ProtocolHardeningProfile, ToolActivationRequest, TransportControlOperation, VpnDeploymentPlan,
    VpnDeploymentStatusRequest,
};
use spiderweb::BusPublisher;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_COMMAND_BYTES: usize = 8 * 1024;
const MAX_CONNECTIONS: usize = 32;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub type HostGuardHandle = Arc<tokio::sync::Mutex<HostKillSwitch>>;

fn reply(status: &'static str, message: impl AsRef<str>) -> String {
    serde_json::json!({"status": status, "message": message.as_ref()}).to_string()
}

/// Live state used by the control health endpoint. The host-interface flag
/// records startup configuration; link and runner state are sampled per request.
#[derive(Clone)]
pub struct MeshHealth {
    daemon: Arc<MeshDaemon>,
    host_interface_configured: bool,
    runner_active: Arc<AtomicBool>,
    host_bridge_active: Option<Arc<AtomicBool>>,
}

impl MeshHealth {
    pub fn new(
        daemon: Arc<MeshDaemon>,
        host_interface_configured: bool,
        runner_active: Arc<AtomicBool>,
        host_bridge_active: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            daemon,
            host_interface_configured,
            runner_active,
            host_bridge_active,
        }
    }

    fn response(&self) -> String {
        let runner_active = self.runner_active.load(Ordering::Acquire);
        let host_bridge_active = self
            .host_bridge_active
            .as_ref()
            .is_some_and(|active| active.load(Ordering::Acquire));
        let established_peers = self.daemon.established_peers().len();
        let configured_peers = self.daemon.config().peers.len();
        let mesh_killed = self.daemon.is_killed();
        let (status, message) = if !runner_active {
            ("degraded", "mesh daemon is not running")
        } else if mesh_killed {
            ("degraded", "mesh data path is blocked by the kill switch")
        } else if established_peers == 0 {
            ("degraded", "no mesh peer session is established")
        } else if !self.host_interface_configured {
            (
                "degraded",
                "mesh link is established without a host tunnel interface",
            )
        } else if !host_bridge_active {
            ("degraded", "host tunnel bridge is not running")
        } else {
            ("ok", "mesh link and host tunnel bridge are running")
        };
        serde_json::json!({
            "status": status,
            "message": message,
            "node_control_online": true,
            "mesh_bound": true,
            "mesh_runner_active": runner_active,
            "mesh_killed": mesh_killed,
            "established_peers": established_peers,
            "configured_peers": configured_peers,
            "host_interface_configured": self.host_interface_configured,
            "host_bridge_active": host_bridge_active,
            "local_addr": self.daemon.local_addr().ok().map(|addr| addr.to_string()),
        })
        .to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum LightconeLifecycleState {
    Unknown = 0,
    Running = 1,
    Crashed = 2,
    Quarantined = 3,
    Detached = 4,
}

impl LightconeLifecycleState {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Running => "running",
            Self::Crashed => "crashed",
            Self::Quarantined => "quarantined",
            Self::Detached => "detached",
        }
    }
}

/// Tracks the supervised Lightcone strand independently of its retained
/// receipt ledger. Subscribe before supervision begins; named events do not replay.
#[derive(Clone)]
pub struct LightconeLifecycleMonitor {
    state: Arc<AtomicU8>,
}

impl LightconeLifecycleMonitor {
    pub fn subscribe(publisher: &BusPublisher) -> Self {
        let monitor = Self {
            state: Arc::new(AtomicU8::new(LightconeLifecycleState::Unknown as u8)),
        };
        let state = Arc::clone(&monitor.state);
        publisher.subscribe_exact(
            spiderweb::SYS_LIFECYCLE,
            Box::new(move |_socket, payload| {
                let Ok(event) = payload.downcast::<spiderweb::LifecycleEvent>() else {
                    return;
                };
                use spiderweb::LifecycleEvent;
                let next = match event.as_ref() {
                    LifecycleEvent::Registered { name, .. }
                    | LifecycleEvent::Restarted { name, .. }
                        if name == imperium_net_lightcone::NAME =>
                    {
                        Some(LightconeLifecycleState::Running)
                    }
                    LifecycleEvent::Crashed { name, .. }
                        if name == imperium_net_lightcone::NAME =>
                    {
                        Some(LightconeLifecycleState::Crashed)
                    }
                    LifecycleEvent::Quarantined { name, .. }
                        if name == imperium_net_lightcone::NAME =>
                    {
                        Some(LightconeLifecycleState::Quarantined)
                    }
                    LifecycleEvent::Detached { name } if name == imperium_net_lightcone::NAME => {
                        Some(LightconeLifecycleState::Detached)
                    }
                    _ => None,
                };
                if let Some(next) = next {
                    state.store(next as u8, Ordering::Release);
                }
            }),
        );
        monitor
    }

    fn state(&self) -> LightconeLifecycleState {
        match self.state.load(Ordering::Acquire) {
            1 => LightconeLifecycleState::Running,
            2 => LightconeLifecycleState::Crashed,
            3 => LightconeLifecycleState::Quarantined,
            4 => LightconeLifecycleState::Detached,
            _ => LightconeLifecycleState::Unknown,
        }
    }
}

/// Address of the control surface (Unix domain socket path).
pub fn control_endpoint() -> String {
    unix::socket_path().to_string_lossy().into_owned()
}

#[derive(Clone)]
struct ControlState {
    bus: Arc<BusPublisher>,
    staging: Option<Arc<StagingArea>>,
    mesh: Option<MeshHealth>,
    lightcone: Option<Arc<LightconeService>>,
    lightcone_lifecycle: LightconeLifecycleMonitor,
    transport: Option<Arc<LiveTransportRuntime>>,
    host_guard: Option<HostGuardHandle>,
}

impl ControlState {
    fn new(
        bus: Arc<BusPublisher>,
        staging: Option<Arc<StagingArea>>,
        mesh: Option<MeshHealth>,
        lightcone: Option<Arc<LightconeService>>,
        lightcone_lifecycle: LightconeLifecycleMonitor,
        transport: Option<Arc<LiveTransportRuntime>>,
        host_guard: Option<HostGuardHandle>,
    ) -> Self {
        Self {
            bus,
            staging,
            mesh,
            lightcone,
            lightcone_lifecycle,
            transport,
            host_guard,
        }
    }
}

pub async fn serve_with_staging(
    bus: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    mesh: Option<MeshHealth>,
    lightcone: Option<Arc<LightconeService>>,
    lightcone_lifecycle: LightconeLifecycleMonitor,
    transport: Option<Arc<LiveTransportRuntime>>,
    host_guard: Option<HostGuardHandle>,
) {
    serve_inner(Arc::new(ControlState::new(
        bus,
        Some(staging),
        mesh,
        lightcone,
        lightcone_lifecycle,
        transport,
        host_guard,
    )))
    .await;
}

async fn serve_inner(state: Arc<ControlState>) {
    unix::serve(state).await;
}

// Line-delimited request/response over any byte stream. Kept generic over
// AsyncRead + AsyncWrite so the socket listener and this handler stay decoupled.
async fn handle_connection<S>(stream: S, state: Arc<ControlState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    loop {
        let line = match tokio::time::timeout(COMMAND_TIMEOUT, read_bounded_line(&mut reader)).await
        {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                let _ = writer
                    .write_all(format!("{}\n", reply("error", error.to_string())).as_bytes())
                    .await;
                break;
            }
            Err(_) => break,
        };
        let response = dispatch_connection_command(&line, &state).await;
        if writer.write_all(response.as_bytes()).await.is_err()
            || writer.write_all(b"\n").await.is_err()
        {
            break;
        }
    }
}

async fn dispatch_connection_command(line: &str, state: &ControlState) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.as_slice() {
        ["vpn", "profile", "rotate"] | ["vpn", "profile", "rotate", _] => {
            let Some(runtime) = state.transport.as_ref() else {
                return reply("error", "live transport profiles are not configured");
            };
            let target = parts.get(3).copied();
            let result = runtime.rotate_profile(target).await;
            runtime
                .report_outcome(
                    None,
                    TransportControlOperation::RotateProfile,
                    target.map(ToString::to_string),
                    &result,
                )
                .await;
            match result {
                Ok(transition) => serde_json::json!({
                    "status": "ok",
                    "message": "profile rotation applied after backend and active-path verification",
                    "transition": transition,
                })
                .to_string(),
                Err(error) => reply("error", format!("profile rotation rejected: {error}")),
            }
        }
        ["vpn", "transport", "set-active", protocol] => {
            let Some(runtime) = state.transport.as_ref() else {
                return reply("error", "live transport profiles are not configured");
            };
            let result = runtime.set_active(protocol).await;
            runtime
                .report_outcome(
                    None,
                    TransportControlOperation::SetActive,
                    Some((*protocol).to_string()),
                    &result,
                )
                .await;
            match result {
                Ok(transition) => serde_json::json!({
                    "status": "ok",
                    "message": "active transport applied after backend and active-path verification",
                    "transition": transition,
                })
                .to_string(),
                Err(error) => reply("error", format!("active transport rejected: {error}")),
            }
        }
        ["vpn", "health"] => render_node_health(state).await,
        ["vpn", "killswitch", mode, reason @ ..] => {
            let reason = if reason.is_empty() {
                "operator requested killswitch change".to_string()
            } else {
                reason.join(" ")
            };
            apply_kill_switch(state, mode, &reason).await
        }
        _ => dispatch_command_with_health(
            line,
            &state.bus,
            state.staging.as_deref(),
            state.mesh.as_ref(),
            state.lightcone.as_deref(),
            Some(&state.lightcone_lifecycle),
        ),
    }
}

async fn render_node_health(state: &ControlState) -> String {
    let response = dispatch_command_with_health(
        "vpn health",
        &state.bus,
        state.staging.as_deref(),
        state.mesh.as_ref(),
        state.lightcone.as_deref(),
        Some(&state.lightcone_lifecycle),
    );
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&response) else {
        return reply("error", "node health could not be serialized");
    };
    let (mode, table) = host_guard_snapshot(state.host_guard.as_ref()).await;
    if let Some(fields) = value.as_object_mut() {
        fields.insert("host_guard_installed".into(), mode.is_some().into());
        fields.insert(
            "host_guard_mode".into(),
            mode.map(host_guard_mode_label)
                .unwrap_or("unavailable")
                .into(),
        );
        fields.insert(
            "host_egress_blocked".into(),
            (mode == Some(HostGuardMode::Engaged)).into(),
        );
        fields.insert("host_guard_table".into(), serde_json::json!(table));
    }
    value.to_string()
}

async fn host_guard_snapshot(
    guard: Option<&HostGuardHandle>,
) -> (Option<HostGuardMode>, Option<String>) {
    match guard {
        Some(guard) => {
            let guard = guard.lock().await;
            (Some(guard.mode()), Some(guard.table_name().to_string()))
        }
        None => (None, None),
    }
}

fn host_guard_mode_label(mode: HostGuardMode) -> &'static str {
    match mode {
        HostGuardMode::Armed => "armed",
        HostGuardMode::Engaged => "engaged",
        HostGuardMode::Disarmed => "disarmed",
    }
}

async fn apply_kill_switch(state: &ControlState, mode: &str, reason: &str) -> String {
    let (mesh_state, host_state) = match mode {
        "engage" | "engaged" => (KillSwitchState::Engaged, HostGuardMode::Engaged),
        "arm" | "armed" => (KillSwitchState::Armed, HostGuardMode::Armed),
        "disarm" | "disarmed" => (KillSwitchState::Disarmed, HostGuardMode::Disarmed),
        _ => return reply("error", "unknown killswitch state"),
    };
    if state.mesh.is_none() && state.host_guard.is_none() {
        return reply("error", "neither mesh VPN nor opt-in host guard is running");
    }

    // Host blocking goes first on Engage. For Arm/Disarm, the mesh resumes
    // before host blocking is removed, so a failed step retains the block.
    if matches!(host_state, HostGuardMode::Engaged) {
        if let Some(guard) = &state.host_guard {
            if let Err(error) = guard.lock().await.set_mode(host_state) {
                return reply("error", format!("host guard engage failed: {error}"));
            }
        }
    }
    if let Some(mesh) = state.mesh.as_ref() {
        if let Err(error) = apply_mesh_kill_switch(&state.bus, mesh, &mesh_state, reason) {
            let (mode, _) = host_guard_snapshot(state.host_guard.as_ref()).await;
            return serde_json::json!({
                "status": "error",
                "message": error,
                "host_guard_mode": mode.map(host_guard_mode_label).unwrap_or("unavailable"),
                "host_egress_blocked": mode == Some(HostGuardMode::Engaged),
            })
            .to_string();
        }
    }
    if !matches!(host_state, HostGuardMode::Engaged) {
        if let Some(guard) = &state.host_guard {
            if let Err(error) = guard.lock().await.set_mode(host_state) {
                return reply("error", format!("host guard mode change failed: {error}"));
            }
        }
    }

    let (host_mode, table) = host_guard_snapshot(state.host_guard.as_ref()).await;
    let mesh_blocked = state
        .mesh
        .as_ref()
        .is_some_and(|mesh| mesh.daemon.is_killed());
    let host_blocked = host_mode == Some(HostGuardMode::Engaged);
    let message = if host_blocked {
        "host non-loopback egress blocked; mesh data path blocked when present"
    } else if mesh_blocked {
        "mesh data path blocked; host traffic is not guarded"
    } else if host_mode.is_some() {
        "host guard allows traffic; mesh data path running when present"
    } else {
        "mesh data path running; host traffic is not guarded"
    };
    serde_json::json!({
        "status": "ok",
        "message": message,
        "mesh_data_path_blocked": mesh_blocked,
        "host_guard_installed": host_mode.is_some(),
        "host_guard_mode": host_mode.map(host_guard_mode_label).unwrap_or("unavailable"),
        "host_egress_blocked": host_blocked,
        "host_guard_table": table,
    })
    .to_string()
}

fn apply_mesh_kill_switch(
    bus: &BusPublisher,
    mesh: &MeshHealth,
    mode: &KillSwitchState,
    reason: &str,
) -> Result<(), String> {
    if !mesh.runner_active.load(Ordering::Acquire) {
        return Err("mesh daemon is not running".into());
    }
    BusEvent::publish(
        bus,
        "net.transport.killswitch.command",
        Message::KillSwitchCommand(KillSwitchCommand {
            state: mode.clone(),
            reason: reason.to_string(),
            issued_at: chrono::Utc::now(),
        }),
    )
    .map_err(|error| format!("mesh kill switch command failed: {error}"))?;
    if mesh.daemon.is_killed() != matches!(mode, KillSwitchState::Engaged) {
        return Err("mesh kill switch command was not applied".into());
    }
    Ok(())
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::with_capacity(256);
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(chunk.len(), |offset| offset + 1);
        if bytes.len() + consumed > MAX_COMMAND_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "command exceeds 8 KiB",
            ));
        }
        bytes.extend_from_slice(&chunk[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "command is not UTF-8"))
}

// Windows support was dropped; the control surface is Unix-socket only.
#[cfg(not(unix))]
compile_error!(
    "imperium-cli requires a Unix platform: the control surface is a Unix domain socket"
);

#[cfg(unix)]
mod unix {
    use super::*;
    use std::fs::{self, DirBuilder, Permissions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Semaphore;

    pub(super) fn effective_uid() -> u32 {
        // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
        unsafe { libc::geteuid() }
    }

    fn trusted_runtime_dir(root: &Path) -> Option<PathBuf> {
        let canonical = fs::canonicalize(root).ok()?;
        let root_metadata = fs::metadata(&canonical).ok()?;
        if !root_metadata.is_dir()
            || root_metadata.uid() != effective_uid()
            || root_metadata.permissions().mode() & 0o077 != 0
        {
            return None;
        }
        // Unprivileged user namespaces map this host's user to euid 0 while
        // host-root-owned / and /tmp appear as the kernel overflow UID. Trust
        // only those exact base paths under their expected immutable/sticky
        // modes; a writable nonsticky or other unmapped ancestor still fails.
        let overflow_uid = fs::read_to_string("/proc/sys/kernel/overflowuid")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok());
        for ancestor in canonical.ancestors() {
            let metadata = fs::symlink_metadata(ancestor).ok()?;
            let mode = metadata.permissions().mode();
            let namespace_base = overflow_uid == Some(metadata.uid())
                && ((ancestor == Path::new("/") && mode & 0o022 == 0)
                    || (ancestor == Path::new("/tmp") && mode & 0o1777 == 0o1777));
            if !metadata.file_type().is_dir()
                || (metadata.uid() != effective_uid() && metadata.uid() != 0 && !namespace_base)
                || (mode & 0o022 != 0 && mode & 0o1000 == 0)
            {
                return None;
            }
        }
        Some(canonical)
    }

    // A shared runtime root or ancestor can let another user rename a private
    // child directory. Use the sticky /tmp parent in that case.
    pub fn socket_path() -> PathBuf {
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            if let Some(root) = trusted_runtime_dir(Path::new(&dir)) {
                return root.join("imperium/control.sock");
            }
        }
        PathBuf::from(format!("/tmp/imperium-{}/control.sock", effective_uid()))
    }

    pub(super) fn prepare_socket_dir(parent: &Path) -> io::Result<()> {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        if let Err(error) = builder.create(parent) {
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir() || metadata.uid() != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control socket directory is not an owner-controlled directory",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(parent, Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    pub(super) async fn remove_stale_socket(path: &Path) -> io::Result<()> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket() || metadata.uid() != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control endpoint is not an owner-controlled socket",
            ));
        }
        match UnixStream::connect(path).await {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "control socket already has a live server",
            )),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path),
            Err(error) => Err(error),
        }
    }

    pub async fn serve(state: Arc<ControlState>) {
        let path = socket_path();
        if let Some(parent) = path.parent() {
            if let Err(error) = prepare_socket_dir(parent) {
                tracing::error!(path = %parent.display(), %error, "failed to secure control socket directory");
                return;
            }
        }
        if let Err(error) = remove_stale_socket(&path).await {
            tracing::error!(path = %path.display(), %error, "control socket is unavailable");
            return;
        }

        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "failed to bind control socket");
                return;
            }
        };
        if let Err(error) = fs::set_permissions(&path, Permissions::from_mode(0o600)) {
            tracing::error!(path = %path.display(), %error, "failed to secure control socket");
            let _ = fs::remove_file(&path);
            return;
        }

        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let peer_uid = match stream.peer_cred() {
                        Ok(credentials) => credentials.uid(),
                        Err(error) => {
                            tracing::warn!(%error, "could not verify control socket peer");
                            continue;
                        }
                    };
                    if peer_uid != effective_uid() {
                        tracing::warn!(peer_uid, "denied control socket peer");
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        let _ = stream
                            .write_all(
                                format!("{}\n", reply("error", "control server busy")).as_bytes(),
                            )
                            .await;
                        continue;
                    };
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, state).await;
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, "control socket accept failed");
                }
            }
        }
    }
}

#[cfg(test)]
fn dispatch_command(line: &str, bus: &BusPublisher) -> String {
    dispatch_command_with_staging(line, bus, None)
}

#[cfg(test)]
fn dispatch_command_with_staging(
    line: &str,
    bus: &BusPublisher,
    staging: Option<&StagingArea>,
) -> String {
    dispatch_command_with_health(line, bus, staging, None, None, None)
}

fn dispatch_command_with_health(
    line: &str,
    bus: &BusPublisher,
    staging: Option<&StagingArea>,
    mesh: Option<&MeshHealth>,
    lightcone: Option<&LightconeService>,
    lightcone_lifecycle: Option<&LightconeLifecycleMonitor>,
) -> String {
    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    match parts.as_slice() {
        ["cluster", "status"] => reply("ok", "cluster status requested"),
        ["vpn", "health"] => match mesh {
            Some(mesh) => mesh.response(),
            None => serde_json::json!({
                "status": "unavailable",
                "message": "mesh VPN was not started",
                "node_control_online": true,
                "mesh_bound": false,
                "mesh_runner_active": false,
                "mesh_killed": false,
                "established_peers": 0,
                "configured_peers": 0,
                "host_interface_configured": false,
                "host_bridge_active": false,
                "local_addr": null,
            })
            .to_string(),
        },
        ["vpn", "lightcone", "status"] => {
            render_lightcone_status(lightcone, mesh, lightcone_lifecycle)
        }
        ["vpn", "policy", "apply", policy_id] => {
            if policy_id.trim().is_empty() {
                return reply("error", "policy id cannot be empty");
            }
            let _ = BusEvent::publish(
                bus,
                "net.cluster.policy.apply",
                Message::PolicyApplyRequest(PolicyApplyRequest {
                    policy_id: (*policy_id).to_string(),
                    config_blob: Vec::new(),
                    requested_at: chrono::Utc::now(),
                }),
            );
            reply("ok", format!("policy apply requested: {policy_id}"))
        }
        ["vpn", "nat", "aggressive", "on" | "off"] => reply(
            "error",
            "aggressive NAT probing is unavailable: no live probe executor",
        ),
        ["vpn", "nat", "aggressive", _] => reply("error", "expected on or off"),
        ["vpn", "masque", "configure", json] => {
            match serde_json::from_str::<MasqueTunnelConfig>(json) {
                Ok(config) => {
                    let tunnel_id = config.tunnel_id.clone();
                    let _ = BusEvent::publish(
                        bus,
                        "net.transport.masque.configure",
                        Message::MasqueTunnelConfig(config),
                    );
                    reply("ok", format!("MASQUE config dispatched: {tunnel_id}"))
                }
                Err(e) => reply("error", format!("invalid MASQUE config: {e}")),
            }
        }
        ["vpn", "deployment", "status"] => {
            let _ = BusEvent::publish(
                bus,
                "net.vpn.deployment.status_request",
                Message::VpnDeploymentStatusRequest(VpnDeploymentStatusRequest {
                    requested_by: "control_pipe".to_string(),
                    requested_at: chrono::Utc::now(),
                }),
            );
            reply("ok", "deployment status requested")
        }
        ["vpn", "deployment", "apply"] => reply("error", "deployment plan json is required"),
        ["vpn", "deployment", "apply", json] => publish_deployment_plan(bus, json),
        ["vpn", "hardening", "preset"] => reply("error", "hardening preset is required"),
        ["vpn", "hardening", "preset", request] => publish_hardening_preset(bus, request),
        ["vpn", "hardening", "apply"] => reply("error", "hardening profile json is required"),
        ["vpn", "hardening", "apply", json] => publish_hardening_profile(bus, json),
        ["vpn", "toolkit", "activate"] => reply("error", "tool name is required"),
        ["vpn", "toolkit", "activate", request] => publish_toolkit_activation(bus, request),
        ["signatures", "pending"] => render_pending_signatures(staging),
        ["signatures", "approve", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = BusEvent::publish(
                    bus,
                    "net.signatures.approve_request",
                    Message::SignatureApprovalRequest(
                        imperium_protocol::SignatureApprovalRequest { candidate_id: uuid },
                    ),
                );
                reply("ok", format!("approval request dispatched for {id}"))
            }
            Err(_) => reply("error", "invalid UUID"),
        },
        ["signatures", "reject", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = BusEvent::publish(
                    bus,
                    "net.signatures.reject_request",
                    Message::SignatureRejected(imperium_protocol::SignatureRejected {
                        candidate_id: uuid,
                        rejected_by: imperium_protocol::PeerId::new(),
                        rejected_at: chrono::Utc::now(),
                        reason: "operator rejected".to_string(),
                    }),
                );
                reply("ok", format!("rejection dispatched for {uuid}"))
            }
            Err(_) => reply("error", "invalid UUID"),
        },
        ["signatures", "reject", id, reason] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = BusEvent::publish(
                    bus,
                    "net.signatures.reject_request",
                    Message::SignatureRejected(imperium_protocol::SignatureRejected {
                        candidate_id: uuid,
                        rejected_by: imperium_protocol::PeerId::new(),
                        rejected_at: chrono::Utc::now(),
                        reason: reason.to_string(),
                    }),
                );
                reply("ok", format!("rejection dispatched for {uuid}"))
            }
            Err(_) => reply("error", "invalid UUID"),
        },
        ["signatures", "extract", ids_arg, ..] => {
            let event_ids_str: Vec<&str> = ids_arg.split(',').map(|s| s.trim()).collect();
            let mut event_ids = Vec::new();
            for id_str in &event_ids_str {
                match uuid::Uuid::parse_str(id_str) {
                    Ok(uuid) => event_ids.push(imperium_protocol::EventId(uuid)),
                    Err(_) => return reply("error", format!("invalid event UUID: {id_str}")),
                }
            }
            let _ = BusEvent::publish(
                bus,
                "net.signatures.extraction_request",
                Message::ExtractionRequest(imperium_protocol::ExtractionRequest {
                    triggering_event_ids: event_ids,
                    reason: "operator requested via control pipe".into(),
                    requested_by: "operator".into(),
                }),
            );
            reply(
                "ok",
                format!("extraction requested for {} events", event_ids_str.len()),
            )
        }
        ["signatures", "show", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => render_signature_candidate(uuid, staging),
            Err(_) => reply("error", "invalid UUID"),
        },
        ["shutdown"] => {
            let _ = BusEvent::publish(
                bus,
                "emergency.cli.operator_shutdown",
                Message::EmergencyShutdown(imperium_protocol::EmergencyShutdown {
                    reason: "operator requested shutdown via control pipe".into(),
                    triggered_at: chrono::Utc::now(),
                    active_protocol: None,
                    standby_protocol: None,
                }),
            );
            reply("ok", "shutdown initiated")
        }
        _ => reply("error", "unknown command"),
    }
}

/// Snapshot only. Receipt and mesh counters are local observations; neither
/// grants authority nor certifies the diagnostic world as sealed.
fn render_lightcone_status(
    lightcone: Option<&LightconeService>,
    mesh: Option<&MeshHealth>,
    lightcone_lifecycle: Option<&LightconeLifecycleMonitor>,
) -> String {
    let Some(lightcone) = lightcone else {
        return serde_json::json!({
            "status": "unavailable",
            "message": "passive Lightcone service is not installed",
            "installed": false,
            "working": false,
            "filter_enforced": false,
            "filter_mode": "unavailable",
            "evidence_scope": "local_runtime_only",
        })
        .to_string();
    };

    let info = lightcone.info();
    let mesh_stats = mesh.map(|mesh| mesh.daemon.stats());
    let lifecycle = lightcone_lifecycle
        .map(LightconeLifecycleMonitor::state)
        .unwrap_or(LightconeLifecycleState::Unknown);
    let mesh_runner_active = mesh.is_some_and(|mesh| mesh.runner_active.load(Ordering::Acquire));
    let pending_observations = mesh_stats.map(|stats| {
        stats
            .lightcone_observations_published
            .saturating_sub(info.rx.saturating_add(info.tx))
    });
    let handoff_fault = mesh_stats.is_some_and(|stats| {
        stats.lightcone_observations_dropped > 0 || stats.lightcone_publish_errors > 0
    });
    let lifecycle_fault = matches!(
        lifecycle,
        LightconeLifecycleState::Crashed
            | LightconeLifecycleState::Quarantined
            | LightconeLifecycleState::Detached
    );
    let faulted = info.failures > 0 || handoff_fault || lifecycle_fault;
    let working = info.rx > 0
        && info.tx > 0
        && info.latest > 0
        && !faulted
        && lifecycle == LightconeLifecycleState::Running
        && mesh_runner_active
        && pending_observations == Some(0)
        && mesh_stats.is_some_and(|stats| stats.lightcone_observations_published > 0);
    let activity_seen = info.latest > 0
        || mesh_stats.is_some_and(|stats| {
            stats.lightcone_observations_queued > 0 || stats.lightcone_observations_published > 0
        });
    let (status, message) = if faulted {
        (
            "degraded",
            "local Lightcone path has failures or dropped observations; diagnostic world remains unsealed",
        )
    } else if working {
        (
            "ok",
            "inbound and outbound receipts observed without counted handoff loss; local runtime evidence only",
        )
    } else if activity_seen {
        (
            "incomplete",
            "activity observed without complete inbound, outbound, and mesh handoff evidence",
        )
    } else {
        (
            "idle",
            "passive Lightcone installed; no frames observed yet",
        )
    };
    serde_json::json!({
        "status": status,
        "message": message,
        "installed": true,
        "working": working,
        "filter_enforced": false,
        "filter_mode": "diagnostic_only",
        "evidence_scope": "local_runtime_only",
        "working_scope": "observed_since_startup; idle liveness is not measured",
        "strand_lifecycle": lifecycle.label(),
        "mesh_runner_active": mesh_runner_active,
        "has_receipts": info.latest > 0,
        "pending_observations": pending_observations,
        "world": info.world,
        "world_kind": "trained_path_lightcone",
        "trained": info.trained,
        "trained_paths": info.trained_paths,
        "deny_paths": info.deny_paths,
        "folds": info.folds,
        "admitted": info.admitted,
        "local_diagnostic": true,
        "sealed": info.sealed,
        "unsealed": !info.sealed,
        "passive": info.passive,
        "holds_verdict": info.holds_verdict,
        "rx": info.rx,
        "tx": info.tx,
        "raw_ip_rx": info.raw_ip_rx,
        "raw_ip_tx": info.raw_ip_tx,
        "mesh_rx": info.mesh_rx,
        "mesh_tx": info.mesh_tx,
        "failures": info.failures,
        "latest": info.latest,
        "oldest": info.oldest,
        "lightcone_observations_queued": mesh_stats.map(|stats| stats.lightcone_observations_queued),
        "lightcone_observations_published": mesh_stats.map(|stats| stats.lightcone_observations_published),
        "lightcone_observations_dropped": mesh_stats.map(|stats| stats.lightcone_observations_dropped),
        "lightcone_publish_errors": mesh_stats.map(|stats| stats.lightcone_publish_errors),
    })
    .to_string()
}

fn render_signature_candidate(uuid: uuid::Uuid, staging: Option<&StagingArea>) -> String {
    let Some(staging) = staging else {
        return serde_json::json!({
            "status": "error",
            "candidate_id": uuid,
            "message": "signature staging unavailable"
        })
        .to_string();
    };

    match staging.candidate(uuid) {
        Some(snapshot) => serde_json::json!({
            "status": "ok",
            "candidate_status": candidate_status_label(&snapshot.status),
            "candidate": snapshot.candidate,
            "rejection_reason": snapshot.rejection_reason
        })
        .to_string(),
        None => serde_json::json!({
            "status": "error",
            "candidate_id": uuid,
            "message": "candidate not found"
        })
        .to_string(),
    }
}

fn render_pending_signatures(staging: Option<&StagingArea>) -> String {
    let Some(staging) = staging else {
        return serde_json::json!({
            "status": "error",
            "message": "signature staging unavailable"
        })
        .to_string();
    };

    let candidates = staging.pending_candidates();
    serde_json::json!({
        "status": "ok",
        "pending_count": candidates.len(),
        "candidates": candidates
    })
    .to_string()
}

fn candidate_status_label(status: &CandidateStatus) -> &'static str {
    match status {
        CandidateStatus::Pending => "pending",
        CandidateStatus::Approved => "approved",
        CandidateStatus::Rejected => "rejected",
    }
}

fn publish_deployment_plan(bus: &BusPublisher, json: &str) -> String {
    match serde_json::from_str::<VpnDeploymentPlan>(json) {
        Ok(plan) => {
            let deployment_id = plan.deployment_id;
            let _ = BusEvent::publish(
                bus,
                "net.vpn.deployment.apply",
                Message::VpnDeploymentPlan(plan),
            );
            reply("ok", format!("deployment plan dispatched: {deployment_id}"))
        }
        Err(e) => reply("error", format!("invalid deployment plan: {e}")),
    }
}

fn publish_hardening_preset(bus: &BusPublisher, request: &str) -> String {
    let mut parts = request.trim().splitn(2, ' ');
    let Some(preset) = parts.next().filter(|preset| !preset.trim().is_empty()) else {
        return reply("error", "hardening preset is required");
    };
    let protocol_name = parts
        .next()
        .filter(|protocol| !protocol.trim().is_empty())
        .map(ToString::to_string);

    let profile = match preset {
        "balanced" => imperium_net_transport::HardeningController::balanced_profile(protocol_name),
        "resilience" => {
            imperium_net_transport::HardeningController::resilience_profile(protocol_name)
        }
        "fortress" => imperium_net_transport::HardeningController::fortress_profile(protocol_name),
        _ => return reply("error", "unknown hardening preset"),
    };

    publish_valid_hardening_profile(bus, profile)
}

fn publish_hardening_profile(bus: &BusPublisher, json: &str) -> String {
    match serde_json::from_str::<ProtocolHardeningProfile>(json) {
        Ok(profile) => publish_valid_hardening_profile(bus, profile),
        Err(e) => reply("error", format!("invalid hardening profile: {e}")),
    }
}

fn publish_valid_hardening_profile(
    bus: &BusPublisher,
    profile: ProtocolHardeningProfile,
) -> String {
    if let Err(e) = imperium_net_transport::HardeningController::validate(&profile) {
        return reply("error", format!("invalid hardening profile: {e}"));
    }

    let profile_id = profile.profile_id.clone();
    let _ = BusEvent::publish(
        bus,
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(profile),
    );

    reply("ok", format!("hardening profile dispatched: {profile_id}"))
}

fn publish_toolkit_activation(bus: &BusPublisher, request: &str) -> String {
    let mut parts = request.trim().splitn(2, ' ');
    let Some(tool_name) = parts.next().filter(|name| !name.trim().is_empty()) else {
        return reply("error", "tool name is required");
    };
    let trigger = parts
        .next()
        .filter(|trigger| !trigger.trim().is_empty())
        .unwrap_or("operator.manual_toolkit_activation");

    let mut context = HashMap::new();
    context.insert("requested_by".to_string(), "control_pipe".to_string());

    let _ = BusEvent::publish(
        bus,
        "net.toolkit.request",
        Message::ToolActivationReq(ToolActivationRequest {
            tool_name: tool_name.to_string(),
            trigger: trigger.to_string(),
            context,
            timestamp: chrono::Utc::now(),
        }),
    );

    reply("ok", format!("toolkit activation requested: {tool_name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    /// A named subscription feeding an owned bounded queue — the shape an async
    /// consumer outside a strand must have now that delivery is push-based.
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

    // Restores XDG_RUNTIME_DIR on drop so the socket-path test does not leak
    // environment changes into other tests in the same process.
    #[cfg(unix)]
    struct EnvGuard {
        previous: Option<String>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                previous: std::env::var("XDG_RUNTIME_DIR").ok(),
            }
        }

        fn set(key: &str, value: &str) -> Self {
            let guard = Self::capture();
            std::env::set_var(key, value);
            guard
        }

        fn unset(key: &str) -> Self {
            let guard = Self::capture();
            std::env::remove_var(key);
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
    }

    #[test]
    fn dispatch_cluster_status() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("cluster status", &bus);
        assert!(resp.contains("cluster status requested"));
    }

    #[tokio::test]
    async fn dispatch_vpn_profile_rotate_requires_live_profiles() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let lifecycle = LightconeLifecycleMonitor::subscribe(&bus);
        let state = ControlState::new(bus, None, None, None, lifecycle, None, None);
        let resp = dispatch_connection_command("vpn profile rotate xray", &state).await;
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(value["status"], "error");
        assert!(value["message"]
            .as_str()
            .unwrap()
            .contains("not configured"));
    }

    #[test]
    fn dispatch_vpn_nat_aggressive_on_reports_unavailable() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("vpn nat aggressive on", &bus);
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(value["status"], "error");
        assert!(value["message"].as_str().unwrap().contains("unavailable"));
    }

    #[tokio::test]
    async fn dispatch_vpn_transport_set_active_requires_live_profiles() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let lifecycle = LightconeLifecycleMonitor::subscribe(&bus);
        let state = ControlState::new(bus, None, None, None, lifecycle, None, None);
        let resp = dispatch_connection_command("vpn transport set-active masque", &state).await;
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(value["status"], "error");
        assert!(value["message"]
            .as_str()
            .unwrap()
            .contains("not configured"));
    }

    #[test]
    fn dispatch_vpn_health_without_mesh_is_unavailable() {
        let bus = spiderweb::Bus::open().publisher();
        let value: serde_json::Value =
            serde_json::from_str(&dispatch_command("vpn health", &bus)).unwrap();
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["mesh_bound"], false);
        assert_eq!(value["node_control_online"], true);
    }

    #[test]
    fn dispatch_lightcone_status_without_service_is_unavailable() {
        let bus = spiderweb::Bus::open().publisher();
        let value: serde_json::Value =
            serde_json::from_str(&dispatch_command("vpn lightcone status", &bus)).unwrap();
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["installed"], false);
        assert_eq!(value["working"], false);
        assert_eq!(value["filter_enforced"], false);
        assert_eq!(value["filter_mode"], "unavailable");
    }

    #[test]
    fn dispatch_lightcone_status_reads_live_diagnostic_service() {
        let bus = spiderweb::Bus::open().publisher();
        let service = LightconeService::new().unwrap();
        let initial: serde_json::Value = serde_json::from_str(&dispatch_command_with_health(
            "vpn lightcone status",
            &bus,
            None,
            None,
            Some(&service),
            None,
        ))
        .unwrap();
        assert_eq!(initial["status"], "idle");
        assert_eq!(initial["installed"], true);
        assert_eq!(initial["working"], false);
        assert_eq!(initial["filter_enforced"], false);
        assert_eq!(initial["filter_mode"], "diagnostic_only");
        service
            .observe_with_format(
                imperium_net_lightcone::WireDirection::Inbound,
                imperium_protocol::LightconeFrameFormat::MeshDatagram,
                b"structural probe",
            )
            .unwrap();
        service
            .observe_with_format(
                imperium_net_lightcone::WireDirection::Outbound,
                imperium_protocol::LightconeFrameFormat::MeshDatagram,
                b"second probe",
            )
            .unwrap();
        let before = service.info();
        let response = dispatch_command_with_health(
            "vpn lightcone status",
            &bus,
            None,
            None,
            Some(&service),
            None,
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let after = service.info();

        assert_eq!(value["status"], "incomplete");
        assert_eq!(value["installed"], true);
        assert_eq!(value["working"], false); // no mesh handoff evidence
        assert_eq!(value["world"], before.world);
        assert_eq!(value["world_kind"], "trained_path_lightcone");
        assert_eq!(value["trained_paths"], before.trained_paths);
        assert_eq!(value["admitted"], before.admitted);
        assert_eq!(value["local_diagnostic"], true);
        assert_eq!(value["unsealed"], true);
        assert_eq!(value["passive"], true);
        assert_eq!(value["holds_verdict"], false);
        assert_eq!(value["rx"], 1);
        assert_eq!(value["tx"], 1);
        assert_eq!(value["latest"], 2);
        assert_eq!(value["oldest"], 1);
        assert_eq!(value["has_receipts"], true);
        assert_eq!(value["strand_lifecycle"], "unknown");
        assert!(value["pending_observations"].is_null());
        assert!(value["lightcone_observations_queued"].is_null());
        assert_eq!(before.latest, after.latest); // status did not admit or publish
    }

    #[test]
    fn lightcone_lifecycle_monitor_tracks_only_its_strand() {
        let bus = spiderweb::Bus::open().publisher();
        let monitor = LightconeLifecycleMonitor::subscribe(&bus);
        assert_eq!(monitor.state(), LightconeLifecycleState::Unknown);

        let registered = |name: &str| spiderweb::LifecycleEvent::Registered {
            name: name.to_string(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        bus.publish(spiderweb::SYS_LIFECYCLE, registered("unrelated"))
            .unwrap();
        assert_eq!(monitor.state(), LightconeLifecycleState::Unknown);
        bus.publish(
            spiderweb::SYS_LIFECYCLE,
            registered(imperium_net_lightcone::NAME),
        )
        .unwrap();
        assert_eq!(monitor.state(), LightconeLifecycleState::Running);

        bus.publish(
            spiderweb::SYS_LIFECYCLE,
            spiderweb::LifecycleEvent::Crashed {
                name: imperium_net_lightcone::NAME.into(),
                reason: "test fault".into(),
            },
        )
        .unwrap();
        assert_eq!(monitor.state(), LightconeLifecycleState::Crashed);
        let service = LightconeService::new().unwrap();
        let value: serde_json::Value = serde_json::from_str(&dispatch_command_with_health(
            "vpn lightcone status",
            &bus,
            None,
            None,
            Some(&service),
            Some(&monitor),
        ))
        .unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["strand_lifecycle"], "crashed");
        assert_eq!(value["working"], false);

        bus.publish(
            spiderweb::SYS_LIFECYCLE,
            spiderweb::LifecycleEvent::Restarted {
                name: imperium_net_lightcone::NAME.into(),
                attempt: 1,
            },
        )
        .unwrap();
        assert_eq!(monitor.state(), LightconeLifecycleState::Running);
        bus.publish(
            spiderweb::SYS_LIFECYCLE,
            spiderweb::LifecycleEvent::Quarantined {
                name: imperium_net_lightcone::NAME.into(),
                reason: "test quarantine".into(),
            },
        )
        .unwrap();
        assert_eq!(monitor.state(), LightconeLifecycleState::Quarantined);
    }

    #[test]
    fn user_input_in_reply_is_json_escaped() {
        let bus = spiderweb::Bus::open().publisher();
        let value: serde_json::Value =
            serde_json::from_str(&dispatch_command("vpn policy apply a\"b\\c", &bus)).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["message"], "policy apply requested: a\"b\\c");
    }

    #[tokio::test]
    async fn dispatch_vpn_killswitch_without_mesh_or_host_guard_reports_unavailable() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let lifecycle = LightconeLifecycleMonitor::subscribe(&bus);
        let state = ControlState::new(bus, None, None, None, lifecycle, None, None);
        let resp = dispatch_connection_command("vpn killswitch engage dns leak", &state).await;
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(value["status"], "error");
        assert!(value["message"]
            .as_str()
            .unwrap()
            .contains("neither mesh VPN nor opt-in host guard"));

        let health: serde_json::Value =
            serde_json::from_str(&dispatch_connection_command("vpn health", &state).await).unwrap();
        assert_eq!(health["host_guard_installed"], false);
        assert_eq!(health["host_guard_mode"], "unavailable");
        assert_eq!(health["host_egress_blocked"], false);
    }

    #[test]
    fn dispatch_vpn_hardening_preset() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("vpn hardening preset balanced masque", &bus);
        assert!(resp.contains("hardening profile dispatched"));
    }

    #[test]
    fn dispatch_vpn_hardening_apply_rejects_bad_json() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("vpn hardening apply {}", &bus);
        assert!(resp.contains("invalid hardening profile"));
    }

    #[test]
    fn dispatch_vpn_toolkit_activate() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command(
            "vpn toolkit activate transport.diagnostics manual check",
            &bus,
        );
        assert!(resp.contains("toolkit activation requested"));
    }

    #[test]
    fn dispatch_vpn_deployment_apply() {
        let bus = spiderweb::Bus::open().publisher();
        let plan = imperium_protocol::VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![
                imperium_protocol::VpnDeploymentNodeSpec {
                    label: "operator".into(),
                    role: imperium_protocol::VpnDeploymentRole::Operator,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32000".parse().unwrap()),
                    capabilities: vec!["vpn.cluster.admin".into()],
                },
                imperium_protocol::VpnDeploymentNodeSpec {
                    label: "client".into(),
                    role: imperium_protocol::VpnDeploymentRole::Client,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32001".parse().unwrap()),
                    capabilities: vec!["vpn.client".into()],
                },
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: chrono::Utc::now(),
        };
        let resp = dispatch_command(
            &format!(
                "vpn deployment apply {}",
                serde_json::to_string(&plan).unwrap()
            ),
            &bus,
        );

        assert!(resp.contains("deployment plan dispatched"));
    }

    #[tokio::test]
    async fn dispatch_vpn_deployment_status() {
        let bus = spiderweb::Bus::open().publisher();
        let mut sub = subscribe_queue(&bus, "net.vpn.deployment.status_request", 32);
        let resp = dispatch_command("vpn deployment status", &bus);

        assert!(resp.contains("deployment status requested"));
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("deployment status request")
            .unwrap();
        assert!(matches!(
            event.message,
            Message::VpnDeploymentStatusRequest(request)
                if request.requested_by == "control_pipe"
        ));
    }

    #[test]
    fn dispatch_signatures_pending() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("signatures pending", &bus);
        assert!(resp.contains("signature staging unavailable"));
    }

    #[test]
    fn dispatch_signatures_pending_with_staging_returns_candidates() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(Arc::clone(&bus));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: "rule pending { condition: true }".into(),
            description: "pending candidate".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.91,
        };
        let id = staging.submit(candidate).unwrap();

        let resp = dispatch_command_with_staging("signatures pending", &bus, Some(&staging));
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(value["status"], "ok");
        assert_eq!(value["pending_count"], 1);
        assert_eq!(value["candidates"][0]["id"], id.to_string());
    }

    #[tokio::test]
    async fn dispatch_signatures_approve_valid_uuid() {
        let bus = spiderweb::Bus::open().publisher();
        let mut sub = subscribe_queue(&bus, "net.signatures.approve_request", 32);
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures approve {}", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("approval request dispatched"));
        // The typed request must reach the staging path, not just log a reply.
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("typed approve request published")
            .unwrap();
        assert!(matches!(
            event.message,
            Message::SignatureApprovalRequest(req) if req.candidate_id == id
        ));
    }

    #[test]
    fn dispatch_signatures_approve_invalid_uuid() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("signatures approve not-a-uuid", &bus);
        assert!(resp.contains("invalid UUID"));
    }

    #[test]
    fn dispatch_signatures_reject_valid_uuid() {
        let bus = spiderweb::Bus::open().publisher();
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures reject {} false positive", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("rejection dispatched"));
    }

    #[test]
    fn dispatch_signatures_extract_valid_ids() {
        let bus = spiderweb::Bus::open().publisher();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let cmd = format!("signatures extract {},{}", id1, id2);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("extraction requested for 2 events"));
    }

    #[test]
    fn dispatch_signatures_extract_invalid_id() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("signatures extract bad-id", &bus);
        assert!(resp.contains("invalid event UUID"));
    }

    #[test]
    fn dispatch_signatures_show_valid_uuid() {
        let bus = spiderweb::Bus::open().publisher();
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures show {}", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains(&id.to_string()));
        assert!(resp.contains("signature staging unavailable"));
    }

    #[test]
    fn dispatch_signatures_show_with_staging_returns_candidate() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(Arc::clone(&bus));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: "rule quoted { condition: true }".into(),
            description: "operator staged candidate".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.88,
        };
        let id = staging.submit(candidate).unwrap();
        let cmd = format!("signatures show {}", id);

        let resp = dispatch_command_with_staging(&cmd, &bus, Some(&staging));
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(value["status"], "ok");
        assert_eq!(value["candidate_status"], "pending");
        assert_eq!(value["candidate"]["id"], id.to_string());
        assert_eq!(
            value["candidate"]["description"],
            "operator staged candidate"
        );
    }

    #[test]
    fn dispatch_shutdown() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("shutdown", &bus);
        assert!(resp.contains("shutdown initiated"));
    }

    #[test]
    fn dispatch_unknown_command() {
        let bus = spiderweb::Bus::open().publisher();
        let resp = dispatch_command("foo bar", &bus);
        assert!(resp.contains("unknown command"));
    }

    #[test]
    fn socket_path_uses_private_xdg_runtime_dir_with_tmp_fallback() {
        // Fallback when XDG_RUNTIME_DIR is unset.
        let fallback = {
            let _guard = EnvGuard::unset("XDG_RUNTIME_DIR");
            super::unix::socket_path()
        };
        assert_eq!(
            fallback,
            std::path::PathBuf::from(format!(
                "/tmp/imperium-{}/control.sock",
                super::unix::effective_uid()
            ))
        );

        // A private runtime directory takes precedence.
        let root = std::env::temp_dir().join(format!("imperium-xdg-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = EnvGuard::set("XDG_RUNTIME_DIR", root.to_str().unwrap());
        assert_eq!(
            super::unix::socket_path(),
            std::fs::canonicalize(&root)
                .unwrap()
                .join("imperium/control.sock")
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(super::unix::socket_path(), fallback);
        std::fs::remove_dir(&root).unwrap();

        // A private leaf is unsafe when its parent can rename that leaf.
        let shared =
            std::env::temp_dir().join(format!("imperium-shared-parent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let private = shared.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = EnvGuard::set("XDG_RUNTIME_DIR", private.to_str().unwrap());
        assert_eq!(super::unix::socket_path(), fallback);
        std::fs::remove_dir(&private).unwrap();
        std::fs::remove_dir(&shared).unwrap();
    }

    #[tokio::test]
    async fn socket_directory_and_live_socket_are_protected() {
        let parent =
            std::env::temp_dir().join(format!("imperium-control-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        super::unix::prepare_socket_dir(&parent).unwrap();
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let socket = parent.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let error = super::unix::remove_stale_socket(&socket).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(socket.exists());
        drop(listener);
        super::unix::remove_stale_socket(&socket).await.unwrap();
        assert!(!socket.exists());
        std::fs::remove_dir(&parent).unwrap();
    }

    #[tokio::test]
    async fn oversized_control_command_is_rejected_before_dispatch() {
        let (mut writer, reader) = tokio::io::duplex(MAX_COMMAND_BYTES + 64);
        let mut reader = BufReader::new(reader);
        let command = vec![b'x'; MAX_COMMAND_BYTES + 1];
        writer.write_all(&command).await.unwrap();
        let error = read_bounded_line(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn dispatch_no_dead_cli_topics() {
        let bus = spiderweb::Bus::open().publisher();
        let id = uuid::Uuid::new_v4();
        let resp = dispatch_command(&format!("signatures approve {}", id), &bus);
        assert!(resp.contains("approval request dispatched"));
        assert!(!resp.contains("cli.signatures"));
    }
}
