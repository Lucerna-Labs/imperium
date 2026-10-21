use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use imperium_cli::{control, mesh_identity, operator_key};
use imperium_memory_log::MemoryLog;
use imperium_net_crypto::HybridSigningKey;
use imperium_net_host::{HostBridge, HostKillSwitch, RouteGuard, TunDevice};
use imperium_net_mesh::{Destination, PeerConfig};
use imperium_net_mesh::{MeshDaemon, MeshNodeConfig};
use imperium_net_sensors::SignatureEngineSensor;
use imperium_net_signatures::{ExtractionLoop, StagingArea};
use imperium_net_toolkit::{ToolManager, ToolManifest, TriggerCondition};
use imperium_net_transport::{HardeningController, LiveProtocolProfile, LiveTransportRuntime};
use imperium_protocol::{BusEvent, ClusterId, Message, PeerId};
use imperium_runtime::{DeploymentOrchestrator, RuntimeCoordinator};
use imperium_store::Store;
use spiderweb::{Bus, BusPublisher};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "imperium", about = "Imperium adaptive VPN cluster defense")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Node lifecycle management
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Cluster membership operations
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Signature database management
    Signatures {
        #[command(subcommand)]
        action: SignatureAction,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Start the Imperium runtime
    Start {
        /// Launch the operator console GUI alongside the runtime
        #[arg(long)]
        gui: bool,
        #[command(flatten)]
        mesh: MeshArgs,
    },
}

/// The mesh link and host interface.
///
/// The mesh data plane starts only when `--mesh-bind` is given; without it the
/// node runs exactly as before. Providing `--mesh-bind` alone makes this node a
/// responder. To dial, pass `--peer` **and** `--expected-peer`, because a
/// handshake needs to know which peer id it is dialling.
#[derive(Args, Clone, Debug)]
struct MeshArgs {
    /// Install an opt-in host egress guard. It allows traffic until an
    /// explicit `vpn killswitch engage` command; requires CAP_NET_ADMIN.
    #[arg(long)]
    host_guard: bool,

    /// JSON array of explicit live Xray/AmneziaWG profiles. No backend binary,
    /// config, path switch, or health command is inferred.
    #[arg(long, value_name = "PATH", requires = "active_profile")]
    transport_profiles: Option<PathBuf>,

    /// Profile id to start and verify before accepting transport controls.
    #[arg(long, value_name = "ID", requires = "transport_profiles")]
    active_profile: Option<String>,

    /// Local UDP address for the encrypted mesh link, e.g. 127.0.0.1:41000.
    /// Supplying this is what starts the mesh data plane.
    #[arg(long, value_name = "ADDR")]
    mesh_bind: Option<SocketAddr>,

    /// A peer to expect, as `<peer-id>@<address>`. Repeatable.
    ///
    /// The address is optional: `<peer-id>` alone means accept-only, which is
    /// the responder shape — the address is learned from the handshake. With no
    /// `--peer` at all this node accepts any peer whose identity is
    /// operator-bound.
    #[arg(long, value_name = "UUID[@ADDR]")]
    peer: Vec<String>,

    /// A destination reachable through a peer, as `<peer-id>=<cidr>`.
    /// Repeatable. This is what decides which peer a packet goes to.
    #[arg(long, value_name = "UUID=CIDR")]
    peer_route: Vec<String>,

    /// Require a specific identity key for a peer, as `<peer-id>=<path>`, where
    /// the path is that node's mesh identity file. Repeatable.
    ///
    /// Belt and braces: the handshake already binds the peer's identity to its
    /// peer id, so this only adds "and it must be exactly this key".
    #[arg(long, value_name = "UUID=PATH")]
    peer_pin: Vec<String>,

    /// Cluster id shared by every node in this mesh. Defaults to a fresh one,
    /// which is only useful for a single node.
    #[arg(long, value_name = "UUID")]
    cluster_id: Option<Uuid>,

    /// Tunnel address for the host interface, e.g. 10.77.0.1.
    #[arg(long, value_name = "IPV4")]
    tunnel_ip: Option<Ipv4Addr>,

    /// Tunnel netmask. The default /24 gives the kernel a connected route for
    /// the tunnel subnet, so two peers reach each other with no route command.
    #[arg(long, value_name = "IPV4", default_value = "255.255.255.0")]
    netmask: Ipv4Addr,

    /// Host interface name (a numeric suffix is added if it is taken).
    #[arg(long, value_name = "NAME", default_value = "imperium")]
    tun: String,

    /// Tunnel MTU. The default keeps a sealed frame inside the 1500-byte
    /// frame ceiling; see `imperium-net-host` for the arithmetic.
    #[arg(long, default_value_t = imperium_net_host::DEFAULT_MTU)]
    mtu: u32,

    /// Run the encrypted link without creating a host interface.
    #[arg(long)]
    no_tun: bool,

    /// Route a destination through the tunnel, e.g. `--route 10.88.0.0/24`.
    /// Repeatable. Only the destinations named here are routed: the default
    /// route is never touched, so this cannot cut the host off from the
    /// network it is using to reach the peer. Removed again on exit.
    #[arg(long, value_name = "CIDR")]
    route: Vec<String>,

    /// Plaintext bytes a session may carry before its key rotates by
    /// re-handshaking. `0` means never, in which case the key lives for the
    /// life of the session.
    #[arg(long, default_value_t = 68_719_476_736)]
    rekey_bytes: u64,

    /// Seconds between link health reports. 0 disables them.
    #[arg(long, default_value_t = 30)]
    report_secs: u64,
}

/// Defaults for construction without the parser (tests, and callers that
/// build a `MeshArgs` programmatically). `Ipv4Addr` has no `Default`, so this
/// is written out rather than derived.
impl Default for MeshArgs {
    fn default() -> Self {
        Self {
            host_guard: false,
            transport_profiles: None,
            active_profile: None,
            mesh_bind: None,
            peer: Vec::new(),
            peer_route: Vec::new(),
            peer_pin: Vec::new(),
            cluster_id: None,
            tunnel_ip: None,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            tun: "imperium".to_string(),
            mtu: imperium_net_host::DEFAULT_MTU,
            no_tun: false,
            route: Vec::new(),
            rekey_bytes: 68_719_476_736,
            report_secs: 30,
        }
    }
}

/// Stack size for threads that do hybrid post-quantum work.
///
/// ML-DSA-65 key material is multi-kilobyte and its generation and signing
/// routines use deep stack frames. Every test in this workspace runs the crypto
/// paths on a 64 MiB thread for exactly that reason. The main thread's default
/// 8 MiB is not enough, so doing this work there aborts the process with
/// "thread 'main' has overflowed its stack" on the first run that has to mint a
/// key. That abort was observed live, not theorised.
const CRYPTO_STACK: usize = 64 * 1024 * 1024;

/// Run `f` on a thread with [`CRYPTO_STACK`] of stack and return its result.
///
/// This blocks the calling executor thread while the work runs, which is fine
/// here: key loading happens once at startup, never on a hot path.
fn with_crypto_stack<T, E>(f: impl FnOnce() -> Result<T, E> + Send + 'static) -> Result<T, E>
where
    T: Send + 'static,
    E: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(CRYPTO_STACK)
        .name("imperium-crypto".to_string())
        .spawn(f)
        .expect("spawn crypto thread")
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// Parse `<peer-id>` or `<peer-id>@<address>`.
fn parse_peer_spec(spec: &str) -> Result<(PeerId, Option<SocketAddr>), String> {
    let (id, addr) = match spec.split_once('@') {
        Some((id, addr)) => (
            id,
            Some(
                addr.trim()
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("bad address in {spec:?}: {e}"))?,
            ),
        ),
        None => (spec, None),
    };
    let uuid = Uuid::parse_str(id.trim()).map_err(|e| format!("bad peer id in {spec:?}: {e}"))?;
    Ok((PeerId(uuid), addr))
}

/// Build the peer table from `--peer`, `--peer-route` and `--peer-pin`.
///
/// Every route and pin is checked against a declared peer, because a spec that
/// names an undeclared peer is a typo, and the failure mode of that typo is a
/// peer that silently never receives traffic.
fn build_peers(args: &MeshArgs) -> Result<Vec<PeerConfig>, String> {
    let mut peers: Vec<PeerConfig> = Vec::new();
    for spec in &args.peer {
        let (peer_id, addr) = parse_peer_spec(spec)?;
        if peers.iter().any(|peer| peer.peer_id == peer_id) {
            return Err(format!("peer {} declared twice", peer_id.0));
        }
        peers.push(PeerConfig {
            peer_id,
            addr,
            pinned_identity_vk: None,
            routes: Vec::new(),
        });
    }

    for spec in &args.peer_route {
        let (id, cidr) = spec
            .split_once('=')
            .ok_or_else(|| format!("expected <peer-id>=<cidr>, got {spec:?}"))?;
        let peer_id = PeerId(
            Uuid::parse_str(id.trim()).map_err(|e| format!("bad peer id in {spec:?}: {e}"))?,
        );
        let destination = Destination::parse(cidr.trim()).map_err(|e| format!("{spec:?}: {e}"))?;
        if destination.is_default() {
            return Err(format!(
                "{spec:?} is the default route; routing everything through one peer is not \
                 implemented and would cut off the peers themselves"
            ));
        }
        let peer = peers
            .iter_mut()
            .find(|peer| peer.peer_id == peer_id)
            .ok_or_else(|| format!("{spec:?} names a peer no --peer declared"))?;
        peer.routes.push(destination);
    }

    for spec in &args.peer_pin {
        let (id, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("expected <peer-id>=<path>, got {spec:?}"))?;
        let peer_id = PeerId(
            Uuid::parse_str(id.trim()).map_err(|e| format!("bad peer id in {spec:?}: {e}"))?,
        );
        let verify_key = mesh_identity::load_verify_key(Path::new(path.trim()))
            .map_err(|e| format!("{spec:?}: {e}"))?;
        let peer = peers
            .iter_mut()
            .find(|peer| peer.peer_id == peer_id)
            .ok_or_else(|| format!("{spec:?} names a peer no --peer declared"))?;
        peer.pinned_identity_vk = Some(verify_key);
    }

    Ok(peers)
}

/// Reject combinations that would otherwise fail silently at runtime.
fn validate_mesh_args(args: &MeshArgs) -> Result<(), String> {
    // No bind means no mesh; every other flag is inert.
    if args.mesh_bind.is_none() {
        return Ok(());
    }
    // A cluster id is not optional, because a node only accepts peers from its
    // own cluster. Without one every node invents a different id and no
    // handshake can ever complete — which shows up at runtime as
    // "peer belongs to a different cluster", naming a cluster the operator
    // never chose. Refusing at startup says what is actually wrong.
    if args.cluster_id.is_none() {
        return Err(
            "--cluster-id is required with --mesh-bind: every node supplies the same value, and \
             a node only accepts peers whose binding carries it"
                .to_string(),
        );
    }

    // Build the peer table once; every other check reads from it.
    let peers = build_peers(args)?;
    // A route or pin naming a peer that was never declared is a typo, and a
    // typo here means a peer that silently never gets traffic.
    for spec in args.peer_route.iter().chain(args.peer_pin.iter()) {
        let (id, _) = spec
            .split_once('=')
            .ok_or_else(|| format!("expected <peer-id>=<value>, got {spec:?}"))?;
        let uuid =
            Uuid::parse_str(id.trim()).map_err(|e| format!("bad peer id in {spec:?}: {e}"))?;
        if !peers.iter().any(|peer| peer.peer_id == PeerId(uuid)) {
            return Err(format!(
                "{spec:?} names peer {uuid}, which no --peer declared"
            ));
        }
    }
    if !args.no_tun && args.tunnel_ip.is_none() {
        return Err("--tunnel-ip is required unless --no-tun is set".to_string());
    }
    // A TUN MTU above the frame ceiling makes every full-size frame oversize, so
    // it is emitted unpadded at its true size and the outer datagram fragments
    // at the IP layer — the very fragmentation the mesh fragments at its own
    // layer in order to avoid.
    if !args.no_tun && args.mtu as usize > imperium_net_mesh::MAX_SAFE_TUN_MTU {
        return Err(format!(
            "--mtu {} is above {}, the largest MTU whose sealed frame still fits a \
             1500-byte path MTU",
            args.mtu,
            imperium_net_mesh::MAX_SAFE_TUN_MTU
        ));
    }

    // Both route flags install kernel routes, so both need an interface. Without
    // this, --peer-route with --no-tun silently installs nothing: the operator
    // asked for routes that were never created and no message says so.
    if args.no_tun && !(args.route.is_empty() && args.peer_route.is_empty()) {
        return Err(
            "--route and --peer-route install kernel routes, so they need an interface to route \
             onto and cannot be combined with --no-tun"
                .to_string(),
        );
    }
    // Reject a default route before anything is installed, rather than relying
    // on the installer to refuse it mid-startup with the interface already up.
    for cidr in &args.route {
        match imperium_net_host::Destination::parse(cidr) {
            Ok(destination) if destination.is_default() => {
                return Err(format!(
                    "--route {cidr} is the default route; routing everything through the \
                     tunnel is not implemented (and would cut off the peer itself)"
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("--route {cidr}: {error}")),
        }
    }
    Ok(())
}

/// Handles owning the live mesh, so the node can shut it down on the way out.
///
/// The daemon handle and runner flag feed the control socket's live health
/// response; the tasks own their own clones for packet processing.
struct MeshRuntime {
    shutdown: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
    daemon: Arc<MeshDaemon>,
    host_interface: bool,
    runner_active: Arc<AtomicBool>,
    host_bridge_active: Option<Arc<AtomicBool>>,
    /// Routes installed through the tunnel, removed when this is dropped or
    /// `shutdown` runs. Kernel state outlives the process, so cleanup is
    /// explicit rather than implied.
    routes: RouteGuard,
}

struct ActiveTaskGuard(Arc<AtomicBool>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl MeshRuntime {
    fn shutdown(mut self) {
        self.shutdown.notify_waiters();
        self.runner_active.store(false, Ordering::SeqCst);
        if let Some(active) = &self.host_bridge_active {
            active.store(false, Ordering::SeqCst);
        }
        for task in self.tasks {
            task.abort();
        }
        // Remove routes before the guard's own Drop, so the removal is ordered
        // and logged rather than happening during teardown.
        self.routes.remove_all();
    }
}

/// The GUI is created by winit and must run on the process main thread.
/// Startup and the bus loop still run on the large-stack node thread.
type GuiLaunch = (
    Arc<BusPublisher>,
    Arc<StagingArea>,
    imperium_gui::SharedUiState,
    String,
    tokio::runtime::Handle,
);

#[derive(Subcommand)]
enum ClusterAction {
    /// Mint a bootstrap token for a new node
    MintToken {
        /// Token expiry duration in hours
        #[arg(long, default_value = "168")]
        expires_hours: u64,
    },
    /// Import a bootstrap token received out-of-band
    ImportToken {
        /// Base32-encoded token string
        token: String,
    },
    /// Approve a pending membership request
    Approve {
        /// Peer ID to approve
        peer_id: String,
    },
    /// Show cluster membership status
    Status,
}

#[derive(Subcommand)]
enum SignatureAction {
    /// List pending signature candidates
    Pending,
    /// Approve a signature candidate
    Approve {
        /// UUID of the candidate to approve
        candidate_id: String,
    },
    /// Reject a signature candidate
    Reject {
        /// UUID of the candidate to reject
        candidate_id: String,
        /// Rejection reason
        #[arg(long, default_value = "operator rejected")]
        reason: String,
    },
    /// Extract a signature from event data
    Extract {
        /// Comma-separated event IDs to extract from
        #[arg(long)]
        events: String,
        /// Reason for extraction
        #[arg(long, default_value = "manual extraction")]
        reason: String,
    },
    /// Show details for a signature candidate
    Show {
        /// UUID of the candidate to show
        candidate_id: String,
    },
}

/// Process entry point.
///
/// Deliberately NOT `#[tokio::main]`, and deliberately not running on the
/// process main thread.
///
/// The node's startup path is one deep, fully-inlined async state machine:
/// every subsystem's `init`, the supervisor engagement, and the strand
/// installation all fold into it, and several of those steps carry
/// multi-kilobyte post-quantum key material and code tables on the stack. On
/// the default 8 MiB main-thread stack this aborts with "thread 'main' has
/// overflowed its stack" before the runtime loop is ever entered — observed by
/// running the binary, not theorised, and it reproduces with no mesh flags at
/// all, so it predates the mesh work.
///
/// Two things fix it together:
///
/// 1. the node runs on a thread sized for the work, so the whole startup chain
///    has room regardless of which step is deepest;
/// 2. the runtime's worker threads are sized too, because a mesh handshake
///    signs and verifies with ML-DSA-65 inside a spawned task and their default
///    is 2 MiB.
///
/// The future is also boxed, so `block_on` does not lay it out on this thread's
/// stack.
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let gui_requested = matches!(
        &cli.command,
        Commands::Node {
            action: NodeAction::Start { gui: true, .. }
        }
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(CRYPTO_STACK)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let runtime_handle = runtime.handle().clone();
    let (gui_tx, gui_rx) = std::sync::mpsc::sync_channel::<GuiLaunch>(1);
    let node = std::thread::Builder::new()
        .stack_size(CRYPTO_STACK)
        .name("imperium-node".to_string())
        .spawn(move || runtime.block_on(Box::pin(run(cli, gui_requested.then_some(gui_tx)))))
        .expect("spawn node thread");

    if gui_requested {
        match gui_rx.recv() {
            Ok((bus, staging, state, endpoint, gui_runtime_handle)) => {
                // `spawn_pump` uses Tokio, while winit needs this process main
                // thread. Entering the running runtime supplies both boundaries.
                let _runtime_context = runtime_handle.enter();
                if let Err(error) = imperium_gui::run_with_state_and_control(
                    Arc::clone(&bus),
                    staging,
                    state,
                    endpoint,
                    gui_runtime_handle,
                ) {
                    tracing::error!(%error, "operator console exited with error");
                }
                // Also stop the node when window construction fails, in which
                // case eframe never gets to call the app's on_exit hook.
                imperium_gui::commands::shutdown(&bus, "operator console exited");
            }
            Err(_) => tracing::error!("node exited before the operator console was ready"),
        }
    }

    node.join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
}

async fn run(cli: Cli, gui_tx: Option<std::sync::mpsc::SyncSender<GuiLaunch>>) {
    match cli.command {
        Commands::Node { action } => match action {
            NodeAction::Start { gui, mesh } => {
                if let Err(error) = validate_mesh_args(&mesh) {
                    eprintln!("imperium: {error}");
                    std::process::exit(2);
                }
                cmd_node_start(gui, mesh, gui_tx).await
            }
        },
        Commands::Cluster { action } => match action {
            ClusterAction::MintToken { expires_hours } => cmd_cluster_mint_token(expires_hours),
            ClusterAction::ImportToken { token } => cmd_cluster_import_token(&token),
            ClusterAction::Approve { peer_id } => cmd_cluster_approve(&peer_id),
            ClusterAction::Status => cmd_cluster_status(),
        },
        Commands::Signatures { action } => match action {
            SignatureAction::Pending => cmd_signatures_pending(),
            SignatureAction::Approve { candidate_id } => cmd_signatures_approve(&candidate_id),
            SignatureAction::Reject {
                candidate_id,
                reason,
            } => cmd_signatures_reject(&candidate_id, &reason),
            SignatureAction::Extract { events, reason } => cmd_signatures_extract(&events, &reason),
            SignatureAction::Show { candidate_id } => cmd_signatures_show(&candidate_id),
        },
    }
}

async fn cmd_node_start(
    gui: bool,
    mesh: MeshArgs,
    gui_tx: Option<std::sync::mpsc::SyncSender<GuiLaunch>>,
) {
    tracing::info!("starting imperium node");

    // ---- The one kernel, and the one shareable handle. -------------------
    //
    // `Bus::run_until` consumes the kernel, so it cannot live behind an `Arc`:
    // the coordinator owns it here, hands it over once at `Supervision::engage`
    // below, and every other participant holds `Arc<BusPublisher>` — the native
    // shareable handle. This replaces the old `Arc<Bus>` that nine crates shared
    // and then tried to consume.
    let mut coordinator = RuntimeCoordinator::new();
    let publisher = coordinator.bus();
    // Lifecycle events are not replayed to late named subscribers. Monitor the
    // Lightcone strand before the kernel installs it.
    let lightcone_lifecycle = control::LightconeLifecycleMonitor::subscribe(&publisher);
    let staging = Arc::new(StagingArea::new(Arc::clone(&publisher)));
    // Named bus subscriptions have no replay. Install the GUI pump before
    // subsystem startup so its initial status is built from real events.
    let gui_state = gui.then(|| imperium_gui::spawn_pump(Arc::clone(&publisher)));

    let kernel = coordinator
        .take_bus()
        .expect("the coordinator's kernel, taken by the process root exactly once");
    let (kernel, _runtime_tasks, lightcone) =
        initialize_node(kernel, Arc::clone(&publisher), Arc::clone(&staging)).await;

    // Install the observer and other queued strands before the mesh can send
    // or receive. A busy handshake can overflow the kernel's small replay
    // tail if socket traffic begins before the run loop installs them.
    let mut supervision = imperium_cli::supervision::Supervision::engage_from_env(kernel);

    let mut host_guard = if mesh.host_guard {
        match HostKillSwitch::install() {
            Ok(guard) => Some(Arc::new(tokio::sync::Mutex::new(guard))),
            Err(error) => {
                eprintln!("imperium: opt-in host guard startup failed: {error}");
                supervision.shutdown();
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let mut transport_runtime = match start_live_transport(&mesh, Arc::clone(&publisher)).await {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("imperium: live transport startup failed: {error}");
            shutdown_host_guard(host_guard.take()).await;
            supervision.shutdown();
            std::process::exit(1);
        }
    };

    // The mesh data plane starts only after its bus consumers can run.
    let mesh_runtime = match start_mesh(&mesh, Arc::clone(&publisher)).await {
        Ok(Some(runtime)) => Some(runtime),
        Ok(None) => None,
        Err(error) => {
            shutdown_live_transport(transport_runtime.take()).await;
            shutdown_host_guard(host_guard.take()).await;
            // A refused host interface is fatal: running without the tunnel
            // while the operator believes it is up is worse than not starting.
            eprintln!("imperium: mesh startup failed: {error}");
            std::process::exit(1);
        }
    };

    tokio::spawn(control::serve_with_staging(
        Arc::clone(&publisher),
        Arc::clone(&staging),
        mesh_runtime.as_ref().map(|runtime| {
            control::MeshHealth::new(
                Arc::clone(&runtime.daemon),
                runtime.host_interface,
                Arc::clone(&runtime.runner_active),
                runtime.host_bridge_active.as_ref().map(Arc::clone),
            )
        }),
        lightcone,
        lightcone_lifecycle,
        transport_runtime
            .as_ref()
            .map(|(runtime, _worker)| Arc::clone(runtime)),
        host_guard.as_ref().map(Arc::clone),
    ));

    if gui {
        tracing::info!(endpoint = %control::control_endpoint(), "subsystems initialized, control surface listening, launching operator console");
        let Some((sender, state)) = gui_tx.zip(gui_state) else {
            tracing::error!("GUI launch channel unavailable");
            supervision.shutdown();
            shutdown_live_transport(transport_runtime.take()).await;
            shutdown_host_guard(host_guard.take()).await;
            if let Some(runtime) = mesh_runtime {
                runtime.shutdown();
            }
            return;
        };
        if sender
            .send((
                Arc::clone(&publisher),
                staging,
                state,
                control::control_endpoint(),
                tokio::runtime::Handle::current(),
            ))
            .is_err()
        {
            tracing::error!("GUI process main thread exited before launch");
        }
        let reason = coordinator.run().await;
        tracing::info!(reason = ?reason, "runtime exited");
        supervision.shutdown();
        shutdown_live_transport(transport_runtime.take()).await;
        shutdown_host_guard(host_guard.take()).await;
        if let Some(runtime) = mesh_runtime {
            runtime.shutdown();
        }
        return;
    }

    tracing::info!(endpoint = %control::control_endpoint(), "subsystems initialized, control surface listening, runtime entering run loop");
    let reason = coordinator.run().await;
    tracing::info!(reason = ?reason, "runtime exited");
    supervision.shutdown();
    shutdown_live_transport(transport_runtime.take()).await;
    shutdown_host_guard(host_guard.take()).await;
    if let Some(runtime) = mesh_runtime {
        runtime.shutdown();
    }
}

type LiveTransportHandles = (Arc<LiveTransportRuntime>, JoinHandle<()>);

async fn start_live_transport(
    args: &MeshArgs,
    publisher: Arc<BusPublisher>,
) -> Result<Option<LiveTransportHandles>, String> {
    let (Some(profile_file), Some(initial_id)) = (&args.transport_profiles, &args.active_profile)
    else {
        if args.transport_profiles.is_some() || args.active_profile.is_some() {
            return Err(
                "--transport-profiles and --active-profile must be supplied together".into(),
            );
        }
        return Ok(None);
    };

    let profiles = read_transport_profile_file(profile_file)?;
    let runtime = Arc::new(
        LiveTransportRuntime::new(Arc::clone(&publisher), profiles, initial_id)
            .map_err(|error| error.to_string())?,
    );
    runtime.start().await.map_err(|error| error.to_string())?;
    let worker = match runtime.subscribe_commands(&publisher) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = runtime.shutdown().await;
            return Err(error.to_string());
        }
    };
    Ok(Some((runtime, worker)))
}

fn read_transport_profile_file(path: &Path) -> Result<Vec<LiveProtocolProfile>, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("transport profile path {}: {error}", path.display()))?;
    let file = std::fs::File::open(&canonical)
        .map_err(|error| format!("open transport profiles {}: {error}", canonical.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect transport profiles: {error}"))?;
    // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != uid && metadata.uid() != 0)
    {
        return Err("transport profile JSON must be an owner/root-owned regular file with no group/world write access".into());
    }
    let overflow_uid = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    if let Some(parent) = canonical.parent() {
        for ancestor in parent.ancestors() {
            let ancestor_meta = std::fs::symlink_metadata(ancestor).map_err(|error| {
                format!("transport profile ancestor {}: {error}", ancestor.display())
            })?;
            let mode = ancestor_meta.permissions().mode();
            let sticky_tmp = ancestor == Path::new("/tmp") && mode & 0o1777 == 0o1777;
            let unmapped_system_base = overflow_uid == Some(ancestor_meta.uid())
                && (ancestor == Path::new("/")
                    || ancestor == Path::new("/tmp")
                    || ancestor == Path::new("/home"));
            if !ancestor_meta.file_type().is_dir()
                || (mode & 0o022 != 0 && !sticky_tmp)
                || (ancestor_meta.uid() != uid && ancestor_meta.uid() != 0 && !unmapped_system_base)
            {
                return Err(format!(
                    "transport profile JSON has an untrusted ancestor: {}",
                    ancestor.display()
                ));
            }
        }
    }
    const MAX_PROFILE_FILE_BYTES: u64 = 1024 * 1024;
    let mut data = Vec::new();
    file.take(MAX_PROFILE_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read transport profiles: {error}"))?;
    if data.len() as u64 > MAX_PROFILE_FILE_BYTES {
        return Err("transport profile file exceeds 1 MiB".into());
    }
    serde_json::from_slice(&data).map_err(|error| format!("parse transport profiles: {error}"))
}

async fn shutdown_live_transport(handles: Option<LiveTransportHandles>) {
    if let Some((runtime, worker)) = handles {
        worker.abort();
        if let Err(error) = runtime.shutdown().await {
            tracing::error!(%error, "live transport shutdown did not complete cleanly");
        }
    }
}

async fn shutdown_host_guard(handle: Option<control::HostGuardHandle>) {
    if let Some(handle) = handle {
        let mut guard = handle.lock().await;
        if let Err(error) = guard.remove() {
            tracing::error!(%error, table = guard.table_name(), "host egress guard cleanup failed");
        }
    }
}

/// Bring up the mesh daemon, and the host interface unless `--no-tun`.
///
/// Returns `Ok(None)` when the mesh was not requested, so a node with no mesh
/// flags behaves exactly as it did before this existed.
async fn start_mesh(
    args: &MeshArgs,
    publisher: Arc<BusPublisher>,
) -> Result<Option<MeshRuntime>, String> {
    let Some(bind_addr) = args.mesh_bind else {
        return Ok(None);
    };

    // The operator key is the cluster trust anchor and is shared by every node.
    let (operator_path, operator) = with_crypto_stack(|| -> Result<_, String> {
        let path =
            operator_key::operator_key_path().map_err(|e| format!("operator key path: {e}"))?;
        let identity =
            operator_key::load_or_generate(&path).map_err(|e| format!("operator key: {e}"))?;
        Ok((path, identity))
    })?;

    // The mesh identity is THIS node's, and is what signs its Hello.
    let (identity_path, identity) = with_crypto_stack(|| -> Result<_, String> {
        let path =
            mesh_identity::mesh_identity_path().map_err(|e| format!("mesh identity path: {e}"))?;
        let identity =
            mesh_identity::load_or_generate(&path).map_err(|e| format!("mesh identity: {e}"))?;
        Ok((path, identity))
    })?;

    let cluster_id = args
        .cluster_id
        .map(ClusterId)
        .unwrap_or_else(ClusterId::new);
    let peers = build_peers(args)?;
    // Counts for the startup log, taken before the table is moved into config.
    let peer_count = peers.len();
    let dial_count = peers.iter().filter(|peer| peer.addr.is_some()).count();

    // Destinations to route through the tunnel.
    //
    // Every per-peer route is installed as a kernel route too, because a prefix
    // with a peer route but no kernel route is a prefix whose traffic never
    // enters the tunnel at all — the daemon would never see it in order to
    // choose a peer. `--route` remains for a prefix not tied to any peer.
    let mut wanted: Vec<Destination> = peers
        .iter()
        .flat_map(|peer| peer.routes.iter().copied())
        .collect();
    for cidr in &args.route {
        wanted.push(Destination::parse(cidr).map_err(|e| format!("--route {cidr}: {e}"))?);
    }
    // Two peers may legitimately claim overlapping prefixes.
    wanted.sort_by_key(|destination| (u32::from(destination.network), destination.prefix));
    wanted.dedup();

    let config = MeshNodeConfig {
        peer_id: identity.peer_id.clone(),
        cluster_id,
        bind_addr,
        peers,
        identity_signing_key: identity.signing_key,
        identity_verifying_key: identity.verify_key,
        operator_signing_key: operator.signing_key,
        operator_verifying_key: operator.verify_key,
        identity_ttl: chrono::Duration::hours(24),
        handshake_retry: Duration::from_secs(2),
        max_handshake_attempts: 6,
        session_idle_secs: 180,
        // 0 is the documented way to say "never rotate".
        session_max_bytes: (args.rekey_bytes > 0).then_some(args.rekey_bytes),
    };

    let (daemon, inbound) = MeshDaemon::bind(config, Arc::clone(&publisher))
        .await
        .map_err(|e| format!("bind {bind_addr}: {e}"))?;
    let local = daemon
        .local_addr()
        .map_err(|e| format!("local address: {e}"))?;

    tracing::info!(
        bound = %local,
        peer_id = %identity.peer_id.0,
        identity_file = %identity_path.display(),
        operator_file = %operator_path.display(),
        peers = peer_count,
        dialing = dial_count,
        "mesh link bound"
    );

    let shutdown = Arc::new(Notify::new());
    let mut tasks = Vec::new();

    let runner_active = Arc::new(AtomicBool::new(true));
    let runner = Arc::clone(&daemon);
    let runner_flag = Arc::clone(&runner_active);
    let daemon_shutdown = Arc::clone(&shutdown);
    tasks.push(tokio::spawn(async move {
        let _active_task = ActiveTaskGuard(runner_flag);
        if let Err(error) = runner.run(daemon_shutdown).await {
            tracing::error!(%error, "mesh daemon stopped with an error");
        }
    }));

    // Owned here rather than inside the interface branch, because it must be
    // returned to the caller so removal happens on the process's own shutdown
    // path. Validation already refuses --route together with --no-tun.
    let mut routes = RouteGuard::new();

    let (bridge_handle, host_bridge_active) = if args.no_tun {
        tracing::warn!("--no-tun: the encrypted link runs without a host interface");
        (None, None)
    } else {
        let tunnel_ip = args
            .tunnel_ip
            .ok_or_else(|| "--tunnel-ip is required unless --no-tun is set".to_string())?;
        let device = TunDevice::create(&args.tun, tunnel_ip, args.netmask, args.mtu)
            .map_err(|e| format!("create interface {}: {e}", args.tun))?;
        tracing::info!(
            name = device.name(),
            mtu = device.mtu(),
            address = %device.address(),
            netmask = %device.netmask(),
            "tunnel interface up (no host routes were changed)"
        );
        // Routes are installed after the interface exists but before the
        // bridge starts, so nothing is sent down a path that is not up yet.
        if !wanted.is_empty() {
            for destination in &wanted {
                routes
                    .install(*destination, device.name())
                    .map_err(|e| format!("install route {destination}: {e}"))?;
            }
            tracing::info!(
                routes = ?routes.destinations(),
                "routing these destinations through the tunnel"
            );
        }
        let (bridge, handle) = HostBridge::new(device, Arc::clone(&daemon), inbound);
        let bridge_shutdown = Arc::clone(&shutdown);
        let active = Arc::new(AtomicBool::new(true));
        let active_task = Arc::clone(&active);
        tasks.push(tokio::spawn(async move {
            let _active_task = ActiveTaskGuard(active_task);
            if let Err(error) = bridge.run(bridge_shutdown).await {
                tracing::error!(%error, "host bridge stopped with an error");
            }
        }));
        (Some(handle), Some(active))
    };

    // Health reporting belongs to the link, not the interface: without it a
    // `--no-tun` run says nothing about whether the handshake ever completed.
    if args.report_secs > 0 {
        tasks.push(tokio::spawn(report_link_health(
            Arc::clone(&daemon),
            bridge_handle,
            args.report_secs,
        )));
    }

    Ok(Some(MeshRuntime {
        shutdown,
        tasks,
        daemon,
        host_interface: !args.no_tun,
        runner_active,
        host_bridge_active,
        routes,
    }))
}

/// Periodic link health, so a live run is observable rather than inferred.
async fn report_link_health(
    daemon: Arc<MeshDaemon>,
    bridge: Option<imperium_net_host::BridgeHandle>,
    every_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(every_secs.max(1)));
    ticker.tick().await; // the first tick fires immediately
    loop {
        ticker.tick().await;
        let mesh = daemon.stats();
        match &bridge {
            Some(bridge) => {
                let host = bridge.stats();
                tracing::info!(
                    established = daemon.is_established(),
                    peers_established = daemon.established_peers().len(),
                    killed = daemon.is_killed(),
                    mesh_datagrams = mesh.datagrams_received,
                    handshakes = mesh.handshakes_completed,
                    frames_opened = mesh.frames_opened,
                    frames_failed = mesh.frames_failed,
                    nat_rebinds = mesh.nat_rebinds,
                    rekeys = mesh.sessions_rekeyed,
                    reassembled = mesh.handshake_datagrams_reassembled,
                    fragments_rejected = mesh.handshake_fragments_rejected,
                    handshake_verifications = mesh.handshake_verifications,
                    handshake_failures = mesh.handshake_failures,
                    cookies_sent = mesh.handshake_cookies_sent,
                    rate_limited = mesh.handshake_rate_limited,
                    cover_sent = mesh.cover_frames_sent,
                    host_in = host.packets_from_host,
                    host_in_dropped = host.packets_from_host_dropped,
                    host_suppressed = host.packets_suppressed,
                    host_out = host.packets_to_host,
                    "mesh link health"
                );
            }
            None => {
                tracing::info!(
                    established = daemon.is_established(),
                    peers_established = daemon.established_peers().len(),
                    killed = daemon.is_killed(),
                    mesh_datagrams = mesh.datagrams_received,
                    handshakes = mesh.handshakes_completed,
                    frames_opened = mesh.frames_opened,
                    frames_failed = mesh.frames_failed,
                    nat_rebinds = mesh.nat_rebinds,
                    rekeys = mesh.sessions_rekeyed,
                    reassembled = mesh.handshake_datagrams_reassembled,
                    fragments_rejected = mesh.handshake_fragments_rejected,
                    handshake_verifications = mesh.handshake_verifications,
                    handshake_failures = mesh.handshake_failures,
                    cookies_sent = mesh.handshake_cookies_sent,
                    rate_limited = mesh.handshake_rate_limited,
                    cover_sent = mesh.cover_frames_sent,
                    "mesh link health (no host interface)"
                );
            }
        }
    }
}

/// Wire every subsystem and queue its supervised strands.
///
/// Takes `&mut RuntimeCoordinator` because the kernel is owned by the
/// coordinator and strand specs must be registered on it directly; every
/// publisher-side call gets the shared `Arc<BusPublisher>` instead.
async fn initialize_node(
    mut kernel: Bus,
    publisher: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
) -> (
    Bus,
    Vec<JoinHandle<()>>,
    Option<Arc<imperium_net_lightcone::LightconeService>>,
) {
    let mut tasks = Vec::new();

    if let Err(e) = imperium_net_cluster::init(&publisher).await {
        tracing::error!(error = %e, "cluster init failed");
    }
    if let Err(e) = imperium_net_mesh::init(&publisher).await {
        tracing::error!(error = %e, "mesh init failed");
    }
    if let Err(e) = imperium_net_transport::init(&publisher).await {
        tracing::error!(error = %e, "transport init failed");
    }
    if let Err(e) = imperium_net_strainer::init(&publisher).await {
        tracing::error!(error = %e, "strainer init failed");
    }
    if let Err(e) = imperium_net_sensors::init(&publisher).await {
        tracing::error!(error = %e, "sensors init failed");
    }
    if let Err(e) = imperium_net_signatures::init(&publisher).await {
        tracing::error!(error = %e, "signatures init failed");
    }
    if let Err(e) = imperium_net_toolkit::init(&publisher).await {
        tracing::error!(error = %e, "toolkit init failed");
    }
    // Passive network Lightcone: additive observation only. If the world fails
    // to load it logs and the node continues — the thesis requires the system
    // to work without its intelligence layer.
    //
    // Its observer loop is the SUPERVISION PILOT: `init` warms the world and
    // returns the strand spec for the frame → receipt loop, and the spec is
    // registered HERE, before `engage_supervision()` below. Strand specs are
    // installed by the kernel's run loop, so registering after engage is refused
    // (`register_strand` returns a clear `StrandRegistrationError`) rather than
    // silently leaving the Lightcone unsupervised.
    let lightcone = match imperium_net_lightcone::init_with_service(&publisher) {
        Ok(Some(installation)) => {
            // Queued on the kernel; the run loop installs it. Registration
            // cannot fail — a spec queued after the loop starts is impossible to
            // write, because the loop consumes the bus.
            kernel.register_spec(installation.spec);
            Some(installation.service)
        }
        // World unavailable (already logged by `init`).
        Ok(None) => None,
        Err(e) => {
            tracing::error!(error = %e, "lightcone init failed");
            None
        }
    };

    // Door two: the brain reads door one's receipts and consolidates self-caused new normal.
    // Supervised like the lightcone; registered before the run loop. It never changes door one.
    let brain = match imperium_net_brain::init_with_service(&publisher) {
        Ok(Some((spec, service))) => {
            kernel.register_spec(spec);
            Some(service)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::error!(error = %e, "brain init failed");
            None
        }
    };
    let _brain = brain; // held for the future `vpn brain status` surface; the strand already runs

    let store = Arc::new(Store::in_memory());
    let memory_log = Arc::new(MemoryLog::default());
    let toolkit = Arc::new(ToolManager::new(Arc::clone(&publisher)));
    let hardening = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    // The deployment orchestrator's two recv loops are supervised strands now:
    // `register_strands` builds it and queues both lane specs before
    // `engage_supervision()`. Its lanes hold their own `Arc`s through the spec
    // factories, so the node does not need the binding — it is kept only to own
    // the fallback instance. On the (currently unreachable) refusal, fall back
    // to an unregistered orchestrator rather than failing the node.
    let _deployment = DeploymentOrchestrator::register_strands(&mut kernel, &publisher);

    register_default_tools(&toolkit);
    if let Err(e) = hardening.apply(HardeningController::balanced_profile(None)) {
        tracing::warn!(error = %e, "failed to apply default hardening profile");
    }
    // The toolkit's activation loop is a supervised strand now (its
    // `tokio::spawn` is gone): queue its spec before `engage_supervision()`.
    imperium_net_toolkit::register_strands(&mut kernel, &publisher, &toolkit);
    // The hardening lane is queued FIRST, bound to THIS controller — the one the
    // balanced profile was just applied to above. `queue_hardening` is
    // idempotent per (bus, strand name), so the transport `register_strands`
    // call below leaves the name claimed by this instance.
    imperium_net_transport::queue_hardening(
        &mut kernel,
        &publisher,
        &hardening,
        imperium_net_transport::HardeningFaultPolicy::from_env(),
    );

    // The memory log's two recv loops are supervised strands now. They share
    // *this* log — the extraction loop and the projection read the same entries.
    imperium_memory_log::register_strands(&mut kernel, &memory_log);

    // The cluster's membership-grant and config-fetch-response loops are
    // supervised strands now. The CLI owns no cluster identity yet, so they
    // start idle and serve whichever managers a node wires to this bus.
    imperium_net_cluster::register_strands(&mut kernel, &publisher);

    let extraction_loop = Arc::new(ExtractionLoop::new(
        Arc::clone(&publisher),
        Arc::clone(&store),
        Arc::clone(&memory_log),
        Arc::clone(&staging),
    ));
    // The extraction loop is a supervised strand now (its tokio::spawned recv
    // loop is gone): queue its spec before `engage_supervision()`.
    imperium_net_signatures::register_strands(&mut kernel, &extraction_loop);

    // The orchestrator's two recv loops are supervised strands now: queue their
    // specs before `engage_supervision()`. Two lanes, not one — the failover
    // path and the noisy sensor path keep independent failure domains. The
    // default config is this node's deployment pair (xray active, amneziawg
    // standby, default policy).
    imperium_net_transport::register_strands(&mut kernel, &publisher);

    // Operator identity is persisted (1C): the same key + PeerId must sign
    // approvals across restarts or the engine cannot verify them. Fail
    // closed: refuse the signature subsystem instead of minting ephemeral
    // keys when the key file cannot be loaded or generated.
    let operator = match with_crypto_stack(|| {
        operator_key::operator_key_path()
            .map_err(|e| e.to_string())
            .and_then(|path| operator_key::load_or_generate(&path).map_err(|e| e.to_string()))
    }) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(
                error = %error,
                "operator key unavailable — signature approval wiring refused"
            );
            tracing::info!(
                task_count = tasks.len(),
                "node wiring complete (signatures refused)"
            );
            return (kernel, tasks, lightcone);
        }
    };
    let operator_id = operator.peer_id;
    let operator_signing_key = operator.signing_key;
    let operator_verify_key = std::sync::Arc::new(operator.verify_key);
    tasks.push(subscribe_signature_approval_requests(
        Arc::clone(&publisher),
        Arc::clone(&staging),
        operator_id.clone(),
        operator_signing_key,
    ));
    tasks.push(subscribe_signature_rejection_requests(
        Arc::clone(&publisher),
        staging,
        operator_id.clone(),
    ));

    let signature_engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&publisher))
            .with_shared_store(Arc::clone(&store))
            .with_operator_verify_key(operator_verify_key),
    );
    // The approval loop is a supervised strand now: queue its spec before
    // `engage_supervision()`. It shares *this* engine (store + operator verify
    // key + database), not a fresh one.
    imperium_net_sensors::register_strands(&mut kernel, &signature_engine);

    tracing::info!(task_count = tasks.len(), "node wiring complete");
    (kernel, tasks, lightcone)
}

fn register_default_tools(toolkit: &ToolManager) {
    toolkit.register(ToolManifest {
        name: "transport.diagnostics".to_string(),
        description:
            "Capture transport state when the orchestrator sees a high-confidence burn signal"
                .to_string(),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(30),
        cooldown_duration: Duration::from_secs(60),
        max_activations_per_hour: 10,
    });
    toolkit.register(ToolManifest {
        name: "forensics.emergency.snapshot".to_string(),
        description: "Capture a bounded emergency snapshot before shutdown containment completes"
            .to_string(),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(60),
        cooldown_duration: Duration::from_secs(300),
        max_activations_per_hour: 3,
    });

    for tool_name in ["transport.diagnostics", "forensics.emergency.snapshot"] {
        if let Err(e) = toolkit.arm(tool_name) {
            tracing::warn!(tool_name, error = %e, "failed to arm default toolkit tool");
        }
    }
}

/// Extract a candidate UUID from an approve-request message.
///
/// Accepts the typed `SignatureApprovalRequest` plus both legacy string
/// envelopes (`cli-approve:<uuid>`, `gui-approve:<uuid>`). The legacy
/// strings are deprecated but kept for one release for in-flight tooling;
/// their use is warn-logged at the call site.
fn approve_request_candidate_id(message: &Message) -> Option<uuid::Uuid> {
    match message {
        Message::SignatureApprovalRequest(req) => Some(req.candidate_id),
        Message::SubsystemReady { name } => {
            for prefix in ["cli-approve:", "gui-approve:"] {
                if let Some(rest) = name.strip_prefix(prefix) {
                    tracing::warn!(
                        prefix,
                        "deprecated approve envelope in use; switch to SignatureApprovalRequest"
                    );
                    return uuid::Uuid::parse_str(rest).ok();
                }
            }
            None
        }
        _ => None,
    }
}

fn subscribe_signature_approval_requests(
    publisher: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    operator_id: PeerId,
    signing_key: HybridSigningKey,
) -> JoinHandle<()> {
    // The consumer owns its own bounded queue. Native delivery is push-based
    // and the kernel keeps no per-subscriber queue, so the callback — which runs
    // on the publisher's thread — does one non-blocking send and nothing else,
    // and the queue is what stops an operator-request burst from stalling a
    // publisher. A full queue drops the event and counts it; the loop reports
    // the count before the next event.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(OPERATOR_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let drops = Arc::clone(&dropped);
    publisher.subscribe_prefix(
        "net.signatures.approve_request",
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<BusEvent>() {
                if tx.try_send(*event).is_err() {
                    drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }),
    );

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            {
                let lagged = dropped.swap(0, Ordering::Relaxed);
                if lagged > 0 {
                    tracing::warn!(
                        lagged,
                        "approve-request queue overflowed; events were dropped"
                    );
                }
                {
                    let topic = event.topic.clone();
                    match approve_request_candidate_id(&event.message) {
                        Some(candidate_id) => {
                            if let Err(e) =
                                staging.approve(candidate_id, &operator_id, &signing_key)
                            {
                                tracing::warn!(
                                    candidate_id = %candidate_id,
                                    error = %e,
                                    "signature approval request failed"
                                );
                            }
                        }
                        None => {
                            tracing::warn!(
                                topic = %topic,
                                message = ?event.message,
                                "dropped approve_request: unrecognized envelope or bad UUID"
                            );
                        }
                    }
                }
            }
        }
    })
}

fn subscribe_signature_rejection_requests(
    publisher: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    operator_id: PeerId,
) -> JoinHandle<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(OPERATOR_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let drops = Arc::clone(&dropped);
    publisher.subscribe_prefix(
        "net.signatures.reject_request",
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<BusEvent>() {
                if tx.try_send(*event).is_err() {
                    drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }),
    );
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let lagged = dropped.swap(0, Ordering::Relaxed);
            if lagged > 0 {
                tracing::warn!(
                    lagged,
                    "reject-request queue overflowed; events were dropped"
                );
            }
            if let Message::SignatureRejected(rejected) = event.message {
                if let Err(e) =
                    staging.reject(rejected.candidate_id, &operator_id, &rejected.reason)
                {
                    tracing::warn!(
                        candidate_id = %rejected.candidate_id,
                        error = %e,
                        "signature rejection request failed"
                    );
                }
            }
        }
    })
}

/// Depth of an operator-request queue. Operator commands arrive one at a time
/// by hand, so the only thing this depth protects against is a burst published
/// by a test or a replay; parity with the depth the deleted shim gave every
/// subscription.
const OPERATOR_QUEUE: usize = 1024;

fn cmd_cluster_mint_token(expires_hours: u64) {
    use imperium_net_cluster::TokenManager;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_protocol::{ClusterId, PeerId};
    use rand::rngs::OsRng;

    let cluster_id = ClusterId::new();
    let operator_id = PeerId::new();
    let mut rng = OsRng;
    let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    let mgr = TokenManager::new(cluster_id, vk);
    let token = mgr.mint_token(
        &operator_id,
        &sk,
        chrono::Duration::hours(expires_hours as i64),
    );

    let json = serde_json::to_string_pretty(&token).expect("serialize token");
    println!("{}", json);
}

fn cmd_cluster_import_token(token_str: &str) {
    tracing::info!(token_len = token_str.len(), "importing bootstrap token");
    match serde_json::from_str::<imperium_protocol::BootstrapTokenPayload>(token_str) {
        Ok(token) => {
            tracing::info!(
                cluster_id = %token.cluster_id.0,
                expires_at = %token.expires_at,
                "token parsed successfully"
            );
            println!("Token imported for cluster {}", token.cluster_id.0);
        }
        Err(e) => {
            eprintln!("Failed to parse token: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_cluster_approve(peer_id_str: &str) {
    tracing::info!(peer_id = peer_id_str, "approving membership request");
    match uuid::Uuid::parse_str(peer_id_str) {
        Ok(id) => println!("Membership approval dispatched for peer {}", id),
        Err(e) => {
            eprintln!("Invalid peer ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_cluster_status() {
    println!("Cluster status: use `imperium node start` to run the node first, then query via control pipe.");
}

fn cmd_signatures_pending() {
    println!("Pending signatures: use `imperium node start` to run the node first, then query via control pipe.");
}

fn cmd_signatures_approve(candidate_id: &str) {
    tracing::info!(candidate_id = candidate_id, "approving signature candidate");
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!("Signature approval dispatched for candidate {}", id),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_signatures_reject(candidate_id: &str, reason: &str) {
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!(
            "Signature rejection dispatched for candidate {} (reason: {})",
            id, reason
        ),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_signatures_extract(events: &str, reason: &str) {
    let ids: Vec<&str> = events.split(',').map(|s| s.trim()).collect();
    let mut valid = Vec::new();
    for id_str in &ids {
        match uuid::Uuid::parse_str(id_str) {
            Ok(id) => valid.push(id),
            Err(e) => {
                eprintln!("Invalid event ID '{}': {}", id_str, e);
                std::process::exit(1);
            }
        }
    }
    println!(
        "Extraction requested for {} events (reason: {}). Use via control pipe on a running node.",
        valid.len(),
        reason
    );
}

fn cmd_signatures_show(candidate_id: &str) {
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!(
            "Show candidate {}: use via control pipe on a running node.",
            id
        ),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A named subscription feeding an owned bounded queue — the shape an async
    /// consumer outside a strand must have now that delivery is push-based.
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
    use clap::CommandFactory;

    #[test]
    fn cli_parses_node_start() {
        let cli = Cli::try_parse_from(["imperium", "node", "start"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Node {
                action: NodeAction::Start { gui: false, .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "mint-token"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::MintToken { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token_with_expiry() {
        let cli =
            Cli::try_parse_from(["imperium", "cluster", "mint-token", "--expires-hours", "24"])
                .unwrap();
        if let Commands::Cluster {
            action: ClusterAction::MintToken { expires_hours },
        } = cli.command
        {
            assert_eq!(expires_hours, 24);
        } else {
            panic!("expected MintToken");
        }
    }

    #[test]
    fn cli_parses_cluster_import_token() {
        let cli =
            Cli::try_parse_from(["imperium", "cluster", "import-token", "ABCDEF123456"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::ImportToken { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_approve() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "approve", "some-peer-id"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::Approve { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_status() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::Status
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_pending() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "pending"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Pending
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_approve() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "approve", "some-uuid"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Approve { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_reject() {
        let cli = Cli::try_parse_from([
            "imperium",
            "signatures",
            "reject",
            "some-uuid",
            "--reason",
            "false positive",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Reject { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_extract() {
        let cli = Cli::try_parse_from([
            "imperium",
            "signatures",
            "extract",
            "--events",
            "uuid1,uuid2",
        ])
        .unwrap();
        if let Commands::Signatures {
            action: SignatureAction::Extract { events, .. },
        } = cli.command
        {
            assert_eq!(events, "uuid1,uuid2");
        } else {
            panic!("expected Extract");
        }
    }

    #[test]
    fn cli_parses_signatures_show() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "show", "some-uuid"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Show { .. }
            }
        ));
    }

    #[test]
    fn cli_rejects_empty_args() {
        assert!(Cli::try_parse_from(["imperium"]).is_err());
    }

    #[test]
    fn cli_help_does_not_panic() {
        Cli::command().debug_assert();
    }

    #[test]
    fn approve_request_accepts_typed_variant() {
        let id = uuid::Uuid::new_v4();
        let msg = Message::SignatureApprovalRequest(imperium_protocol::SignatureApprovalRequest {
            candidate_id: id,
        });
        assert_eq!(approve_request_candidate_id(&msg), Some(id));
    }

    #[test]
    fn approve_request_accepts_gui_legacy_prefix() {
        let id = uuid::Uuid::new_v4();
        let msg = Message::SubsystemReady {
            name: format!("gui-approve:{id}"),
        };
        assert_eq!(approve_request_candidate_id(&msg), Some(id));
    }

    #[test]
    fn approve_request_accepts_cli_legacy_prefix() {
        let id = uuid::Uuid::new_v4();
        let msg = Message::SubsystemReady {
            name: format!("cli-approve:{id}"),
        };
        assert_eq!(approve_request_candidate_id(&msg), Some(id));
    }

    #[test]
    fn approve_request_rejects_unknown_prefix_and_bad_uuid() {
        let unknown = Message::SubsystemReady {
            name: "other-approve:1234".into(),
        };
        assert_eq!(approve_request_candidate_id(&unknown), None);
        let bad_uuid = Message::SubsystemReady {
            name: "gui-approve:not-a-uuid".into(),
        };
        assert_eq!(approve_request_candidate_id(&bad_uuid), None);
        let unrelated = Message::SubsystemReady {
            name: "sensors".into(),
        };
        assert_eq!(approve_request_candidate_id(&unrelated), None);
    }

    #[tokio::test]
    async fn subscriber_approves_gui_and_typed_requests_end_to_end() {
        use imperium_net_crypto::HybridEd25519Mldsa;
        use rand::rngs::OsRng;

        // GUI legacy envelope path.
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = Arc::new(StagingArea::new(Arc::clone(&bus)));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: r#"rule gui_e2e { strings: $a = { AA } condition: $a }"#.into(),
            description: "gui e2e".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.8,
        };
        let gui_id = staging.submit(candidate).unwrap();
        let operator = PeerId::new();
        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let _handle = subscribe_signature_approval_requests(
            Arc::clone(&bus),
            Arc::clone(&staging),
            operator,
            sk,
        );
        let mut approved_sub = subscribe_queue(&bus, "net.signatures.approved", 32);
        BusEvent::publish(
            &bus,
            "net.signatures.approve_request",
            Message::SubsystemReady {
                name: format!("gui-approve:{gui_id}"),
            },
        )
        .unwrap();
        let event =
            tokio::time::timeout(std::time::Duration::from_millis(200), approved_sub.recv())
                .await
                .expect("gui approve reaches staging")
                .unwrap();
        assert!(matches!(
            event.message,
            Message::SignatureApproved(ref a) if a.candidate_id == gui_id
        ));
    }

    #[tokio::test]
    async fn subscriber_approves_typed_request_end_to_end() {
        use imperium_net_crypto::HybridEd25519Mldsa;
        use rand::rngs::OsRng;

        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = Arc::new(StagingArea::new(Arc::clone(&bus)));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: r#"rule typed_e2e { strings: $a = { BB } condition: $a }"#.into(),
            description: "typed e2e".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.8,
        };
        let typed_id = staging.submit(candidate).unwrap();
        let operator = PeerId::new();
        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let _handle = subscribe_signature_approval_requests(
            Arc::clone(&bus),
            Arc::clone(&staging),
            operator,
            sk,
        );
        let mut approved_sub = subscribe_queue(&bus, "net.signatures.approved", 32);
        BusEvent::publish(
            &bus,
            "net.signatures.approve_request",
            Message::SignatureApprovalRequest(imperium_protocol::SignatureApprovalRequest {
                candidate_id: typed_id,
            }),
        )
        .unwrap();
        let event =
            tokio::time::timeout(std::time::Duration::from_millis(200), approved_sub.recv())
                .await
                .expect("typed approve reaches staging")
                .unwrap();
        assert!(matches!(
            event.message,
            Message::SignatureApproved(ref a) if a.candidate_id == typed_id
        ));
    }
}

#[cfg(test)]
mod mesh_args_tests {
    use super::*;

    fn args_with(args: impl FnOnce(&mut MeshArgs)) -> MeshArgs {
        let mut a = MeshArgs::default();
        // Every mesh test needs a cluster id: it is required whenever the mesh
        // is enabled, and the tests below are all about the mesh.
        a.cluster_id = Some(Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap());
        args(&mut a);
        a
    }

    fn mesh_of(cli: Cli) -> MeshArgs {
        match cli.command {
            Commands::Node {
                action: NodeAction::Start { mesh, .. },
            } => mesh,
            _ => panic!("expected node start"),
        }
    }

    #[test]
    fn an_mtu_above_the_frame_ceiling_is_refused() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.mtu = imperium_net_mesh::MAX_SAFE_TUN_MTU as u32 + 1;
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("--mtu"), "{error}");

        // The largest safe MTU is accepted, and the default is well under it.
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.mtu = imperium_net_mesh::MAX_SAFE_TUN_MTU as u32;
        });
        assert!(validate_mesh_args(&args).is_ok());
        assert!(MeshArgs::default().mtu as usize <= imperium_net_mesh::MAX_SAFE_TUN_MTU);
    }

    #[test]
    fn a_mesh_without_a_cluster_id_is_refused_by_name() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.cluster_id = None;
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("--cluster-id"), "{error}");
    }

    #[test]
    fn a_node_with_no_mesh_flags_needs_no_cluster_id() {
        let args = MeshArgs::default();
        assert!(args.cluster_id.is_none());
        assert!(
            validate_mesh_args(&args).is_ok(),
            "no mesh, no cluster id needed"
        );
    }

    #[test]
    fn a_node_with_no_mesh_flags_is_valid_and_means_no_mesh() {
        let args = MeshArgs::default();
        assert!(validate_mesh_args(&args).is_ok());
        assert!(
            args.mesh_bind.is_none(),
            "no bind means the mesh never starts"
        );
    }

    #[test]
    fn binding_alone_is_a_valid_responder() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 2));
        });
        assert!(validate_mesh_args(&args).is_ok());
        assert!(args.peer.is_empty(), "a responder does not dial");
    }

    #[test]
    fn a_peer_without_an_address_is_accept_only() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 2));
            a.peer = vec!["11111111-1111-4111-8111-111111111111".to_string()];
        });
        assert!(validate_mesh_args(&args).is_ok());
        let peers = build_peers(&args).unwrap();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].addr.is_none(), "no address means nothing to dial");
    }

    #[test]
    fn a_peer_spec_parses_an_id_and_an_address() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.peer = vec!["11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string()];
        });
        assert!(validate_mesh_args(&args).is_ok());
        let peers = build_peers(&args).unwrap();
        assert_eq!(peers[0].addr, Some("127.0.0.1:41001".parse().unwrap()));
    }

    #[test]
    fn malformed_peer_specs_are_refused() {
        for spec in [
            "not-a-uuid",
            "not-a-uuid@127.0.0.1:1",
            "11111111-1111-4111-8111-111111111111@nonsense",
        ] {
            let args = args_with(|a| {
                a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
                a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
                a.peer = vec![spec.to_string()];
            });
            assert!(
                validate_mesh_args(&args).is_err(),
                "{spec:?} should be refused"
            );
        }
    }

    #[test]
    fn a_duplicate_peer_is_refused() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.peer = vec![
                "11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string(),
                "11111111-1111-4111-8111-111111111111@127.0.0.1:41002".to_string(),
            ];
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("twice"), "{error}");
    }

    #[test]
    fn per_peer_routes_attach_to_their_peer() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.peer = vec![
                "11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string(),
                "22222222-2222-4222-8222-222222222222@127.0.0.1:41002".to_string(),
            ];
            a.peer_route = vec![
                "11111111-1111-4111-8111-111111111111=10.88.0.0/24".to_string(),
                "22222222-2222-4222-8222-222222222222=10.99.0.0/24".to_string(),
            ];
        });
        assert!(validate_mesh_args(&args).is_ok());
        let peers = build_peers(&args).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[0].routes,
            vec![Destination::parse("10.88.0.0/24").unwrap()]
        );
        assert_eq!(
            peers[1].routes,
            vec![Destination::parse("10.99.0.0/24").unwrap()]
        );
    }

    #[test]
    fn a_route_for_an_undeclared_peer_is_refused() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.peer = vec!["11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string()];
            a.peer_route = vec!["99999999-9999-4999-8999-999999999999=10.88.0.0/24".to_string()];
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("no --peer declared"), "{error}");
    }

    #[test]
    fn a_per_peer_default_route_is_refused() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.peer = vec!["11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string()];
            a.peer_route = vec!["11111111-1111-4111-8111-111111111111=0.0.0.0/0".to_string()];
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("default route"), "{error}");
    }

    #[test]
    fn a_tunnel_address_is_required_unless_the_interface_is_skipped() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("--tunnel-ip"), "{error}");

        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.no_tun = true;
        });
        assert!(validate_mesh_args(&args).is_ok());
    }

    #[test]
    fn routes_parse_and_repeat() {
        let cli = Cli::try_parse_from([
            "imperium",
            "node",
            "start",
            "--mesh-bind",
            "127.0.0.1:41000",
            "--tunnel-ip",
            "10.77.0.1",
            "--cluster-id",
            "33333333-3333-4333-8333-333333333333",
            "--route",
            "10.88.0.0/24",
            "--route",
            "10.99.5.0/24",
        ])
        .expect("parse");
        let mesh = mesh_of(cli);
        assert_eq!(mesh.route, vec!["10.88.0.0/24", "10.99.5.0/24"]);
        assert!(validate_mesh_args(&mesh).is_ok());
    }

    #[test]
    fn routing_without_an_interface_is_refused() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.no_tun = true;
            a.route = vec!["10.88.0.0/24".to_string()];
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("--no-tun"), "{error}");
    }

    #[test]
    fn a_default_route_is_refused_by_name() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.route = vec!["0.0.0.0/0".to_string()];
        });
        let error = validate_mesh_args(&args).expect_err("must be refused");
        assert!(error.contains("default route"), "{error}");
    }

    #[test]
    fn a_malformed_route_is_refused_before_anything_starts() {
        let args = args_with(|a| {
            a.mesh_bind = Some("127.0.0.1:41000".parse().unwrap());
            a.tunnel_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
            a.route = vec!["not-a-cidr".to_string()];
        });
        assert!(validate_mesh_args(&args).is_err());
    }

    #[test]
    fn the_full_flag_set_parses() {
        let cli = Cli::try_parse_from([
            "imperium",
            "node",
            "start",
            "--mesh-bind",
            "127.0.0.1:41000",
            "--peer",
            "11111111-1111-4111-8111-111111111111@127.0.0.1:41001",
            "--peer-route",
            "11111111-1111-4111-8111-111111111111=10.88.0.0/24",
            "--cluster-id",
            "22222222-2222-4222-8222-222222222222",
            "--tunnel-ip",
            "10.77.0.1",
            "--tun",
            "imp0",
            "--mtu",
            "1400",
            "--report-secs",
            "5",
        ])
        .expect("parse");

        let mesh = mesh_of(cli);
        assert_eq!(mesh.mesh_bind, Some("127.0.0.1:41000".parse().unwrap()));
        assert_eq!(
            mesh.peer,
            vec!["11111111-1111-4111-8111-111111111111@127.0.0.1:41001".to_string()]
        );
        assert_eq!(
            mesh.peer_route,
            vec!["11111111-1111-4111-8111-111111111111=10.88.0.0/24".to_string()]
        );
        let peers = build_peers(&mesh).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, Some("127.0.0.1:41001".parse().unwrap()));
        assert_eq!(
            peers[0].routes,
            vec![Destination::parse("10.88.0.0/24").unwrap()]
        );
        assert_eq!(mesh.tunnel_ip, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(mesh.tun, "imp0");
        assert_eq!(mesh.mtu, 1400);
        assert_eq!(mesh.report_secs, 5);
        assert!(validate_mesh_args(&mesh).is_ok());
    }

    #[test]
    fn the_old_invocation_still_parses_unchanged() {
        let cli = Cli::try_parse_from(["imperium", "node", "start"]).expect("parse");
        let mesh = mesh_of(cli);
        assert!(mesh.mesh_bind.is_none());
        assert!(mesh.transport_profiles.is_none());
        assert!(mesh.active_profile.is_none());
        assert!(!mesh.host_guard);
        // Defaults are the documented ones.
        assert_eq!(mesh.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mesh.tun, "imperium");
        assert_eq!(mesh.mtu, imperium_net_host::DEFAULT_MTU);
        assert!(!mesh.no_tun);
    }

    #[test]
    fn explicit_transport_profiles_require_an_active_profile_id() {
        let cli = Cli::try_parse_from([
            "imperium",
            "node",
            "start",
            "--transport-profiles",
            "/tmp/profiles.json",
            "--active-profile",
            "xray-primary",
        ])
        .expect("parse explicit transport flags");
        let args = mesh_of(cli);
        assert_eq!(
            args.transport_profiles,
            Some(PathBuf::from("/tmp/profiles.json"))
        );
        assert_eq!(args.active_profile.as_deref(), Some("xray-primary"));
        assert!(Cli::try_parse_from([
            "imperium",
            "node",
            "start",
            "--transport-profiles",
            "/tmp/profiles.json",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "imperium",
            "node",
            "start",
            "--active-profile",
            "xray-primary",
        ])
        .is_err());
    }

    #[test]
    fn host_guard_is_explicit_opt_in() {
        let args =
            mesh_of(Cli::try_parse_from(["imperium", "node", "start", "--host-guard"]).unwrap());
        assert!(args.host_guard);
        assert!(args.mesh_bind.is_none());
        assert!(validate_mesh_args(&args).is_ok());
    }

    #[test]
    fn transport_profile_json_rejects_writable_file_and_parent() {
        let directory =
            std::env::temp_dir().join(format!("imperium-profile-file-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.join("profiles.json");
        std::fs::write(&file, b"[]").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_transport_profile_file(&file).is_err());

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_transport_profile_file(&file).unwrap().is_empty());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_transport_profile_file(&file).is_err());

        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
