//! The bridge between a TUN device and the mesh daemon.
//!
//! Two pumps:
//!
//! - **host → mesh**: read an IP packet from the TUN device and hand it to the
//!   daemon, which seals it into a mesh frame and sends it to the peer.
//! - **mesh → host**: take a decrypted payload from the daemon and write it to
//!   the TUN device, where the kernel routes it normally.
//!
//! Both are driven through `AsyncFd` on the TUN fd, so neither blocks a worker
//! thread and shutdown is prompt.

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use imperium_net_mesh::{MeshDaemon, MeshInbound, WireDirection};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::tun::{TunDevice, TunError};

/// Largest IP packet we will read. The interface MTU is 1280, so this is
/// generous headroom rather than a limit we expect to hit.
const READ_BUFFER: usize = 4096;

/// How many host packets are held while the session comes up. The kernel emits
/// traffic (IPv6 neighbour discovery especially) the instant the interface is
/// brought up, which is before the handshake has completed; without a queue
/// those first packets are simply lost.
const PRESESSION_QUEUE: usize = 64;

/// How long a held packet stays worth sending. A peer that never answers must
/// not deliver a burst of stale packets minutes later, so held packets age out.
const PRESESSION_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum HostError {
    #[error("tun error: {0}")]
    Tun(#[from] TunError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("mesh daemon error: {0}")]
    Daemon(#[from] imperium_net_mesh::DaemonError),
}

/// What crossed the bridge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BridgeStats {
    /// IP packets read from the host and sealed onto the mesh.
    pub packets_from_host: u64,
    /// Host packets discarded because no session was established yet.
    pub packets_from_host_dropped: u64,
    /// Host packets not sent because the kill switch was engaged. Counted
    /// separately from success, and separately from a drop: suppression is the
    /// operator's own action, not a failure.
    pub packets_suppressed: u64,
    /// Host packets held while the session was coming up.
    pub packets_queued: u64,
    /// Held packets sent once the session established.
    pub packets_flushed: u64,
    /// Held packets discarded for being too old to be useful.
    pub packets_expired: u64,
    /// Decrypted payloads written back to the host.
    pub packets_to_host: u64,
    /// Payloads the kernel refused.
    pub packets_to_host_failed: u64,
    /// Partial writes: a TUN write should be all-or-nothing per packet.
    pub short_writes: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

#[derive(Default)]
struct Counters {
    packets_from_host: AtomicU64,
    packets_from_host_dropped: AtomicU64,
    packets_suppressed: AtomicU64,
    packets_queued: AtomicU64,
    packets_flushed: AtomicU64,
    packets_expired: AtomicU64,
    packets_to_host: AtomicU64,
    packets_to_host_failed: AtomicU64,
    short_writes: AtomicU64,
    read_errors: AtomicU64,
    write_errors: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> BridgeStats {
        BridgeStats {
            packets_from_host: self.packets_from_host.load(Ordering::Relaxed),
            packets_from_host_dropped: self.packets_from_host_dropped.load(Ordering::Relaxed),
            packets_suppressed: self.packets_suppressed.load(Ordering::Relaxed),
            packets_queued: self.packets_queued.load(Ordering::Relaxed),
            packets_flushed: self.packets_flushed.load(Ordering::Relaxed),
            packets_expired: self.packets_expired.load(Ordering::Relaxed),
            packets_to_host: self.packets_to_host.load(Ordering::Relaxed),
            packets_to_host_failed: self.packets_to_host_failed.load(Ordering::Relaxed),
            short_writes: self.short_writes.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
        }
    }
}

/// A read-only view of a running bridge's counters.
#[derive(Clone)]
pub struct BridgeHandle(Arc<Counters>);

impl BridgeHandle {
    pub fn stats(&self) -> BridgeStats {
        self.0.snapshot()
    }
}

pub struct HostBridge {
    device: TunDevice,
    daemon: Arc<MeshDaemon>,
    inbound: mpsc::Receiver<MeshInbound>,
    counters: Arc<Counters>,
}

impl HostBridge {
    /// Build a bridge. `inbound` is the delivery queue from
    /// [`MeshDaemon`]; the returned handle observes the counters while the
    /// bridge runs.
    pub fn new(
        device: TunDevice,
        daemon: Arc<MeshDaemon>,
        inbound: mpsc::Receiver<MeshInbound>,
    ) -> (Self, BridgeHandle) {
        let counters = Arc::new(Counters::default());
        let handle = BridgeHandle(Arc::clone(&counters));
        (
            Self {
                device,
                daemon,
                inbound,
                counters,
            },
            handle,
        )
    }

    /// Run both pumps until `shutdown` fires or a pump stops.
    pub async fn run(self, shutdown: Arc<Notify>) -> Result<BridgeStats, HostError> {
        let HostBridge {
            device,
            daemon,
            inbound,
            counters,
        } = self;

        // AsyncFd requires a non-blocking fd.
        device.set_nonblocking(true)?;
        let device = Arc::new(AsyncFd::new(device)?);

        let mut up: JoinHandle<()> = tokio::spawn(pump_host_to_mesh(
            Arc::clone(&device),
            Arc::clone(&daemon),
            Arc::clone(&counters),
        ));
        let mut down: JoinHandle<()> = tokio::spawn(pump_mesh_to_host(
            Arc::clone(&device),
            Arc::clone(&daemon),
            inbound,
            Arc::clone(&counters),
        ));

        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("host bridge shutting down");
            }
            _ = &mut up => {
                tracing::warn!("host->mesh pump stopped");
            }
            _ = &mut down => {
                tracing::warn!("mesh->host pump stopped");
            }
        }

        up.abort();
        down.abort();

        let stats = counters.snapshot();
        tracing::info!(?stats, "host bridge stopped");
        Ok(stats)
    }
}

async fn pump_host_to_mesh(
    device: Arc<AsyncFd<TunDevice>>,
    daemon: Arc<MeshDaemon>,
    counters: Arc<Counters>,
) {
    let mut buffer = vec![0u8; READ_BUFFER];
    // Packets read from the host before a session existed. Bounded, and aged
    // out on flush so a peer that never answers does not receive a stale burst.
    let mut queue: VecDeque<(Instant, Vec<u8>)> = VecDeque::new();
    loop {
        let mut guard = match device.readable().await {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(%error, "tun readability wait failed");
                return;
            }
        };

        match guard.try_io(|inner| read_fd(inner.as_raw_fd(), &mut buffer)) {
            Ok(Ok(0)) => continue,
            Ok(Ok(len)) => {
                let packet = &buffer[..len];
                // The observer sees the exact layer-3 packet the TUN emitted.
                // Failure to enqueue remains telemetry, never a route decision.
                let _ = daemon.observe_raw_ip(WireDirection::Outbound, packet);
                if daemon.is_established() {
                    // Drain anything held while the session was coming up,
                    // oldest first, so the peer sees the packets in order.
                    while let Some((held_at, held)) = queue.pop_front() {
                        if held_at.elapsed() > PRESESSION_MAX_AGE {
                            counters.packets_expired.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        match daemon.send_payload(&held).await {
                            Ok(()) => {
                                counters.packets_flushed.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => {
                                // The session went away mid-flush; keep the rest
                                // and try again on the next packet.
                                tracing::debug!(%error, "held packet not sent");
                                queue.push_front((held_at, held));
                                break;
                            }
                        }
                    }
                    match daemon.send_payload(packet).await {
                        Ok(()) => {
                            counters.packets_from_host.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            // Suppression is the kill switch, not a failure, and
                            // must not be counted as delivered.
                            if matches!(
                                error,
                                imperium_net_mesh::DaemonError::SuppressedByKillSwitch
                            ) {
                                counters.packets_suppressed.fetch_add(1, Ordering::Relaxed);
                            } else {
                                counters
                                    .packets_from_host_dropped
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            tracing::debug!(%error, len, "host packet not sent");
                        }
                    }
                } else if queue.len() >= PRESESSION_QUEUE {
                    // Bounded: dropping the oldest keeps the most recent state,
                    // which is what a connection wants when it finally comes up.
                    queue.pop_front();
                    counters
                        .packets_from_host_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    queue.push_back((Instant::now(), packet.to_vec()));
                    counters.packets_queued.fetch_add(1, Ordering::Relaxed);
                } else {
                    queue.push_back((Instant::now(), packet.to_vec()));
                    counters.packets_queued.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Err(error)) => {
                counters.read_errors.fetch_add(1, Ordering::Relaxed);
                if is_fatal(&error) {
                    tracing::warn!(%error, "fatal tun read error");
                    return;
                }
                tracing::debug!(%error, "tun read error");
            }
            // Would block: another task consumed the readiness.
            Err(_would_block) => continue,
        }
    }
}

async fn pump_mesh_to_host(
    device: Arc<AsyncFd<TunDevice>>,
    daemon: Arc<MeshDaemon>,
    mut inbound: mpsc::Receiver<MeshInbound>,
    counters: Arc<Counters>,
) {
    while let Some(message) = inbound.recv().await {
        if message.payload.is_empty() || daemon.is_killed() {
            continue;
        }
        let mut guard = match device.writable().await {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(%error, "tun writability wait failed");
                return;
            }
        };

        if daemon.is_killed() {
            continue;
        }
        match guard.try_io(|inner| write_fd(inner.as_raw_fd(), &message.payload)) {
            Ok(Ok(written)) => {
                if written != message.payload.len() {
                    counters.short_writes.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(written, expected = message.payload.len(), "short tun write");
                } else {
                    counters.packets_to_host.fetch_add(1, Ordering::Relaxed);
                    // This packet was actually written into the host TUN.
                    let _ = daemon.observe_raw_ip(WireDirection::Inbound, &message.payload);
                }
            }
            Ok(Err(error)) => {
                counters
                    .packets_to_host_failed
                    .fetch_add(1, Ordering::Relaxed);
                counters.write_errors.fetch_add(1, Ordering::Relaxed);
                if is_fatal(&error) {
                    tracing::warn!(%error, "fatal tun write error");
                    return;
                }
                tracing::debug!(%error, len = message.payload.len(), "tun write failed");
            }
            Err(_would_block) => {
                // The device is not writable right now, which for a TUN
                // device means the queue is full. Dropping is the honest
                // choice: blocking here would stall the mesh receive path.
                counters
                    .packets_to_host_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn read_fd(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let result = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn write_fd(fd: RawFd, buffer: &[u8]) -> io::Result<usize> {
    let result = unsafe { libc::write(fd, buffer.as_ptr() as *const libc::c_void, buffer.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// An error after which the fd is unusable.
fn is_fatal(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EBADF) | Some(libc::ENODEV) | Some(libc::EIO)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_snapshot_starts_at_zero() {
        let counters = Counters::default();
        assert_eq!(counters.snapshot(), BridgeStats::default());
    }

    #[test]
    fn a_read_from_a_bad_fd_is_an_error_not_a_panic() {
        let mut buffer = [0u8; 64];
        let error = read_fd(-1, &mut buffer).expect_err("bad fd must error");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert!(is_fatal(&error));
    }

    #[test]
    fn a_write_to_a_bad_fd_is_an_error_not_a_panic() {
        let error = write_fd(-1, b"x").expect_err("bad fd must error");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }
}
