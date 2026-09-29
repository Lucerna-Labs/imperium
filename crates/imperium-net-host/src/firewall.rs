//! Opt-in Linux host egress guard using libnftables in process.
//!
//! Unique `inet` and `arp` tables own output/postrouting base chains. No other
//! firewall tables are changed. ARMED and DISARMED allow ordinary host traffic;
//! only an explicit ENGAGED command blocks non-loopback egress. Failure to load
//! nftables or install the rules is an error to the caller.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use libloading::Library;
use thiserror::Error;

const CHAINS: [&str; 2] = ["output", "postrouting"];
static NEXT_TABLE: AtomicU64 = AtomicU64::new(0);
static NFT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostGuardMode {
    /// Ready for an operator command; host traffic is not blocked.
    Armed,
    /// Loopback only: host, mesh underlay, and tunnel egress all stop.
    Engaged,
    /// This table no longer restricts egress (other firewall rules still may).
    Disarmed,
}

#[derive(Debug, Error)]
pub enum HostGuardError {
    #[error("nftables library unavailable: {0}")]
    Library(String),
    #[error("nftables kernel operation failed: {0}")]
    Kernel(String),
}

/// Owns one name in the `inet` and `arp` nftables families. Normal `Drop`
/// removes both tables; SIGKILL cannot run Drop, so an Engaged kernel policy
/// remains fail-closed until operator recovery.
pub struct HostKillSwitch {
    table: String,
    mode: HostGuardMode,
    installed: bool,
}

impl HostKillSwitch {
    /// Install ARMED with no active host block. Installation still verifies
    /// libnftables and CAP_NET_ADMIN before the UI can offer Engage.
    pub fn install() -> Result<Self, HostGuardError> {
        let mut guard = Self {
            table: next_table_name(),
            mode: HostGuardMode::Armed,
            installed: false,
        };
        run_nft(&guard.install_commands())?;
        guard.installed = true;
        tracing::info!(table = %guard.table, "host-wide egress guard ready");
        Ok(guard)
    }

    pub fn mode(&self) -> HostGuardMode {
        self.mode
    }

    /// Exact table identifier needed to recover after a crash or SIGKILL.
    pub fn table_name(&self) -> &str {
        &self.table
    }

    /// Replace both base-chain rule sets in one nftables transaction.
    pub fn set_mode(&mut self, mode: HostGuardMode) -> Result<(), HostGuardError> {
        run_nft(&self.mode_commands(mode))?;
        self.mode = mode;
        tracing::info!(table = %self.table, ?mode, "host egress guard mode applied");
        Ok(())
    }

    /// Remove only this guard's tables.
    pub fn remove(&mut self) -> Result<(), HostGuardError> {
        if !self.installed {
            return Ok(());
        }
        run_nft(&format!(
            "delete table arp {}\ndelete table inet {}\n",
            self.table, self.table
        ))?;
        self.installed = false;
        tracing::info!(table = %self.table, "host egress guard removed");
        Ok(())
    }

    fn install_commands(&self) -> String {
        let mut commands = format!("add table inet {}\n", self.table);
        for chain in CHAINS {
            commands.push_str(&format!(
                "add chain inet {} {} {{ type filter hook {} priority 0; policy drop; }}\n",
                self.table, chain, chain
            ));
        }
        commands.push_str(&format!(
            "add table arp {}\nadd chain arp {} output {{ type filter hook output priority 0; policy drop; }}\n",
            self.table, self.table
        ));
        commands.push_str(&self.allow_rules(HostGuardMode::Armed));
        commands
    }

    fn mode_commands(&self, mode: HostGuardMode) -> String {
        let mut commands = String::new();
        for chain in CHAINS {
            commands.push_str(&format!("flush chain inet {} {}\n", self.table, chain));
        }
        commands.push_str(&format!("flush chain arp {} output\n", self.table));
        commands.push_str(&self.allow_rules(mode));
        commands
    }

    fn allow_rules(&self, mode: HostGuardMode) -> String {
        let mut commands = String::new();
        for chain in CHAINS {
            commands.push_str(&format!(
                "add rule inet {} {} oifname \"lo\" accept\n",
                self.table, chain
            ));
            if mode != HostGuardMode::Engaged {
                commands.push_str(&format!("add rule inet {} {} accept\n", self.table, chain));
            }
            commands.push_str(&format!(
                "add rule inet {} {} counter drop\n",
                self.table, chain
            ));
        }
        if mode != HostGuardMode::Engaged {
            commands.push_str(&format!("add rule arp {} output accept\n", self.table));
        }
        commands.push_str(&format!(
            "add rule arp {} output counter drop\n",
            self.table
        ));
        commands
    }
}

impl Drop for HostKillSwitch {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::error!(table = %self.table, %error, "host egress guard cleanup failed; manual recovery required");
        }
    }
}

fn next_table_name() -> String {
    let epoch_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let serial = NEXT_TABLE.fetch_add(1, Ordering::Relaxed);
    format!(
        "imperium_guard_{:x}_{:x}_{:x}",
        std::process::id(),
        epoch_ns,
        serial
    )
}

type NftNew = unsafe extern "C" fn(u32) -> *mut c_void;
type NftFree = unsafe extern "C" fn(*mut c_void);
type NftBuffer = unsafe extern "C" fn(*mut c_void) -> c_int;
type NftGetBuffer = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type NftRun = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;

/// Use a fresh context per operation and serialize libnftables parser access.
fn run_nft(commands: &str) -> Result<(), HostGuardError> {
    let lock = NFT_LOCK.get_or_init(|| Mutex::new(()));
    let _locked = lock
        .lock()
        .map_err(|error| HostGuardError::Library(error.to_string()))?;
    let library = unsafe { Library::new("libnftables.so.1") }
        .map_err(|error| HostGuardError::Library(error.to_string()))?;
    let (new, free, buffer_error, buffer_output, get_error, run): (
        NftNew,
        NftFree,
        NftBuffer,
        NftBuffer,
        NftGetBuffer,
        NftRun,
    ) = unsafe {
        (
            load_symbol(&library, b"nft_ctx_new\0")?,
            load_symbol(&library, b"nft_ctx_free\0")?,
            load_symbol(&library, b"nft_ctx_buffer_error\0")?,
            load_symbol(&library, b"nft_ctx_buffer_output\0")?,
            load_symbol(&library, b"nft_ctx_get_error_buffer\0")?,
            load_symbol(&library, b"nft_run_cmd_from_buffer\0")?,
        )
    };
    let ctx = unsafe { new(0) };
    if ctx.is_null() {
        return Err(HostGuardError::Library("nft_ctx_new returned null".into()));
    }
    let result = (|| {
        if unsafe { buffer_error(ctx) } != 0 || unsafe { buffer_output(ctx) } != 0 {
            return Err(HostGuardError::Library(
                "cannot buffer libnftables output".into(),
            ));
        }
        let command = CString::new(commands)
            .map_err(|_| HostGuardError::Library("internal nft command has NUL".into()))?;
        if unsafe { run(ctx, command.as_ptr()) } != 0 {
            let details = unsafe {
                let pointer = get_error(ctx);
                if pointer.is_null() {
                    "kernel rejected nftables transaction".to_string()
                } else {
                    CStr::from_ptr(pointer).to_string_lossy().trim().to_string()
                }
            };
            return Err(HostGuardError::Kernel(if details.is_empty() {
                "kernel rejected nftables transaction".to_string()
            } else {
                details
            }));
        }
        Ok(())
    })();
    unsafe { free(ctx) };
    result
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, HostGuardError> {
    library
        .get::<T>(name)
        .map(|symbol| *symbol)
        .map_err(|error| HostGuardError::Library(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engaged_rules_block_non_loopback_egress() {
        let guard = HostKillSwitch {
            table: "imperium_guard_test".into(),
            mode: HostGuardMode::Armed,
            installed: false,
        };
        let commands = guard.mode_commands(HostGuardMode::Engaged);
        assert!(commands.contains("flush chain inet imperium_guard_test output"));
        assert!(commands.contains("oifname \"lo\" accept"));
        assert!(!commands.contains("udp sport"));
        assert!(!commands.contains("add rule inet imperium_guard_test output accept"));
    }

    #[test]
    fn installed_rules_cover_both_egress_hooks_without_blocking_until_engage() {
        let guard = HostKillSwitch {
            table: "imperium_guard_test".into(),
            mode: HostGuardMode::Armed,
            installed: false,
        };
        let commands = guard.install_commands();
        assert!(commands.contains("hook output priority 0; policy drop"));
        assert!(commands.contains("hook postrouting priority 0; policy drop"));
        assert!(commands.contains("add chain arp imperium_guard_test output { type filter hook output priority 0; policy drop; }"));
        assert!(commands.contains("add rule inet imperium_guard_test output accept"));
        assert!(commands.contains("add rule inet imperium_guard_test postrouting accept"));
        assert!(!commands.contains("flush ruleset"));
    }
}
