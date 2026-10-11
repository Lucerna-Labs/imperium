use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("failed to spawn: {0}")]
    SpawnFailed(#[from] std::io::Error),
    #[error("process exited with code {0}")]
    ExitCode(i32),
    #[error("process killed after timeout")]
    Timeout,
    #[error("process not running")]
    NotRunning,
    #[error("process already running")]
    AlreadyRunning,
    #[error("max retries exceeded")]
    MaxRetriesExceeded,
}

#[derive(Clone, Debug)]
pub enum RestartPolicy {
    Never,
    OnFailure { max_retries: u32, backoff: Duration },
    Always { backoff: Duration },
}

#[derive(Clone, Debug)]
pub struct ResourceBudget {
    pub memory_bytes: Option<u64>,
    pub cpu_percent: Option<u32>,
    pub max_runtime: Option<Duration>,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            memory_bytes: None,
            cpu_percent: None,
            max_runtime: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessConfig {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub health_check_interval: Duration,
    pub restart_policy: RestartPolicy,
    pub budget: ResourceBudget,
    pub graceful_stop_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed { reason: String },
    Restarting { attempt: u32 },
}

pub struct ManagedProcess {
    config: ProcessConfig,
    state: Arc<watch::Sender<ProcessState>>,
    state_rx: watch::Receiver<ProcessState>,
    child: Option<Child>,
    started_at: Option<DateTime<Utc>>,
    restart_count: u32,
}

impl ManagedProcess {
    pub fn new(config: ProcessConfig) -> Self {
        let (state_tx, state_rx) = watch::channel(ProcessState::Stopped);
        Self {
            config,
            state: Arc::new(state_tx),
            state_rx,
            child: None,
            started_at: None,
            restart_count: 0,
        }
    }

    pub fn state(&self) -> ProcessState {
        self.state_rx.borrow().clone()
    }

    pub fn state_receiver(&self) -> watch::Receiver<ProcessState> {
        self.state_rx.clone()
    }

    pub async fn start(&mut self) -> Result<(), ProcessError> {
        self.spawn_child(None).await
    }

    /// Start the process with `working_dir` as its working directory.
    ///
    /// Same lifecycle, same state transitions and the same error handling as
    /// [`ManagedProcess::start`] — `start` is exactly this call with no
    /// directory — with one addition: the child is spawned in `working_dir`.
    ///
    /// It is a per-start argument rather than a `ProcessConfig` field because
    /// `ProcessConfig` is constructed with exhaustive struct literals by
    /// existing callers (e.g. `imperium-net-transport`'s controller); adding a
    /// field would be a breaking change to every one of them. Callers that need
    /// a working directory call this instead, and callers that do not keep
    /// using [`ManagedProcess::start`].
    pub async fn start_in(&mut self, working_dir: &Path) -> Result<(), ProcessError> {
        self.spawn_child(Some(working_dir)).await
    }

    /// The one spawn path: `start` and `start_in` differ only in `working_dir`.
    async fn spawn_child(&mut self, working_dir: Option<&Path>) -> Result<(), ProcessError> {
        if self.child.is_some() {
            return Err(ProcessError::AlreadyRunning);
        }

        self.state.send_replace(ProcessState::Starting);

        let mut cmd = Command::new(&self.config.binary);
        cmd.args(&self.config.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn()?;

        if let Some(stdout) = child.stdout.take() {
            let name = self
                .config
                .binary
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let name_clone = name.clone();

            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!(process = %name, "[stdout] {}", line);
                }
            });

            if let Some(stderr) = child.stderr.take() {
                tokio::spawn(async move {
                    let reader = BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::warn!(process = %name_clone, "[stderr] {}", line);
                    }
                });
            }
        }

        self.child = Some(child);
        self.started_at = Some(Utc::now());
        self.state.send_replace(ProcessState::Running);

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ProcessError> {
        let child = self.child.as_mut().ok_or(ProcessError::NotRunning)?;
        self.state.send_replace(ProcessState::Stopping);

        let timeout = self.config.graceful_stop_timeout;

        // SIGTERM first; the timeout below escalates to kill().
        #[cfg(unix)]
        {
            if let Some(id) = child.id() {
                unsafe {
                    libc::kill(id as i32, libc::SIGTERM);
                }
            }
        }

        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::error!("error waiting for process: {}", e);
            }
            Err(_) => {
                tracing::warn!("graceful stop timed out, killing process");
                let _ = child.kill().await;
            }
        }

        self.child = None;
        self.started_at = None;
        self.state.send_replace(ProcessState::Stopped);
        Ok(())
    }

    pub async fn check_health(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    let code = status.code().unwrap_or(-1);
                    tracing::warn!("process exited with code {}", code);
                    self.child = None;
                    self.state.send_replace(ProcessState::Failed {
                        reason: format!("exited with code {}", code),
                    });
                    false
                }
                Err(e) => {
                    tracing::error!("health check error: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn runtime_exceeded(&self) -> bool {
        if let (Some(max), Some(started)) = (self.config.budget.max_runtime, self.started_at) {
            let elapsed = (Utc::now() - started).to_std().unwrap_or_default();
            elapsed > max
        } else {
            false
        }
    }

    pub async fn restart(&mut self) -> Result<(), ProcessError> {
        let backoff = match &self.config.restart_policy {
            RestartPolicy::Never => return Err(ProcessError::MaxRetriesExceeded),
            RestartPolicy::OnFailure {
                max_retries,
                backoff,
            } => {
                if self.restart_count >= *max_retries {
                    return Err(ProcessError::MaxRetriesExceeded);
                }
                *backoff
            }
            RestartPolicy::Always { backoff } => *backoff,
        };

        self.restart_count += 1;
        self.state.send_replace(ProcessState::Restarting {
            attempt: self.restart_count,
        });

        if self.child.is_some() {
            self.stop().await?;
        }

        tokio::time::sleep(backoff).await;
        self.start().await
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }

    pub fn is_running(&self) -> bool {
        self.state() == ProcessState::Running && self.child.is_some()
    }

    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_config() -> ProcessConfig {
        let binary = PathBuf::from("echo");
        let args = vec!["hello".into()];

        ProcessConfig {
            binary,
            args,
            env: HashMap::new(),
            health_check_interval: Duration::from_secs(5),
            restart_policy: RestartPolicy::Never,
            budget: ResourceBudget::default(),
            graceful_stop_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn start_and_wait() {
        let mut proc = ManagedProcess::new(echo_config());
        assert_eq!(proc.state(), ProcessState::Stopped);

        proc.start().await.unwrap();
        assert!(matches!(
            proc.state(),
            ProcessState::Running | ProcessState::Starting
        ));

        tokio::time::sleep(Duration::from_millis(500)).await;

        proc.check_health().await;
    }

    #[tokio::test]
    async fn double_start_fails() {
        let config = ProcessConfig {
            binary: PathBuf::from("sleep"),
            args: vec!["10".into()],
            env: HashMap::new(),
            health_check_interval: Duration::from_secs(5),
            restart_policy: RestartPolicy::Never,
            budget: ResourceBudget::default(),
            graceful_stop_timeout: Duration::from_secs(2),
        };

        let mut proc = ManagedProcess::new(config);
        proc.start().await.unwrap();
        assert!(proc.start().await.is_err());
        proc.stop().await.unwrap();
    }

    /// `start_in` is `start` with a working directory: the child is really
    /// spawned there (proved by the file it creates), and the lifecycle is
    /// unchanged. `/bin/sh` is absolute and present wherever the crate's other
    /// process tests can run at all.
    #[tokio::test]
    async fn start_in_runs_the_child_in_the_given_directory() {
        let dir = std::env::temp_dir().join(format!(
            "imperium-managed-process-start-in-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let marker = dir.join("cwd-proof");
        let _ = std::fs::remove_file(&marker);

        let config = ProcessConfig {
            binary: PathBuf::from("/bin/sh"),
            // No `chdir`: the file lands where the *spawn* put the shell.
            args: vec!["-c".into(), "touch cwd-proof".into()],
            env: HashMap::new(),
            health_check_interval: Duration::from_secs(5),
            restart_policy: RestartPolicy::Never,
            budget: ResourceBudget::default(),
            graceful_stop_timeout: Duration::from_secs(2),
        };

        let mut proc = ManagedProcess::new(config);
        assert_eq!(proc.state(), ProcessState::Stopped);
        proc.start_in(&dir).await.expect("spawn in the temp dir");
        assert!(matches!(
            proc.state(),
            ProcessState::Running | ProcessState::Starting
        ));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never created {} — it did not run in the given directory",
                marker.display()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        proc.stop().await.expect("the child is reaped");
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn resource_budget_defaults() {
        let budget = ResourceBudget::default();
        assert!(budget.memory_bytes.is_none());
        assert!(budget.cpu_percent.is_none());
        assert!(budget.max_runtime.is_none());
    }
}
