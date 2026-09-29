use chrono::Utc;
use imperium_protocol::{KillSwitchCommand, KillSwitchState, LeakGuardStatus};

pub struct LeakGuard {
    dns_guard_enabled: bool,
    route_guard_enabled: bool,
    kill_switch: KillSwitchState,
    last_violation: Option<String>,
}

impl LeakGuard {
    pub fn armed() -> Self {
        Self {
            // This type tracks requested policy state. Host DNS and firewall
            // enforcement are outside the current split-tunnel adapter.
            dns_guard_enabled: false,
            route_guard_enabled: false,
            kill_switch: KillSwitchState::Armed,
            last_violation: None,
        }
    }

    pub fn apply_command(&mut self, command: &KillSwitchCommand) {
        self.kill_switch = command.state.clone();
        if matches!(command.state, KillSwitchState::Engaged) {
            self.last_violation = Some(command.reason.clone());
        }
    }

    pub fn record_violation(&mut self, violation: impl Into<String>) {
        self.last_violation = Some(violation.into());
        self.kill_switch = KillSwitchState::Engaged;
    }

    pub fn status(&self) -> LeakGuardStatus {
        LeakGuardStatus {
            dns_guard_enabled: self.dns_guard_enabled,
            route_guard_enabled: self.route_guard_enabled,
            kill_switch: self.kill_switch.clone(),
            last_violation: self.last_violation.clone(),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violation_engages_kill_switch() {
        let mut guard = LeakGuard::armed();
        guard.record_violation("dns outside tunnel");

        let status = guard.status();
        assert_eq!(status.kill_switch, KillSwitchState::Engaged);
        assert_eq!(status.last_violation.as_deref(), Some("dns outside tunnel"));
    }
}
