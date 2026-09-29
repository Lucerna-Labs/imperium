//! App shell: topbar, navigation sidebar, view routing, window lifecycle.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use imperium_net_signatures::StagingArea;
use imperium_protocol::{KillSwitchState, SignatureCandidate};
use parking_lot::RwLock;
use spiderweb::BusPublisher;

use crate::control_socket::ControlReply;
use crate::theme;
use crate::views;
use crate::{commands, spawn_pump, SharedUiState, SignatureDrafts, UiState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Threats,
    Signatures,
    Transport,
    Activity,
}

pub struct ImperiumApp {
    pub bus: Arc<BusPublisher>,
    pub staging: Arc<StagingArea>,
    pub state: Arc<RwLock<UiState>>,
    pub view: View,
    pub pending: Vec<SignatureCandidate>,
    pub drafts: SignatureDrafts,
    pub activity_filter: String,
    last_staging_poll: Instant,
    pub flash: Option<(String, Instant, egui::Color32)>,
    pub engage_armed_at: Option<Instant>,
    pub(crate) control_endpoint: Option<String>,
    runtime_handle: Option<tokio::runtime::Handle>,
    pub(crate) last_control_reply: Option<ControlReply>,
    pending_control: Option<tokio::sync::oneshot::Receiver<Result<ControlReply, String>>>,
}

impl ImperiumApp {
    pub fn new(
        bus: Arc<BusPublisher>,
        staging: Arc<StagingArea>,
        state: Arc<RwLock<UiState>>,
        control_endpoint: Option<String>,
        runtime_handle: Option<tokio::runtime::Handle>,
    ) -> Self {
        Self {
            bus,
            staging,
            state,
            view: View::Dashboard,
            pending: Vec::new(),
            drafts: SignatureDrafts::default(),
            activity_filter: String::new(),
            last_staging_poll: Instant::now(),
            flash: None,
            engage_armed_at: None,
            control_endpoint,
            runtime_handle,
            last_control_reply: None,
            pending_control: None,
        }
    }

    fn poll_staging(&mut self) {
        if self.last_staging_poll.elapsed() >= Duration::from_millis(500) {
            self.refresh_staging_now();
        }
    }

    pub fn refresh_staging_now(&mut self) {
        self.pending = self.staging.pending_candidates();
        self.last_staging_poll = Instant::now();
    }

    pub fn flash(&mut self, message: impl Into<String>, color: egui::Color32) {
        self.flash = Some((message.into(), Instant::now(), color));
    }

    pub(crate) fn control_pending(&self) -> bool {
        self.pending_control.is_some()
    }

    pub(crate) fn control_available(&self) -> bool {
        self.control_endpoint.is_some() && self.runtime_handle.is_some()
    }

    pub(crate) fn request_kill_switch(&mut self, state: KillSwitchState, reason: &str) {
        if self.pending_control.is_some() {
            return;
        }
        let Some(endpoint) = self.control_endpoint.as_deref() else {
            self.flash("local control socket unavailable", theme::DANGER);
            return;
        };
        let Some(runtime) = self.runtime_handle.as_ref() else {
            self.flash("local control runtime unavailable", theme::DANGER);
            return;
        };
        self.pending_control = Some(commands::kill_switch(runtime, endpoint, state, reason));
        self.flash(
            "control request sent — awaiting confirmed state",
            theme::WARN,
        );
    }

    fn poll_control(&mut self) {
        let result = match self.pending_control.as_mut() {
            Some(receiver) => match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    Some(Err("local control worker stopped without a reply".into()))
                }
            },
            None => None,
        };
        if let Some(result) = result {
            self.pending_control = None;
            match result {
                Ok(reply) => {
                    let color = if !reply.ok() || reply.host_egress_blocked == Some(true) {
                        theme::DANGER
                    } else {
                        theme::OK
                    };
                    let message = if reply.ok() {
                        reply.message.clone()
                    } else {
                        format!("control rejected: {}", reply.message)
                    };
                    self.last_control_reply = Some(reply);
                    self.flash(message, color);
                }
                Err(error) => {
                    self.last_control_reply = None;
                    self.flash(error, theme::DANGER);
                }
            }
        }
    }
}

/// Convenience entry point when the caller has not already started the pump.
/// The caller must have entered a Tokio runtime so the pump can be spawned.
pub fn run(bus: Arc<BusPublisher>, staging: Arc<StagingArea>) -> Result<(), eframe::Error> {
    let state = spawn_pump(Arc::clone(&bus));
    run_with_state(bus, staging, state)
}

/// Open the native console on the process main thread using a pump started
/// before subsystem initialization, so startup status events are observed.
pub fn run_with_state(
    bus: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    state: SharedUiState,
) -> Result<(), eframe::Error> {
    run_with_optional_control(bus, staging, state, None, None)
}

/// The production entry point. Operator kill-switch actions use the node's
/// owner-only control socket so host and mesh state change in the same order.
pub fn run_with_state_and_control(
    bus: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    state: SharedUiState,
    control_endpoint: String,
    runtime_handle: tokio::runtime::Handle,
) -> Result<(), eframe::Error> {
    run_with_optional_control(
        bus,
        staging,
        state,
        Some(control_endpoint),
        Some(runtime_handle),
    )
}

fn run_with_optional_control(
    bus: Arc<BusPublisher>,
    staging: Arc<StagingArea>,
    state: SharedUiState,
    control_endpoint: Option<String>,
    runtime_handle: Option<tokio::runtime::Handle>,
) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Imperium — Cluster Defense Console")
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "imperium",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(ImperiumApp::new(
                bus,
                staging,
                state,
                control_endpoint,
                runtime_handle,
            )))
        }),
    )
}

impl eframe::App for ImperiumApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_control();
        self.poll_staging();
        let ctx = ui.ctx().clone();
        // Keep the console feeling live even when the bus is quiet.
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::Panel::top("topbar")
            .exact_size(58.0)
            .show_separator_line(false)
            .frame(
                egui::Frame::default()
                    .fill(theme::PANEL)
                    .inner_margin(egui::Margin::symmetric(16, 0)),
            )
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("IMPERIUM")
                                .size(17.0)
                                .strong()
                                .color(theme::ACCENT),
                        );
                        ui.label(
                            egui::RichText::new("cluster defense console")
                                .size(12.0)
                                .color(theme::TEXT_DIM),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if theme::solid_button(ui, "Shut down", theme::DANGER) {
                                commands::shutdown(&self.bus, "operator shut down via console");
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            let clock = chrono::Local::now().format("%H:%M:%S").to_string();
                            ui.label(
                                egui::RichText::new(clock)
                                    .monospace()
                                    .size(12.5)
                                    .color(theme::TEXT_DIM),
                            );

                            let rate = {
                                let state = self.state.read();
                                state.threats_last_minute()
                            };
                            theme::pill(ui, theme::ACCENT, &format!("{rate}/min threats"));

                            let state = self.state.read();
                            let (color, orch_label) = orchestrator_pill(&state);
                            drop(state);
                            theme::pill(ui, color, &orch_label);

                            let state = self.state.read();
                            let (color, ks_label) = kill_switch_pill(&state);
                            drop(state);
                            theme::pill(ui, color, &ks_label);
                        });
                    });
                });
            });

        if let Some((message, at, color)) = &self.flash {
            if at.elapsed() < Duration::from_secs(3) {
                let message = message.clone();
                let color = *color;
                egui::Panel::top("flash")
                    .exact_size(30.0)
                    .show_separator_line(false)
                    .frame(egui::Frame::default().fill(theme::PANEL))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 3.5, color);
                            ui.label(
                                egui::RichText::new(message)
                                    .size(12.5)
                                    .color(color)
                                    .strong(),
                            );
                        });
                    });
            } else {
                self.flash = None;
            }
        }

        egui::Panel::left("nav")
            .exact_size(190.0)
            .resizable(false)
            .frame(
                egui::Frame::default()
                    .fill(theme::PANEL)
                    .inner_margin(egui::Margin::symmetric(10, 14)),
            )
            .show(ui, |ui| {
                nav_item(ui, &mut self.view, View::Dashboard, "Dashboard", None);
                nav_item(
                    ui,
                    &mut self.view,
                    View::Threats,
                    "Threat feed",
                    Some(state_threat_rate(&self.state)),
                );
                nav_item(
                    ui,
                    &mut self.view,
                    View::Signatures,
                    "Signatures",
                    Some(self.pending.len() as u32),
                );
                nav_item(ui, &mut self.view, View::Transport, "Transport", None);
                nav_item(ui, &mut self.view, View::Activity, "Activity", None);

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(10.0);
                    ui.separator();
                    let uptime = self.state.read().started_at;
                    let mins = chrono::Utc::now()
                        .signed_duration_since(uptime)
                        .num_minutes()
                        .max(0);
                    ui.label(
                        egui::RichText::new(format!("console session · {mins} min"))
                            .size(12.0)
                            .color(theme::TEXT_DIM),
                    );
                    ui.label(
                        egui::RichText::new("operator authority")
                            .size(12.0)
                            .color(theme::TEXT_DIM),
                    );
                    ui.add_space(6.0);
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ui, |ui| match self.view {
                View::Dashboard => {
                    egui::ScrollArea::vertical()
                        .id_salt("dashboard_view")
                        .show(ui, |ui| {
                            egui::Frame::default()
                                .inner_margin(egui::Margin {
                                    left: 0,
                                    right: 24,
                                    top: 0,
                                    bottom: 0,
                                })
                                .show(ui, |ui| views::dashboard::show(ui, self));
                        });
                }
                View::Transport => {
                    egui::ScrollArea::vertical()
                        .id_salt("transport_view")
                        .show(ui, |ui| {
                            egui::Frame::default()
                                .inner_margin(egui::Margin {
                                    left: 0,
                                    right: 24,
                                    top: 0,
                                    bottom: 0,
                                })
                                .show(ui, |ui| views::transport::show(ui, self));
                        });
                }
                View::Threats => views::threats::show(ui, self),
                View::Signatures => views::signatures::show(ui, self),
                View::Activity => views::activity::show(ui, self),
            });
    }

    fn on_exit(&mut self) {
        // Closing the console takes the node down with it — the GUI is the
        // runtime, not a detachable viewer.
        commands::shutdown(&self.bus, "operator closed the console window");
    }
}

fn nav_item(ui: &mut egui::Ui, view: &mut View, candidate: View, label: &str, badge: Option<u32>) {
    let selected = *view == candidate;
    let frame = egui::Frame::default()
        .fill(if selected {
            theme::ACCENT_SOFT
        } else {
            egui::Color32::TRANSPARENT
        })
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(12, 8));

    let response = frame
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let text_color = if selected { theme::ACCENT } else { theme::TEXT };
                let rich = egui::RichText::new(label).size(13.5).color(text_color);
                ui.label(if selected { rich.strong() } else { rich });
                if let Some(count) = badge.filter(|c| *c > 0) {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(24.0, 17.0), egui::Sense::hover());
                        ui.painter()
                            .rect_filled(rect, 8, theme::ACCENT.gamma_multiply(0.2));
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            count.to_string(),
                            egui::FontId::proportional(11.0),
                            theme::ACCENT,
                        );
                    });
                }
            })
        })
        .response
        .interact(egui::Sense::click());
    if response.clicked() {
        *view = candidate;
    }
    if selected {
        let rect = response.rect;
        let bar = egui::Rect::from_min_max(
            egui::pos2(rect.left() - 8.0, rect.top() + 4.0),
            egui::pos2(rect.left() - 5.0, rect.bottom() - 4.0),
        );
        ui.painter().rect_filled(bar, 2, theme::ACCENT);
    }
}

fn state_threat_rate(state: &RwLock<UiState>) -> u32 {
    state.read().threats_last_minute()
}

fn orchestrator_pill(state: &UiState) -> (egui::Color32, String) {
    use imperium_protocol::OrchestratorState;
    match state.orchestrator {
        Some(OrchestratorState::Steady) => (theme::OK, "steady".to_string()),
        Some(OrchestratorState::Failover) => (theme::WARN, "failover".into()),
        Some(OrchestratorState::Healing) => (theme::WARN, "healing".into()),
        Some(OrchestratorState::Emergency) => (theme::DANGER, "emergency".into()),
        None => (theme::TEXT_DIM, "state unknown".into()),
    }
}

fn kill_switch_pill(state: &UiState) -> (egui::Color32, String) {
    use imperium_protocol::KillSwitchState;
    if state.pending_kill_switch.is_some() {
        return (theme::WARN, "mesh kill switch pending".into());
    }
    match state.kill_switch {
        Some(KillSwitchState::Disarmed) => (theme::TEXT_DIM, "mesh kill switch disarmed".into()),
        Some(KillSwitchState::Armed) => (theme::WARN, "mesh kill switch armed".into()),
        Some(KillSwitchState::Engaged) => (theme::DANGER, "mesh kill switch ENGAGED".into()),
        None => (theme::TEXT_DIM, "mesh kill switch unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn native_gui_thread_dispatches_control_with_explicit_runtime_handle() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let path =
            std::env::temp_dir().join(format!("imperium-gui-thread-{}.sock", uuid::Uuid::new_v4()));
        let listener = {
            let _runtime_context = runtime.enter();
            tokio::net::UnixListener::bind(&path).unwrap()
        };
        let server = runtime.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                input.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert_eq!(input, b"vpn killswitch engage gui confirmation\n");
            stream.write_all(b"{\"status\":\"ok\",\"message\":\"host egress blocked\",\"mesh_data_path_blocked\":true,\"host_guard_installed\":true,\"host_guard_mode\":\"engaged\",\"host_egress_blocked\":true}\n").await.unwrap();
        });

        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = Arc::new(StagingArea::new(Arc::clone(&bus)));
        let state = Arc::new(RwLock::new(UiState::new()));
        let handle = runtime.handle().clone();
        let cleanup_path = path.clone();
        let gui = std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            let mut app = ImperiumApp::new(
                bus,
                staging,
                state,
                Some(path.to_string_lossy().into_owned()),
                Some(handle),
            );
            app.request_kill_switch(KillSwitchState::Engaged, "gui confirmation");
            assert!(app.control_pending());
            for _ in 0..100 {
                app.poll_control();
                if !app.control_pending() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                app.last_control_reply
                    .as_ref()
                    .and_then(|reply| reply.host_egress_blocked),
                Some(true)
            );
        });
        gui.join().unwrap();
        runtime.block_on(server).unwrap();
        std::fs::remove_file(cleanup_path).unwrap();
    }
}
