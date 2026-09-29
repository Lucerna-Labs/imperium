//! Transport controls and status. Controls without a running executor are
//! visibly unavailable rather than reporting success after a bus request.

use std::time::{Duration, Instant};

use eframe::egui;

use crate::app::ImperiumApp;
use crate::{commands, theme};

pub fn show(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    ui.heading(
        egui::RichText::new("Transport")
            .size(20.0)
            .strong()
            .color(theme::TEXT),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Operator controls and observed mesh status. Emergency shutdown remains available from the top bar.")
            .size(12.0)
            .color(theme::TEXT_DIM),
    );
    ui.add_space(12.0);

    ui.columns(2, |columns| {
        kill_switch_card(&mut columns[0], app);
        protocol_card(&mut columns[1], app);
    });
    ui.add_space(12.0);
    ui.columns(2, |columns| {
        hardening_card(&mut columns[0], app);
        nat_card(&mut columns[1]);
    });
}

fn kill_switch_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width((width - 30.0).max(0.0));
            theme::heading(ui, "NETWORK KILL SWITCH");
            ui.add_space(8.0);

            let (color, label) = {
                let state = app.state.read();
                match state.kill_switch {
                    Some(imperium_protocol::KillSwitchState::Disarmed) => {
                        (theme::TEXT_DIM, "disarmed")
                    }
                    Some(imperium_protocol::KillSwitchState::Armed) => (theme::WARN, "armed"),
                    Some(imperium_protocol::KillSwitchState::Engaged) => (theme::DANGER, "ENGAGED"),
                    None => (theme::TEXT_DIM, "unknown"),
                }
            };
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(label).size(24.0).strong().color(color));
            });
            ui.add_space(10.0);
            ui.label(
                egui::RichText::new("The local control service coordinates mesh and the optional host guard. Host blocking is shown only after a confirmed reply.")
                    .size(12.0)
                    .color(theme::TEXT_DIM),
            );
            if let Some(reply) = app.last_control_reply.as_ref() {
                let (host_status, host_color) = match (
                    reply.host_guard_installed,
                    reply.host_egress_blocked,
                ) {
                    (Some(true), Some(true)) =>
                        ("Host non-loopback egress blocked · confirmed".to_string(), theme::DANGER),
                    (Some(true), Some(false)) => (
                        format!("Host guard {} · egress open", reply.host_guard_mode.as_deref().unwrap_or("active")),
                        theme::TEXT_DIM,
                    ),
                    (Some(false), _) => ("Host guard not installed · mesh only".to_string(), theme::WARN),
                    _ => ("Host guard state unconfirmed".to_string(), theme::WARN),
                };
                ui.label(egui::RichText::new(host_status).size(12.0).color(host_color));
                if let Some(mesh_blocked) = reply.mesh_data_path_blocked {
                    ui.label(
                        egui::RichText::new(if mesh_blocked {
                            "Mesh data path blocked · control confirmed"
                        } else {
                            "Mesh data path open · control confirmed"
                        })
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                    );
                }
            } else {
                ui.label(
                    egui::RichText::new("Host guard state unconfirmed")
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            }
            if app.control_pending() {
                ui.label(
                    egui::RichText::new("Local control request pending · awaiting reply")
                        .size(12.0)
                        .color(theme::WARN),
                );
            } else if let Some(pending) = app.state.read().pending_kill_switch.clone() {
                ui.label(
                    egui::RichText::new(format!("Request pending: {pending:?}. Awaiting mesh status."))
                        .size(12.0)
                        .color(theme::WARN),
                );
            } else if !app.control_available() {
                ui.label(
                    egui::RichText::new("Local control socket unavailable; controls disabled")
                        .size(12.0)
                        .color(theme::WARN),
                );
            }
            ui.add_space(6.0);
            ui.add_enabled_ui(app.control_available() && !app.control_pending(), |ui| ui.horizontal(|ui| {
                if theme::ghost_button(ui, "Disarm") {
                    app.request_kill_switch(
                        imperium_protocol::KillSwitchState::Disarmed,
                        "operator disarmed via console",
                    );
                }
                if theme::ghost_button(ui, "Arm") {
                    app.request_kill_switch(
                        imperium_protocol::KillSwitchState::Armed,
                        "operator armed via console",
                    );
                }

                // Engaging can block the mesh and optional host egress; ask
                // for a confirming second click within a few seconds.
                let armed_recently = app
                    .engage_armed_at
                    .map(|at| at.elapsed() < Duration::from_secs(4))
                    .unwrap_or(false);
                let engage_label = if armed_recently {
                    "Confirm ENGAGE"
                } else {
                    "Engage"
                };
                if theme::solid_button(ui, engage_label, theme::DANGER) {
                    if armed_recently {
                        app.engage_armed_at = None;
                        app.request_kill_switch(
                            imperium_protocol::KillSwitchState::Engaged,
                            "operator engaged via console",
                        );
                    } else {
                        app.engage_armed_at = Some(Instant::now());
                        app.flash("click again to confirm engage", theme::WARN);
                    }
                }
            }));
        });
    });
}

fn protocol_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width((width - 30.0).max(0.0));
            theme::heading(ui, "ACTIVE / STANDBY PROTOCOLS");
            ui.add_space(8.0);
            let (active, standby, decision) = {
                let state = app.state.read();
                (
                    state.active_protocol.clone().unwrap_or_else(|| "—".into()),
                    state.standby_protocol.clone().unwrap_or_else(|| "—".into()),
                    state.last_decision.clone(),
                )
            };
            egui::Grid::new("protocols")
                .num_columns(2)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    pair(ui, "active", &active, theme::ACCENT);
                    pair(ui, "standby", &standby, theme::TEXT_DIM);
                    if let Some(d) = &decision {
                        pair(ui, "last decision", d, theme::TEXT);
                    }
                });
            ui.add_space(10.0);
            ui.add_enabled(false, egui::Button::new("Rotate profiles"))
                .on_disabled_hover_text("No active protocol controller is connected to this node.");
            ui.label(
                egui::RichText::new("Rotation unavailable: no active protocol controller.")
                    .size(12.0)
                    .color(theme::TEXT_DIM),
            );
        });
    });
}

fn hardening_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width((width - 30.0).max(0.0));
            theme::heading(ui, "HARDENING PROFILE");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                for preset in ["balanced", "resilience", "fortress"] {
                    let selected = {
                        let state = app.state.read();
                        state
                            .last_hardening
                            .as_ref()
                            .map(|h| h.accepted && h.profile_id.contains(preset))
                            .unwrap_or(false)
                    };
                    let label = if selected {
                        egui::RichText::new(preset).strong().color(theme::ACCENT)
                    } else {
                        egui::RichText::new(preset).color(theme::TEXT)
                    };
                    if ui.add(egui::Button::new(label)).clicked() {
                        match commands::hardening_preset(&app.bus, preset, None) {
                            Ok(()) => app.flash(
                                format!("{preset} hardening requested — awaiting status"),
                                theme::WARN,
                            ),
                            Err(e) => app.flash(e, theme::DANGER),
                        }
                    }
                }
            });
            ui.add_space(6.0);
            let status = {
                let state = app.state.read();
                state.last_hardening.clone()
            };
            match status {
                Some(h) => {
                    let (color, word) = if h.accepted {
                        (theme::OK, "accepted")
                    } else {
                        (theme::DANGER, "rejected")
                    };
                    ui.label(
                        egui::RichText::new(format!(
                            "{word} · {} · {}",
                            h.profile_id,
                            h.protocol_name.as_deref().unwrap_or("all protocols")
                        ))
                        .size(12.0)
                        .color(color),
                    );
                }
                None => {
                    ui.label(
                        egui::RichText::new("hardening status unknown")
                            .size(12.0)
                            .color(theme::TEXT_DIM),
                    );
                }
            }
        });
    });
}

fn nat_card(ui: &mut egui::Ui) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width((width - 30.0).max(0.0));
            theme::heading(ui, "NAT TRAVERSAL");
            ui.add_space(8.0);
            ui.add_enabled(
                false,
                egui::Checkbox::new(&mut false, "Aggressive probing (opt-in)"),
            )
            .on_disabled_hover_text("The mesh has no NAT probe executor connected.");
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("Unavailable: the mesh has no NAT probe executor connected.")
                    .size(12.0)
                    .color(theme::TEXT_DIM),
            );
        });
    });
}

fn pair(ui: &mut egui::Ui, key: &str, value: &str, color: egui::Color32) {
    ui.label(egui::RichText::new(key).size(12.0).color(theme::TEXT_DIM));
    ui.label(egui::RichText::new(value).size(13.0).color(color));
    ui.end_row();
}
