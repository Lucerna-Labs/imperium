//! Dashboard: headline stats, threat telemetry sparkline, subsystem roll-up,
//! deployment state, recent activity.

use eframe::egui;

use crate::app::ImperiumApp;
use crate::{theme, UiState};

pub fn show(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    ui.heading(
        egui::RichText::new("Dashboard")
            .size(20.0)
            .strong()
            .color(theme::TEXT),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Deterministic floor visible at a glance — sensors sharpen it.")
            .size(12.0)
            .color(theme::TEXT_DIM),
    );
    ui.add_space(14.0);

    stat_row(ui, app);
    ui.add_space(12.0);

    ui.columns(2, |columns| {
        telemetry_card(&mut columns[0], app);
        subsystems_card(&mut columns[1], app);
    });
    ui.add_space(12.0);

    ui.columns(2, |columns| {
        deployment_card(&mut columns[0], app);
        recent_activity_card(&mut columns[1], app);
    });
}

fn stat_row(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let state = app.state.read();
    ui.columns(3, |columns| {
        let (orch_color, orch_label) = match state.orchestrator {
            Some(imperium_protocol::OrchestratorState::Steady) => (theme::OK, "Steady"),
            Some(imperium_protocol::OrchestratorState::Failover) => (theme::WARN, "Failover"),
            Some(imperium_protocol::OrchestratorState::Healing) => (theme::WARN, "Healing"),
            Some(imperium_protocol::OrchestratorState::Emergency) => (theme::DANGER, "Emergency"),
            None => (theme::TEXT_DIM, "Unknown"),
        };
        stat_card(
            &mut columns[0],
            "ORCHESTRATOR",
            orch_label,
            state.last_decision.as_deref().unwrap_or("no decisions yet"),
            orch_color,
        );

        let active = state.active_protocol.clone().unwrap_or_else(|| "—".into());
        stat_card(
            &mut columns[1],
            "ACTIVE PROTOCOL",
            &active,
            "latest observed decision",
            theme::ACCENT,
        );

        let (ks_color, ks_label) = match state.kill_switch {
            Some(imperium_protocol::KillSwitchState::Disarmed) => (theme::TEXT_DIM, "Disarmed"),
            Some(imperium_protocol::KillSwitchState::Armed) => (theme::WARN, "Armed"),
            Some(imperium_protocol::KillSwitchState::Engaged) => (theme::DANGER, "Engaged"),
            None => (theme::TEXT_DIM, "Unknown"),
        };
        stat_card(
            &mut columns[2],
            "MESH KILL SWITCH",
            ks_label,
            "mesh data path only",
            ks_color,
        );
    });
    ui.add_space(10.0);
    ui.columns(3, |columns| {
        stat_card(
            &mut columns[0],
            "THREATS / MIN",
            &state.threats_last_minute().to_string(),
            &format!("{} total assessed", state.threats.len()),
            theme::ACCENT,
        );

        stat_card(
            &mut columns[1],
            "SIGNATURES",
            &app.pending.len().to_string(),
            "pending operator review",
            if app.pending.is_empty() {
                theme::TEXT_DIM
            } else {
                theme::WARN
            },
        );

        lightcone_card(&mut columns[2], &state);
    });
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, sub: &str, color: egui::Color32) {
    let content_width = (ui.available_width() - 30.0).max(158.0);
    theme::card().show(ui, |ui| {
        ui.set_min_width(content_width);
        theme::heading(ui, label);
        ui.add_space(2.0);
        ui.label(egui::RichText::new(value).size(22.0).strong().color(color));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(sub).size(12.0).color(theme::TEXT_DIM));
    });
}

fn lightcone_card(ui: &mut egui::Ui, state: &UiState) {
    let content_width = (ui.available_width() - 30.0).max(158.0);
    let v4_confirmed =
        state.subsystems.contains_key("imperium-net-lightcone") || state.lightcone_receipt_seen;
    let (value, status, color) = match state.lightcone_latest_sequence {
        Some(sequence) => (
            format!(
                "{} in · {} out",
                state.lightcone_inbound_receipts, state.lightcone_outbound_receipts
            ),
            if v4_confirmed {
                format!("v4 · passive diagnostic · unsealed · latest #{sequence}")
            } else {
                format!("expected v4 · receipt pack unconfirmed · latest #{sequence}")
            },
            theme::ACCENT,
        ),
        None => (
            "Waiting for receipts".to_string(),
            if v4_confirmed {
                "v4 loaded · passive diagnostic · unsealed".to_string()
            } else {
                "expected v4 · awaiting receipt".to_string()
            },
            theme::TEXT_DIM,
        ),
    };
    let card = theme::card().show(ui, |ui| {
        ui.set_min_width(content_width);
        theme::heading(ui, "LIGHTCONE RECEIPTS");
        ui.add_space(2.0);
        ui.label(egui::RichText::new(value).size(18.0).strong().color(color));
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(status)
                .size(12.0)
                .color(theme::TEXT_DIM),
        );
        ui.label(
            egui::RichText::new("FILTER NOT ENFORCED")
                .size(12.0)
                .strong()
                .color(theme::DANGER),
        );
    });
    card.response.on_hover_text(
        "Receipt activity is diagnostic, not a packet or flow forwarding gate. This console cannot see frames dropped before a receipt.",
    );
}

fn telemetry_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        ui.set_min_width(width - 30.0);
        theme::card().show(ui, |ui| {
            theme::heading(ui, "THREAT TELEMETRY · LAST 2 MINUTES");
            ui.add_space(6.0);

            let series: Vec<u32> = {
                let state = app.state.read();
                state.current_threat_series()
            };
            let peak = series.iter().copied().max().unwrap_or(0);
            let plot_peak = peak.max(1);

            let plot_height = 120.0;
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), plot_height),
                egui::Sense::hover(),
            );
            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, 6.0, theme::BG);

            // Baseline grid: three faint horizontal rules.
            for i in 1..3 {
                let y = rect.top() + rect.height() * i as f32 / 3.0;
                let mut from = rect.left_bottom();
                from.y = y;
                let mut to = rect.right_bottom();
                to.y = y;
                painter.line_segment(
                    [from, to],
                    egui::Stroke::new(1.0, theme::BORDER.gamma_multiply(0.5)),
                );
            }

            let n = series.len().max(1) as f32;
            let point = |i: usize, v: u32| -> egui::Pos2 {
                let x = rect.left() + 6.0 + (i as f32 / n) * (rect.width() - 12.0);
                let y =
                    rect.bottom() - 6.0 - (v as f32 / plot_peak as f32) * (rect.height() - 18.0);
                egui::pos2(x, y)
            };

            let mut fill_points = Vec::with_capacity(series.len() + 2);
            for (i, v) in series.iter().enumerate() {
                fill_points.push(point(i, *v));
            }
            fill_points.push(egui::pos2(
                fill_points.last().unwrap().x,
                rect.bottom() - 6.0,
            ));
            fill_points.push(egui::pos2(point(0, 0).x, rect.bottom() - 6.0));
            painter.add(egui::Shape::convex_polygon(
                fill_points,
                theme::ACCENT.gamma_multiply(0.12),
                egui::Stroke::NONE,
            ));

            let line_points: Vec<egui::Pos2> = series
                .iter()
                .enumerate()
                .map(|(i, v)| point(i, *v))
                .collect();
            painter.add(egui::Shape::line(
                line_points,
                egui::Stroke::new(2.0, theme::ACCENT),
            ));

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("peak {peak}/s"))
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("{} assessed total", {
                            let state = app.state.read();
                            state.threats.len()
                        }))
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                    );
                });
            });
        });
    });
}

fn subsystems_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        ui.set_min_width(width - 30.0);
        theme::card().show(ui, |ui| {
            theme::heading(ui, "SUBSYSTEMS INITIALIZED");
            ui.add_space(6.0);
            let state = app.state.read();
            if state.subsystems.is_empty() {
                ui.label(
                    egui::RichText::new("waiting for initialization events…")
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("dashboard_subsystems")
                    .max_height(168.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (name, since) in &state.subsystems {
                            ui.horizontal(|ui| {
                                let (dot, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(dot.center(), 3.0, theme::OK);
                                ui.label(egui::RichText::new(name).size(12.5).color(theme::TEXT));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let mins = chrono::Utc::now()
                                            .signed_duration_since(*since)
                                            .num_minutes()
                                            .max(0);
                                        ui.label(
                                            egui::RichText::new(format!("{mins} min"))
                                                .size(12.0)
                                                .color(theme::TEXT_DIM),
                                        );
                                    },
                                );
                            });
                        }
                    });
            }
        });
    });
}

fn deployment_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width(width - 30.0);
            theme::heading(ui, "VPN DEPLOYMENT");
            ui.add_space(6.0);
            let state = app.state.read();
            match &state.last_deployment {
                Some(d) => {
                    egui::Grid::new("deployment")
                        .num_columns(2)
                        .spacing([28.0, 6.0])
                        .show(ui, |ui| {
                            grid_pair(ui, "deployment", &d.deployment_id.to_string()[..8]);
                            grid_pair(ui, "state", if d.accepted { "accepted" } else { "rejected" });
                            grid_pair(ui, "nodes", &format!("{}/{}", d.approved_nodes, d.planned_nodes));
                            grid_pair(ui, "sessions", &d.established_sessions.to_string());
                            grid_pair(ui, "relay fallbacks", &d.relay_fallbacks_selected.to_string());
                            grid_pair(ui, "config version", &d.config_version.to_string());
                        });
                }
                None => {
                    ui.label(
                        egui::RichText::new(
                            "No deployment applied. Publish a VpnDeploymentPlan via the control socket or Ordo.",
                        )
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                    );
                }
            }
        });
    });
}

fn grid_pair(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(egui::RichText::new(key).size(12.0).color(theme::TEXT_DIM));
    ui.label(egui::RichText::new(value).size(12.5).color(theme::TEXT));
    ui.end_row();
}

fn recent_activity_card(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    let width = ui.available_width();
    ui.vertical(|ui| {
        theme::card().show(ui, |ui| {
            ui.set_min_width(width - 30.0);
            theme::heading(ui, "RECENT ACTIVITY");
            ui.add_space(6.0);
            let state = app.state.read();
            if state.activity.is_empty() {
                ui.label(
                    egui::RichText::new("bus is quiet")
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("dashboard_recent_activity")
                    .max_height(150.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for row in state.activity.iter().rev().take(7) {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(
                                        row.timestamp.format("%H:%M:%S").to_string(),
                                    )
                                    .monospace()
                                    .size(12.0)
                                    .color(theme::TEXT_DIM),
                                );
                                ui.label(egui::RichText::new(&row.label).size(12.0).color(
                                    if row.emergency {
                                        theme::DANGER
                                    } else {
                                        theme::TEXT
                                    },
                                ));
                            });
                        }
                    });
            }
        });
    });
}
