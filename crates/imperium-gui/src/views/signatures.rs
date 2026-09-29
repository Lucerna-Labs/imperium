//! Signatures: the operator approval gate. Candidates wait in staging until
//! an operator decides; nothing is promoted automatically.

use eframe::egui;

use crate::app::ImperiumApp;
use crate::{commands, theme};

pub fn show(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    ui.heading(
        egui::RichText::new("Signature approval")
            .size(20.0)
            .strong()
            .color(theme::TEXT),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Extracted candidates are staged until an operator approves or rejects them. The bundled signature database always loads; approvals only extend it.")
            .size(12.0)
            .color(theme::TEXT_DIM),
    );
    ui.add_space(12.0);

    if app.pending.is_empty() {
        theme::card().show(ui, |ui| {
            ui.set_min_height(180.0);
            ui.vertical_centered(|ui| {
                ui.add_space(48.0);
                ui.label(
                    egui::RichText::new("no candidates awaiting review")
                        .size(14.0)
                        .color(theme::TEXT_DIM),
                );
                ui.label(
                    egui::RichText::new("candidates appear here after `signatures extract <event_id>` or a sensor-triggered extraction")
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
                ui.add_space(48.0);
            });
        });
        return;
    }

    let pending = app.pending.clone();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for candidate in &pending {
                candidate_card(ui, app, candidate);
                ui.add_space(10.0);
            }
        });
}

fn candidate_card(
    ui: &mut egui::Ui,
    app: &mut ImperiumApp,
    candidate: &imperium_protocol::SignatureCandidate,
) {
    let confidence_color = if candidate.confidence >= 0.75 {
        theme::WARN
    } else {
        theme::ACCENT
    };

    theme::card().show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            theme::pill(
                ui,
                confidence_color,
                &format!("{:.0}% confidence", candidate.confidence * 100.0),
            );
            ui.label(
                egui::RichText::new(format!(
                    "extracted {}",
                    candidate.extracted_at.format("%Y-%m-%d %H:%M UTC")
                ))
                .size(12.0)
                .color(theme::TEXT_DIM),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(candidate.id.to_string())
                        .monospace()
                        .size(12.0)
                        .color(theme::TEXT_DIM),
                );
            });
        });
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(&candidate.description)
                .size(14.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.add_space(6.0);
        theme::heading(ui, "PROPOSED RULE");
        ui.add_space(2.0);
        egui::Frame::default()
            .fill(theme::BG)
            .corner_radius(6)
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_max_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .id_salt(candidate.id)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut candidate.rule_text.clone())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                    });
            });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let reason = app.drafts.reject_reasons.entry(candidate.id).or_default();
            ui.add(
                egui::TextEdit::singleline(reason)
                    .desired_width(280.0)
                    .hint_text("rejection reason (logged)"),
            );
            if theme::solid_button(ui, "Reject", theme::DANGER) {
                let reason = reason.trim().to_string();
                let reason = if reason.is_empty() {
                    "operator rejected via console".to_string()
                } else {
                    reason
                };
                commands::reject_signature(&app.bus, candidate.id, &reason);
                app.flash(
                    format!("rejected candidate {}", &candidate.id.to_string()[..8]),
                    theme::DANGER,
                );
                app.refresh_staging_now();
            }
            if theme::solid_button(ui, "Approve", theme::OK) {
                commands::approve_signature(&app.bus, candidate.id);
                app.flash(
                    format!("approval dispatched for {}", &candidate.id.to_string()[..8]),
                    theme::OK,
                );
                app.refresh_staging_now();
            }
        });
    });
}
