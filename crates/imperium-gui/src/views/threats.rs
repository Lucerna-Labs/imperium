//! Threat feed: live ThreatAssessment stream from classifiers and the
//! signature engine.

use eframe::egui;

use crate::app::ImperiumApp;
use crate::theme;

pub fn show(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("Threat feed")
                .size(20.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let rate = {
                let state = app.state.read();
                (state.threats_last_minute(), state.threats.len())
            };
            theme::pill(
                ui,
                theme::ACCENT,
                &format!("{}/min · {} total", rate.0, rate.1),
            );
        });
    });
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Classifier and signature-engine assessments, newest first. Assessments sharpen the deterministic floor; they never replace it.")
            .size(12.0)
            .color(theme::TEXT_DIM),
    );
    ui.add_space(12.0);

    let rows: Vec<crate::ThreatRow> = {
        let state = app.state.read();
        state.threats.iter().rev().cloned().collect()
    };

    if rows.is_empty() {
        theme::card().show(ui, |ui| {
            ui.set_min_height(200.0);
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(
                    egui::RichText::new("sensors quiet — no threats assessed")
                        .size(14.0)
                        .color(theme::TEXT_DIM),
                );
                ui.add_space(60.0);
            });
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for row in &rows {
                let confidence_color = if row.confidence >= 0.75 {
                    theme::DANGER
                } else if row.confidence >= 0.4 {
                    theme::WARN
                } else {
                    theme::TEXT_DIM
                };
                theme::accented_card(confidence_color).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(row.timestamp.format("%H:%M:%S").to_string())
                                .monospace()
                                .size(12.0)
                                .color(theme::TEXT_DIM),
                        );
                        theme::pill(ui, confidence_color, &row.source);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{:.0}% confidence",
                                    row.confidence * 100.0
                                ))
                                .size(12.0)
                                .color(confidence_color),
                            );
                            theme::metric_bar(ui, row.confidence, confidence_color);
                        });
                    });
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(&row.description)
                            .size(13.5)
                            .color(theme::TEXT),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(format!("suggested action · {}", row.action))
                            .size(12.0)
                            .color(theme::TEXT_DIM),
                    );
                });
                ui.add_space(8.0);
            }
        });
}
