//! Activity: the raw bus wire — every event the console has seen, newest
//! first, filterable by topic fragment.

use eframe::egui;

use crate::app::ImperiumApp;
use crate::theme;

pub fn show(ui: &mut egui::Ui, app: &mut ImperiumApp) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("Activity")
                .size(20.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.activity_filter)
                    .desired_width(240.0)
                    .hint_text("filter by topic fragment…"),
            );
        });
    });
    ui.add_space(4.0);
    let events_total = app.state.read().events_total;
    ui.label(
        egui::RichText::new(format!(
            "{events_total} bus events observed by this console. Emergency events are highlighted."
        ))
        .size(12.0)
        .color(theme::TEXT_DIM),
    );
    ui.add_space(12.0);

    let query = app.activity_filter.trim().to_lowercase();
    let rows: Vec<crate::ActivityRow> = {
        let state = app.state.read();
        state
            .activity
            .iter()
            .rev()
            .filter(|row| {
                query.is_empty()
                    || row.topic.to_lowercase().contains(&query)
                    || row.label.to_lowercase().contains(&query)
            })
            .cloned()
            .collect()
    };

    if rows.is_empty() {
        theme::card().show(ui, |ui| {
            ui.set_min_height(120.0);
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.label(
                    egui::RichText::new(if query.is_empty() {
                        "bus is quiet"
                    } else {
                        "no events match the filter"
                    })
                    .size(13.0)
                    .color(theme::TEXT_DIM),
                );
                ui.add_space(30.0);
            });
        });
        return;
    }

    theme::card().show(ui, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for row in &rows {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(row.timestamp.format("%H:%M:%S").to_string())
                                .monospace()
                                .size(12.0)
                                .color(theme::TEXT_DIM),
                        );
                        ui.label(
                            egui::RichText::new(row.topic.as_ref())
                                .monospace()
                                .size(12.0)
                                .color(if row.emergency {
                                    theme::DANGER
                                } else {
                                    theme::ACCENT.gamma_multiply(0.75)
                                }),
                        );
                        ui.label(
                            egui::RichText::new(&row.label)
                                .size(12.5)
                                .color(theme::TEXT),
                        );
                    });
                }
            });
    });
}
