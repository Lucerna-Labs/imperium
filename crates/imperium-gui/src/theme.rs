//! Console theme: a dark operations palette applied through egui's style
//! system. All geometry/color constants live here so the views stay about
//! content.

use eframe::egui;

// Palette — deep slate surfaces, one cyan accent, semantic status colors.
pub const BG: egui::Color32 = egui::Color32::from_rgb(11, 13, 17);
pub const PANEL: egui::Color32 = egui::Color32::from_rgb(15, 18, 23);
pub const CARD: egui::Color32 = egui::Color32::from_rgb(21, 25, 32);
pub const CARD_HOVER: egui::Color32 = egui::Color32::from_rgb(28, 34, 43);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(39, 46, 58);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(226, 231, 238);
pub const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(138, 147, 161);
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(56, 208, 238);
pub const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(24, 55, 66);
pub const OK: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);
pub const WARN: egui::Color32 = egui::Color32::from_rgb(245, 158, 11);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(239, 68, 68);

pub fn install(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.panel_fill = PANEL;
        v.extreme_bg_color = BG;
        v.faint_bg_color = CARD;
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = ACCENT_SOFT;
        v.selection.stroke = egui::Stroke::new(1.0, ACCENT);

        let w = &mut v.widgets;
        w.noninteractive.bg_fill = CARD;
        w.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
        w.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_DIM);
        w.noninteractive.corner_radius = egui::CornerRadius::same(6);
        w.inactive.bg_fill = CARD_HOVER;
        w.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
        w.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = egui::CornerRadius::same(6);
        w.hovered.bg_fill = CARD_HOVER;
        w.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
        w.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);
        w.hovered.corner_radius = egui::CornerRadius::same(6);
        w.active.bg_fill = ACCENT_SOFT;
        w.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
        w.active.fg_stroke = egui::Stroke::new(1.0, TEXT);
        w.active.corner_radius = egui::CornerRadius::same(6);
        w.open.bg_fill = CARD;
        w.open.corner_radius = egui::CornerRadius::same(6);

        let s = &mut style.spacing;
        s.item_spacing = egui::vec2(10.0, 8.0);
        s.button_padding = egui::vec2(14.0, 7.0);
        s.interact_size = egui::vec2(24.0, 24.0);
    });
}

/// Standard content card: soft surface, hairline border, generous padding.
pub fn card() -> egui::Frame {
    egui::Frame::default()
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(14))
}

/// Card with a tinted border signaling status (threat rows, alerts).
pub fn accented_card(accent: egui::Color32) -> egui::Frame {
    egui::Frame::default()
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.45)))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(12))
}

/// Status pill: colored dot + label.
pub fn pill(ui: &mut egui::Ui, color: egui::Color32, label: &str) -> egui::Response {
    let size = egui::vec2(pill_width(label), 20.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 10, color.gamma_multiply(0.14));
    painter.circle_filled(egui::pos2(rect.left() + 10.0, rect.center().y), 3.5, color);
    painter.text(
        egui::pos2(rect.left() + 20.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.5),
        color,
    );
    response
}

fn pill_width(label: &str) -> f32 {
    30.0 + label.chars().count() as f32 * 6.5
}

/// Small horizontal metric bar (confidence and similar fractions).
pub fn metric_bar(ui: &mut egui::Ui, fraction: f64, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 6.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3, CARD_HOVER);
    let frac = fraction.clamp(0.0, 1.0) as f32;
    let mut fill = rect;
    fill.set_width(rect.width() * frac);
    if fill.width() > 0.0 {
        painter.rect_filled(fill, 3, color);
    }
}

/// Section heading inside a card.
pub fn heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(12.0)
            .color(TEXT_DIM)
            .strong(),
    );
}

/// Filled button in a semantic color with dark text for contrast.
pub fn solid_button(ui: &mut egui::Ui, label: &str, color: egui::Color32) -> bool {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(egui::Color32::from_rgb(10, 12, 15))
                .strong(),
        )
        .fill(color),
    )
    .clicked()
}

/// Quiet secondary button for non-destructive actions.
pub fn ghost_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add(egui::Button::new(egui::RichText::new(label).color(TEXT)))
        .clicked()
}
