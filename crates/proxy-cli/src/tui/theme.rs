//! Colours and styles, in one place so the palette stays consistent.

use super::*;

pub(super) fn leg_style(on: bool) -> Style {
    if on {
        Style::new().fg(Color::Yellow)
    } else {
        muted()
    }
}

pub(super) fn leg_note(leg: &str, on: bool, released: usize) -> String {
    if on {
        format!("holding {leg}")
    } else {
        format!("not holding {leg} — released {released}")
    }
}

/// Secondary text: hints, empty states, field labels, inactive borders.
///
/// Dims the terminal's *own* foreground rather than naming a colour.
/// `Color::DarkGray` is ANSI bright-black — one specific dark value, which
/// disappears against a transparent or light background. `DIM` is relative to
/// whatever foreground the user actually has, so it stays readable in terminals
/// we cannot see, and degrades to plain (still legible) text where the terminal
/// ignores it.
///
/// Change this one function to restyle every hint in the UI.
pub(super) fn muted() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

/// Background fill for a highlighted-but-unfocused row. Backgrounds are a
/// different problem from text — they need a real colour to shade a cell — so
/// they deliberately do not go through [`muted`].
pub(super) const INACTIVE_BG: Color = Color::DarkGray;

/// Severity at a glance. The point of the colour is that "critical" should not
/// need reading.
pub(super) fn severity_color(severity: &str) -> Color {
    match severity {
        "critical" => Color::Red,
        "high" => Color::LightRed,
        "medium" => Color::Yellow,
        "low" => Color::Cyan,
        _ => Color::Gray,
    }
}

pub(super) fn status_color(status: StatusCode) -> Color {
    match status.as_u16() {
        500.. => Color::Red,
        400..500 => Color::LightRed,
        300..400 => Color::Yellow,
        _ => Color::Green,
    }
}
