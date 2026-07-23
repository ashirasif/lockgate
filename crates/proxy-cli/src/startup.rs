//! The startup screen: choose a project before anything else opens.
//!
//! This runs as its own phase, on its own terminal, *before* the engine exists —
//! the engine is per-project, and `tui::run` already takes one that is open. So
//! the picker sits between opening the registry and opening the project's engine:
//! it hands back a [`Project`], and only then does `main` spawn the proxy, the
//! MCP server and the main TUI.
//!
//! One input bar doubles as search and create. It fuzzy-filters the projects you
//! have, shows the best few, and — when what you typed is not already a project —
//! offers to create it. `Ctrl-d` forgets the selected one (the registry row only;
//! the traffic stays on disk, as [`Registry::forget`] promises).

use std::io;
use std::path::{Path, PathBuf};

use proxy_core::model::now_micros;
use proxy_core::{Project, Registry};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Paragraph},
};

/// ANSI-Shadow wordmark. Fixed width (42 cells); the column is sized around it.
const LOGO: &[&str] = &[
    r"██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗",
    r"██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝",
    r"██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ",
    r"██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ",
    r"██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ",
    r"╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
];

/// The centred column's width. Wide enough for the logo, narrow enough to feel
/// like a prompt rather than a page.
const WIDTH: u16 = 46;

/// At most this many matching projects are offered; a create row may follow.
const MAX_RESULTS: usize = 4;

/// Show the picker and block until the user opens or creates a project, or quits.
///
/// Runs its own `init`/`restore`, so it is fully decoupled from the main TUI's
/// terminal and from the engine (which does not exist yet). `Ok(None)` means the
/// user left without opening anything — `main` should exit cleanly.
pub fn pick(registry: &Registry, projects_dir: &Path) -> io::Result<Option<Project>> {
    let mut terminal = ratatui::init();
    let result = Picker::new(registry, projects_dir).run(&mut terminal);
    ratatui::restore();
    result
}

/// A row the user can act on: an existing project, or the offer to create one.
enum Row {
    Open(Project),
    Create(String),
}

struct Picker<'a> {
    registry: &'a Registry,
    projects_dir: &'a Path,
    /// Every known project, loaded once. Reloaded only after a forget.
    all: Vec<Project>,
    query: String,
    rows: Vec<Row>,
    selected: usize,
    /// When `Some`, `Ctrl-d` armed a delete and we are waiting on y/n.
    confirm: Option<Project>,
}

/// What one keypress decided.
enum Outcome {
    Stay,
    Quit,
    Chosen(Project),
}

impl<'a> Picker<'a> {
    fn new(registry: &'a Registry, projects_dir: &'a Path) -> Self {
        // A registry read failing here is not worth aborting startup over: an
        // empty list just means the picker opens on a create-only prompt, which
        // is exactly the brand-new-user path anyway.
        let all = registry.list().unwrap_or_default();
        let mut picker = Self {
            registry,
            projects_dir,
            all,
            query: String::new(),
            rows: Vec::new(),
            selected: 0,
            confirm: None,
        };
        picker.recompute();
        picker
    }

    fn run(mut self, terminal: &mut DefaultTerminal) -> io::Result<Option<Project>> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match self.handle(key.code, key.modifiers)? {
                Outcome::Stay => {}
                Outcome::Quit => return Ok(None),
                Outcome::Chosen(project) => return Ok(Some(project)),
            }
        }
    }

    /// Rebuild the visible rows from the query, and reset the selection to the
    /// top so the best match is what Enter would take.
    fn recompute(&mut self) {
        let query = self.query.trim();

        let mut scored: Vec<(i32, &Project)> = self
            .all
            .iter()
            .filter_map(|p| fuzzy(query, &p.name).map(|score| (score, p)))
            .collect();
        // Score first; `list()` already returns most-recently-opened first, so
        // equal scores keep that order under a stable sort.
        scored.sort_by(|a, b| b.0.cmp(&a.0));

        self.rows = scored
            .into_iter()
            .take(MAX_RESULTS)
            .map(|(_, p)| Row::Open(p.clone()))
            .collect();

        // Offer creation unless the query is empty or already names a project.
        let names_existing = self
            .all
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(query));
        if !query.is_empty() && !names_existing {
            self.rows.push(Row::Create(query.to_string()));
        }

        self.selected = 0;
    }

    fn handle(&mut self, code: KeyCode, mods: KeyModifiers) -> io::Result<Outcome> {
        // Ctrl-c always leaves, even mid-confirm.
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            return Ok(Outcome::Quit);
        }

        // A delete is armed: nothing else is live until it is answered.
        if let Some(project) = self.confirm.take() {
            match code {
                KeyCode::Char('y') => {
                    self.registry.forget(project.id).map_err(to_io)?;
                    self.all = self.registry.list().map_err(to_io)?;
                    self.recompute();
                }
                // Any other key cancels; re-arm nothing.
                _ => {}
            }
            return Ok(Outcome::Stay);
        }

        let ctrl = mods.contains(KeyModifiers::CONTROL);
        match code {
            KeyCode::Esc => return Ok(Outcome::Quit),
            KeyCode::Enter => {
                if let Some(project) = self.activate()? {
                    return Ok(Outcome::Chosen(project));
                }
            }
            KeyCode::Up => self.move_up(),
            KeyCode::Down => self.move_down(),
            KeyCode::Char('p') if ctrl => self.move_up(),
            KeyCode::Char('n') if ctrl => self.move_down(),
            KeyCode::Char('d') if ctrl => {
                if let Some(Row::Open(project)) = self.rows.get(self.selected) {
                    self.confirm = Some(project.clone());
                }
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.recompute();
            }
            // Plain typing (ignore other control chords so they cannot leak in).
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
            }
            _ => {}
        }
        Ok(Outcome::Stay)
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.rows.len() {
            self.selected += 1;
        }
    }

    /// Turn the selected row into a project — opening an existing one, or
    /// creating the typed name. `None` when there is nothing to act on (an empty
    /// registry with an empty query).
    fn activate(&self) -> io::Result<Option<Project>> {
        match self.rows.get(self.selected) {
            Some(Row::Open(project)) => Ok(Some(project.clone())),
            Some(Row::Create(name)) => {
                let root = self.projects_dir.join(name);
                self.registry
                    .create(name, &root, now_micros())
                    .map(Some)
                    .map_err(to_io)
            }
            None => Ok(None),
        }
    }

    // --- rendering ---

    fn draw(&self, frame: &mut Frame) {
        let width = WIDTH.min(frame.area().width);
        // logo(6) + tagline(1) + gap(1) + input(3) + rows(5) + gap(1) + hint(1).
        let height = 18u16.min(frame.area().height);
        let column = center(frame.area(), width, height);

        let [logo, tagline, _gap, input, rows, _gap2, hint] = Layout::vertical([
            Constraint::Length(LOGO.len() as u16),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length((MAX_RESULTS + 1) as u16),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(column);

        self.draw_logo(frame, logo);
        frame.render_widget(
            Line::from(format!("an intercepting proxy · v{}", env!("CARGO_PKG_VERSION")))
                .centered()
                .fg(Color::DarkGray),
            tagline,
        );
        self.draw_input(frame, input);
        self.draw_rows(frame, rows);
        self.draw_hint(frame, hint);
    }

    fn draw_logo(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = LOGO
            .iter()
            .map(|l| Line::from(*l).centered().fg(Color::Cyan))
            .collect();
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn draw_input(&self, frame: &mut Frame, area: Rect) {
        let body = Line::from(vec![
            Span::styled("❯ ", Style::new().fg(Color::Cyan)),
            Span::raw(&self.query),
            // A block cursor, so the bar reads as focused.
            Span::styled("▏", Style::new().fg(Color::Cyan)),
        ]);
        frame.render_widget(
            Paragraph::new(body).block(
                Block::bordered()
                    .title(" open or create a project ")
                    .border_style(Style::new().fg(Color::DarkGray)),
            ),
            area,
        );
    }

    fn draw_rows(&self, frame: &mut Frame, area: Rect) {
        let inner = area.width as usize;
        let lines: Vec<Line> = self
            .rows
            .iter()
            .enumerate()
            .map(|(i, row)| self.row_line(i, row, inner))
            .collect();
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn row_line(&self, index: usize, row: &Row, width: usize) -> Line<'static> {
        let selected = index == self.selected;
        let marker = if selected { "▸ " } else { "  " };

        match row {
            Row::Open(project) => {
                let deleting = self
                    .confirm
                    .as_ref()
                    .is_some_and(|c| c.id == project.id);
                let left = format!("{marker}{}", project.name);
                let right = ago(project.last_opened);
                let pad = width
                    .saturating_sub(left.chars().count())
                    .saturating_sub(right.chars().count() + 8); // +8 for "opened "
                let mut name_style = Style::new();
                if deleting {
                    name_style = name_style.fg(Color::Red).add_modifier(Modifier::BOLD);
                } else if selected {
                    name_style = name_style.add_modifier(Modifier::BOLD);
                }
                Line::from(vec![
                    Span::styled(left, name_style),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(format!("opened {right}"), Style::new().fg(Color::DarkGray)),
                ])
            }
            Row::Create(name) => {
                let text = format!("{marker}+ create \u{201c}{name}\u{201d}");
                let style = if selected {
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(Color::Green)
                };
                Line::from(Span::styled(text, style))
            }
        }
    }

    fn draw_hint(&self, frame: &mut Frame, area: Rect) {
        let line = match &self.confirm {
            Some(project) => Line::from(format!(
                "delete \u{201c}{}\u{201d}? y/n · traffic stays on disk",
                project.name
            ))
            .centered()
            .fg(Color::Red),
            None => Line::from("↑↓ move    ⏎ open    ^d delete    esc quit")
                .centered()
                .fg(Color::DarkGray),
        };
        frame.render_widget(line, area);
    }
}

/// Case-insensitive subsequence match. `None` when `query` is not a subsequence
/// of `name`; a higher score means a tighter match. Consecutive hits and a match
/// at the very start are rewarded, so `acme` ranks `acme` over `a-c-m-e`.
///
/// Hand-rolled, like the crate's base64/glob/JSON: one small function beats a
/// fuzzy-match dependency for a menu that never exceeds a handful of names.
fn fuzzy(query: &str, name: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let mut score = 0i32;
    let mut run = 0i32;
    let mut chars = name.chars().map(|c| c.to_ascii_lowercase());
    for q in query.chars().map(|c| c.to_ascii_lowercase()) {
        // Advance `name` to the next occurrence of `q`.
        let mut matched = false;
        for c in chars.by_ref() {
            if c == q {
                matched = true;
                break;
            }
            run = 0; // a gap breaks the consecutive run
        }
        if !matched {
            return None;
        }
        run += 1;
        score += 1 + run; // reward longer unbroken runs
    }
    // A prefix match (query starts the name) is the strongest signal.
    if name.to_ascii_lowercase().starts_with(&query.to_ascii_lowercase()) {
        score += 5;
    }
    Some(score)
}

/// A short "when was this last opened" for the menu, in the operator's own idea
/// of recent: relative within a week, an absolute date beyond it. `None` (never
/// opened) reads as "just now" — a project you create is opened immediately.
fn ago(last_opened: Option<i64>) -> String {
    let Some(then) = last_opened else {
        return "just now".to_string();
    };
    let secs = (now_micros() - then) / 1_000_000;
    match secs {
        s if s < 60 => "just now".to_string(),
        s if s < 3_600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3_600),
        s if s < 604_800 => format!("{}d ago", s / 86_400),
        _ => {
            use chrono::{Local, TimeZone};
            match Local.timestamp_micros(then) {
                chrono::LocalResult::Single(t) => t.format("%b %e").to_string(),
                _ => "a while ago".to_string(),
            }
        }
    }
}

/// A `width`×`height` rectangle centred inside `area`, clamped to it.
fn center(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

/// Registry calls return `rusqlite::Error`, which this crate does not depend on
/// by name; fold any of them into an `io::Error` by their message.
fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Where projects live under the data directory. Kept here so the caller passes
/// one path and the picker builds project roots the same way `main` does.
pub fn projects_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("projects")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    /// A registry in a throwaway directory, seeded with `names`.
    fn seeded(names: &[&str]) -> (Registry, PathBuf) {
        let dir = std::env::temp_dir().join(format!("proxy-picker-test-{}", now_micros()));
        let projects = dir.join("projects");
        let registry = Registry::open(&dir.join("registry.db")).unwrap();
        for name in names {
            registry
                .create(name, &projects.join(name), now_micros())
                .unwrap();
        }
        (registry, projects)
    }

    /// Render a picker to an in-memory buffer, one `String` per row, so we can
    /// assert on layout and content the way the TUI tests do.
    fn render(picker: &Picker) -> String {
        let mut terminal = Terminal::new(TestBackend::new(60, 24)).unwrap();
        terminal.draw(|frame| picker.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    #[ignore = "visual preview; run with --ignored --nocapture"]
    fn preview() {
        let (registry, dir) = seeded(&["acme", "acme-staging", "acmelabs"]);
        let picker = Picker::new(&registry, &dir);
        println!("\n{}\n", render(&picker));
    }

    #[test]
    fn logo_and_existing_projects_render() {
        let (registry, dir) = seeded(&["acme", "acme-staging"]);
        let picker = Picker::new(&registry, &dir);
        let screen = render(&picker);
        assert!(screen.contains("██████"), "logo missing");
        assert!(screen.contains("open or create a project"), "input title missing");
        assert!(screen.contains("acme"), "project missing");
        assert!(screen.contains("opened"), "recency missing");
        assert!(screen.contains("esc quit"), "hint missing");
    }

    #[test]
    fn a_new_name_offers_to_create_it() {
        let (registry, dir) = seeded(&["acme"]);
        let mut picker = Picker::new(&registry, &dir);
        for c in "widgets".chars() {
            picker.query.push(c);
        }
        picker.recompute();
        let screen = render(&picker);
        assert!(screen.contains("create"), "create row missing for a new name");
        assert!(screen.contains("widgets"), "typed name missing");
    }

    #[test]
    fn an_exact_name_does_not_offer_to_create() {
        let (registry, dir) = seeded(&["acme"]);
        let mut picker = Picker::new(&registry, &dir);
        for c in "acme".chars() {
            picker.query.push(c);
        }
        picker.recompute();
        assert!(
            matches!(picker.rows.as_slice(), [Row::Open(_)]),
            "an exact match should not grow a create row"
        );
    }

    #[test]
    fn ctrl_d_arms_a_delete_and_the_hint_changes() {
        let (registry, dir) = seeded(&["acme"]);
        let mut picker = Picker::new(&registry, &dir);
        let out = picker
            .handle(KeyCode::Char('d'), KeyModifiers::CONTROL)
            .unwrap();
        assert!(matches!(out, Outcome::Stay));
        assert!(picker.confirm.is_some(), "ctrl-d should arm a delete");
        assert!(render(&picker).contains("delete"), "confirm hint missing");

        // 'y' forgets it; the list empties.
        picker
            .handle(KeyCode::Char('y'), KeyModifiers::NONE)
            .unwrap();
        assert!(picker.confirm.is_none());
        assert!(picker.all.is_empty(), "forget should drop the project");
    }

    #[test]
    fn enter_on_a_new_name_creates_and_returns_it() {
        let (registry, dir) = seeded(&[]);
        let mut picker = Picker::new(&registry, &dir);
        for c in "fresh".chars() {
            picker.query.push(c);
        }
        picker.recompute();
        match picker.handle(KeyCode::Enter, KeyModifiers::NONE).unwrap() {
            Outcome::Chosen(project) => assert_eq!(project.name, "fresh"),
            _ => panic!("Enter on a create row should choose the new project"),
        }
    }

    #[test]
    fn fuzzy_requires_subsequence() {
        assert!(fuzzy("acme", "acme-staging").is_some());
        assert!(fuzzy("acs", "acme-staging").is_some()); // a…c…s
        assert!(fuzzy("xyz", "acme").is_none());
        assert!(fuzzy("", "anything").is_some());
    }

    #[test]
    fn fuzzy_prefers_prefix_and_runs() {
        // Exact prefix beats a scattered subsequence of the same length.
        let prefix = fuzzy("acme", "acme").unwrap();
        let scattered = fuzzy("acme", "a-c-m-e").unwrap();
        assert!(prefix > scattered, "{prefix} !> {scattered}");
    }

    #[test]
    fn fuzzy_is_case_insensitive() {
        assert!(fuzzy("ACME", "acme").is_some());
        assert!(fuzzy("acme", "ACME").is_some());
    }

    #[test]
    fn ago_reads_relative_then_absolute() {
        let now = now_micros();
        assert_eq!(ago(Some(now)), "just now");
        assert_eq!(ago(Some(now - 5 * 60 * 1_000_000)), "5m ago");
        assert_eq!(ago(Some(now - 3 * 3_600 * 1_000_000)), "3h ago");
        assert_eq!(ago(Some(now - 2 * 86_400 * 1_000_000)), "2d ago");
        assert_eq!(ago(None), "just now");
    }
}
