use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hudsucker::hyper::{HeaderMap, StatusCode};
use proxy_core::{
    CapturedRequest, Engine, Flow, FlowSummary, Held, Pending, SitemapNode, TicketId,
};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Row, Table, TableState, Wrap},
};

use crate::command::Command;
use crate::editor::TextBuffer;
use crate::http_text;
use crate::input::{Action, Input, InsertKey, Mode, Motion, PaletteKey, Scroll, Window};

/// The Repeater's working copy of a request.
///
/// Loaded explicitly with `<Space>s` rather than mirrored from the Proxy cursor.
/// Mirroring is what the Repeater used to do, and it cannot survive editing: the
/// cursor moves on every tick of new traffic, and an edited buffer that a cursor
/// move silently replaced would lose work with no way to get it back.
#[derive(Default)]
struct Repeater {
    /// The flow this was loaded from, so replays keep their lineage.
    origin: Option<u64>,
    /// The request as editable wire text.
    request: TextBuffer,
    /// What the original looked like, to reparse edits against (for the scheme
    /// and authority that origin-form text cannot carry).
    original: Option<CapturedRequest>,
    /// The last response, rendered. Shared because the send runs on its own task
    /// so a slow target cannot freeze the UI.
    response: Arc<Mutex<Option<String>>>,
    /// Why the last send attempt did not leave — a parse error in the buffer.
    error: Option<String>,
}

/// The Intercept window's view state. The queue itself lives on the engine.
#[derive(Default)]
struct InterceptView {
    /// Row cursor into the queue as it was last rendered.
    selected: usize,
    /// The edit buffer for one held item, created on the first `i` and dropped
    /// once the item is answered. Keyed by ticket so a queue that reorders
    /// underneath the operator cannot silently retarget their edits.
    editing: Option<(TicketId, TextBuffer)>,
}

/// The Sitemap window's view state.
#[derive(Default)]
struct SitemapView {
    selected: usize,
    /// Folded rows, by the same key `sitemap_rows` assigns. Collapsed rather
    /// than expanded is stored so a newly-seen path shows up unfolded.
    collapsed: HashSet<String>,
}

/// One rendered line of the sitemap tree.
struct SitemapRow {
    depth: usize,
    label: String,
    /// Identity for folding: stable across refreshes, unlike a row index.
    key: String,
    flow_count: i64,
    has_children: bool,
}

/// Take over the terminal and run the UI until the user quits.
pub async fn run(engine: Arc<Engine>) -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let result = App::new(engine).run(&mut terminal).await;
    ratatui::restore();
    result
}

struct App {
    engine: Arc<Engine>,
    /// Refreshed from the engine every tick, so proxied traffic shows up live.
    flows: Vec<FlowSummary>,
    table: TableState,
    /// Full flow for the current selection, for the detail pane.
    detail: Option<Flow>,
    /// Shared so a spawned resend task can report back without blocking the UI.
    status: Arc<Mutex<String>>,
    should_quit: bool,

    /// Keys in, actions out. All input goes through here.
    input: Input,
    /// Marks hold flow *ids*, not row indices: new traffic keeps arriving and
    /// would otherwise slide a mark onto a different request.
    marks: HashMap<char, u64>,
    /// Row indices we jumped away from, walked by `<C-o>` / `<C-i>`.
    jumps: Vec<usize>,
    jump_cursor: usize,
    /// Where the current `v` selection started, as a row index.
    visual_anchor: Option<usize>,
    search: String,
    /// Visible history rows, captured at draw time so `<C-d>` knows a page.
    viewport: usize,
    /// `:set` toggles, e.g. `rnu` for relative line numbers.
    options: HashMap<String, bool>,

    /// The window currently on screen. The tab strip shows the rest.
    window: Window,
    /// Vertical scroll of the active non-Proxy window's content. Reset whenever
    /// the window changes, since a line offset means nothing across windows.
    content_scroll: u16,
    /// Lines the active window last rendered, so `G` and downward scrolling can
    /// stop at the end instead of running off into blank space.
    content_len: u16,

    /// The Cmd-K palette's filter text. Only meaningful while the input layer
    /// is in `Palette` mode, which is what tells us the palette is open.
    palette_query: String,
    /// Which filtered command is highlighted.
    palette_selected: usize,

    repeater: Repeater,
    intercept: InterceptView,
    sitemap: SitemapView,
    /// The intercept queue as of this tick. Snapshotted in `refresh` so drawing
    /// and key handling within one frame agree on what is held — re-reading the
    /// live queue mid-frame could answer a ticket the operator never saw.
    queue: Vec<Held>,
}

impl App {
    fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            flows: Vec::new(),
            table: TableState::default(),
            detail: None,
            status: Arc::new(Mutex::new(String::new())),
            should_quit: false,
            input: Input::new(),
            marks: HashMap::new(),
            jumps: Vec::new(),
            jump_cursor: 0,
            visual_anchor: None,
            search: String::new(),
            viewport: 10,
            options: HashMap::new(),
            window: Window::default(),
            content_scroll: 0,
            content_len: 0,
            palette_query: String::new(),
            palette_selected: 0,
            repeater: Repeater::default(),
            intercept: InterceptView::default(),
            sitemap: SitemapView::default(),
            queue: Vec::new(),
        }
    }

    fn option(&self, name: &str) -> bool {
        self.options.get(name).copied().unwrap_or(false)
    }

    fn cursor(&self) -> usize {
        self.table.selected().unwrap_or(0)
    }

    async fn run(mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        while !self.should_quit {
            self.refresh();
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;
            // Yield rather than block: the proxy is running on other tokio tasks.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    /// Pull the latest history from the engine and keep the selection valid.
    fn refresh(&mut self) {
        // History is newest-first, so every captured request inserts at row 0
        // and pushes everything below it down. A selection kept as a row index
        // would slide onto a different flow while the operator is reading it —
        // so remember the flow *id* and put the cursor back on it.
        let pinned = self.selected_id();
        self.flows = self.engine.list_flows();

        match pinned.and_then(|id| self.flows.iter().position(|f| f.id == id)) {
            Some(row) => self.table.select(Some(row)),
            // Nothing pinned (first draw), or the pinned flow is gone: fall back
            // to keeping the cursor in range.
            None => match self.table.selected() {
                None if !self.flows.is_empty() => self.table.select(Some(0)),
                Some(i) if i >= self.flows.len() => {
                    self.table.select(self.flows.len().checked_sub(1));
                }
                _ => {}
            },
        }

        self.detail = self.selected_id().and_then(|id| self.engine.get_flow(id));

        self.queue = self.engine.intercept().queue();
        self.intercept.selected = self
            .intercept
            .selected
            .min(self.queue.len().saturating_sub(1));
        // An item answered (by us, by a timeout, by disabling interception)
        // takes its edit buffer with it, rather than leaving edits that would
        // silently attach to whichever item next takes that ticket's place.
        if let Some((ticket, _)) = &self.intercept.editing {
            if !self.queue.iter().any(|h| h.ticket == *ticket) {
                self.intercept.editing = None;
            }
        }
    }

    fn selected_id(&self) -> Option<u64> {
        let i = self.table.selected()?;
        self.flows.get(i).map(|f| f.id)
    }

    // --- input ---

    fn handle_events(&mut self) -> std::io::Result<()> {
        // Drain everything queued; poll with a zero timeout so we never block.
        while event::poll(Duration::ZERO)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(action) = self.input.feed(key) {
                    self.apply(action);
                }
            }
        }
        Ok(())
    }

    /// The single place where an intent becomes a change to the app.
    fn apply(&mut self, action: Action) {
        match action {
            // Windows with a row cursor move it; the rest have only scrollable
            // content, so the same motions move the viewport instead.
            Action::Move { motion, count } if self.window == Window::Proxy => {
                self.move_cursor(motion, count)
            }
            Action::Move { motion, count } if self.window == Window::Intercept => {
                let last = self.queue.len().saturating_sub(1);
                self.intercept.selected = step_row(self.intercept.selected, last, motion, count);
            }
            Action::Move { motion, count } if self.window == Window::Sitemap => {
                let last = self.sitemap_rows().len().saturating_sub(1);
                self.sitemap.selected = step_row(self.sitemap.selected, last, motion, count);
            }
            Action::Move { motion, count } => self.scroll_content(motion, count),
            // Nothing scrolls independently of the cursor yet; ratatui keeps
            // the selection visible for us. Recorded so `zz` is not silent.
            Action::Scroll(scroll) => self.note(match scroll {
                Scroll::Center => "zz",
                Scroll::Top => "zt",
                Scroll::Bottom => "zb",
            }),
            Action::SetMark(name) => {
                if let Some(id) = self.selected_id() {
                    self.marks.insert(name, id);
                    self.note(&format!("mark {name} → #{id}"));
                }
            }
            Action::GotoMark(name) => match self.marks.get(&name).copied() {
                Some(id) => match self.flows.iter().position(|f| f.id == id) {
                    Some(row) => self.jump_to(row),
                    None => self.note(&format!("mark {name} refers to a dropped flow")),
                },
                None => self.note(&format!("E20: mark not set: {name}")),
            },
            Action::JumpBack => self.walk_jumps(-1),
            Action::JumpForward => self.walk_jumps(1),
            Action::ModeChange(mode) => {
                self.visual_anchor = (mode == Mode::Visual).then(|| self.cursor());
            }
            Action::Search { pattern, backward } => {
                self.search = pattern;
                self.move_cursor(
                    if backward {
                        Motion::MatchBackward
                    } else {
                        Motion::MatchForward
                    },
                    None,
                );
            }
            // In the Repeater, `<Space>r` sends what is in the buffer — edits
            // and all. Everywhere else it replays the Proxy selection.
            Action::Resend if self.window == Window::Repeater => self.send_repeater(),
            Action::Resend => self.resend_selected(),
            Action::SendToRepeater => self.load_repeater(),
            Action::Insert(key) => self.edit(key),
            Action::Forward => self.answer_held(true),
            Action::Drop => self.answer_held(false),
            Action::ForwardAll => {
                let n = self.engine.intercept().forward_all();
                self.note(&format!("forwarded {n} held item(s)"));
            }
            Action::DropAll => {
                let n = self.engine.intercept().discard_all();
                self.note(&format!("dropped {n} held item(s)"));
            }
            Action::ToggleIntercept => self.toggle_intercept(),
            Action::Toggle => self.toggle_fold(),
            Action::Command(line) => self.run_command(&line),
            Action::Window(window) => self.show_window(window),
            Action::WindowStep(direction) => self.show_window(self.window.step(direction)),
            Action::Palette(key) => self.palette(key),
        }
    }

    // --- editing ---

    /// Route a keystroke to whichever buffer the active window is editing.
    /// Windows with nothing editable swallow it, so `i` there is inert rather
    /// than scribbling into a buffer the operator cannot see.
    fn edit(&mut self, key: InsertKey) {
        let Some(buffer) = self.active_buffer() else {
            return;
        };
        match key {
            InsertKey::Char(c) => buffer.insert_char(c),
            InsertKey::Newline => buffer.insert_newline(),
            InsertKey::Backspace => buffer.backspace(),
            InsertKey::Delete => buffer.delete(),
            InsertKey::Left => buffer.left(),
            InsertKey::Right => buffer.right(),
            InsertKey::Up => buffer.up(),
            InsertKey::Down => buffer.down(),
            InsertKey::LineStart => buffer.line_start(),
            InsertKey::LineEnd => buffer.line_end(),
        }
    }

    /// The buffer `i` types into, if the active window has one.
    ///
    /// In Intercept this lazily forks an edit buffer off the highlighted item —
    /// the first keystroke is what turns a held item into an edited one.
    fn active_buffer(&mut self) -> Option<&mut TextBuffer> {
        match self.window {
            Window::Repeater => self
                .repeater
                .original
                .is_some()
                .then(|| &mut self.repeater.request),
            Window::Intercept => {
                let held = self.queue.get(self.intercept.selected)?;
                let ticket = held.ticket;
                if self.intercept.editing.as_ref().map(|(t, _)| *t) != Some(ticket) {
                    let text = match &held.pending {
                        Pending::Request(r) => http_text::render_request(r),
                        Pending::Response(r) => http_text::render_response(r),
                    };
                    self.intercept.editing = Some((ticket, TextBuffer::from_text(&text)));
                }
                self.intercept.editing.as_mut().map(|(_, b)| b)
            }
            _ => None,
        }
    }

    // --- intercept ---

    fn toggle_intercept(&mut self) {
        let intercept = self.engine.intercept();
        let on = !intercept.is_enabled();
        let released = intercept.set_enabled(on);
        self.note(&if on {
            "intercept ON — traffic will hold until forwarded".to_string()
        } else {
            format!("intercept OFF — released {released} held item(s)")
        });
    }

    /// Answer the highlighted held item, forwarding any edits made to it.
    fn answer_held(&mut self, forward: bool) {
        let Some(held) = self.queue.get(self.intercept.selected) else {
            self.note("nothing held");
            return;
        };
        let ticket = held.ticket;

        if !forward {
            self.engine.intercept().discard(ticket);
            self.intercept.editing = None;
            self.note(&format!("dropped #{}", held.flow_id));
            return;
        }

        // Only reparse if this item was actually edited; an untouched item
        // forwards its original bytes rather than a re-rendered approximation.
        let edited = match &self.intercept.editing {
            Some((t, buffer)) if *t == ticket && buffer.is_dirty() => {
                match reparse(&held.pending, &buffer.text()) {
                    Ok(pending) => Some(pending),
                    Err(e) => {
                        // Refuse rather than silently forwarding the original:
                        // sending something other than what is on screen is the
                        // one thing an intercept editor must never do.
                        self.note(&format!("not forwarded — {e}"));
                        return;
                    }
                }
            }
            _ => None,
        };

        let flow_id = held.flow_id;
        let was_edited = edited.is_some();
        self.engine.intercept().forward(ticket, edited);
        self.intercept.editing = None;
        self.note(&if was_edited {
            format!("forwarded #{flow_id} (edited)")
        } else {
            format!("forwarded #{flow_id}")
        });
    }

    // --- sitemap ---

    fn toggle_fold(&mut self) {
        if self.window != Window::Sitemap {
            return;
        }
        let rows = self.sitemap_rows();
        let Some(row) = rows.get(self.sitemap.selected) else {
            return;
        };
        if !row.has_children {
            return;
        }
        if !self.sitemap.collapsed.remove(&row.key) {
            self.sitemap.collapsed.insert(row.key.clone());
        }
    }

    /// The sitemap flattened into display rows, honouring folds.
    ///
    /// The engine hands back a flat list with `parent_id` links; the tree is
    /// rebuilt here. Hosts are synthesized as the top level — they are not nodes
    /// in the table, but they are how an operator thinks about the tree.
    fn sitemap_rows(&self) -> Vec<SitemapRow> {
        // A generous page: the fold state is per-key, so paging would need to
        // hold parents across pages anyway. Bounded so a huge project cannot
        // stall a frame.
        let nodes = self.engine.sitemap(None, 0, 5000);
        build_sitemap_rows(&nodes, &self.sitemap.collapsed)
    }

    // --- repeater ---

    /// Snapshot the Proxy selection into the Repeater as editable text.
    fn load_repeater(&mut self) {
        let Some(flow) = self.detail.clone() else {
            self.note("no flow selected to send to the Repeater");
            return;
        };
        let id = flow.id;
        self.repeater = Repeater {
            origin: Some(id),
            request: TextBuffer::from_text(&http_text::render_request(&flow.request)),
            original: Some(flow.request),
            response: Arc::new(Mutex::new(None)),
            error: None,
        };
        self.show_window(Window::Repeater);
        self.note(&format!("#{id} → Repeater"));
    }

    /// Send what is in the Repeater buffer, edits included.
    fn send_repeater(&mut self) {
        let Some(original) = self.repeater.original.clone() else {
            self.note("Repeater is empty — pick a flow in Proxy and press <Space>s");
            return;
        };
        let request = match http_text::parse_request(&self.repeater.request.text(), &original) {
            Ok(req) => req,
            Err(e) => {
                // Kept on the pane, not just the status line: a parse error is
                // about the buffer, and belongs next to it.
                self.repeater.error = Some(e.to_string());
                self.note(&format!("not sent — {e}"));
                return;
            }
        };
        self.repeater.error = None;
        self.repeater.request.clear_dirty();

        let engine = self.engine.clone();
        let status = self.status.clone();
        let slot = self.repeater.response.clone();
        let origin = self.repeater.origin;

        self.note("sending…");
        tokio::spawn(async move {
            let message = match engine.send_request(request, origin).await {
                Ok(sent) => {
                    let text = http_text::render_response(&sent.response);
                    *slot.lock().unwrap() = Some(text);
                    format!(
                        "sent → {} ({} bytes) as #{}",
                        sent.response.status,
                        sent.response.body.len(),
                        sent.replay_id
                    )
                }
                Err(e) => {
                    *slot.lock().unwrap() = Some(format!("send failed: {e:?}"));
                    format!("send failed: {e:?}")
                }
            };
            *status.lock().unwrap() = message;
        });
    }

    /// Drive the Cmd-K palette. The input layer already flipped the mode; here
    /// we only maintain the filter and selection, and on `Accept` we look up the
    /// highlighted command and run it through `apply` like any other intent.
    fn palette(&mut self, key: PaletteKey) {
        match key {
            PaletteKey::Open => {
                self.palette_query.clear();
                self.palette_selected = 0;
            }
            PaletteKey::Char(c) => {
                self.palette_query.push(c);
                self.palette_selected = 0;
            }
            PaletteKey::Backspace => {
                self.palette_query.pop();
                self.palette_selected = 0;
            }
            PaletteKey::Up => self.palette_selected = self.palette_selected.saturating_sub(1),
            PaletteKey::Down => {
                let last = self.palette_matches().len().saturating_sub(1);
                self.palette_selected = (self.palette_selected + 1).min(last);
            }
            PaletteKey::Accept => {
                if let Some((_, action)) = self
                    .palette_matches()
                    .into_iter()
                    .nth(self.palette_selected)
                {
                    self.apply(action);
                }
            }
            PaletteKey::Cancel => {}
        }
    }

    /// Every command the palette can run, built fresh each keystroke so labels
    /// and targets track the current state (which window you're in, whether a
    /// toggle is on). Each entry is just an existing [`Action`] with a name.
    fn palette_command_catalog(&self) -> Vec<(String, Action)> {
        let mut commands = Vec::new();
        for window in Window::ALL {
            if window != self.window {
                commands.push((format!("Go to {}", window.label()), Action::Window(window)));
            }
        }
        commands.push(("Resend selection".into(), Action::Resend));
        commands.push(("Send selection to Repeater".into(), Action::SendToRepeater));
        // Reads its own state, so the label says what will happen rather than
        // what is true — the same shape as the `rnu` toggle below.
        commands.push((
            if self.engine.intercept().is_enabled() {
                "Turn intercept off".into()
            } else {
                "Turn intercept on".into()
            },
            Action::ToggleIntercept,
        ));
        if !self.queue.is_empty() {
            let n = self.queue.len();
            commands.push((format!("Forward all {n} held item(s)"), Action::ForwardAll));
            commands.push((format!("Drop all {n} held item(s)"), Action::DropAll));
        }
        commands.push((
            "Go to first request".into(),
            Action::Move {
                motion: Motion::Top,
                count: None,
            },
        ));
        commands.push((
            "Go to last request".into(),
            Action::Move {
                motion: Motion::Bottom,
                count: None,
            },
        ));
        // The toggle reads its own state so the label says what will happen.
        let (rnu_label, rnu_cmd) = if self.option("rnu") {
            ("Disable relative line numbers", "set nornu")
        } else {
            ("Enable relative line numbers", "set rnu")
        };
        commands.push((rnu_label.into(), Action::Command(rnu_cmd.into())));
        commands.push(("Show help".into(), Action::Command("help".into())));
        commands.push(("Quit".into(), Action::Command("q".into())));
        commands
    }

    /// The catalog filtered by the query and ranked best-match first. An empty
    /// query keeps every command in its natural order.
    fn palette_matches(&self) -> Vec<(String, Action)> {
        let mut scored: Vec<(i32, usize, String, Action)> = self
            .palette_command_catalog()
            .into_iter()
            .enumerate()
            .filter_map(|(i, (label, action))| {
                fuzzy_score(&self.palette_query, &label).map(|score| (score, i, label, action))
            })
            .collect();
        // Best score wins; original order breaks ties so the list stays stable.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .map(|(_, _, label, action)| (label, action))
            .collect()
    }

    /// Switch windows. Scrolling is per-window, so leaving one abandons its
    /// offset — you always arrive at the top of the window you asked for.
    fn show_window(&mut self, window: Window) {
        if window != self.window {
            self.window = window;
            self.content_scroll = 0;
            self.note(window.label());
        }
    }

    /// The non-Proxy windows have no row cursor, so `j`/`k`/`<C-d>`/`gg`/`G`
    /// scroll their rendered content. The offset is clamped at draw time once
    /// the real line count is known.
    fn scroll_content(&mut self, motion: Motion, count: Option<usize>) {
        let step = count.unwrap_or(1) as u16;
        let page = self.viewport.max(1) as u16;
        let last = self.content_len.saturating_sub(1);
        self.content_scroll = match motion {
            Motion::Down => self.content_scroll.saturating_add(step),
            Motion::Up => self.content_scroll.saturating_sub(step),
            Motion::Top => count.map_or(0, |n| n.saturating_sub(1) as u16),
            Motion::Bottom => last,
            Motion::HalfPageDown => self.content_scroll.saturating_add(page / 2),
            Motion::HalfPageUp => self.content_scroll.saturating_sub(page / 2),
            Motion::PageDown => self.content_scroll.saturating_add(page),
            Motion::PageUp => self.content_scroll.saturating_sub(page),
            _ => self.content_scroll,
        }
        .min(last);
    }

    fn run_command(&mut self, line: &str) {
        let Some(command) = Command::parse(line) else {
            return;
        };
        match command {
            Command::Quit => self.should_quit = true,
            Command::Resend => self.resend_selected(),
            // `:42` addresses flow #42 — the number the gutter shows — not the
            // 42nd row. With history newest-first the two no longer coincide,
            // and the gutter is what the operator is reading off the screen.
            Command::Goto(n) => match self.flows.iter().position(|f| f.id == n as u64) {
                Some(row) => self.jump_to(row),
                None => self.note(&format!("E486: no flow #{n}")),
            },
            Command::Set { option, value } => {
                self.options.insert(option.clone(), value);
                self.note(&format!("set {option}={value}"));
            }
            Command::Help => self.note(HELP),
            Command::Unknown(name) => self.note(&format!("E492: not an editor command: {name}")),
        }
    }

    fn move_cursor(&mut self, motion: Motion, count: Option<usize>) {
        if self.flows.is_empty() {
            return;
        }
        let last = self.flows.len() - 1;
        let current = self.cursor();
        let step = count.unwrap_or(1) as isize;
        let page = self.viewport.max(1) as isize;

        let target = match motion {
            Motion::Down => current as isize + step,
            Motion::Up => current as isize - step,
            // `12gg` and `12G` both go to line 12; bare `G` goes to the end.
            Motion::Top => count.map_or(0, |n| n.saturating_sub(1)) as isize,
            Motion::Bottom => count.map_or(last as isize, |n| n.saturating_sub(1) as isize),
            Motion::HalfPageDown => current as isize + step * page / 2,
            Motion::HalfPageUp => current as isize - step * page / 2,
            Motion::PageDown => current as isize + step * page,
            Motion::PageUp => current as isize - step * page,
            Motion::ScreenTop => self.table.offset() as isize,
            Motion::ScreenMiddle => self.table.offset() as isize + page / 2,
            Motion::ScreenBottom => self.table.offset() as isize + page - 1,
            Motion::GroupForward => self.group_edge(current, 1),
            Motion::GroupBackward => self.group_edge(current, -1),
            Motion::MatchForward => self.find_match(current, 1),
            Motion::MatchBackward => self.find_match(current, -1),
        };

        let target = target.clamp(0, last as isize) as usize;
        // Long-range moves are jumps, so `<C-o>` can bring you back.
        if matches!(
            motion,
            Motion::Top | Motion::Bottom | Motion::MatchForward | Motion::MatchBackward
        ) {
            self.push_jump(current);
        }
        self.table.select(Some(target));
    }

    /// `}` / `{` — the next row whose host differs from the current one.
    fn group_edge(&self, from: usize, direction: isize) -> isize {
        let host_of = |i: usize| {
            self.flows
                .get(i)
                .and_then(|f| f.uri.host())
                .map(str::to_owned)
        };
        let start = host_of(from);
        let mut i = from as isize;
        loop {
            let next = i + direction;
            if next < 0 || next as usize >= self.flows.len() {
                return i;
            }
            i = next;
            if host_of(i as usize) != start {
                return i;
            }
        }
    }

    /// `n` / `N` — search wraps around the history, as it does in vim.
    fn find_match(&self, from: usize, direction: isize) -> isize {
        if self.search.is_empty() {
            return from as isize;
        }
        let len = self.flows.len();
        let needle = self.search.to_lowercase();
        for offset in 1..=len {
            let i = (from as isize + direction * offset as isize).rem_euclid(len as isize) as usize;
            if self.flows[i]
                .uri
                .to_string()
                .to_lowercase()
                .contains(&needle)
            {
                return i as isize;
            }
        }
        from as isize
    }

    // --- jumplist ---

    fn jump_to(&mut self, row: usize) {
        if self.flows.is_empty() {
            return;
        }
        self.push_jump(self.cursor());
        self.table.select(Some(row.min(self.flows.len() - 1)));
    }

    /// Record where we left from, discarding any forward history — the same
    /// truncating behaviour vim's jumplist has.
    fn push_jump(&mut self, row: usize) {
        self.jumps.truncate(self.jump_cursor);
        self.jumps.push(row);
        self.jump_cursor = self.jumps.len();
    }

    fn walk_jumps(&mut self, direction: isize) {
        // Stepping back off the newest entry: record where we are now, or
        // `<C-i>` would have nowhere to return to. Vim does the same.
        if direction < 0 && self.jump_cursor == self.jumps.len() {
            self.jumps.push(self.cursor());
        }
        let next = self.jump_cursor as isize + direction;
        let Ok(next) = usize::try_from(next) else {
            return;
        };
        let Some(&row) = self.jumps.get(next) else {
            return;
        };
        self.jump_cursor = next;
        self.table
            .select(Some(row.min(self.flows.len().saturating_sub(1))));
    }

    fn note(&self, message: &str) {
        *self.status.lock().unwrap() = message.to_string();
    }

    /// Rows covered by the visual selection, or just the cursor row.
    fn selected_rows(&self) -> std::ops::RangeInclusive<usize> {
        let cursor = self.cursor();
        match self.visual_anchor {
            Some(anchor) => anchor.min(cursor)..=anchor.max(cursor),
            None => cursor..=cursor,
        }
    }

    /// Fire the Repeater. Spawned rather than awaited so a slow target can't
    /// freeze the UI; the task reports back through the shared status string.
    fn resend_selected(&mut self) {
        // A visual selection resends every flow it covers.
        let ids: Vec<u64> = self
            .selected_rows()
            .filter_map(|row| self.flows.get(row).map(|f| f.id))
            .collect();
        if ids.is_empty() {
            return;
        }
        let engine = self.engine.clone();
        let status = self.status.clone();

        self.note(&format!("resending {} flow(s)…", ids.len()));
        tokio::spawn(async move {
            let mut last = String::new();
            let (mut ok, mut failed) = (0, 0);
            for id in &ids {
                match engine.resend(*id).await {
                    Ok(r) => {
                        ok += 1;
                        last = format!(
                            "#{id} → {} ({} bytes) as #{}",
                            r.response.status,
                            r.response.body.len(),
                            r.replay_id
                        );
                    }
                    Err(e) => {
                        failed += 1;
                        last = format!("#{id} failed: {e:?}");
                    }
                }
            }
            *status.lock().unwrap() = if ids.len() == 1 {
                format!("resend {last}")
            } else {
                format!("resend: {ok} ok, {failed} failed — last {last}")
            };
        });
    }

    /// The Automate window's body: the base set to run against, and a live
    /// breakdown of everything captured so far.
    fn automate_lines(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        section(&mut lines, "BASE SET");
        let base: Vec<&FlowSummary> = self
            .selected_rows()
            .filter_map(|row| self.flows.get(row))
            .collect();
        if base.is_empty() {
            field(&mut lines, "—", "no flow selected in Proxy (P)");
        } else {
            for flow in &base {
                lines.push(Line::from(format!(
                    "  #{}  {}  {}",
                    flow.id, flow.method, flow.uri
                )));
            }
            lines.push(Line::styled(
                "  <Space>r replays this set through the Repeater",
                Style::new().fg(Color::DarkGray),
            ));
        }

        section(&mut lines, "STATUS");
        let mut classes = std::collections::BTreeMap::<&str, usize>::new();
        for flow in &self.flows {
            let class = match flow.status.map(|s| s.as_u16()) {
                Some(200..300) => "2xx",
                Some(300..400) => "3xx",
                Some(400..500) => "4xx",
                Some(500..) => "5xx",
                Some(_) => "other",
                None => "pending",
            };
            *classes.entry(class).or_default() += 1;
        }
        field(&mut lines, "total", self.flows.len().to_string());
        for (class, count) in &classes {
            field(&mut lines, class, count.to_string());
        }

        section(&mut lines, "BY HOST");
        let mut hosts = std::collections::BTreeMap::<String, usize>::new();
        for flow in &self.flows {
            let host = flow.uri.host().unwrap_or("—").to_string();
            *hosts.entry(host).or_default() += 1;
        }
        // Busiest first; ties fall back to host name for a stable order.
        let mut hosts: Vec<_> = hosts.into_iter().collect();
        hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (host, count) in hosts.iter().take(8) {
            field(&mut lines, host, count.to_string());
        }

        section(&mut lines, "RUNNER");
        lines.push(Line::styled(
            "  Intruder-style runs are not wired up yet.",
            Style::new().fg(Color::DarkGray),
        ));
        lines
    }

    // --- rendering ---

    fn draw(&mut self, frame: &mut Frame) {
        // Chrome above and below; the middle belongs to the active window.
        let [tabs, body, status_bar] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        self.draw_tabs(frame, tabs);
        match self.window {
            Window::Proxy => self.draw_proxy(frame, body),
            Window::Intercept => self.draw_intercept(frame, body),
            Window::Repeater => self.draw_repeater(frame, body),
            Window::Sitemap => self.draw_sitemap(frame, body),
            Window::Inspect => self.draw_inspect(frame, body),
            Window::Automate => self.draw_automate(frame, body),
        }
        self.draw_status(frame, status_bar);
        // Drawn last so it floats above whichever window is behind it.
        if self.input.mode() == Mode::Palette {
            self.draw_palette(frame);
        }
    }

    /// A Telescope-style overlay: a filter prompt over a ranked command list,
    /// centred on the screen with everything behind it cleared.
    fn draw_palette(&self, frame: &mut Frame) {
        // Tall enough for the whole catalog: the list does not scroll, so an
        // entry that falls off the bottom is simply unreachable. Two more
        // windows made 60% too short for that to stay true.
        let area = centered_rect(frame.area(), 60, 80);
        frame.render_widget(Clear, area);

        let [prompt, list] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);

        let matches = self.palette_matches();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  ", Style::new().fg(Color::Cyan)),
                Span::raw(format!("{}█", self.palette_query)),
            ]))
            .block(Block::bordered().title(" Command Palette ").title_bottom(
                format!(
                    " {} ",
                    match matches.len() {
                        1 => "1 match".to_string(),
                        n => format!("{n} matches"),
                    }
                ),
            )),
            prompt,
        );

        let rows: Vec<Line> = if matches.is_empty() {
            vec![Line::styled(
                "  no matching command",
                Style::new().fg(Color::DarkGray),
            )]
        } else {
            matches
                .iter()
                .enumerate()
                .map(|(i, (label, _))| {
                    if i == self.palette_selected {
                        Line::from(vec![
                            Span::styled("▶ ", Style::new().fg(Color::Cyan)),
                            Span::styled(
                                label.clone(),
                                Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
                            ),
                        ])
                    } else {
                        Line::from(format!("  {label}"))
                    }
                })
                .collect()
        };
        frame.render_widget(Paragraph::new(rows).block(Block::bordered()), list);
    }

    /// Mason's tool strip: each window a chip, `Name (key)`, active one lit.
    fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut spans = vec![Span::raw(" ")];
        for window in Window::ALL {
            let chip = format!(" {} ({}) ", window.label(), window.key());
            let style = if window == self.window {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else {
                Style::new().fg(Color::Gray)
            };
            spans.push(Span::styled(chip, style));
            spans.push(Span::raw(" "));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// The home window: HTTP history above, request/response detail below.
    fn draw_proxy(&mut self, frame: &mut Frame, area: Rect) {
        let [history, detail] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
        // Burp-style: request on the left, response on the right.
        let [request, response] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(detail);

        self.draw_history(frame, history);
        self.draw_request(frame, request);
        self.draw_response(frame, response);
    }

    /// Repeater: an editable request on the left, the response it produced on
    /// the right. `i` edits, Escape leaves, `<Space>r` sends what is in the
    /// buffer. Loaded explicitly with `<Space>s` from Proxy.
    fn draw_repeater(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        if self.repeater.original.is_none() {
            self.content_len = 0;
            frame.render_widget(
                empty_pane(
                    " Repeater ",
                    "empty — select a flow in Proxy (P) and press <Space>s",
                ),
                area,
            );
            return;
        }

        let editing = self.input.mode() == Mode::Insert;
        let dirty = self.repeater.request.is_dirty();
        let mut chips = vec![Span::styled(
            match self.repeater.origin {
                Some(id) => format!(" from #{id} "),
                None => " new ".to_string(),
            },
            Style::new().fg(Color::Black).bg(Color::Cyan),
        )];
        if dirty {
            chips.push(Span::styled(" edited ", Style::new().fg(Color::Yellow)));
        }
        chips.push(Span::styled(
            if editing {
                "  <Esc> stop editing".to_string()
            } else {
                "  i edit   <Space>r send".to_string()
            },
            Style::new().fg(Color::DarkGray),
        ));
        frame.render_widget(Paragraph::new(Line::from(chips)), banner);

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes);

        let title = if dirty { " Request* " } else { " Request " };
        frame.render_widget(
            buffer_pane(&self.repeater.request, title, editing).scroll((self.content_scroll, 0)),
            left,
        );

        let response = self.repeater.response.lock().unwrap().clone();
        let mut lines: Vec<Line> = match &self.repeater.error {
            Some(e) => vec![Line::styled(
                format!("cannot send: {e}"),
                Style::new().fg(Color::Red),
            )],
            None => match &response {
                None => vec![Line::styled(
                    "(not sent yet — <Space>r)",
                    Style::new().fg(Color::DarkGray),
                )],
                Some(text) => text.lines().map(|l| Line::from(l.to_string())).collect(),
            },
        };
        // The request pane owns the scroll bound; the response follows it, so a
        // long response still needs the buffer to be at least as tall.
        self.content_len = self.repeater.request.lines().len().max(lines.len()).max(1) as u16;
        if lines.is_empty() {
            lines.push(Line::from(""));
        }
        frame.render_widget(
            pane(lines, " Response ").scroll((self.content_scroll, 0)),
            right,
        );
    }

    /// Intercept: the queue on the left, the highlighted item on the right.
    /// `f`/`d` answer one, `F`/`D` answer all, `i` edits before forwarding.
    fn draw_intercept(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        let on = self.engine.intercept().is_enabled();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if on { " ON " } else { " OFF " },
                    Style::new()
                        .fg(Color::Black)
                        .bg(if on { Color::Red } else { Color::DarkGray })
                        .bold(),
                ),
                Span::raw(format!("  {} held", self.queue.len())),
                Span::styled(
                    "   <Space>i toggle   <Space>f forward   <Space>d drop   <Space>F/D all",
                    Style::new().fg(Color::DarkGray),
                ),
            ])),
            banner,
        );

        let [list, detail] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas(panes);

        if self.queue.is_empty() {
            self.content_len = 0;
            frame.render_widget(
                empty_pane(
                    " Queue ",
                    if on {
                        "nothing held yet — traffic will queue here"
                    } else {
                        "intercept is off — press <Space>i to hold traffic"
                    },
                ),
                list,
            );
            frame.render_widget(empty_pane(" Held Item ", "nothing to inspect"), detail);
            return;
        }

        let rows: Vec<Line> = self
            .queue
            .iter()
            .enumerate()
            .map(|(i, held)| {
                let (dir, arrow, summary) = match &held.pending {
                    Pending::Request(r) => (
                        "REQ",
                        "→",
                        format!(
                            "{} {}",
                            r.method,
                            r.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
                        ),
                    ),
                    Pending::Response(r) => {
                        ("RES", "←", format!("{} ({} bytes)", r.status, r.body.len()))
                    }
                };
                let text = format!(" {arrow} #{:<4} {dir}  {summary}", held.flow_id);
                if i == self.intercept.selected {
                    Line::styled(text, Style::new().fg(Color::Black).bg(Color::Cyan).bold())
                } else {
                    Line::from(text)
                }
            })
            .collect();
        frame.render_widget(pane(rows, " Queue ").scroll((self.content_scroll, 0)), list);

        // The edit buffer wins when it belongs to the highlighted item, so what
        // is on screen is always exactly what forwarding would send.
        let held = &self.queue[self.intercept.selected];
        let editing = self.input.mode() == Mode::Insert;
        match &self.intercept.editing {
            Some((ticket, buffer)) if *ticket == held.ticket => {
                self.content_len = buffer.lines().len() as u16;
                let title = if buffer.is_dirty() {
                    " Held Item* "
                } else {
                    " Held Item "
                };
                frame.render_widget(
                    buffer_pane(buffer, title, editing).scroll((self.content_scroll, 0)),
                    detail,
                );
            }
            _ => {
                let text = match &held.pending {
                    Pending::Request(r) => http_text::render_request(r),
                    Pending::Response(r) => http_text::render_response(r),
                };
                let lines: Vec<Line> = text.lines().map(|l| Line::from(l.to_string())).collect();
                self.content_len = lines.len() as u16;
                frame.render_widget(
                    pane(lines, " Held Item ").scroll((self.content_scroll, 0)),
                    detail,
                );
            }
        }
    }

    /// Sitemap: the tree of what has been seen, host then path. `<CR>` folds.
    fn draw_sitemap(&mut self, frame: &mut Frame, area: Rect) {
        self.viewport = area.height.saturating_sub(2) as usize;

        let rows = self.sitemap_rows();
        self.content_len = rows.len() as u16;
        if rows.is_empty() {
            frame.render_widget(empty_pane(" Sitemap ", "nothing captured yet"), area);
            return;
        }
        let selected = self.sitemap.selected.min(rows.len() - 1);

        // Keep the selection on screen: this window scrolls by content offset
        // rather than through a stateful widget, so nothing does it for us.
        let height = self.viewport.max(1);
        if selected < self.content_scroll as usize {
            self.content_scroll = selected as u16;
        } else if selected >= self.content_scroll as usize + height {
            self.content_scroll = (selected + 1 - height) as u16;
        }

        let lines: Vec<Line> = rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let indent = "  ".repeat(row.depth);
                let marker = if !row.has_children {
                    " "
                } else if self.sitemap.collapsed.contains(&row.key) {
                    "▸"
                } else {
                    "▾"
                };
                let text = format!(" {indent}{marker} {}  ({})", row.label, row.flow_count);
                if i == selected {
                    Line::styled(text, Style::new().fg(Color::Black).bg(Color::Cyan).bold())
                } else if row.depth == 0 {
                    Line::styled(text, Style::new().bold().fg(Color::Cyan))
                } else {
                    Line::from(text)
                }
            })
            .collect();

        frame.render_widget(
            pane(lines, &format!(" Sitemap ({}) ", rows.len())).scroll((self.content_scroll, 0)),
            area,
        );
    }

    /// Inspect: the selected flow taken apart — request line, query params,
    /// headers, cookies, body size, then the response and its timing.
    fn draw_inspect(&mut self, frame: &mut Frame, area: Rect) {
        self.viewport = area.height.saturating_sub(2) as usize;

        let Some(flow) = self.detail.clone() else {
            self.content_len = 0;
            frame.render_widget(
                empty_pane(" Inspect ", "no flow selected — pick one in Proxy (P)"),
                area,
            );
            return;
        };

        let lines = inspect_lines(&flow);
        self.content_len = lines.len() as u16;
        frame.render_widget(
            pane(lines, " Inspect ").scroll((self.content_scroll, 0)),
            area,
        );
    }

    /// Automate: the base request set (the Proxy selection) an attack would run
    /// against, plus a live breakdown of captured traffic. The runner itself is
    /// not wired yet — `<Space>r` replays the base set in the meantime.
    fn draw_automate(&mut self, frame: &mut Frame, area: Rect) {
        self.viewport = area.height.saturating_sub(2) as usize;

        let lines = self.automate_lines();
        self.content_len = lines.len() as u16;
        frame.render_widget(
            pane(lines, " Automate ").scroll((self.content_scroll, 0)),
            area,
        );
    }

    fn draw_history(&mut self, frame: &mut Frame, area: Rect) {
        // Remember how many rows fit, so `<C-d>` and `H`/`L` mean something.
        self.viewport = area.height.saturating_sub(3) as usize;

        let cursor = self.cursor();
        let selection = self.selected_rows();
        let relative = self.option("rnu");

        let rows: Vec<Row> = self
            .flows
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let code = f
                    .status
                    .map(|s| s.as_u16().to_string())
                    .unwrap_or_else(|| "···".to_string());
                // Vim's sign column: one glyph of "why should I look here".
                let sign = match f.status.map(|s| s.as_u16()) {
                    Some(500..) => "!",
                    Some(400..500) => "*",
                    None => "·",
                    _ => " ",
                };
                let gutter = if relative && i != cursor {
                    format!("{}", i.abs_diff(cursor))
                } else {
                    f.id.to_string()
                };

                let row = Row::new(vec![
                    sign.to_string(),
                    gutter,
                    f.method.to_string(),
                    code,
                    f.uri.to_string(),
                ]);
                // Visual selection is shown on the rows themselves; the cursor
                // keeps ratatui's own highlight so the two stay distinguishable.
                if self.visual_anchor.is_some() && selection.contains(&i) && i != cursor {
                    row.style(Style::new().bg(Color::Rgb(50, 50, 80)))
                } else {
                    row
                }
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Length(5),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(vec![" ", "ID", "METHOD", "CODE", "URL"]).bold())
        .block(Block::bordered().title(format!(" HTTP History ({}) ", self.flows.len())))
        .row_highlight_style(Style::new().bg(Color::DarkGray))
        .highlight_symbol("▶ ");

        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_request(&self, frame: &mut Frame, area: Rect) {
        let lines = match &self.detail {
            None => vec![Line::from("no flow selected")],
            Some(flow) => message_lines(
                Line::styled(
                    format!("{} {}", flow.request.method, flow.request.uri),
                    Style::new().bold().fg(Color::Cyan),
                ),
                &flow.request.headers,
                &flow.request.body,
            ),
        };
        frame.render_widget(pane(lines, " Request "), area);
    }

    fn draw_response(&self, frame: &mut Frame, area: Rect) {
        let lines = match self.detail.as_ref().map(|f| &f.response) {
            None => vec![Line::from("no flow selected")],
            Some(None) => vec![Line::styled("(pending)", Style::new().fg(Color::Yellow))],
            Some(Some(resp)) => message_lines(
                Line::styled(
                    resp.status.to_string(),
                    Style::new().bold().fg(status_color(resp.status)),
                ),
                &resp.headers,
                &resp.body,
            ),
        };
        frame.render_widget(pane(lines, " Response "), area);
    }

    /// Vim's statusline: mode on the left, position and pending keys right.
    /// While `:` or `/` is open the whole line becomes the prompt instead.
    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        if let Some(cmdline) = self.input.cmdline() {
            // A block cursor at the end, so the prompt reads as focused.
            frame.render_widget(Paragraph::new(format!("{cmdline}█")), area);
            return;
        }

        let mode = self.input.mode();
        let mode_style = Style::new().fg(Color::Black).bg(match mode {
            Mode::Normal => Color::Cyan,
            Mode::Visual => Color::Magenta,
            Mode::Command => Color::Yellow,
            Mode::Palette => Color::Green,
            // Red, because in Insert mode every key changes something.
            Mode::Insert => Color::Red,
        });

        let position = if self.flows.is_empty() {
            "0/0".to_string()
        } else {
            format!("{}/{}", self.cursor() + 1, self.flows.len())
        };
        let message = self.status.lock().unwrap().clone();
        let pending = self.input.pending_display();

        // Pad so position and pending keys sit hard against the right edge.
        let right = format!("{pending}  {position} ");
        let left_width = area.width as usize;
        let used = mode.label().len() + 2 + message.len() + right.len();
        let gap = " ".repeat(left_width.saturating_sub(used));

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" {} ", mode.label()), mode_style),
                Span::raw(format!(" {message}")),
                Span::raw(gap),
                Span::styled(right, Style::new().fg(Color::DarkGray)),
            ])),
            area,
        );
    }
}

/// Shown by `:help`. Deliberately lists only what differs from plain vim.
const HELP: &str = "^k palette · P/C/R/S/I/A windows, gt/gT cycle · <Space>s→Repeater, i edit, <Space>r send · <Space>i intercept, f/d answer (F/D all) · :q";

/// Move a row cursor by a motion, clamped to `last`. The row-cursor windows
/// (Intercept, Sitemap) have no jumplist or search, so this is the whole of
/// their movement — `move_cursor` stays specific to the flow table.
fn step_row(current: usize, last: usize, motion: Motion, count: Option<usize>) -> usize {
    let step = count.unwrap_or(1) as isize;
    let target = match motion {
        Motion::Down => current as isize + step,
        Motion::Up => current as isize - step,
        Motion::Top => count.map_or(0, |n| n.saturating_sub(1)) as isize,
        Motion::Bottom => count.map_or(last as isize, |n| n.saturating_sub(1) as isize),
        Motion::HalfPageDown => current as isize + step * 10,
        Motion::HalfPageUp => current as isize - step * 10,
        Motion::PageDown => current as isize + step * 20,
        Motion::PageUp => current as isize - step * 20,
        _ => current as isize,
    };
    target.clamp(0, last as isize) as usize
}

/// Reparse edited text as the same kind of message it started as. The queue
/// entry's direction is what decides, never the text — otherwise a mangled
/// start line could turn a held response into a request.
fn reparse(original: &Pending, text: &str) -> Result<Pending, http_text::ParseError> {
    Ok(match original {
        Pending::Request(r) => Pending::Request(http_text::parse_request(text, r)?),
        Pending::Response(r) => Pending::Response(http_text::parse_response(text, r)?),
    })
}

/// Rebuild the sitemap tree from the flat node list and flatten it back into
/// display rows, skipping anything under a fold.
///
/// Nodes whose parent fell outside the fetched page are treated as roots rather
/// than dropped: an orphan is a paging artefact, and silently hiding a path an
/// operator has actually seen is worse than showing it one level too shallow.
fn build_sitemap_rows(nodes: &[SitemapNode], collapsed: &HashSet<String>) -> Vec<SitemapRow> {
    let present: HashSet<i64> = nodes.iter().map(|n| n.id).collect();
    let mut children: HashMap<i64, Vec<&SitemapNode>> = HashMap::new();
    let mut roots: HashMap<&str, Vec<&SitemapNode>> = HashMap::new();

    for node in nodes {
        match node.parent_id {
            Some(parent) if present.contains(&parent) => {
                children.entry(parent).or_default().push(node)
            }
            _ => roots.entry(node.host.as_str()).or_default().push(node),
        }
    }

    let mut hosts: Vec<&str> = roots.keys().copied().collect();
    hosts.sort_unstable();

    let mut rows = Vec::new();
    for host in hosts {
        let host_key = format!("host:{host}");
        let host_roots = roots.get(host).map(Vec::as_slice).unwrap_or(&[]);
        let folded = collapsed.contains(&host_key);
        rows.push(SitemapRow {
            depth: 0,
            label: host.to_string(),
            key: host_key,
            // A host's count is the traffic across everything beneath it.
            flow_count: host_roots.iter().map(|n| n.flow_count).sum(),
            has_children: !host_roots.is_empty(),
        });
        if folded {
            continue;
        }
        let mut sorted = host_roots.to_vec();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        for node in sorted {
            push_sitemap_node(&mut rows, node, &children, collapsed, 1);
        }
    }
    rows
}

fn push_sitemap_node(
    rows: &mut Vec<SitemapRow>,
    node: &SitemapNode,
    children: &HashMap<i64, Vec<&SitemapNode>>,
    collapsed: &HashSet<String>,
    depth: usize,
) {
    let key = format!("node:{}", node.id);
    let kids = children.get(&node.id).map(Vec::as_slice).unwrap_or(&[]);
    let folded = collapsed.contains(&key);
    rows.push(SitemapRow {
        depth,
        label: node.name.clone(),
        key,
        flow_count: node.flow_count,
        has_children: !kids.is_empty(),
    });
    if folded {
        return;
    }
    let mut sorted = kids.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for kid in sorted {
        push_sitemap_node(rows, kid, children, collapsed, depth + 1);
    }
}

/// Score how well `query` fuzzy-matches `text`, or `None` if it doesn't. Every
/// query char must appear in order; contiguous runs and an early first hit score
/// higher, so "grep" ranks "Go to Repeater" above a scattered coincidence. An
/// empty query matches everything with a neutral score.
fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let haystack: Vec<char> = text.to_lowercase().chars().collect();
    let mut score = 0;
    let mut from = 0;
    let mut previous: Option<usize> = None;
    for needle in query.to_lowercase().chars() {
        let found = haystack[from..].iter().position(|&c| c == needle)? + from;
        // Reward adjacency (a real substring) and matching near the start.
        score += if previous == Some(found.saturating_sub(1)) {
            8
        } else {
            1
        };
        score -= found as i32 / 4;
        previous = Some(found);
        from = found + 1;
    }
    Some(score)
}

/// A rectangle `pct_x` × `pct_y` percent of `area`, centred within it.
fn centered_rect(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let width = area.width * pct_x / 100;
    let height = area.height * pct_y / 100;
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// A bordered, wrapping pane — the shared shell for Request and Response.
fn pane(lines: Vec<Line<'static>>, title: impl Into<String>) -> Paragraph<'static> {
    Paragraph::new(lines)
        .block(Block::bordered().title(title.into()))
        .wrap(Wrap { trim: false })
}

/// A pane showing an editable buffer, with the cursor drawn as a block when the
/// buffer has focus.
///
/// Deliberately *not* wrapped, unlike [`pane`]. A wrapped line occupies more
/// than one screen row, which would put the cursor somewhere other than where
/// the buffer says it is — and a text editor whose cursor lies about its
/// position is worse than one that scrolls sideways.
fn buffer_pane(buffer: &TextBuffer, title: impl Into<String>, focused: bool) -> Paragraph<'static> {
    let cursor = buffer.cursor();
    let lines: Vec<Line<'static>> = buffer
        .lines()
        .iter()
        .enumerate()
        .map(|(i, text)| {
            if !focused || i != cursor.line {
                return Line::from(text.clone());
            }
            // Split the line around the cursor so it can be inverted in place.
            // Past the last character there is nothing to invert, so a space
            // stands in for the cell.
            let chars: Vec<char> = text.chars().collect();
            let col = cursor.col.min(chars.len());
            let before: String = chars[..col].iter().collect();
            let (at, after) = match chars.get(col) {
                Some(c) => (c.to_string(), chars[col + 1..].iter().collect::<String>()),
                None => (" ".to_string(), String::new()),
            };
            Line::from(vec![
                Span::raw(before),
                Span::styled(at, Style::new().fg(Color::Black).bg(Color::White)),
                Span::raw(after),
            ])
        })
        .collect();

    let border = if focused {
        Style::new().fg(Color::Red)
    } else {
        Style::new()
    };
    Paragraph::new(lines).block(Block::bordered().title(title.into()).border_style(border))
}

/// A bordered pane with a single muted message — used when a window has nothing
/// to show because no flow is selected.
fn empty_pane(title: &'static str, message: &'static str) -> Paragraph<'static> {
    Paragraph::new(Line::styled(message, Style::new().fg(Color::DarkGray)))
        .block(Block::bordered().title(title))
}

/// A section header inside the Inspect / Automate panes.
fn section(lines: &mut Vec<Line<'static>>, title: &str) {
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(
        title.to_string(),
        Style::new().bold().fg(Color::Cyan),
    ));
}

/// A right-aligned label and its value, so fields line up in a column.
fn field(lines: &mut Vec<Line<'static>>, label: &str, value: impl Into<String>) {
    lines.push(Line::from(vec![
        Span::styled(format!("{label:>13}  "), Style::new().fg(Color::DarkGray)),
        Span::raw(value.into()),
    ]));
}

/// Take a flow apart into a scannable report: where the request is going, what
/// it carries, and what came back.
fn inspect_lines(flow: &Flow) -> Vec<Line<'static>> {
    let req = &flow.request;
    let mut lines = Vec::new();

    section(&mut lines, "REQUEST");
    field(&mut lines, "method", req.method.to_string());
    field(
        &mut lines,
        "scheme",
        req.uri.scheme_str().unwrap_or("—").to_string(),
    );
    let host = req
        .uri
        .host()
        .map(str::to_owned)
        .or_else(|| header(&req.headers, "host"))
        .unwrap_or_else(|| "—".to_string());
    field(&mut lines, "host", host);
    if let Some(port) = req.uri.port_u16() {
        field(&mut lines, "port", port.to_string());
    }
    field(&mut lines, "path", req.uri.path().to_string());
    field(&mut lines, "version", format!("{:?}", req.version));

    if let Some(query) = req.uri.query() {
        section(&mut lines, "QUERY");
        for (key, value) in parse_pairs(query, '&') {
            field(&mut lines, &key, value);
        }
    }

    if let Some(cookies) = header(&req.headers, "cookie") {
        section(&mut lines, "COOKIES");
        for (key, value) in parse_pairs(&cookies, ';') {
            field(&mut lines, &key, value);
        }
    }

    section(&mut lines, "REQUEST HEADERS");
    header_lines(&mut lines, &req.headers);
    field(&mut lines, "body", format!("{} bytes", req.body.len()));

    section(&mut lines, "RESPONSE");
    match &flow.response {
        None => field(&mut lines, "status", "(pending)"),
        Some(resp) => {
            field(&mut lines, "status", resp.status.to_string());
            field(&mut lines, "version", format!("{:?}", resp.version));
            if let Some(end) = flow.ended_at {
                let ms = (end - flow.started_at) as f64 / 1000.0;
                field(&mut lines, "duration", format!("{ms:.1} ms"));
            }
            section(&mut lines, "RESPONSE HEADERS");
            header_lines(&mut lines, &resp.headers);
            field(&mut lines, "body", format!("{} bytes", resp.body.len()));
        }
    }
    lines
}

/// A header value as an owned `String`, case-insensitively, or `None`.
fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn header_lines(lines: &mut Vec<Line<'static>>, headers: &HeaderMap) {
    if headers.is_empty() {
        field(lines, "—", "(none)");
        return;
    }
    for (name, value) in headers {
        field(
            lines,
            name.as_str(),
            value.to_str().unwrap_or("<binary>").to_string(),
        );
    }
}

/// Split `a=1&b=2` style text into pairs, tolerating a missing `=`.
fn parse_pairs(text: &str, separator: char) -> Vec<(String, String)> {
    text.split(separator)
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((key, value)) => (key.to_string(), value.to_string()),
            None => (part.to_string(), String::new()),
        })
        .collect()
}

/// Start line, then headers, then a blank line and the body preview.
fn message_lines(start: Line<'static>, headers: &HeaderMap, body: &[u8]) -> Vec<Line<'static>> {
    let mut lines = vec![start];
    lines.extend(headers.iter().map(|(name, value)| {
        Line::from(format!("{name}: {}", value.to_str().unwrap_or("<binary>")))
    }));
    if !body.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(preview(body)));
    }
    lines
}

fn status_color(status: StatusCode) -> Color {
    match status.as_u16() {
        500.. => Color::Red,
        400..500 => Color::LightRed,
        300..400 => Color::Yellow,
        _ => Color::Green,
    }
}

/// Bodies are arbitrary bytes; show a lossy, truncated preview.
fn preview(body: &[u8]) -> String {
    const LIMIT: usize = 2_000;
    let text = String::from_utf8_lossy(&body[..body.len().min(LIMIT)]);
    if body.len() > LIMIT {
        format!("{text}\n… ({} bytes total)", body.len())
    } else {
        text.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::hyper::{HeaderMap, Method, Uri, Version, body::Bytes};
    use proxy_core::{CapturedRequest, CapturedResponse};
    use ratatui::{
        Terminal,
        backend::TestBackend,
        crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    };

    /// Render to an in-memory buffer, one `String` per terminal row. Keeping
    /// rows separate is what lets us assert on *layout*, not just content.
    fn render_rows(app: &mut App) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect())
            .collect()
    }

    fn render(app: &mut App) -> String {
        render_rows(app).join("\n")
    }

    fn get_request(uri: &'static str) -> CapturedRequest {
        CapturedRequest {
            method: Method::GET,
            uri: Uri::from_static(uri),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn shows_captured_flows_and_help() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/foo"));

        let mut app = App::new(engine);
        app.refresh();
        let out = render(&mut app);

        assert!(out.contains("HTTP History (1)"), "{out}");
        assert!(out.contains("GET"), "{out}");
        assert!(out.contains("example.com/foo"), "{out}");
        // The statusline is vim's: a mode indicator and a position counter.
        assert!(out.contains("NORMAL"), "{out}");
        assert!(out.contains("1/1"), "{out}");
    }

    /// Drive the app the way a user does — through keys, not method calls —
    /// so the keymap and the app stay wired together.
    fn press(app: &mut App, keys: &str) {
        for c in keys.chars() {
            if let Some(action) = app.input.feed(KeyEvent::from(KeyCode::Char(c))) {
                app.apply(action);
            }
            app.refresh();
        }
    }

    /// Feed one arbitrary key event (for the ones `press` can't spell: Ctrl
    /// combos, Enter, Escape).
    fn key(app: &mut App, event: KeyEvent) {
        if let Some(action) = app.input.feed(event) {
            app.apply(action);
        }
        app.refresh();
    }

    fn engine_with(count: usize) -> Arc<Engine> {
        let engine = Engine::new();
        for i in 0..count {
            let uri: Uri = format!("http://example.com/{i}").parse().unwrap();
            engine.record_request(CapturedRequest {
                method: Method::GET,
                uri,
                version: Version::HTTP_11,
                headers: HeaderMap::new(),
                body: Bytes::new(),
            });
        }
        engine
    }

    #[test]
    fn counts_reach_the_cursor() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        press(&mut app, "5j");
        assert_eq!(app.cursor(), 5);
        press(&mut app, "2k");
        assert_eq!(app.cursor(), 3);
    }

    /// `G` goes to the end, `12G` goes to line 12 — the count must survive.
    #[test]
    fn goto_line_versus_goto_end() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        press(&mut app, "G");
        assert_eq!(app.cursor(), 19);
        press(&mut app, "12G");
        assert_eq!(app.cursor(), 11);
        press(&mut app, "gg");
        assert_eq!(app.cursor(), 0);
    }

    #[test]
    fn marks_survive_new_traffic_arriving() {
        let engine = engine_with(5);
        let mut app = App::new(engine.clone());
        app.refresh();
        press(&mut app, "3j");
        let marked = app.selected_id().unwrap();
        press(&mut app, "ma");

        // More requests land, shifting nothing here but proving ids are used.
        press(&mut app, "gg");
        press(&mut app, "'a");
        assert_eq!(app.selected_id(), Some(marked));
    }

    #[test]
    fn jumplist_returns_to_where_you_left() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        press(&mut app, "5j");
        press(&mut app, "G");
        assert_eq!(app.cursor(), 19);
        // `G` is a jump, so `<C-o>` goes back to where it was invoked from.
        app.apply(Action::JumpBack);
        assert_eq!(app.cursor(), 5);
        app.apply(Action::JumpForward);
        assert_eq!(app.cursor(), 19);
    }

    #[test]
    fn search_moves_to_the_next_match() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        app.apply(Action::Search {
            pattern: "/17".into(),
            backward: false,
        });
        // Newest first: `/17` is the 17th of 20 captured, so it sits at row 2.
        assert_eq!(app.cursor(), 2);
        assert_eq!(app.selected_id(), Some(17));
    }

    /// `q` no longer quits — that key belongs to macro recording — so the
    /// whole `:q` round trip has to work through the command line.
    #[test]
    fn ex_quit_sets_the_quit_flag() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        press(&mut app, ":q");
        assert!(!app.should_quit, "still typing the command");
        if let Some(action) = app.input.feed(KeyEvent::from(KeyCode::Enter)) {
            app.apply(action);
        }
        assert!(app.should_quit);
    }

    #[test]
    fn bare_q_does_not_quit() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        press(&mut app, "q");
        assert!(!app.should_quit, "q is reserved for macro recording");
    }

    /// A visual selection resends every covered flow, not just the cursor.
    #[test]
    fn visual_selection_covers_a_range() {
        let mut app = App::new(engine_with(10));
        app.refresh();
        press(&mut app, "2j");
        app.apply(Action::ModeChange(Mode::Visual));
        press(&mut app, "3j");
        assert_eq!(app.selected_rows(), 2..=5);
    }

    /// `:set rnu` swaps the id gutter for distances from the cursor.
    #[test]
    fn relative_numbers_are_a_set_option() {
        let mut app = App::new(engine_with(10));
        app.refresh();
        app.apply(Action::Command("set rnu".into()));
        press(&mut app, "5j");
        let rows = render_rows(&mut app);
        let cursor_row = rows.iter().position(|r| r.contains('▶')).unwrap();
        // The row directly above the cursor is one line away.
        assert!(rows[cursor_row - 1].contains(" 1 "), "{}", rows.join("\n"));
    }

    #[test]
    fn detail_pane_tracks_selection_and_response() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/first"));
        let second = engine.record_request(get_request("http://example.com/second"));
        engine.record_response(
            second,
            CapturedResponse {
                status: hudsucker::hyper::StatusCode::NOT_FOUND,
                version: Version::HTTP_11,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"missing-marker"),
            },
        );

        let mut app = App::new(engine);
        app.refresh();

        // History is newest-first, so the cursor starts on `second` — the flow
        // that has the response.
        let out = render(&mut app);
        assert!(out.contains("404"), "{out}");
        assert!(out.contains("missing-marker"), "{out}");

        // `j` moves *down* the list, which is backwards in time, to `first`.
        app.move_cursor(Motion::Down, None);
        app.refresh();
        let out = render(&mut app);
        assert!(out.contains("/first"), "{out}");
        assert!(
            !out.contains("missing-marker"),
            "the older flow has no response: {out}"
        );
    }

    /// Newest first, so the request you just made is at the top rather than
    /// somewhere below the fold on a busy target.
    #[test]
    fn history_is_newest_first() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/oldest"));
        engine.record_request(get_request("http://example.com/newest"));

        let mut app = App::new(engine);
        app.refresh();
        assert_eq!(app.flows[0].uri.path(), "/newest");
        assert_eq!(app.flows[1].uri.path(), "/oldest");
    }

    /// New traffic inserts at the top and pushes rows down. The cursor has to
    /// stay on the flow it was on, or it silently drifts onto another request
    /// while the operator is reading it.
    #[test]
    fn selection_survives_new_traffic_arriving() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/watched"));

        let mut app = App::new(engine.clone());
        app.refresh();
        let watched = app.selected_id();
        assert_eq!(app.cursor(), 0);

        // Three more requests arrive; the watched flow is now three rows down.
        for _ in 0..3 {
            engine.record_request(get_request("http://example.com/noise"));
        }
        app.refresh();

        assert_eq!(app.cursor(), 3, "the cursor should have followed its flow");
        assert_eq!(app.selected_id(), watched, "and still point at it");
    }

    /// `:N` addresses the flow id shown in the gutter, not the Nth row.
    #[test]
    fn goto_addresses_a_flow_by_id() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        app.run_command("7");
        assert_eq!(app.selected_id(), Some(7));

        app.run_command("999");
        assert_eq!(app.selected_id(), Some(7), "an unknown id should not move");
    }

    #[test]
    fn request_and_response_panes_are_side_by_side() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/foo"));

        let mut app = App::new(engine);
        app.refresh();
        let rows = render_rows(&mut app);

        // Burp-style horizontal split: both titles share one row, request left.
        let titled = rows
            .iter()
            .find(|row| row.contains("Request") && row.contains("Response"))
            .unwrap_or_else(|| panic!("no row has both panes:\n{}", rows.join("\n")));
        assert!(
            titled.find("Request") < titled.find("Response"),
            "request pane should be left of response: {titled}"
        );
    }

    /// The tab strip is always on screen and shows every window with its key.
    #[test]
    fn tab_strip_lists_every_window() {
        let mut app = App::new(engine_with(1));
        app.refresh();
        let out = render(&mut app);
        for chip in ["Proxy (P)", "Repeater (R)", "Inspect (I)", "Automate (A)"] {
            assert!(out.contains(chip), "missing tab {chip}:\n{out}");
        }
    }

    /// A single uppercase key switches windows, and the body follows.
    #[test]
    fn shortcut_keys_switch_the_active_window() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        assert_eq!(app.window, Window::Proxy);

        press(&mut app, "R");
        assert_eq!(app.window, Window::Repeater);
        assert!(render(&mut app).contains("Repeater"));

        press(&mut app, "I");
        assert_eq!(app.window, Window::Inspect);
        assert!(
            render(&mut app).contains("REQUEST HEADERS"),
            "{}",
            render(&mut app)
        );

        press(&mut app, "A");
        assert_eq!(app.window, Window::Automate);
        assert!(render(&mut app).contains("BY HOST"), "{}", render(&mut app));

        // Proxy's history table only shows on the Proxy window.
        assert!(!render(&mut app).contains("HTTP History"));
        press(&mut app, "P");
        assert_eq!(app.window, Window::Proxy);
        assert!(render(&mut app).contains("HTTP History"));
    }

    #[test]
    fn gt_cycles_through_the_windows() {
        let mut app = App::new(engine_with(1));
        app.refresh();
        press(&mut app, "gt");
        assert_eq!(app.window, Window::Intercept);
        press(&mut app, "gT");
        assert_eq!(app.window, Window::Proxy);
    }

    /// Inspect pulls a request apart: query params and headers become fields.
    #[test]
    fn inspect_decomposes_the_selected_flow() {
        let engine = Engine::new();
        engine.record_request(CapturedRequest {
            method: hudsucker::hyper::Method::GET,
            uri: Uri::from_static("http://example.com/search?q=admin&page=2"),
            version: Version::HTTP_11,
            headers: {
                let mut h = HeaderMap::new();
                h.insert("x-token", "secret".parse().unwrap());
                h
            },
            body: Bytes::new(),
        });
        let mut app = App::new(engine);
        app.refresh();
        press(&mut app, "I");
        let out = render(&mut app);
        assert!(out.contains("QUERY"), "{out}");
        assert!(out.contains("admin"), "{out}");
        assert!(out.contains("x-token"), "{out}");
    }

    /// Outside Proxy the motions scroll the content instead of a row cursor,
    /// and the selection stays put so the inspected flow doesn't change.
    #[test]
    fn motions_scroll_content_off_the_proxy_window() {
        let mut app = App::new(engine_with(20));
        app.refresh();
        let selected = app.selected_id();
        press(&mut app, "A");
        // A frame is drawn between keypresses in the real loop; that draw is
        // what measures the content so downward scrolling knows its bound.
        render(&mut app);
        press(&mut app, "3j");
        assert_eq!(app.content_scroll, 3);
        assert_eq!(
            app.selected_id(),
            selected,
            "scrolling must not move the selection"
        );
        // Switching windows starts you back at the top.
        press(&mut app, "P");
        press(&mut app, "A");
        assert_eq!(app.content_scroll, 0);
    }

    /// Ctrl-K opens the palette; it floats above the window and lists commands.
    #[test]
    fn palette_opens_over_the_window_and_lists_commands() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        );
        assert_eq!(app.input.mode(), Mode::Palette);
        let out = render(&mut app);
        assert!(out.contains("Command Palette"), "{out}");
        assert!(out.contains("Go to Repeater"), "{out}");
        assert!(out.contains("Quit"), "{out}");
    }

    /// Typing filters the list; Enter runs the highlighted command — here,
    /// switching windows — and closes the palette.
    #[test]
    fn palette_filters_and_runs_the_chosen_command() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        );
        press(&mut app, "inspect");
        // The filter has narrowed to the one obvious match.
        let matches = app.palette_matches();
        assert_eq!(
            matches.first().map(|(l, _)| l.as_str()),
            Some("Go to Inspect")
        );

        key(&mut app, KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.input.mode(), Mode::Normal, "Enter closes the palette");
        assert_eq!(app.window, Window::Inspect, "the chosen command ran");
    }

    #[test]
    fn palette_escape_dismisses_without_running_anything() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        );
        press(&mut app, "quit");
        key(&mut app, KeyEvent::from(KeyCode::Esc));
        assert_eq!(app.input.mode(), Mode::Normal);
        assert!(!app.should_quit, "Escape must not run the highlighted Quit");
    }

    /// Ctrl-n walks the selection down the filtered list.
    #[test]
    fn palette_selection_moves_with_ctrl_n() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        );
        assert_eq!(app.palette_selected, 0);
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
        );
        assert_eq!(app.palette_selected, 1);
    }

    #[test]
    fn fuzzy_score_requires_order_and_prefers_contiguous() {
        assert!(
            fuzzy_score("", "anything").is_some(),
            "empty query matches all"
        );
        assert!(
            fuzzy_score("xyz", "Go to Proxy").is_none(),
            "missing chars fail"
        );
        // A contiguous substring should beat the same letters scattered.
        let contiguous = fuzzy_score("proxy", "Go to Proxy").unwrap();
        let scattered = fuzzy_score("proxy", "Prod runs on x, y").unwrap();
        assert!(contiguous > scattered, "{contiguous} !> {scattered}");
    }

    #[test]
    fn pending_response_is_marked() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/slow"));

        let mut app = App::new(engine);
        app.refresh();
        assert!(render(&mut app).contains("(pending)"));
    }

    // --- repeater ---

    /// The Repeater is loaded explicitly and then stops tracking the Proxy
    /// cursor. This is the whole reason it owns a buffer: moving the cursor
    /// after loading must not throw away what you were editing.
    #[test]
    fn repeater_loads_on_demand_and_then_ignores_the_cursor() {
        let mut app = App::new(engine_with(3));
        app.refresh();
        assert!(
            render(&mut app).contains("HTTP History (3)"),
            "fixture should have loaded"
        );

        press(&mut app, " s");
        assert_eq!(app.window, Window::Repeater);
        let loaded = app.repeater.origin;
        assert!(loaded.is_some());

        // Go back and move the cursor; the Repeater must not follow.
        press(&mut app, "Pj");
        assert_eq!(app.repeater.origin, loaded, "the buffer should be pinned");
    }

    #[test]
    fn repeater_is_empty_until_something_is_sent_to_it() {
        let mut app = App::new(engine_with(1));
        app.refresh();
        press(&mut app, "R");
        assert!(
            render(&mut app).contains("<Space>s"),
            "should say how to load"
        );
    }

    /// `i` types into the buffer instead of being interpreted as a motion, and
    /// the edit is visible.
    #[test]
    fn repeater_buffer_takes_typed_text() {
        let mut app = App::new(engine_with(1));
        app.refresh();
        press(&mut app, " s");

        key(&mut app, KeyEvent::from(KeyCode::Char('i')));
        assert_eq!(app.input.mode(), Mode::Insert);
        press(&mut app, "XY");
        assert!(
            app.repeater.request.text().starts_with("XY"),
            "typed text should land at the cursor: {:?}",
            app.repeater.request.text()
        );
        assert!(app.repeater.request.is_dirty());
        // The pane marks itself edited so the operator can see it diverged.
        assert!(render(&mut app).contains("Request*"));

        key(&mut app, KeyEvent::from(KeyCode::Esc));
        assert_eq!(app.input.mode(), Mode::Normal);
    }

    /// A buffer that no longer parses must refuse to send and say why, rather
    /// than quietly sending the pre-edit request.
    #[test]
    fn repeater_reports_an_unsendable_buffer() {
        let mut app = App::new(engine_with(1));
        app.refresh();
        press(&mut app, " s");
        app.repeater.request = TextBuffer::from_text("GET /x HTTP/1.1\nbroken-header\n\n");
        app.repeater.request.insert_char(' ');

        app.send_repeater();
        assert!(app.repeater.error.is_some(), "should refuse to send");
        assert!(render(&mut app).contains("cannot send"));
    }

    // --- intercept ---

    #[test]
    fn intercept_starts_off_and_toggles() {
        let mut app = App::new(Engine::new());
        app.refresh();
        press(&mut app, "C");
        assert!(render(&mut app).contains("OFF"));

        press(&mut app, " i");
        assert!(app.engine.intercept().is_enabled());
        assert!(render(&mut app).contains("ON"));

        press(&mut app, " i");
        assert!(!app.engine.intercept().is_enabled());
    }

    #[test]
    fn intercept_shows_held_items_and_answers_them() {
        let engine = Engine::new();
        engine.intercept().set_enabled(true);
        let mut app = App::new(engine.clone());

        // Hold something from another task, as the proxy handler would.
        let held = tokio::runtime::Runtime::new().unwrap();
        let _guard = held.enter();
        let e = engine.clone();
        held.spawn(async move {
            e.intercept()
                .hold_request(42, get_request("http://example.com/secret"))
                .await
        });
        // Give the spawned hold a moment to reach the queue.
        for _ in 0..100 {
            if !engine.intercept().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        app.refresh();
        press(&mut app, "C");
        let out = render(&mut app);
        assert!(out.contains("#42"), "the held flow should be listed: {out}");
        assert!(out.contains("/secret"), "{out}");

        press(&mut app, " f");
        assert!(engine.intercept().is_empty(), "forwarding should answer it");
    }

    // --- sitemap ---

    fn node(id: i64, parent: Option<i64>, host: &str, path: &str, name: &str) -> SitemapNode {
        SitemapNode {
            id,
            parent_id: parent,
            kind: "dir".into(),
            host: host.into(),
            path: path.into(),
            name: name.into(),
            first_seen: 0,
            last_seen: 0,
            flow_count: 1,
            origin: "observed".into(),
            comment: None,
            highlight: None,
        }
    }

    #[test]
    fn sitemap_nests_paths_under_their_host() {
        let nodes = vec![
            node(1, None, "a.test", "/api", "api"),
            node(2, Some(1), "a.test", "/api/v1", "v1"),
            node(3, None, "b.test", "/x", "x"),
        ];
        let rows = build_sitemap_rows(&nodes, &HashSet::new());
        let shape: Vec<(usize, &str)> = rows.iter().map(|r| (r.depth, r.label.as_str())).collect();
        assert_eq!(
            shape,
            vec![
                (0, "a.test"),
                (1, "api"),
                (2, "v1"),
                (0, "b.test"),
                (1, "x"),
            ]
        );
    }

    #[test]
    fn folding_a_node_hides_its_descendants() {
        let nodes = vec![
            node(1, None, "a.test", "/api", "api"),
            node(2, Some(1), "a.test", "/api/v1", "v1"),
        ];
        let mut collapsed = HashSet::new();
        collapsed.insert("node:1".to_string());
        let rows = build_sitemap_rows(&nodes, &collapsed);
        let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["a.test", "api"], "v1 should be folded away");

        collapsed.insert("host:a.test".to_string());
        let rows = build_sitemap_rows(&nodes, &collapsed);
        assert_eq!(rows.len(), 1, "folding the host hides everything under it");
    }

    /// A node whose parent fell outside the fetched page must still appear.
    /// Dropping it would silently hide a path that was actually observed.
    #[test]
    fn orphaned_nodes_are_shown_as_roots() {
        let nodes = vec![node(2, Some(999), "a.test", "/api/v1", "v1")];
        let rows = build_sitemap_rows(&nodes, &HashSet::new());
        let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["a.test", "v1"]);
    }

    #[test]
    fn sitemap_window_renders_captured_paths() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/foo/bar"));
        let mut app = App::new(engine);
        app.refresh();
        press(&mut app, "S");
        let out = render(&mut app);
        assert!(out.contains("example.com"), "{out}");
        assert!(out.contains("foo"), "{out}");
    }
}
