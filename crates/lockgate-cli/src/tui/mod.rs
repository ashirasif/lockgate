//! The terminal interface.
//!
//! Everything here hangs off one [`App`], which owns the whole of the screen's
//! state and is driven by a single loop in [`App::run`]. The split across files
//! is by *what a piece of code is for*, not by what type it touches — `App`'s
//! methods live in whichever module matches their job:
//!
//! - [`mod@actions`] — what a keystroke turns into, and the buffer editing behind it
//! - [`mod@commands`] — the per-window commands, the palette, motions, the jumplist
//! - [`mod@draw`] — the frame every window is drawn into, and the Proxy window
//! - [`mod@panels`] — the windows with a pane layout of their own
//! - [`mod@widgets`], [`mod@theme`], [`mod@util`] — the pieces those draws are built from
//!
//! This module keeps the state itself: the view structs, `App` and its fields,
//! the run loop, and [`App::refresh`], which is the one place engine state is
//! read into the screen.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hudsucker::hyper::{HeaderMap, StatusCode};
use lockgate_core::{
    CapturedRequest, Engine, Flow, FlowId, FlowSummary, Held, Pending, Revision, SitemapNode,
    TicketId,
};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{Event, EventStream, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Row, Table, TableState, Wrap},
};

use futures_util::StreamExt;

use crate::command::Command;
use crate::editor::{Cursor, TextBuffer, Yank};
use crate::input::{Action, Column, Input, InsertKey, Mode, Motion, PaletteKey, Scroll, Window};
use crate::vim;
use lockgate_core::http_text;

mod actions;
mod commands;
mod draw;
mod panels;
#[cfg(test)]
mod tests;
mod theme;
mod util;
mod widgets;

use theme::*;
use util::*;
use widgets::*;

/// How long the loop will sit idle before it looks for new traffic.
///
/// Only traffic needs a timer — input wakes the loop on its own. Five times a
/// second is imperceptible for a request appearing in the history, and it is 4x
/// fewer wakeups than the loop used to take just to ask whether a key had
/// arrived.
const IDLE_TICK: Duration = Duration::from_millis(200);

/// One Repeater session: a request you are iterating on, and everything you
/// have sent from it.
///
/// Loaded explicitly with `<Space>s` rather than mirrored from the Proxy cursor.
/// Mirroring is what the Repeater used to do, and it cannot survive editing: the
/// cursor moves on every tick of new traffic, and an edited buffer that a cursor
/// move silently replaced would lose work with no way to get it back.
#[derive(Default)]
struct Session {
    /// The flow this was loaded from, so replays keep their lineage.
    origin: Option<u64>,
    /// The request as editable wire text.
    request: TextBuffer,
    /// What the original looked like, to reparse edits against (for the scheme
    /// and authority that origin-form text cannot carry).
    original: Option<CapturedRequest>,
    /// Why the last send attempt did not leave — a parse error in the buffer.
    error: Option<String>,
    /// Every send from this session, oldest first.
    history: Vec<Exchange>,
    /// Which exchange the response pane is showing. `None` means the newest,
    /// and *stays* newest as sends land — stepping back pins it so a slow
    /// response cannot yank the view off what you were reading.
    viewing: Option<usize>,
}

/// One send: what went out, and what came back.
#[derive(Default)]
struct Exchange {
    /// The request text as sent, so history shows what was actually on the wire
    /// rather than whatever the buffer says now.
    request: String,
    /// Filled by the send task. Shared rather than channelled because a send
    /// runs on its own task so a slow target cannot freeze the UI, and the
    /// draw path only ever reads it.
    result: Arc<Mutex<Option<SendResult>>>,
}

/// What came back, with the two numbers worth knowing at a glance.
struct SendResult {
    /// The rendered response, or the failure in its place.
    text: String,
    /// Body bytes. `None` when the send failed before a response existed.
    bytes: Option<usize>,
    /// Wall-clock for the round trip. Measured here rather than in the engine
    /// because it is a property of this send, not of the flow it recorded.
    millis: u128,
    failed: bool,
}

impl SendResult {
    /// The two numbers Caido puts in the corner: how much came back, and how
    /// long it took.
    fn summary(&self) -> String {
        match self.bytes {
            Some(bytes) => format!("{bytes} B · {}ms", self.millis),
            None => format!("failed · {}ms", self.millis),
        }
    }
}

impl Session {
    /// The exchange the response pane should show.
    fn current(&self) -> Option<&Exchange> {
        match self.viewing {
            Some(i) => self.history.get(i),
            None => self.history.last(),
        }
    }

    /// Position in history as `(nth, total)`, 1-based for display.
    fn position(&self) -> Option<(usize, usize)> {
        let total = self.history.len();
        if total == 0 {
            return None;
        }
        let index = self.viewing.unwrap_or(total - 1);
        Some((index + 1, total))
    }

    /// A short name for the tab: the host being hit, which is the thing that
    /// tells two sessions apart at a glance.
    fn label(&self) -> String {
        self.original
            .as_ref()
            .and_then(|r| r.uri.host().map(str::to_string))
            .unwrap_or_else(|| "empty".to_string())
    }
}

/// How the response pane renders what it is showing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum View {
    /// Exactly the bytes that arrived.
    #[default]
    Raw,
    /// Reformatted for reading. Distinct from `gq`, which *edits* a buffer —
    /// this only changes the view, so a response you are inspecting is never
    /// misrepresented as something you could have sent.
    Pretty,
}

/// The Repeater window: several sessions, one on screen.
struct Repeater {
    sessions: Vec<Session>,
    /// Index into `sessions`. Kept in range by every mutation, so the draw path
    /// can index without checking.
    active: usize,
    /// Whether the buffer has the keys.
    ///
    /// The Repeater is almost all buffer, so it is tempting to leave it always
    /// focused — but the buffer keymap claims `I`, `A`, `P` and `gt`, and a
    /// window you cannot leave is a trap. `<CR>` steps in, `<Esc>` steps out.
    focused: bool,
    view: View,
}

impl Default for Repeater {
    fn default() -> Self {
        // One session always exists, so "the Repeater is empty" is a statement
        // about a session having no request rather than a separate state the
        // whole window can be in.
        Self {
            sessions: vec![Session::default()],
            active: 0,
            focused: false,
            view: View::default(),
        }
    }
}

impl Repeater {
    fn session(&self) -> &Session {
        &self.sessions[self.active]
    }

    fn session_mut(&mut self) -> &mut Session {
        &mut self.sessions[self.active]
    }

    /// Open a new session and switch to it.
    fn open(&mut self) {
        self.sessions.push(Session::default());
        self.active = self.sessions.len() - 1;
    }

    /// Close the active session. The last one is emptied rather than removed,
    /// so there is always somewhere to land.
    fn close(&mut self) {
        if self.sessions.len() == 1 {
            self.sessions[0] = Session::default();
            return;
        }
        self.sessions.remove(self.active);
        self.active = self.active.min(self.sessions.len() - 1);
    }

    fn select(&mut self, index: usize) -> bool {
        if index >= self.sessions.len() {
            return false;
        }
        self.active = index;
        true
    }

    /// Step through history. Returns false at either end, so the caller can say
    /// so rather than silently doing nothing.
    ///
    /// Landing on the newest exchange means *following* the newest — `viewing`
    /// goes back to `None` — rather than pinning to its index. The two look
    /// identical until a send lands, and then only the former shows it.
    fn step_history(&mut self, forward: bool) -> bool {
        let total = self.sessions[self.active].history.len();
        if total == 0 {
            return false;
        }
        let session = &mut self.sessions[self.active];
        let newest = total - 1;
        let current = session.viewing.unwrap_or(newest);

        if !forward {
            if current == 0 {
                return false;
            }
            session.viewing = Some(current - 1);
            return true;
        }

        if current + 1 >= newest {
            // Already following the newest: there is nowhere further forward.
            if session.viewing.is_none() {
                return false;
            }
            session.viewing = None;
            return true;
        }
        session.viewing = Some(current + 1);
        true
    }
}

/// The Intercept window's view state. The queues themselves live on the engine.
///
/// Four panes: the two legs of an exchange side by side, each a queue above its
/// own preview. The legs are answered independently, so each column carries its
/// own cursor and its own edit buffer, and `<C-w>h`/`<C-w>l` choose which one
/// the keys act on.
/// Which half of a column has the keys: the queue, or the preview under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Pane {
    #[default]
    Table,
    Preview,
}

#[derive(Default)]
struct InterceptView {
    focus: Column,
    /// `<CR>` steps down into the preview, Escape steps back up. Movement keys
    /// walk queue rows in `Table` and buffer lines in `Preview`, which is what
    /// makes the preview feel like a buffer rather than a viewport.
    pane: Pane,
    /// Row cursor per column, into that leg's queue as last rendered.
    request_row: usize,
    response_row: usize,
    /// The edit buffer for one held item per column, created on the first `i`
    /// and dropped once that item is answered. Keyed by ticket so a queue that
    /// reorders underneath the operator cannot silently retarget their edits.
    request_edit: Option<(TicketId, TextBuffer)>,
    response_edit: Option<(TicketId, TextBuffer)>,
}

impl InterceptView {
    fn row(&self, requests: bool) -> usize {
        if requests {
            self.request_row
        } else {
            self.response_row
        }
    }

    fn edit(&mut self, requests: bool) -> &mut Option<(TicketId, TextBuffer)> {
        if requests {
            &mut self.request_edit
        } else {
            &mut self.response_edit
        }
    }

    /// The focused column holds requests on the left, responses on the right —
    /// the order traffic actually travels in.
    fn showing_requests(&self) -> bool {
        self.focus == Column::Left
    }
}

/// The Sitemap window's view state.
#[derive(Default)]
struct SitemapView {
    selected: usize,
    /// Folded rows, by the same key `sitemap_rows` assigns. Collapsed rather
    /// than expanded is stored so a newly-seen path shows up unfolded.
    collapsed: HashSet<String>,
}

/// The Scope window's view state. The scopes and rules themselves live in the
/// project database, read fresh each refresh.
///
/// Two panes: the scopes on the left, the highlighted scope's rules on the
/// right. `<C-w>` moves between them, matching Intercept.
#[derive(Default)]
struct ScopeView {
    column: Column,
    scope_row: usize,
    rule_row: usize,
}

/// The Findings window's view state.
///
/// Same shape as `NotesView`, because a finding's write-up is edited the same
/// way a note is: one buffer, focused with `<CR>`, saved on the way out. What
/// differs is what the buffer *is* — four prose columns rendered as one
/// markdown document (`lockgate_core::WriteUp`) and split apart again on save.
#[derive(Default)]
struct FindingsView {
    row: usize,
    /// Whether the write-up pane has the keys.
    focused: bool,
    /// The finding being edited, by id, and its buffer. Keyed by id rather than
    /// by row so a refresh that reorders the list cannot land your typing in a
    /// different finding.
    edit: Option<(i64, TextBuffer)>,
}

/// The Notes window's view state. The notes themselves are read fresh each
/// refresh; this is the cursor and the one buffer being typed into.
#[derive(Default)]
struct NotesView {
    row: usize,
    /// Whether the body pane has the keys. Same shape as the Repeater's
    /// `focused`: with it set the vim grammar takes every keystroke.
    focused: bool,
    /// The note being edited, by id, and its buffer. Keyed by id rather than by
    /// row so a refresh that reorders the list cannot land your typing in a
    /// different note.
    edit: Option<(i64, TextBuffer)>,
}

/// A buffer handed out to the operator's own editor, and where to put it back.
///
/// The edit is deferred rather than done inline because it needs the terminal:
/// the TUI has to release the alternate screen before the editor can draw, and
/// only the run loop owns the terminal handle.
struct EditJob {
    target: EditTarget,
    /// What went out, so an unchanged file can be told from a saved one.
    before: String,
}

enum EditTarget {
    Repeater,
    /// A note, identified by id so the text cannot land on whatever the cursor
    /// moved to while the editor was open.
    Note(i64),
    /// A finding's write-up, by id, for the same reason.
    Finding(i64),
    /// A held item, identified by ticket so the result cannot land on whatever
    /// took its place while the editor was open.
    Held {
        requests: bool,
        ticket: TicketId,
    },
}

impl EditTarget {
    /// The scratch file's extension, so the editor picks a sensible filetype:
    /// wire text is not markdown and highlighting it as such is worse than
    /// nothing.
    fn extension(&self) -> &'static str {
        match self {
            EditTarget::Note(_) | EditTarget::Finding(_) => "md",
            EditTarget::Repeater | EditTarget::Held { .. } => "http",
        }
    }
}

/// One rendered line of the sitemap tree.
struct SitemapRow {
    depth: usize,
    label: String,
    /// Identity for folding: stable across refreshes, unlike a row index.
    key: String,
    flow_count: i64,
    has_children: bool,
    /// The host this row belongs to, carried on every row — scoping from a
    /// path row should mean the same thing as scoping from its host.
    host: String,
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
    /// WebSocket connections, listed in their own window. Parallel to `flows`
    /// so the two histories never mix.
    ws_flows: Vec<FlowSummary>,
    /// Where the connection list is scrolled to. A bare offset rather than a
    /// `TableState`, because `ws_row` is the cursor and the widget is handed a
    /// window — the state has nothing left to remember.
    ws_offset: usize,
    ws_row: usize,
    /// Flow ids removed from *view* — `d` in the Proxy and WebSocket windows.
    ///
    /// Nothing is deleted: the rows stay in the database, the MCP sees them,
    /// and a restart shows them again. Both lists draw from one `flow` table,
    /// so one id set covers the HTTP and WebSocket histories alike, and the
    /// set lives only as long as the session — which is what makes hiding a
    /// safe thing to do to a capture you cannot re-take.
    hidden: HashSet<u64>,
    /// Set when something other than the engine changes what the history
    /// lists should contain — the scope filter or a hide, both applied at
    /// read time rather than being properties of the capture.
    flows_stale: bool,
    /// Which flow `detail` was read for, so a cursor that has not moved does
    /// not pay for the read again.
    detail_id: Option<u64>,
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
    scope: ScopeView,
    /// Findings as of the last refresh, and the Findings window's view state.
    findings: Vec<lockgate_core::Finding>,
    findings_view: FindingsView,
    /// The id of a finding just filed, posted by the writer task and consumed by
    /// the next `refresh` — the same hand-off `created_note` makes, and for the
    /// same reason: the create is spawned, so it cannot touch the app directly.
    created_finding: Arc<Mutex<Option<i64>>>,
    /// Notes as of the last refresh, and the Notes window's view state.
    notes: Vec<lockgate_core::Note>,
    notes_view: NotesView,
    /// The id of a note just created, posted by the writer task and consumed by
    /// the next `refresh`. Shared the way `status` is, and for the same reason:
    /// the create is spawned, so it cannot touch the app directly.
    created_note: Arc<Mutex<Option<i64>>>,
    /// Scopes as of the last refresh, and the highlighted one's rules.
    scopes: Vec<lockgate_core::scope::Scope>,
    scope_rules: Vec<lockgate_core::scope::ScopeRule>,
    /// Whether the active scope actually filters what the other windows list.
    ///
    /// A bypass rather than an edit: narrowing to check whether scope is why
    /// something is missing is routine, and making that mean "retype your
    /// rules afterwards" is how people stop using scope at all.
    scope_filter: bool,
    /// The two intercept queues as of this tick. Snapshotted in `refresh` so
    /// drawing and key handling within one frame agree on what is held —
    /// re-reading the live queue mid-frame could answer a ticket the operator
    /// never saw.
    held_requests: Vec<Held>,
    held_responses: Vec<Held>,

    /// The unnamed register. On the app rather than the buffer so a yank in one
    /// preview can be pasted into another — copying a header from a response
    /// into a request is the whole point.
    yank: Yank,
    /// Memo for syntect-highlighted bodies. `RefCell` because the draw path
    /// only has `&self`, and highlighting is a cache *write* on a miss.
    syntax_cache: crate::highlighter::SharedCache,
    /// Set by `e`, consumed by the run loop once it can free the terminal.
    pending_edit: Option<EditJob>,
    /// Makes each scratch file unique within a session.
    edit_seq: u64,
}

impl App {
    fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            flows: Vec::new(),
            table: TableState::default(),
            ws_flows: Vec::new(),
            ws_offset: 0,
            ws_row: 0,
            hidden: HashSet::new(),
            flows_stale: false,
            detail_id: None,
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
            scope: ScopeView::default(),
            findings: Vec::new(),
            findings_view: FindingsView::default(),
            created_finding: Arc::new(Mutex::new(None)),
            notes: Vec::new(),
            notes_view: NotesView::default(),
            created_note: Arc::new(Mutex::new(None)),
            scopes: Vec::new(),
            scope_rules: Vec::new(),
            scope_filter: true,
            held_requests: Vec::new(),
            held_responses: Vec::new(),
            yank: Yank::default(),
            syntax_cache: crate::highlighter::SharedCache::default(),
            pending_edit: None,
            edit_seq: 0,
        }
    }

    /// The queue for one leg, as snapshotted this tick.
    fn held(&self, requests: bool) -> &[Held] {
        if requests {
            &self.held_requests
        } else {
            &self.held_responses
        }
    }

    fn option(&self, name: &str) -> bool {
        self.options.get(name).copied().unwrap_or(false)
    }

    fn cursor(&self) -> usize {
        self.table.selected().unwrap_or(0)
    }

    async fn run(mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        // The revision the loaded data belongs to. `None` forces the first pass
        // to load, and is how the editor asks for a reload on the way back.
        let mut loaded: Option<Revision> = None;
        // Input is awaited, not polled. The loop used to wake 20 times a second
        // and ask whether a key had arrived, which put 50-100ms between a
        // keystroke and the frame that showed it — the difference between an
        // editor that feels like vim and one that feels like a form.
        let mut events = EventStream::new();

        while !self.should_quit {
            // Read before the reload, not after: a write landing in between then
            // makes the next tick reload again, which is the harmless direction
            // to be wrong in. Reading after could bind fresh data to a revision
            // that already describes newer data, and that staleness would last
            // until something else happened to change.
            let revision = self.engine.revision();
            let engine_changed = loaded != Some(revision);
            if engine_changed || self.flows_stale {
                self.reload_flows();
                self.flows_stale = false;
            }
            loaded = Some(revision);
            self.refresh_view(engine_changed);

            // Drawn unconditionally, and deliberately: the status line and the
            // Repeater's result are filled in by spawned tasks and read straight
            // out of their mutexes here, so they are not covered by the engine
            // revision. Skipping frames would leave "sending…" on screen until
            // something unrelated moved. A frame nothing has changed costs a
            // diff against the last one, which is far below the reload it
            // replaces.
            terminal.draw(|frame| self.draw(frame))?;

            tokio::select! {
                event = events.next() => match event {
                    Some(Ok(event)) => {
                        self.handle_event(event);
                        // A held key or a paste arrives as a burst. Applying the
                        // whole burst before drawing keeps a pasted body from
                        // costing one frame per character.
                        while let Ok(Some(Ok(event))) =
                            tokio::time::timeout(Duration::ZERO, events.next()).await
                        {
                            self.handle_event(event);
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    // stdin is closed: there is no further input to wait for,
                    // and waiting anyway would spin.
                    None => break,
                },
                // Nothing can wake us for a captured request the way a keystroke
                // can, so traffic is found by looking. Five times a second is
                // plenty for that, where input has to be immediate.
                _ = tokio::time::sleep(IDLE_TICK) => {}
            }

            // Handing the terminal to an editor has to happen out here, where
            // the terminal handle lives — and between draws, never during one.
            if let Some(job) = self.pending_edit.take() {
                // The editor takes stdin along with the terminal, so our reader
                // has to let go first or the two of us race for the keys.
                // Crossterm's reader has a wake pipe, so dropping it interrupts
                // the pending read rather than swallowing a keystroke on the way
                // out.
                drop(events);
                self.run_editor(job, terminal).await;
                events = EventStream::new();
                loaded = None;
            }
        }
        Ok(())
    }

    /// Reload everything the screen shows, in one go.
    ///
    /// The loop does not use this — it reloads the two halves on their own
    /// schedules, which is the whole point of them being separate. This is the
    /// way back in for the paths that cannot reason about what changed: the
    /// return from `$EDITOR`, and the tests.
    fn refresh(&mut self) {
        self.reload_flows();
        self.refresh_view(true);
    }

    /// The expensive read: the two history lists, and the cursor pinning that
    /// belongs with them.
    ///
    /// A long capture is tens of thousands of flows, and materialising them all
    /// costs ~20ms — far more than a keystroke can afford. Only two things can
    /// change what this returns: the engine, and the scope filter. Both are
    /// watched by the run loop, so this runs when the answer can have moved and
    /// not otherwise.
    fn reload_flows(&mut self) {
        // History is newest-first, so every captured request inserts at row 0
        // and pushes everything below it down. A selection kept as a row index
        // would slide onto a different flow while the operator is reading it —
        // so remember the flow *id* and put the cursor back on it.
        let pinned = self.selected_id();
        // Scope is a *view* filter, applied at read time — nothing was dropped
        // at capture, so turning it off shows everything again.
        self.flows = if self.scope_filter {
            self.engine.list_flows_in_scope()
        } else {
            self.engine.list_flows()
        };

        self.ws_flows = if self.scope_filter {
            self.engine.list_ws_flows_in_scope()
        } else {
            self.engine.list_ws_flows()
        };
        // Hiding is a view concern like scope: applied after the read, so the
        // engine never learns about it and every hidden row is still on disk.
        if !self.hidden.is_empty() {
            self.flows.retain(|f| !self.hidden.contains(&f.id));
            self.ws_flows.retain(|f| !self.hidden.contains(&f.id));
        }
        self.ws_row = self.ws_row.min(self.ws_flows.len().saturating_sub(1));

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
    }

    /// The small reads — findings, notes, scopes, the intercept queues — and
    /// the detail pane.
    ///
    /// These are tens of rows, not tens of thousands, so they run on every pass
    /// rather than waiting on a revision. That is what keeps the Scope window's
    /// rule list following its own cursor, and an MCP client's writes visible
    /// without a keystroke to shake them loose.
    fn refresh_view(&mut self, engine_changed: bool) {
        self.findings = self.engine.list_findings();
        self.findings_view.row = self
            .findings_view
            .row
            .min(self.findings.len().saturating_sub(1));
        // A finding filed since the last tick: land the cursor on it, now that
        // it is actually in the list. Filing one is usually the prelude to
        // writing it up, so this is where the write-up starts.
        if let Some(id) = self.created_finding.lock().unwrap().take()
            && let Some(row) = self.findings.iter().position(|f| f.id == id)
        {
            self.findings_view.row = row;
            self.findings_view.edit = None;
        }
        // An edit buffer for a finding that is gone — deleted here or from the
        // MCP — has nowhere to save back to, so it goes with it.
        if let Some((id, _)) = &self.findings_view.edit
            && !self.findings.iter().any(|f| f.id == *id)
        {
            self.findings_view.edit = None;
            self.findings_view.focused = false;
        }

        self.notes = self.engine.list_notes();
        self.notes_view.row = self.notes_view.row.min(self.notes.len().saturating_sub(1));
        // A note created since the last tick: land the cursor on it, now that
        // it is actually in the list.
        if let Some(id) = self.created_note.lock().unwrap().take()
            && let Some(row) = self.notes.iter().position(|n| n.id == id)
        {
            self.notes_view.row = row;
            self.notes_view.edit = None;
        }
        // An edit buffer for a note that is gone — deleted here or from the MCP
        // — has nowhere to save back to, so it goes with it.
        if let Some((id, _)) = &self.notes_view.edit
            && !self.notes.iter().any(|n| n.id == *id)
        {
            self.notes_view.edit = None;
            self.notes_view.focused = false;
        }

        self.scopes = self.engine.scopes();
        self.scope.scope_row = self
            .scope
            .scope_row
            .min(self.scopes.len().saturating_sub(1));
        self.scope_rules = match self.scopes.get(self.scope.scope_row) {
            Some(scope) => self.engine.scope_rules(scope.id),
            None => Vec::new(),
        };
        self.scope.rule_row = self
            .scope
            .rule_row
            .min(self.scope_rules.len().saturating_sub(1));

        // The detail pane is a whole flow with its bodies attached, read off
        // disk. It is refetched when the cursor lands on a different flow — or
        // when the engine moved under the one it is already on, which is how a
        // response arriving fills in the pane you are watching.
        let selected = self.selected_id();
        if engine_changed || selected != self.detail_id {
            self.detail = selected.and_then(|id| self.engine.get_flow(id));
            self.detail_id = selected;
        }

        self.sync_buffer_focus();

        self.held_requests = self.engine.intercept().queue_of(true);
        self.held_responses = self.engine.intercept().queue_of(false);
        self.intercept.request_row = self
            .intercept
            .request_row
            .min(self.held_requests.len().saturating_sub(1));
        self.intercept.response_row = self
            .intercept
            .response_row
            .min(self.held_responses.len().saturating_sub(1));

        // An item answered (by us, by a timeout, by a leg being switched off)
        // takes its edit buffer with it, rather than leaving edits that would
        // silently attach to whichever item next takes that ticket's place.
        drop_stale_edit(&mut self.intercept.request_edit, &self.held_requests);
        drop_stale_edit(&mut self.intercept.response_edit, &self.held_responses);
    }

    fn selected_id(&self) -> Option<u64> {
        let i = self.table.selected()?;
        self.flows.get(i).map(|f| f.id)
    }

    // --- input ---

    /// Returns whether anything was acted on, which the run loop takes as a
    /// reason to reload: a keystroke can move the cursor, and the detail pane is
    /// read from the database per selected row.
    /// Apply one terminal event. Anything that is not a key press — a release,
    /// a resize, a mouse report — is not input this interface takes.
    fn handle_event(&mut self, event: Event) {
        if let Event::Key(key) = event
            && key.kind == KeyEventKind::Press
            && let Some(action) = self.input.feed(key)
        {
            self.apply(action);
        }
    }

    fn sync_buffer_focus(&mut self) {
        let editing = match self.window {
            Window::Repeater => self.repeater.focused && self.repeater.session().original.is_some(),
            Window::Intercept => self.intercept.pane == Pane::Preview,
            Window::Notes => self.notes_view.focused && !self.notes.is_empty(),
            Window::Findings => self.findings_view.focused && !self.findings.is_empty(),
            _ => false,
        };
        self.input.set_buffer_focus(editing);
    }
}
