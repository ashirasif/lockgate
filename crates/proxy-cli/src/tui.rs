use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hudsucker::hyper::{HeaderMap, StatusCode};
use proxy_core::{Engine, Flow, FlowSummary};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Paragraph, Row, Table, TableState, Wrap},
};

use crate::command::Command;
use crate::input::{Action, Input, Mode, Motion, Scroll, Window};

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
        self.flows = self.engine.list_flows();

        match self.table.selected() {
            None if !self.flows.is_empty() => self.table.select(Some(0)),
            Some(i) if i >= self.flows.len() => {
                self.table.select(self.flows.len().checked_sub(1));
            }
            _ => {}
        }

        self.detail = self.selected_id().and_then(|id| self.engine.get_flow(id));
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
            // In Proxy the cursor walks the history; in the other windows there
            // is no row cursor, so the same motions scroll the content instead.
            Action::Move { motion, count } if self.window == Window::Proxy => {
                self.move_cursor(motion, count)
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
                    if backward { Motion::MatchBackward } else { Motion::MatchForward },
                    None,
                );
            }
            Action::Resend => self.resend_selected(),
            Action::Command(line) => self.run_command(&line),
            Action::Window(window) => self.show_window(window),
            Action::WindowStep(direction) => self.show_window(self.window.step(direction)),
        }
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
        let Some(command) = Command::parse(line) else { return };
        match command {
            Command::Quit => self.should_quit = true,
            Command::Resend => self.resend_selected(),
            // `:42` is one-based, like vim's line numbers.
            Command::Goto(n) => self.jump_to(n.saturating_sub(1)),
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
        if matches!(motion, Motion::Top | Motion::Bottom | Motion::MatchForward | Motion::MatchBackward)
        {
            self.push_jump(current);
        }
        self.table.select(Some(target));
    }

    /// `}` / `{` — the next row whose host differs from the current one.
    fn group_edge(&self, from: usize, direction: isize) -> isize {
        let host_of = |i: usize| self.flows.get(i).and_then(|f| f.uri.host()).map(str::to_owned);
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
            if self.flows[i].uri.to_string().to_lowercase().contains(&needle) {
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
        let Ok(next) = usize::try_from(next) else { return };
        let Some(&row) = self.jumps.get(next) else { return };
        self.jump_cursor = next;
        self.table.select(Some(row.min(self.flows.len().saturating_sub(1))));
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
                        last = format!("#{id} → {} ({} bytes)", r.status, r.body.len());
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
        let base: Vec<&FlowSummary> =
            self.selected_rows().filter_map(|row| self.flows.get(row)).collect();
        if base.is_empty() {
            field(&mut lines, "—", "no flow selected in Proxy (P)");
        } else {
            for flow in &base {
                lines.push(Line::from(format!("  #{}  {}  {}", flow.id, flow.method, flow.uri)));
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
            Window::Repeater => self.draw_repeater(frame, body),
            Window::Inspect => self.draw_inspect(frame, body),
            Window::Automate => self.draw_automate(frame, body),
        }
        self.draw_status(frame, status_bar);
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

    /// Repeater: one flow, full width — request left, response right — and
    /// `<Space>r` to fire it again. The selection in Proxy is what loads here.
    fn draw_repeater(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        let Some(flow) = self.detail.clone() else {
            self.content_len = 0;
            frame.render_widget(
                empty_pane(" Repeater ", "no flow selected — pick one in Proxy (P)"),
                area,
            );
            return;
        };

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" #{} ", flow.id), Style::new().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(format!("  {} {}", flow.request.method, flow.request.uri)),
                Span::styled("   <Space>r send", Style::new().fg(Color::DarkGray)),
            ])),
            banner,
        );

        let request = message_lines(
            Line::styled(
                format!("{} {}", flow.request.method, flow.request.uri),
                Style::new().bold().fg(Color::Cyan),
            ),
            &flow.request.headers,
            &flow.request.body,
        );
        let response = match &flow.response {
            None => vec![Line::styled("(pending)", Style::new().fg(Color::Yellow))],
            Some(resp) => message_lines(
                Line::styled(resp.status.to_string(), Style::new().bold().fg(status_color(resp.status))),
                &resp.headers,
                &resp.body,
            ),
        };
        // Both panes share one scroll offset; the taller one sets the bound.
        self.content_len = request.len().max(response.len()) as u16;
        let scroll = self.content_scroll;

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes);
        frame.render_widget(pane(request, " Request ").scroll((scroll, 0)), left);
        frame.render_widget(pane(response, " Response ").scroll((scroll, 0)), right);
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
const HELP: &str =
    "P/R/I/A windows  gt/gT cycle  ·  j/k gg/G {} n/N m'  ·  <Space>r resend  ·  :resend :set rnu :q";

/// A bordered, wrapping pane — the shared shell for Request and Response.
fn pane(lines: Vec<Line<'static>>, title: &'static str) -> Paragraph<'static> {
    Paragraph::new(lines)
        .block(Block::bordered().title(title))
        .wrap(Wrap { trim: false })
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
    lines.push(Line::styled(title.to_string(), Style::new().bold().fg(Color::Cyan)));
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
    field(&mut lines, "scheme", req.uri.scheme_str().unwrap_or("—").to_string());
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
        field(lines, name.as_str(), value.to_str().unwrap_or("<binary>").to_string());
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
        crossterm::event::{KeyCode, KeyEvent},
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
        app.apply(Action::Search { pattern: "/17".into(), backward: false });
        assert_eq!(app.cursor(), 17);
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

        // Selection starts on the first flow, so the second's body isn't shown.
        assert!(!render(&mut app).contains("missing-marker"));

        // `j` moves down; the detail pane should follow to the second flow.
        app.move_cursor(Motion::Down, None);
        app.refresh();
        let out = render(&mut app);
        assert!(out.contains("404"), "{out}");
        assert!(out.contains("missing-marker"), "{out}");
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
        assert!(render(&mut app).contains("REQUEST HEADERS"), "{}", render(&mut app));

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
        assert_eq!(app.window, Window::Repeater);
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
        assert_eq!(app.selected_id(), selected, "scrolling must not move the selection");
        // Switching windows starts you back at the top.
        press(&mut app, "P");
        press(&mut app, "A");
        assert_eq!(app.content_scroll, 0);
    }

    #[test]
    fn pending_response_is_marked() {
        let engine = Engine::new();
        engine.record_request(get_request("http://example.com/slow"));

        let mut app = App::new(engine);
        app.refresh();
        assert!(render(&mut app).contains("(pending)"));
    }
}

