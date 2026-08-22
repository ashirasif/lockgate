//! The frame: the window chrome every draw goes through, and the Proxy,
//! WebSocket and Automate windows.

use super::*;

impl App {
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
                muted(),
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
            muted(),
        ));
        lines
    }

    // --- rendering ---

    pub(super) fn draw(&mut self, frame: &mut Frame) {
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
            Window::WebSocket => self.draw_websocket(frame, body),
            Window::Intercept => self.draw_intercept(frame, body),
            Window::Repeater => self.draw_repeater(frame, body),
            Window::Sitemap => self.draw_sitemap(frame, body),
            Window::Scope => self.draw_scope(frame, body),
            Window::Findings => self.draw_findings(frame, body),
            Window::Notes => self.draw_notes(frame, body),
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
    /// The list scrolls to keep the highlight visible. Sizing the box to fit the
    /// whole catalog was the old approach and it does not hold: the catalog
    /// grows, and an entry below the fold is simply unreachable.
    fn draw_palette(&self, frame: &mut Frame) {
        let area = centered_rect(frame.area(), 60, 70);
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
            vec![Line::styled("  no matching command", muted())]
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
        // Scroll so the highlight is always on screen, keeping it as far up the
        // list as it can be — the highlight only leaves the top once you have
        // paged past what fits.
        let visible = list.height.saturating_sub(2).max(1) as usize;
        let scroll = self.palette_selected.saturating_sub(visible - 1) as u16;
        frame.render_widget(
            Paragraph::new(rows)
                .block(Block::bordered())
                .scroll((scroll, 0)),
            list,
        );
    }

    /// Mason's tool strip: each window a chip, `Name (key)`, active one lit.
    fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        // No separator span: nine windows have to share one line, and each chip
        // already carries its own padding. Full names when they fit, abbreviated
        // when they do not — a narrow terminal loses letters, never chips.
        let compact = Window::strip_width(false) > area.width;
        let mut spans = Vec::new();
        for window in Window::ALL {
            let label = if compact {
                window.tab_label()
            } else {
                window.label()
            };
            let chip = format!(" {} ({}) ", label, window.key());
            let style = if window == self.window {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else {
                Style::new().fg(Color::Gray)
            };
            spans.push(Span::styled(chip, style));
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
        let visual = self.visual_anchor.is_some();

        let window = visible_window(self.table.offset(), cursor, self.flows.len(), self.viewport);
        // The widget is handed a slice, so the state it scrolls is the slice's.
        // `H` / `M` / `L` read `offset()` as an index into the whole capture,
        // though, so the real offset goes back into `self.table` — which stays
        // the one place the absolute cursor and offset live.
        *self.table.offset_mut() = window.start;

        let rows: Vec<Row> = self.flows[window.clone()]
            .iter()
            .enumerate()
            .map(|(row, f)| {
                let i = window.start + row;
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
                    clock_time(f.started_at),
                    f.method.to_string(),
                    code,
                    f.uri.to_string(),
                ]);
                // Visual selection is shown on the rows themselves; the cursor
                // keeps ratatui's own highlight so the two stay distinguishable.
                if visual && selection.contains(&i) && i != cursor {
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
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(5),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(vec![" ", "ID", "TIME", "METHOD", "CODE", "URL"]).bold())
        .block(Block::bordered().title(format!(" HTTP History ({}) ", self.flows.len())))
        .row_highlight_style(Style::new().bg(INACTIVE_BG))
        .highlight_symbol("▶ ");

        // Window-relative: the slice starts at the top of the screen, and the
        // cursor sits wherever it falls inside it. An empty capture selects
        // nothing, which is also what keeps the highlight column from appearing.
        let mut view =
            TableState::new().with_selected(self.flows.get(cursor).map(|_| cursor - window.start));
        frame.render_stateful_widget(table, area, &mut view);
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

    /// One flow's frames, oldest first, rendered as a transcript.
    ///
    /// Shared by the WebSocket window's frame pane. The most recent
    /// [`WS_FRAME_CAP`] are kept: a chatty socket carries thousands, and reading
    /// them all every tick would be the one thing that makes this window slow.
    fn ws_frame_lines(&self, flow_id: FlowId) -> Vec<Line<'static>> {
        let all = self.engine.ws_messages(flow_id);
        let total = all.len();
        let start = total.saturating_sub(WS_FRAME_CAP);

        let mut lines = Vec::new();
        if start > 0 {
            lines.push(Line::styled(format!("… {start} earlier frame(s)"), muted()));
        }
        lines.extend(all[start..].iter().map(|m| {
            // Arrows rather than the stored "c2s"/"s2c": direction is the thing
            // you scan for, and a glyph reads faster.
            let (arrow, style) = match m.direction.as_str() {
                "c2s" => ("▶ ", Style::new().fg(Color::Cyan)),
                _ => ("◀ ", Style::new().fg(Color::Green)),
            };
            let text = match m.opcode.as_str() {
                "text" => String::from_utf8_lossy(&m.payload).to_string(),
                "close" => "(close)".to_string(),
                other => format!("({other}, {} bytes)", m.payload.len()),
            };
            Line::from(vec![
                Span::styled(arrow, style),
                Span::raw(text.replace('\n', " ")),
            ])
        }));
        lines
    }

    /// The WebSocket window: connections on top, the selected one's handshake
    /// and frame transcript below. A mirror of Proxy's layout, for the traffic
    /// Proxy deliberately no longer shows.
    fn draw_websocket(&mut self, frame: &mut Frame, area: Rect) {
        let [history, detail] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
        let [handshake, frames] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(detail);

        self.viewport = history.height.saturating_sub(3) as usize;

        if self.ws_flows.is_empty() {
            frame.render_widget(
                empty_pane(
                    " WebSocket ",
                    "no WebSocket connections yet — they appear here when a page opens one",
                ),
                history,
            );
            frame.render_widget(empty_pane(" Handshake ", ""), handshake);
            frame.render_widget(empty_pane(" Frames ", ""), frames);
            self.content_len = 0;
            return;
        }

        let row = self.ws_row.min(self.ws_flows.len() - 1);

        // --- connections ---
        // Windowed for the same reason the HTTP history is; see `visible_window`.
        let window = visible_window(self.ws_offset, row, self.ws_flows.len(), self.viewport);
        self.ws_offset = window.start;

        let rows: Vec<Row> = self.ws_flows[window.clone()]
            .iter()
            .map(|f| {
                Row::new(vec![
                    "⇅".to_string(),
                    f.id.to_string(),
                    clock_time(f.started_at),
                    f.uri.to_string(),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(vec![" ", "ID", "TIME", "URL"]).bold())
        .block(Block::bordered().title(format!(" WebSocket ({}) ", self.ws_flows.len())))
        .row_highlight_style(Style::new().bg(INACTIVE_BG))
        .highlight_symbol("▶ ");
        let mut view = TableState::new().with_selected(Some(row - window.start));
        frame.render_stateful_widget(table, history, &mut view);

        // --- detail ---
        let flow_id = self.ws_flows[row].id;
        let handshake_lines = match self.engine.get_flow(flow_id) {
            Some(flow) => message_lines(
                Line::styled(
                    format!("{} {}", flow.request.method, flow.request.uri),
                    Style::new().bold().fg(Color::Cyan),
                ),
                &flow.request.headers,
                &flow.request.body,
            ),
            None => vec![Line::styled("(gone)", muted())],
        };
        frame.render_widget(pane(handshake_lines, " Handshake "), handshake);

        let frame_lines = self.ws_frame_lines(flow_id);
        let title = format!(" Frames ({}) ", frame_lines.len());
        self.content_len = frame_lines.len() as u16;
        frame.render_widget(
            pane(frame_lines, title).scroll((self.content_scroll, 0)),
            frames,
        );
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
                Span::styled(right, muted()),
            ])),
            area,
        );
    }
}
