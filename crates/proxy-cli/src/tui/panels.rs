//! The windows with a pane layout of their own: Repeater, Intercept, Scope,
//! Notes, Findings, Sitemap.

use super::*;

impl App {
    /// Repeater: an editable request on the left, the response it produced on
    /// the right. `i` edits, Escape leaves, `<Space>r` sends what is in the
    /// buffer. Loaded explicitly with `<Space>s` from Proxy.
    pub(super) fn draw_repeater(&mut self, frame: &mut Frame, area: Rect) {
        let [tabs, banner, panes] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        self.draw_repeater_tabs(frame, tabs);

        if self.repeater.session().original.is_none() {
            self.content_len = 0;
            frame.render_widget(
                empty_pane(
                    " Repeater ",
                    "empty — select a flow in Proxy (P) and press <Space>s",
                ),
                panes,
            );
            frame.render_widget(
                Paragraph::new(Line::styled(
                    "  n new tab   x close   gs / {count}gs switch",
                    muted(),
                )),
                banner,
            );
            return;
        }

        let inserting = self.input.mode() == Mode::Insert;
        let editing = self.repeater.focused;
        let dirty = self.repeater.session().request.is_dirty();

        self.draw_repeater_status(frame, banner, editing, dirty);

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes);

        // Pinned to an older exchange, the request pane shows what was *sent*
        // then, not what the buffer says now. Showing the live buffer beside an
        // old response would pair a request with a reply it never produced.
        let pinned = self
            .repeater
            .session()
            .viewing
            .and_then(|i| self.repeater.session().history.get(i))
            .map(|e| e.request.clone());

        // Built only when pinned, so the live path borrows the real buffer
        // rather than copying it on every frame.
        let pinned_buffer = pinned.as_deref().map(TextBuffer::from_text);
        let (title, buffer, focused) = match &pinned_buffer {
            Some(buffer) => (" Request (sent) ".to_string(), buffer, false),
            None => (
                if dirty { " Request* " } else { " Request " }.to_string(),
                &self.repeater.session().request,
                editing,
            ),
        };
        let border = if focused {
            Style::new().fg(Color::Cyan)
        } else {
            muted()
        };
        BufferView {
            buffer,
            cache: Some(&self.syntax_cache),
            title,
            focused,
            inserting,
            border,
            scroll: self.content_scroll,
        }
        .render(frame, left);

        self.draw_repeater_response(frame, right);
    }

    /// The tab strip. One entry per session, labelled by the host it targets,
    /// because that is what tells two sessions apart at a glance.
    fn draw_repeater_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut spans = Vec::new();
        for (i, session) in self.repeater.sessions.iter().enumerate() {
            let active = i == self.repeater.active;
            let unsent = session.original.is_some() && session.history.is_empty();
            let style = if active {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else {
                muted()
            };
            // The number is the key that selects it, so it is never cosmetic.
            spans.push(Span::styled(
                format!(
                    " {} {}{} ",
                    i + 1,
                    session.label(),
                    if unsent { "*" } else { "" }
                ),
                style,
            ));
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled("n +", muted()));
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// Origin, history position, and the two numbers worth knowing about the
    /// response on screen.
    fn draw_repeater_status(&self, frame: &mut Frame, area: Rect, editing: bool, dirty: bool) {
        let session = self.repeater.session();
        let mut chips = vec![Span::styled(
            match session.origin {
                Some(id) => format!(" from #{id} "),
                None => " new ".to_string(),
            },
            Style::new().fg(Color::Black).bg(Color::Cyan),
        )];
        if dirty {
            chips.push(Span::styled(" edited ", Style::new().fg(Color::Yellow)));
        }

        if let Some((nth, total)) = session.position() {
            // Pinned to an older exchange is worth flagging: the response on
            // screen is then not the one the buffer would produce.
            let pinned = session.viewing.is_some();
            chips.push(Span::styled(
                format!(" {nth}/{total} "),
                if pinned {
                    Style::new().fg(Color::Yellow)
                } else {
                    muted()
                },
            ));
        }

        // Read under the lock and copy out: `take` would empty the slot and the
        // response would vanish after one frame.
        if let Some(result) = session
            .current()
            .and_then(|e| e.result.lock().unwrap().as_ref().map(SendResult::summary))
        {
            chips.push(Span::styled(format!(" {result} "), muted()));
        }

        chips.push(Span::styled(
            match self.repeater.view {
                View::Pretty => " Pretty ",
                View::Raw => " Raw ",
            },
            Style::new().fg(Color::Cyan),
        ));

        chips.push(Span::styled(
            if editing {
                "  vim keys   <Esc> leave".to_string()
            } else {
                "  <CR> edit  gq format  gs tab  p view  [ ] history  <Space>r send".to_string()
            },
            muted(),
        ));
        frame.render_widget(Paragraph::new(Line::from(chips)), area);
    }

    /// The response pane, showing whichever exchange history is pointed at.
    fn draw_repeater_response(&mut self, frame: &mut Frame, area: Rect) {
        let session = self.repeater.session();
        let pretty = self.repeater.view == View::Pretty;

        // A real response gets the buffer treatment — numbers, syntax, sideways
        // scroll. A placeholder is one styled line and would look absurd with a
        // gutter beside it.
        let body: Result<String, Line<'static>> = match &session.error {
            Some(e) => Err(Line::styled(
                format!("cannot send: {e}"),
                Style::new().fg(Color::Red),
            )),
            None => match session.current() {
                None => Err(Line::styled("(not sent yet — <Space>r)", muted())),
                Some(exchange) => {
                    let held = exchange.result.lock().unwrap();
                    match held.as_ref() {
                        None => Err(Line::styled("(in flight…)", Style::new().fg(Color::Yellow))),
                        Some(result) if result.failed => Err(Line::styled(
                            result.text.clone(),
                            Style::new().fg(Color::Red),
                        )),
                        // Pretty is a *view*: the reformat is rebuilt every
                        // frame and never touches what was received, so a
                        // response is never misrepresented as something you
                        // could have sent. A body that will not reformat shows
                        // as it arrived rather than as an error.
                        Some(result) if pretty => {
                            Ok(proxy_core::pretty::pretty_message(&result.text)
                                .map(|(text, _)| text)
                                .unwrap_or_else(|_| result.text.clone()))
                        }
                        Some(result) => Ok(result.text.clone()),
                    }
                }
            },
        };

        let request_lines = self.repeater.session().request.lines().len();
        match body {
            Err(message) => {
                self.content_len = request_lines.max(1) as u16;
                frame.render_widget(
                    pane(vec![message], " Response ").scroll((self.content_scroll, 0)),
                    area,
                );
            }
            Ok(text) => {
                // The request pane owns the scroll bound; the response follows
                // it, so a long response still needs the buffer to be at least
                // as tall.
                let buffer = TextBuffer::from_text(&text);
                self.content_len = request_lines.max(buffer.lines().len()).max(1) as u16;
                BufferView {
                    buffer: &buffer,
                    cache: Some(&self.syntax_cache),
                    title: " Response ".to_string(),
                    focused: false,
                    inserting: false,
                    border: muted(),
                    scroll: self.content_scroll,
                }
                .render(frame, area);
            }
        }
    }

    /// Intercept: four panes. The two legs of an exchange side by side, each a
    /// queue above a preview of its highlighted item.
    ///
    /// Requests sit left and responses right — the order traffic travels. Both
    /// previews are editable, so what is on screen is exactly what forwarding
    /// would send.
    pub(super) fn draw_intercept(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);

        let intercept = self.engine.intercept();
        let (on, legs) = (
            intercept.is_enabled(),
            [intercept.holds_requests(), intercept.holds_responses()],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if on { " HOLDING " } else { " OFF " },
                    Style::new()
                        .fg(Color::Black)
                        .bg(if on { Color::Red } else { INACTIVE_BG })
                        .bold(),
                ),
                Span::styled(
                    format!("  [{}] requests", if legs[0] { "x" } else { " " }),
                    leg_style(legs[0]),
                ),
                Span::styled(
                    format!("  [{}] responses", if legs[1] { "x" } else { " " }),
                    leg_style(legs[1]),
                ),
                Span::styled(
                    if self.intercept.pane == Pane::Preview {
                        "   vim: w/W b/B f{c} v/V ciw di\" 2dd  yy→clipboard  u   <Esc> back"
                    } else {
                        "   <CR> open  ^g $EDITOR  gq format  f forward  d drop  F/D all  ^w pane"
                    },
                    muted(),
                ),
            ])),
            banner,
        );

        // Two columns, each split into a queue over its preview — the shape in
        // the reference UI, and the shape the two independent legs call for.
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes);
        let [req_list, req_view] =
            Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(left);
        let [res_list, res_view] =
            Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(right);

        // The focused queue is what `j`/`k` walks, so it sets the page size.
        self.viewport = req_list.height.saturating_sub(2) as usize;

        self.draw_intercept_column(frame, true, req_list, req_view, on);
        self.draw_intercept_column(frame, false, res_list, res_view, on);
    }

    /// One leg of the Intercept window: its queue, and a preview of the
    /// highlighted item beneath it.
    fn draw_intercept_column(
        &mut self,
        frame: &mut Frame,
        requests: bool,
        list_area: Rect,
        view_area: Rect,
        on: bool,
    ) {
        let focused = self.intercept.showing_requests() == requests;
        let (noun, plural) = if requests {
            ("request", "requests")
        } else {
            ("response", "responses")
        };
        let leg_on = if requests {
            self.engine.intercept().holds_requests()
        } else {
            self.engine.intercept().holds_responses()
        };

        let held = self.held(requests).to_vec();
        let row = self
            .intercept
            .row(requests)
            .min(held.len().saturating_sub(1));

        // Exactly one of the four panes has the keys, and its border says so.
        // Lighting the whole column would leave it ambiguous whether `j` walks
        // the queue or the buffer.
        let active = |pane: Pane| focused && self.intercept.pane == pane;
        let border_for = |pane: Pane| {
            if active(pane) {
                Style::new().fg(Color::Cyan)
            } else {
                muted()
            }
        };
        let border = border_for(Pane::Table);
        let title = format!(" Queued {plural} ({}) ", held.len());

        if held.is_empty() {
            let why = if !on {
                format!("intercept is off — <Space>i to queue {plural}")
            } else if !leg_on {
                format!(
                    "{plural} are not being held — <Space>{} to hold them",
                    if requests { "1" } else { "2" }
                )
            } else {
                format!("no {plural} queued")
            };
            frame.render_widget(
                Paragraph::new(Line::styled(why, muted()))
                    .block(Block::bordered().title(title).border_style(border)),
                list_area,
            );
            frame.render_widget(
                Paragraph::new(Line::styled(
                    format!("select a {noun} to view it here"),
                    muted(),
                ))
                .block(
                    Block::bordered()
                        .title(format!(" {} ", capitalize(noun)))
                        .border_style(border_for(Pane::Preview)),
                ),
                view_area,
            );
            return;
        }

        let rows: Vec<Line> = held
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let summary = match &item.pending {
                    Pending::Request(r) => format!(
                        "{:<6} {}",
                        r.method.as_str(),
                        r.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
                    ),
                    Pending::Response(r) => {
                        format!("{:<6} {} bytes", r.status.as_u16(), r.body.len())
                    }
                };
                let text = format!(" #{:<5} {summary}", item.flow_id);
                if i == row {
                    // Fully lit only while the queue has the keys. Stepping into
                    // the preview dims it to a marker: still showing which item
                    // you are looking at, no longer claiming `j` will move it.
                    let style = if active(Pane::Table) {
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                    } else {
                        Style::new().bg(INACTIVE_BG)
                    };
                    Line::styled(text, style)
                } else {
                    Line::from(text)
                }
            })
            .collect();

        // Keep the cursor on screen; this pane scrolls by offset, so nothing
        // does it for us.
        let visible = list_area.height.saturating_sub(2).max(1) as usize;
        let scroll = row.saturating_sub(visible.saturating_sub(1)) as u16;
        frame.render_widget(
            Paragraph::new(rows)
                .block(Block::bordered().title(title).border_style(border))
                .scroll((scroll, 0)),
            list_area,
        );

        // The buffer wins when it belongs to the highlighted item.
        let item = &held[row];
        let in_preview = active(Pane::Preview);
        let inserting = in_preview && self.input.mode() == Mode::Insert;
        let view_border = border_for(Pane::Preview);
        let view_scroll = if focused { self.content_scroll } else { 0 };

        match self.intercept.edit(requests) {
            Some((ticket, buffer)) if *ticket == item.ticket => {
                let title = format!(
                    " {}{}{} ",
                    capitalize(noun),
                    if buffer.is_dirty() { "*" } else { "" },
                    ""
                );
                // Show the cursor whenever the preview has the keys, not only
                // while inserting — that is what makes it navigable rather than
                // a block of text that happens to scroll.
                if focused {
                    self.content_len = buffer.lines().len() as u16;
                }
                BufferView {
                    buffer,
                    cache: Some(&self.syntax_cache),
                    title,
                    focused: in_preview,
                    inserting,
                    border: view_border,
                    scroll: view_scroll,
                }
                .render(frame, view_area);
            }
            _ => {
                let text = render_pending(&item.pending);
                let lines: Vec<Line> = crate::syntax::highlighted_lines(&text);
                if focused {
                    self.content_len = lines.len() as u16;
                }
                frame.render_widget(
                    Paragraph::new(lines)
                        .block(
                            Block::bordered()
                                .title(format!(" {} ", capitalize(noun)))
                                .border_style(view_border),
                        )
                        .wrap(Wrap { trim: false })
                        .scroll((view_scroll, 0)),
                    view_area,
                );
            }
        }
    }

    /// Scope: the named scopes on the left, the highlighted one's rules on the
    /// right.
    ///
    /// Only one scope is active at a time, and it is the active one that filters
    /// the other windows — so which is active has to be visible at a glance,
    /// not inferred from a highlight that also means "the cursor is here".
    pub(super) fn draw_scope(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        let active = self.scopes.iter().find(|s| s.is_active);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if self.scope_filter { " FILTERING " } else { " BYPASSED " },
                    Style::new()
                        .fg(Color::Black)
                        .bg(if self.scope_filter { Color::Cyan } else { INACTIVE_BG }),
                ),
                Span::styled(
                    match active {
                        Some(scope) => format!("  {}  ", scope.name),
                        None => "  no active scope — everything is in scope  ".to_string(),
                    },
                    Style::new().fg(Color::Cyan),
                ),
                Span::styled(
                    "n new  a include  x exclude  d delete  <CR> activate/toggle  ^w pane  <Space>c bypass",
                    muted(),
                ),
            ])),
            banner,
        );

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas(panes);

        let on_scopes = self.scope.column == Column::Left;
        let border_for = |mine: bool| {
            if mine {
                Style::new().fg(Color::Cyan)
            } else {
                muted()
            }
        };

        // --- scopes ---
        let rows: Vec<Line> = if self.scopes.is_empty() {
            vec![Line::styled("no scopes — n to create one", muted())]
        } else {
            self.scopes
                .iter()
                .enumerate()
                .map(|(i, scope)| {
                    // The dot is the answer to "which one is filtering?"; the
                    // highlight only says where the cursor is.
                    let marker = if scope.is_active { "●" } else { "○" };
                    let text = format!(" {marker} {} ", scope.name);
                    if i == self.scope.scope_row {
                        Line::styled(
                            text,
                            if on_scopes {
                                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                            } else {
                                Style::new().bg(INACTIVE_BG)
                            },
                        )
                    } else if scope.is_active {
                        Line::styled(text, Style::new().fg(Color::Cyan))
                    } else {
                        Line::from(text)
                    }
                })
                .collect()
        };
        frame.render_widget(
            Paragraph::new(rows).block(
                Block::bordered()
                    .title(format!(" Scopes ({}) ", self.scopes.len()))
                    .border_style(border_for(on_scopes)),
            ),
            left,
        );

        // --- rules ---
        let rows: Vec<Line> = if self.scope_rules.is_empty() {
            vec![Line::styled(
                "no rules — everything is in scope (a to include)",
                muted(),
            )]
        } else {
            self.scope_rules
                .iter()
                .enumerate()
                .map(|(i, rule)| {
                    let selected = i == self.scope.rule_row && !on_scopes;
                    let mut spans = vec![
                        // Include and exclude read as opposites at a glance;
                        // excludes always win, so they need to stand out.
                        Span::styled(
                            match rule.action {
                                proxy_core::scope::Action::Include => " + ",
                                proxy_core::scope::Action::Exclude => " − ",
                            },
                            match rule.action {
                                proxy_core::scope::Action::Include => Style::new().fg(Color::Green),
                                proxy_core::scope::Action::Exclude => Style::new().fg(Color::Red),
                            },
                        ),
                        Span::styled(format!("{:<6}", kind_label(rule)), muted()),
                        Span::raw(rule_pattern(rule)),
                    ];
                    if !rule.enabled {
                        spans.push(Span::styled("  (off)", muted()));
                    }
                    let mut line = Line::from(spans);
                    if selected {
                        line = line.style(Style::new().bg(INACTIVE_BG));
                    } else if i == self.scope.rule_row {
                        line = line.style(Style::new().bg(INACTIVE_BG).add_modifier(Modifier::DIM));
                    }
                    line
                })
                .collect()
        };
        let title = match self.scopes.get(self.scope.scope_row) {
            Some(scope) => format!(" Rules — {} ", scope.name),
            None => " Rules ".to_string(),
        };
        frame.render_widget(
            Paragraph::new(rows).block(
                Block::bordered()
                    .title(title)
                    .border_style(border_for(!on_scopes)),
            ),
            right,
        );

        self.content_len = self.scopes.len().max(self.scope_rules.len()) as u16;
    }

    /// Notes: the titles on the left, the highlighted note's body on the right,
    /// editable in place.
    ///
    /// The body is a real buffer rather than rendered text, because a note is
    /// something you write, not something you read back — Findings can afford a
    /// read-only detail pane, this cannot.
    pub(super) fn draw_notes(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        let focused = self.notes_view.focused && !self.notes.is_empty();
        frame.render_widget(
            Paragraph::new(Line::styled(
                if focused {
                    "  vim keys   ^g $EDITOR   gq format   <Esc> save and leave"
                } else {
                    "  <CR> edit   n new   r retitle   d delete"
                },
                muted(),
            )),
            banner,
        );

        if self.notes.is_empty() {
            frame.render_widget(
                empty_pane(" Notes ", "nothing written yet — :note <title> starts one"),
                panes,
            );
            self.content_len = 0;
            return;
        }

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
                .areas(panes);

        let selected = self.notes_view.row;
        let rows: Vec<Line> = self
            .notes
            .iter()
            .enumerate()
            .map(|(i, note)| {
                let line = Line::from(vec![
                    Span::styled(format!(" {:>4} ", format!("#{}", note.id)), muted()),
                    Span::raw(note.title.clone()),
                ]);
                if i == selected {
                    line.style(Style::new().bg(INACTIVE_BG))
                } else {
                    line
                }
            })
            .collect();

        frame.render_widget(
            Paragraph::new(rows).block(
                Block::bordered()
                    .title(format!(" Notes ({}) ", self.notes.len()))
                    // The lit border follows the keys, so it is on the list
                    // exactly while the list is what the keys move.
                    .border_style(if focused {
                        Style::new().fg(Color::DarkGray)
                    } else {
                        Style::new().fg(Color::Cyan)
                    }),
            ),
            left,
        );

        let inserting = self.input.mode() == Mode::Insert;
        let scroll = self.content_scroll;
        let title = self
            .notes
            .get(selected)
            .map(|n| n.title.clone())
            .unwrap_or_default();
        // Borrowed after everything that needs `&self` above, since the buffer
        // comes out of the same struct mutably.
        let Some(buffer) = self.note_buffer() else {
            return;
        };
        let dirty = buffer.is_dirty();
        let lines = buffer.lines().len() as u16;

        BufferView {
            buffer,
            // Markdown, not an HTTP message: the HTTP highlighter would light
            // up prose as though it were headers.
            cache: None,
            title: format!(" {}{} ", title, if dirty { " *" } else { "" }),
            focused,
            inserting,
            border: if focused {
                Style::new().fg(Color::Cyan)
            } else {
                Style::new().fg(Color::DarkGray)
            },
            scroll,
        }
        .render(frame, right);
        self.content_len = lines;
    }

    /// Findings: the list on the left, the highlighted one in full on the right.
    ///
    /// Severity and status are the two things that move during triage, so they
    /// are the two things a single key changes. The write-up is the part you
    /// sit and type, so it is a real buffer rather than rendered text.
    pub(super) fn draw_findings(&mut self, frame: &mut Frame, area: Rect) {
        let [banner, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        self.viewport = panes.height.saturating_sub(2) as usize;

        let focused = self.findings_view.focused && !self.findings.is_empty();
        frame.render_widget(
            Paragraph::new(Line::styled(
                if focused {
                    // No `gq` here: the buffer is prose, and the formatter
                    // knows how to pretty-print an HTTP message, not markdown.
                    "  vim keys   ^g $EDITOR   ## Reproduction / Impact / Remediation   <Esc> save and leave"
                } else {
                    "  <CR> write up   s severity   c status   r retitle   d delete"
                },
                muted(),
            )),
            banner,
        );

        if self.findings.is_empty() {
            frame.render_widget(
                empty_pane(
                    " Findings ",
                    "nothing filed — select a flow in Proxy (P) and press <Space>f",
                ),
                panes,
            );
            self.content_len = 0;
            return;
        }

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                .areas(panes);

        let rows: Vec<Line> = self
            .findings
            .iter()
            .enumerate()
            .map(|(i, finding)| {
                let mut spans = vec![
                    Span::styled(
                        format!(" {:<8} ", finding.severity),
                        Style::new().fg(severity_color(&finding.severity)).bold(),
                    ),
                    Span::raw(finding.title.clone()),
                ];
                // Anything not still a draft has been looked at; saying so in
                // the list is what stops you re-reading the same finding.
                if finding.status != "draft" {
                    spans.push(Span::styled(format!("  [{}]", finding.status), muted()));
                }
                let line = Line::from(spans);
                if i == self.findings_view.row {
                    line.style(Style::new().bg(INACTIVE_BG))
                } else {
                    line
                }
            })
            .collect();

        frame.render_widget(
            Paragraph::new(rows).block(
                Block::bordered()
                    .title(format!(" Findings ({}) ", self.findings.len()))
                    // The lit border follows the keys, so it is on the list
                    // exactly while the list is what the keys move.
                    .border_style(if focused {
                        Style::new().fg(Color::DarkGray)
                    } else {
                        Style::new().fg(Color::Cyan)
                    }),
            ),
            left,
        );

        // The right column is the facts on top and the write-up underneath.
        // They are split because only one of them is editable: severity, status,
        // host and evidence are set by keys and by what you filed it from, and
        // putting them in the buffer would invite typing over them.
        let Some(finding) = self.findings.get(self.findings_view.row) else {
            frame.render_widget(empty_pane(" Detail ", "no finding selected"), right);
            self.content_len = self.findings.len() as u16;
            return;
        };

        let mut facts = vec![Line::from(vec![
            Span::styled(
                format!(" {} ", finding.severity),
                Style::new().fg(severity_color(&finding.severity)).bold(),
            ),
            Span::styled(format!("· {} ", finding.status), muted()),
            Span::styled(format!("· {}", finding.origin), muted()),
        ])];
        if let Some(host) = &finding.host {
            let path = finding.path.clone().unwrap_or_default();
            facts.push(Line::from(format!(" {host}{path}")));
        }
        if let Some(cwe) = &finding.cwe {
            facts.push(Line::styled(format!(" {cwe}"), muted()));
        }
        // Evidence is what makes a finding reproducible, so it is shown even
        // when everything else is empty.
        let evidence = if finding.evidence.is_empty() {
            " evidence: (none)".to_string()
        } else {
            let flows = finding
                .evidence
                .iter()
                .map(|(flow_id, label)| match label {
                    Some(label) => format!("#{flow_id} {label}"),
                    None => format!("#{flow_id}"),
                })
                .collect::<Vec<_>>()
                .join("  ");
            format!(" evidence: {flows}")
        };
        facts.push(Line::styled(evidence, muted()));

        // The facts block takes the height it needs; the write-up gets the
        // rest, since that is the part being worked on.
        let [meta, body] =
            Layout::vertical([Constraint::Length(facts.len() as u16), Constraint::Min(0)])
                .areas(right);
        frame.render_widget(Paragraph::new(facts), meta);

        let inserting = self.input.mode() == Mode::Insert;
        let scroll = self.content_scroll;
        let title = finding.title.clone();
        // Borrowed after everything that needs `&self` above, since the buffer
        // comes out of the same struct mutably.
        let Some(buffer) = self.write_up_buffer() else {
            return;
        };
        let dirty = buffer.is_dirty();
        let lines = buffer.lines().len() as u16;

        BufferView {
            buffer,
            // Markdown, not an HTTP message: the HTTP highlighter would light up
            // prose as though it were headers.
            cache: None,
            title: format!(" {}{} ", title, if dirty { " *" } else { "" }),
            focused,
            inserting,
            border: if focused {
                Style::new().fg(Color::Cyan)
            } else {
                Style::new().fg(Color::DarkGray)
            },
            scroll,
        }
        .render(frame, body);
        self.content_len = lines.max(self.findings.len() as u16);
    }

    /// Sitemap: the tree of what has been seen, host then path. `<CR>` folds.
    pub(super) fn draw_sitemap(&mut self, frame: &mut Frame, area: Rect) {
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
}
