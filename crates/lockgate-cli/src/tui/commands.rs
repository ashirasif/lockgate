//! The window-specific commands — intercept, findings, notes, scope, the
//! Repeater — plus the palette, cursor motions and the jumplist.

use super::*;

impl App {
    pub(super) fn toggle_intercept(&mut self) {
        let intercept = self.engine.intercept();
        let on = !intercept.is_enabled();
        let released = intercept.set_enabled(on);
        self.note(&if on {
            "intercept ON — traffic will hold until forwarded".to_string()
        } else {
            format!("intercept OFF — released {released} held item(s)")
        });
    }

    /// Answer the highlighted item in the focused column, forwarding any edits.
    pub(super) fn answer_held(&mut self, forward: bool) {
        let requests = self.intercept.showing_requests();
        let leg = if requests { "request" } else { "response" };
        let Some(held) = self.held(requests).get(self.intercept.row(requests)) else {
            self.note(&format!("no {leg} held"));
            return;
        };
        let (ticket, flow_id, pending) = (held.ticket, held.flow_id, held.pending.clone());

        if !forward {
            self.engine.intercept().discard(ticket);
            *self.intercept.edit(requests) = None;
            self.note(&format!("dropped {leg} #{flow_id}"));
            return;
        }

        // Only reparse if this item was actually edited; an untouched item
        // forwards its original bytes rather than a re-rendered approximation.
        let edited = match self.intercept.edit(requests) {
            Some((t, buffer)) if *t == ticket && buffer.is_dirty() => {
                match reparse(&pending, &buffer.text()) {
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

        let was_edited = edited.is_some();
        self.engine.intercept().forward(ticket, edited);
        *self.intercept.edit(requests) = None;
        self.note(&if was_edited {
            format!("forwarded {leg} #{flow_id} (edited)")
        } else {
            format!("forwarded {leg} #{flow_id}")
        });
    }

    // --- sitemap ---

    pub(super) fn toggle_fold(&mut self) {
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
    pub(super) fn sitemap_rows(&self) -> Vec<SitemapRow> {
        // A generous page: the fold state is per-key, so paging would need to
        // hold parents across pages anyway. Bounded so a huge project cannot
        // stall a frame.
        let mut nodes = self.engine.sitemap(None, 0, 5000);
        if self.scope_filter {
            let matcher = self.engine.scope_matcher();
            if !matcher.is_unrestricted() {
                nodes.retain(|n| matcher.matches_host_path(&n.host, &n.path));
            }
        }
        build_sitemap_rows(&nodes, &self.sitemap.collapsed)
    }

    // --- findings ---

    /// The vocabularies, in the order the keys walk them. Same values the MCP
    /// tools validate against — the columns are free text with no CHECK, so a
    /// typo here would persist and skew later filters.
    pub(super) const SEVERITIES: &'static [&'static str] =
        &["info", "low", "medium", "high", "critical"];
    pub(super) const STATUSES: &'static [&'static str] = &[
        "draft",
        "confirmed",
        "false_positive",
        "reported",
        "fixed",
        "wont_fix",
    ];

    /// Step the highlighted finding's severity or status one along.
    ///
    /// Cycling rather than prompting: triage is a repeated motion over many
    /// findings, and a menu per change would make it a chore.
    pub(super) fn cycle_finding(&mut self, severity: bool) {
        let Some(finding) = self.findings.get(self.findings_view.row) else {
            self.note("no finding selected");
            return;
        };
        let (id, current) = (
            finding.id,
            if severity {
                finding.severity.clone()
            } else {
                finding.status.clone()
            },
        );
        let vocabulary = if severity {
            Self::SEVERITIES
        } else {
            Self::STATUSES
        };
        // An unrecognised value starts from the beginning rather than sticking.
        let next = vocabulary
            .iter()
            .position(|v| *v == current)
            .map_or(0, |i| (i + 1) % vocabulary.len());
        let next = vocabulary[next];

        let changed = if severity {
            self.engine.set_finding_triage(id, Some(next), None)
        } else {
            self.engine.set_finding_triage(id, None, Some(next))
        };
        if changed == 0 {
            self.note("could not update the finding");
            return;
        }
        self.refresh();
        self.note(&format!("#{id} → {next}"));
    }

    pub(super) fn delete_finding(&mut self) {
        let Some(finding) = self.findings.get(self.findings_view.row) else {
            return;
        };
        let (id, title) = (finding.id, finding.title.clone());
        if self.engine.delete_finding(id) == 0 {
            self.note("could not delete the finding");
            return;
        }
        // Drop the buffer first: saving it afterwards would write the write-up
        // of a finding that no longer exists.
        if self.findings_view.edit.as_ref().map(|(i, _)| *i) == Some(id) {
            self.findings_view.edit = None;
            self.findings_view.focused = false;
        }
        self.refresh();
        self.note(&format!("deleted {title:?}"));
    }

    /// File the selected flow as a finding. `:finding <title>`.
    ///
    /// Deliberately one field. A finding starts as "this looks wrong, and here
    /// is the request" — the prose belongs in an editor later, and a form up
    /// front is how you end up not filing it at all.
    pub(super) fn file_finding(&mut self, title: &str) {
        let title = title.trim();
        if title.is_empty() {
            self.note("usage: :finding <title>   (files the selected flow)");
            return;
        }
        let Some(flow) = self.detail.as_ref() else {
            self.note("no flow selected to attach as evidence");
            return;
        };

        let new = lockgate_core::NewFinding {
            title: title.to_string(),
            // Draft and info: a finding you have not triaged yet should not
            // claim a severity you did not choose.
            severity: "info".to_string(),
            status: "draft".to_string(),
            cvss_vector: None,
            cvss_score: None,
            cvss_version: None,
            cwe: None,
            description_md: String::new(),
            repro_md: None,
            impact_md: None,
            remediation_md: None,
            host: flow.request.uri.host().map(str::to_string),
            path: Some(flow.request.uri.path().to_string()),
            evidence: vec![(flow.id as i64, Some("observed".to_string()))],
        };

        let engine = self.engine.clone();
        let status = self.status.clone();
        let created = self.created_finding.clone();
        let flow_id = flow.id;
        // Findings go through the writer task, so this cannot be awaited here
        // without blocking the draw loop. The id comes back through
        // `created_finding`, which `refresh` picks up — that is what puts the
        // cursor on the new finding rather than on whatever row 0 held before
        // the write landed.
        tokio::spawn(async move {
            let message = match engine.create_finding(new).await {
                Ok(id) => {
                    *created.lock().unwrap() = Some(id);
                    format!("filed finding #{id} from flow #{flow_id} — T then <CR> to write it up")
                }
                Err(e) => format!("could not file: {e:?}"),
            };
            *status.lock().unwrap() = message;
        });
    }

    /// Retitle the highlighted finding. `:finding! <title>`.
    ///
    /// The bang is vim's "and mean it", exactly as in `:note!`: `:finding` with
    /// no bang always files a new one, so the destructive reading of a bare
    /// title is never the accidental one.
    pub(super) fn rename_finding(&mut self, title: &str) {
        let title = title.trim();
        if title.is_empty() {
            self.note("usage: :finding! <title>   (retitles the highlighted finding)");
            return;
        }
        let Some(finding) = self.findings.get(self.findings_view.row) else {
            self.note("no finding selected");
            return;
        };
        let id = finding.id;
        if self.engine.set_finding_title(id, title) == 0 {
            self.note("could not retitle the finding");
            return;
        }
        self.refresh();
        self.note(&format!("#{id} → {title:?}"));
    }

    // --- notes ---

    /// Start a note. `:note <title>`, or `<Space>n` from anywhere.
    ///
    /// One field, like `:finding`. A note is a document you write *into*, so
    /// the title is only what gets you a page to write on; the body arrives by
    /// typing, not by filling in a prompt.
    pub(super) fn create_note(&mut self, title: &str) {
        let title = title.trim();
        if title.is_empty() {
            self.note("usage: :note <title>   (starts a project note)");
            return;
        }

        let new = lockgate_core::NewNote {
            title: title.to_string(),
            body_md: String::new(),
        };

        let engine = self.engine.clone();
        let status = self.status.clone();
        let created = self.created_note.clone();
        // Notes go through the writer task like findings, so this cannot be
        // awaited here without blocking the draw loop. The id comes back
        // through `created_note`, which `refresh` picks up — that is what puts
        // the cursor on the new note rather than on whatever row 0 held before
        // the write landed.
        tokio::spawn(async move {
            let message = match engine.create_note(new).await {
                Ok(id) => {
                    *created.lock().unwrap() = Some(id);
                    format!("started note #{id} — <CR> to write it")
                }
                Err(e) => format!("could not start the note: {e:?}"),
            };
            *status.lock().unwrap() = message;
        });
    }

    /// Retitle the highlighted note. `:note! <title>`.
    pub(super) fn rename_note(&mut self, title: &str) {
        let title = title.trim();
        if title.is_empty() {
            self.note("usage: :note! <title>   (retitles the highlighted note)");
            return;
        }
        let Some(note) = self.notes.get(self.notes_view.row) else {
            self.note("no note selected");
            return;
        };
        let id = note.id;
        if self.engine.update_note(id, Some(title), None) == 0 {
            self.note("could not retitle the note");
            return;
        }
        self.refresh();
        self.note(&format!("#{id} → {title:?}"));
    }

    pub(super) fn delete_note(&mut self) {
        let Some(note) = self.notes.get(self.notes_view.row) else {
            return;
        };
        let (id, title) = (note.id, note.title.clone());
        if self.engine.delete_note(id) == 0 {
            self.note("could not delete the note");
            return;
        }
        // Drop the buffer first: saving it afterwards would write the body of a
        // note that no longer exists.
        if self.notes_view.edit.as_ref().map(|(i, _)| *i) == Some(id) {
            self.notes_view.edit = None;
            self.notes_view.focused = false;
        }
        self.refresh();
        self.note(&format!("deleted {title:?}"));
    }

    // --- scope ---

    /// The scope that edits apply to: the active one, or a first one created on
    /// demand so adding a host from the Sitemap always lands somewhere.
    fn target_scope(&mut self) -> Option<i64> {
        if let Some(scope) = self.scopes.iter().find(|s| s.is_active) {
            return Some(scope.id);
        }
        if let Some(scope) = self.scopes.first() {
            return Some(scope.id);
        }
        match self.engine.create_scope("default") {
            Ok(id) => {
                // Created scopes are inert until active, and a scope nobody
                // activated would silently not filter.
                let _ = self.engine.set_active_scope(id);
                Some(id)
            }
            Err(e) => {
                self.note(&format!("could not create a scope: {e:?}"));
                None
            }
        }
    }

    fn sitemap_host(&self) -> Option<String> {
        let rows = self.sitemap_rows();
        rows.get(self.sitemap.selected).map(|row| row.host.clone())
    }

    /// Put the highlighted host in scope.
    ///
    /// Two rules, because `*.linear.app` does not match the apex `linear.app` —
    /// there is no leading label for `*` to consume. One without the other is a
    /// scope that silently misses either the site or all of its subdomains.
    pub(super) fn scope_add_host(&mut self) {
        let Some(host) = self.sitemap_host() else {
            self.note("no host selected");
            return;
        };
        let Some(scope_id) = self.target_scope() else {
            return;
        };

        let existing: Vec<String> = self
            .engine
            .scope_rules(scope_id)
            .iter()
            .filter_map(|r| r.spec.host.as_ref().map(|(_, p)| p.clone()))
            .collect();

        let mut added = 0;
        for pattern in [host.clone(), format!("*.{host}")] {
            if existing.iter().any(|p| p == &pattern) {
                continue;
            }
            let spec = lockgate_core::scope::RuleSpec::host(
                lockgate_core::scope::HostKind::Glob,
                pattern.clone(),
            );
            match self
                .engine
                .add_scope_rule(scope_id, lockgate_core::scope::Action::Include, &spec)
            {
                Ok(_) => added += 1,
                Err(e) => {
                    self.note(&format!("could not add {pattern}: {e:?}"));
                    return;
                }
            }
        }
        self.refresh();
        self.note(&match added {
            0 => format!("{host} was already in scope"),
            n => format!("{host} in scope (+{n} rules)"),
        });
    }

    /// Drop every rule naming the highlighted host, apex and wildcard alike.
    pub(super) fn scope_remove_host(&mut self) {
        let Some(host) = self.sitemap_host() else {
            self.note("no host selected");
            return;
        };
        let Some(scope_id) = self.target_scope() else {
            return;
        };

        let wildcard = format!("*.{host}");
        let doomed: Vec<i64> = self
            .engine
            .scope_rules(scope_id)
            .iter()
            .filter(|r| {
                r.spec
                    .host
                    .as_ref()
                    .is_some_and(|(_, p)| p == &host || p == &wildcard)
            })
            .map(|r| r.id)
            .collect();

        if doomed.is_empty() {
            self.note(&format!("{host} is not named by any rule"));
            return;
        }
        let removed = doomed.len();
        for id in doomed {
            if let Err(e) = self.engine.delete_scope_rule(id) {
                self.note(&format!("could not remove a rule: {e:?}"));
                return;
            }
        }
        self.refresh();
        self.note(&format!("{host} out of scope (−{removed} rules)"));
    }

    /// `<CR>` in the Scope window: activate a scope, or toggle a rule.
    pub(super) fn scope_enter(&mut self) {
        if self.scope.column == Column::Left {
            let Some(scope) = self.scopes.get(self.scope.scope_row) else {
                self.note("no scope to activate");
                return;
            };
            let (id, name) = (scope.id, scope.name.clone());
            match self.engine.set_active_scope(id) {
                Ok(()) => {
                    self.refresh();
                    self.note(&format!("active scope: {name}"));
                }
                Err(e) => self.note(&format!("could not activate: {e:?}")),
            }
            return;
        }

        let Some(rule) = self.scope_rules.get(self.scope.rule_row) else {
            self.note("no rule selected");
            return;
        };
        let (id, enabled) = (rule.id, rule.enabled);
        match self.engine.set_scope_rule_enabled(id, !enabled) {
            Ok(()) => {
                self.refresh();
                self.note(if enabled { "rule off" } else { "rule on" });
            }
            Err(e) => self.note(&format!("could not toggle: {e:?}")),
        }
    }

    /// `d` in the Scope window: delete the highlighted rule, or scope.
    pub(super) fn scope_delete(&mut self) {
        if self.scope.column == Column::Left {
            let Some(scope) = self.scopes.get(self.scope.scope_row) else {
                return;
            };
            let (id, name) = (scope.id, scope.name.clone());
            match self.engine.delete_scope(id) {
                Ok(()) => {
                    self.refresh();
                    self.note(&format!("deleted scope {name}"));
                }
                Err(e) => self.note(&format!("could not delete: {e:?}")),
            }
            return;
        }

        let Some(rule) = self.scope_rules.get(self.scope.rule_row) else {
            self.note("no rule selected");
            return;
        };
        let id = rule.id;
        match self.engine.delete_scope_rule(id) {
            Ok(()) => {
                self.refresh();
                self.note("rule deleted");
            }
            Err(e) => self.note(&format!("could not delete: {e:?}")),
        }
    }

    /// Add a rule to the scope under the cursor.
    ///
    /// Glob unless the pattern says otherwise: `re:` for a regex, `cidr:` for a
    /// network. Glob is the default because it is what people mean and, unlike
    /// an unanchored regex, it cannot silently match more than it looks like.
    pub(super) fn scope_add_rule(&mut self, pattern: &str, action: lockgate_core::scope::Action) {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            self.note("usage: :scope add <pattern>   (re: or cidr: to change kind)");
            return;
        }
        let Some(scope_id) = self
            .scopes
            .get(self.scope.scope_row)
            .map(|s| s.id)
            .or_else(|| self.target_scope())
        else {
            return;
        };

        let (kind, pattern) = match pattern.split_once(':') {
            Some(("re", rest)) => (lockgate_core::scope::HostKind::Regex, rest.trim()),
            Some(("cidr", rest)) => (lockgate_core::scope::HostKind::Cidr, rest.trim()),
            _ => (lockgate_core::scope::HostKind::Glob, pattern),
        };

        let spec = lockgate_core::scope::RuleSpec::host(kind, pattern);
        match self.engine.add_scope_rule(scope_id, action, &spec) {
            Ok(_) => {
                self.refresh();
                self.note(&format!("added {pattern}"));
            }
            // add_rule compiles the pattern before storing it, so a bad regex
            // is refused here rather than breaking the matcher later.
            Err(e) => self.note(&format!("rejected: {e:?}")),
        }
    }

    pub(super) fn scope_new(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            self.note("usage: :scope new <name>");
            return;
        }
        match self.engine.create_scope(name) {
            Ok(id) => {
                if self.scopes.is_empty() {
                    // The first scope may as well be the active one; a scope
                    // that filters nothing looks broken.
                    let _ = self.engine.set_active_scope(id);
                }
                self.refresh();
                self.scope.scope_row = self
                    .scopes
                    .iter()
                    .position(|s| s.id == id)
                    .unwrap_or(self.scope.scope_row);
                self.note(&format!("created scope {name}"));
            }
            Err(e) => self.note(&format!("could not create: {e:?}")),
        }
    }

    // --- repeater ---

    /// Snapshot the Proxy selection into the Repeater as editable text.
    pub(super) fn load_repeater(&mut self) {
        let Some(flow) = self.detail.clone() else {
            self.note("no flow selected to send to the Repeater");
            return;
        };
        let id = flow.id;
        let session = Session {
            origin: Some(id),
            request: TextBuffer::from_text(&http_text::render_request_decoded(&flow.request)),
            original: Some(flow.request),
            ..Session::default()
        };
        // Land in a fresh tab unless the current one is untouched, so sending a
        // second flow over cannot discard a request you were editing.
        if self.repeater.session().original.is_some() {
            self.repeater.open();
        }
        *self.repeater.session_mut() = session;
        self.repeater.focused = false;
        self.show_window(Window::Repeater);
        self.note(&format!(
            "#{id} → Repeater tab {}",
            self.repeater.active + 1
        ));
    }

    /// Send what is in the Repeater buffer, edits included.
    pub(super) fn send_repeater(&mut self) {
        let Some(original) = self.repeater.session().original.clone() else {
            self.note("Repeater is empty — pick a flow in Proxy and press <Space>s");
            return;
        };
        let request =
            match http_text::parse_request(&self.repeater.session().request.text(), &original) {
                Ok(req) => req,
                Err(e) => {
                    // Kept on the pane, not just the status line: a parse error is
                    // about the buffer, and belongs next to it.
                    self.repeater.session_mut().error = Some(e.to_string());
                    self.note(&format!("not sent — {e}"));
                    return;
                }
            };
        self.repeater.session_mut().error = None;
        self.repeater.session_mut().request.clear_dirty();

        let engine = self.engine.clone();
        let status = self.status.clone();
        let origin = self.repeater.session().origin;

        // The exchange is recorded before the send returns, so history shows an
        // in-flight request rather than nothing until it lands.
        let sent_text = self.repeater.session().request.text();
        let slot = Arc::new(Mutex::new(None));
        let session = self.repeater.session_mut();
        session.history.push(Exchange {
            request: sent_text,
            result: slot.clone(),
        });
        // Any send jumps the view back to the newest, which is the one you just
        // asked for.
        session.viewing = None;

        self.note("sending…");
        tokio::spawn(async move {
            // Timed here rather than in the engine: this is a property of this
            // send, not of the flow it records.
            let started = std::time::Instant::now();
            let outcome = engine.send_request(request, origin).await;
            let millis = started.elapsed().as_millis();

            let (result, message) = match outcome {
                Ok(sent) => {
                    let bytes = sent.response.body.len();
                    (
                        SendResult {
                            text: http_text::render_response_decoded(&sent.response),
                            bytes: Some(bytes),
                            millis,
                            failed: false,
                        },
                        format!(
                            "sent → {} ({bytes} bytes, {millis}ms) as #{}",
                            sent.response.status, sent.replay_id
                        ),
                    )
                }
                Err(e) => (
                    SendResult {
                        text: format!("send failed: {e:?}"),
                        bytes: None,
                        millis,
                        failed: true,
                    },
                    format!("send failed: {e:?}"),
                ),
            };
            *slot.lock().unwrap() = Some(result);
            *status.lock().unwrap() = message;
        });
    }

    /// Drive the Cmd-K palette. The input layer already flipped the mode; here
    /// we only maintain the filter and selection, and on `Accept` we look up the
    /// highlighted command and run it through `apply` like any other intent.
    pub(super) fn palette(&mut self, key: PaletteKey) {
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
        let intercept = self.engine.intercept();
        commands.push((
            if intercept.holds_requests() {
                "Stop holding requests".into()
            } else {
                "Hold requests".into()
            },
            Action::ToggleHoldRequests,
        ));
        commands.push((
            if intercept.holds_responses() {
                "Stop holding responses".into()
            } else {
                "Hold responses".into()
            },
            Action::ToggleHoldResponses,
        ));
        let held = self.held_requests.len() + self.held_responses.len();
        if held > 0 {
            commands.push((
                format!("Forward all {held} held item(s)"),
                Action::ForwardAll,
            ));
            commands.push((format!("Drop all {held} held item(s)"), Action::DropAll));
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
    pub(super) fn palette_matches(&self) -> Vec<(String, Action)> {
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
    pub(super) fn show_window(&mut self, window: Window) {
        if window != self.window {
            // Leaving Notes is a way out of an open note, so it saves. Same for
            // an open write-up in Findings.
            if self.window == Window::Notes {
                self.save_note();
                self.notes_view.focused = false;
            }
            if self.window == Window::Findings {
                self.save_write_up();
                self.findings_view.focused = false;
            }
            self.window = window;
            self.content_scroll = 0;
            // Window-scoped bindings resolve against this, so it has to move
            // with the window or `f` would still mean forward after leaving.
            self.input.set_window(window);
            // Always arrive on the queue, not inside a preview you stepped into
            // three windows ago.
            self.intercept.pane = Pane::Table;
            self.note(window.label());
        }
    }

    /// The non-Proxy windows have no row cursor, so `j`/`k`/`<C-d>`/`gg`/`G`
    /// scroll their rendered content. The offset is clamped at draw time once
    /// the real line count is known.
    pub(super) fn scroll_content(&mut self, motion: Motion, count: Option<usize>) {
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

    pub(super) fn run_command(&mut self, line: &str) {
        let Some(command) = Command::parse(line) else {
            return;
        };
        match command {
            Command::Quit => {
                // Last chance for an open note or write-up: quitting is a way
                // out of the buffer like any other, and the only one with no
                // next tick.
                self.save_note();
                self.save_write_up();
                self.should_quit = true;
            }
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
            Command::Pretty => self.format_buffer(),
            Command::Finding(title) => self.file_finding(&title),
            Command::RenameFinding(title) => self.rename_finding(&title),
            Command::Note(title) => self.create_note(&title),
            Command::RenameNote(title) => self.rename_note(&title),
            Command::Scope { verb, argument } => self.run_scope_command(&verb, &argument),
            Command::Help => self.note(HELP),
            Command::Unknown(name) => self.note(&format!("E492: not an editor command: {name}")),
        }
    }

    /// `:scope …`. Verbs rather than keys because every one of these takes a
    /// pattern or a name, and free text has to be typed somewhere.
    pub(super) fn run_scope_command(&mut self, verb: &str, argument: &str) {
        match verb {
            "new" => self.scope_new(argument),
            "add" | "include" => {
                self.scope_add_rule(argument, lockgate_core::scope::Action::Include)
            }
            "exclude" | "ex" => {
                self.scope_add_rule(argument, lockgate_core::scope::Action::Exclude)
            }
            "use" => {
                match self
                    .scopes
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(argument.trim()))
                {
                    Some(scope) => {
                        let (id, name) = (scope.id, scope.name.clone());
                        match self.engine.set_active_scope(id) {
                            Ok(()) => {
                                self.refresh();
                                self.note(&format!("active scope: {name}"));
                            }
                            Err(e) => self.note(&format!("could not activate: {e:?}")),
                        }
                    }
                    None => self.note(&format!("no scope named {argument:?}")),
                }
            }
            "off" | "bypass" => self.set_scope_filter(false),
            "on" => self.set_scope_filter(true),
            "" => self.note("usage: :scope new|add|exclude|use|on|off [argument]"),
            other => self.note(&format!("unknown: :scope {other}")),
        }
    }

    /// Turn scope filtering off or on without touching the rules.
    pub(super) fn set_scope_filter(&mut self, on: bool) {
        self.scope_filter = on;
        // The filter is applied when the history is read, so changing it means
        // the lists have to be read again — and the engine has not moved, so
        // nothing else would ask for that.
        self.flows_stale = true;
        self.refresh();
        self.note(if on {
            "scope filtering on"
        } else {
            "scope bypassed — showing everything"
        });
    }

    pub(super) fn move_cursor(&mut self, motion: Motion, count: Option<usize>) {
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

    pub(super) fn jump_to(&mut self, row: usize) {
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

    pub(super) fn walk_jumps(&mut self, direction: isize) {
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

    pub(super) fn note(&self, message: &str) {
        *self.status.lock().unwrap() = message.to_string();
    }

    /// Rows covered by the visual selection, or just the cursor row.
    pub(super) fn selected_rows(&self) -> std::ops::RangeInclusive<usize> {
        let cursor = self.cursor();
        match self.visual_anchor {
            Some(anchor) => anchor.min(cursor)..=anchor.max(cursor),
            None => cursor..=cursor,
        }
    }

    /// Fire the Repeater. Spawned rather than awaited so a slow target can't
    /// freeze the UI; the task reports back through the shared status string.
    pub(super) fn resend_selected(&mut self) {
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
}
