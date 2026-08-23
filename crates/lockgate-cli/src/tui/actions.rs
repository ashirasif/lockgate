//! Everything a keystroke turns into: the action dispatch, the vim buffer
//! editing behind it, and the handoff to `$EDITOR`.

use super::*;

impl App {
    /// Drop out of the TUI, run the operator's editor over a scratch file, and
    /// come back.
    ///
    /// The proxy keeps running throughout — it lives on other tasks — so traffic
    /// is still captured and anything held stays held while you edit.
    ///
    /// Whether the file changed *is* the save signal: `:wq` writes and the edit
    /// lands, `:q!` doesn't and it doesn't. That means we never have to ask the
    /// editor what the user did, which is good, because there is no portable way
    /// to find out.
    pub(super) async fn run_editor(&mut self, job: EditJob, terminal: &mut DefaultTerminal) {
        self.edit_seq += 1;
        let path = std::env::temp_dir().join(format!(
            // Extension carried from the target so an editor picks a sensible
            // filetype for syntax.
            "lockgate-edit-{}-{}.{}",
            std::process::id(),
            self.edit_seq,
            job.target.extension()
        ));

        if let Err(e) = std::fs::write(&path, &job.before) {
            self.note(&format!("could not write scratch file: {e}"));
            return;
        }

        // Give the terminal back before spawning: the editor needs the real
        // screen, not our alternate one.
        ratatui::restore();
        let status = editor_command(&path).status().await;
        *terminal = ratatui::init();
        let _ = terminal.clear();

        match status {
            Ok(status) if status.success() => match std::fs::read_to_string(&path) {
                Ok(after) if after != job.before => self.apply_edit(job, after),
                Ok(_) => self.note("no changes"),
                Err(e) => self.note(&format!("could not read back the edit: {e}")),
            },
            // A non-zero exit is how an editor reports it did not finish
            // cleanly. Taking the file anyway would apply a half-finished edit.
            Ok(status) => self.note(&format!("editor exited {status}; nothing applied")),
            Err(e) => self.note(&format!("could not start editor: {e}")),
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Put an edited buffer back where it came from.
    pub(super) fn apply_edit(&mut self, job: EditJob, text: String) {
        let mut buffer = TextBuffer::from_text(&text);
        // It came back changed, so it is dirty by definition — `from_text`
        // starts clean, and forwarding only reparses a dirty buffer.
        buffer.mark_dirty();

        match job.target {
            EditTarget::Repeater => {
                self.repeater.session_mut().request = buffer;
                self.note("edit applied — <Space>r to send");
            }
            EditTarget::Note(id) => {
                // The note may have been deleted — from the MCP, say — while
                // the editor was open.
                if !self.notes.iter().any(|n| n.id == id) {
                    self.note("that note is gone; edit discarded");
                    return;
                }
                self.notes_view.edit = Some((id, buffer));
                // `:wq` in $EDITOR means saved, so make it so rather than
                // leaving it dirty for an <Esc> the operator has no reason to
                // expect is still owed.
                self.save_note();
            }
            EditTarget::Finding(id) => {
                // The finding may have been deleted — from the MCP, say —
                // while the editor was open.
                if !self.findings.iter().any(|f| f.id == id) {
                    self.note("that finding is gone; edit discarded");
                    return;
                }
                self.findings_view.edit = Some((id, buffer));
                self.save_write_up();
            }
            EditTarget::Held { requests, ticket } => {
                // The item may have been answered while the editor was open.
                if !self.held(requests).iter().any(|h| h.ticket == ticket) {
                    self.note("that item is no longer held; edit discarded");
                    return;
                }
                *self.intercept.edit(requests) = Some((ticket, buffer));
                // `:wq` means "done with this one" — go back to the queue, which
                // is where forwarding it happens.
                self.intercept.pane = Pane::Table;
                self.note("edit applied — f to forward");
            }
        }
    }

    /// Stage the focused buffer for editing. The run loop picks this up.
    pub(super) fn request_external_edit(&mut self) {
        let job = match self.window {
            Window::Repeater => self.repeater.session().original.as_ref().map(|_| EditJob {
                target: EditTarget::Repeater,
                before: self.repeater.session().request.text(),
            }),
            Window::Notes => {
                let note = self.notes.get(self.notes_view.row);
                note.map(|note| EditJob {
                    target: EditTarget::Note(note.id),
                    // Prefer what is in the buffer over the stored body, so
                    // typing a line and then reaching for `e` does not throw
                    // that line away.
                    before: match &self.notes_view.edit {
                        Some((id, buffer)) if *id == note.id => buffer.text(),
                        _ => note.body_md.clone(),
                    },
                })
            }
            Window::Findings => {
                let finding = self.findings.get(self.findings_view.row);
                finding.map(|finding| EditJob {
                    target: EditTarget::Finding(finding.id),
                    // Prefer the buffer over the stored columns, for the same
                    // reason Notes does: a line typed here and then handed to
                    // $EDITOR should still be there when it opens.
                    before: match &self.findings_view.edit {
                        Some((id, buffer)) if *id == finding.id => buffer.text(),
                        _ => finding.write_up(),
                    },
                })
            }
            Window::Intercept => {
                let requests = self.intercept.showing_requests();
                let row = self.intercept.row(requests);
                let held = self.held(requests).get(row).cloned();
                held.map(|held| {
                    // Prefer edits already made in-pane over the original, so
                    // `i` then `e` does not silently throw the first ones away.
                    let before = match self.intercept.edit(requests) {
                        Some((t, b)) if *t == held.ticket => b.text(),
                        _ => render_pending(&held.pending),
                    };
                    EditJob {
                        target: EditTarget::Held {
                            requests,
                            ticket: held.ticket,
                        },
                        before,
                    }
                })
            }
            _ => None,
        };

        match job {
            Some(job) => self.pending_edit = Some(job),
            None => self.note("nothing to edit here"),
        }
    }

    /// The single place where an intent becomes a change to the app.
    pub(super) fn apply(&mut self, action: Action) {
        self.apply_inner(action);
        self.sync_buffer_focus();
    }

    fn apply_inner(&mut self, action: Action) {
        match action {
            // Windows with a row cursor move it; the rest have only scrollable
            // content, so the same motions move the viewport instead.
            Action::Move { motion, count } if self.window == Window::Proxy => {
                self.move_cursor(motion, count)
            }
            // Inside a preview the motions walk the buffer; on a queue they
            // walk rows.
            Action::Move { motion, count }
                if self.window == Window::Intercept && self.intercept.pane == Pane::Preview =>
            {
                self.move_in_preview(motion, count)
            }
            Action::Move { motion, count } if self.window == Window::Intercept => {
                let requests = self.intercept.showing_requests();
                let last = self.held(requests).len().saturating_sub(1);
                let row = step_row(self.intercept.row(requests), last, motion, count);
                if requests {
                    self.intercept.request_row = row;
                } else {
                    self.intercept.response_row = row;
                }
                // A different item means a different buffer to look at.
                self.content_scroll = 0;
            }
            Action::Move { motion, count } if self.window == Window::WebSocket => {
                let last = self.ws_flows.len().saturating_sub(1);
                self.ws_row = step_row(self.ws_row, last, motion, count);
            }
            Action::Move { motion, count } if self.window == Window::Findings => {
                // Only reached with the write-up unfocused — with focus the keys
                // go to the vim grammar instead. Moving off a finding is a way
                // out of its buffer, so it saves like any other.
                self.save_write_up();
                let last = self.findings.len().saturating_sub(1);
                self.findings_view.row = step_row(self.findings_view.row, last, motion, count);
                self.content_scroll = 0;
            }
            Action::Move { motion, count } if self.window == Window::Notes => {
                // Only reached with the body unfocused — with focus the keys go
                // to the vim grammar instead. Moving off a note is a way out of
                // its buffer, so it saves like any other.
                self.save_note();
                let last = self.notes.len().saturating_sub(1);
                self.notes_view.row = step_row(self.notes_view.row, last, motion, count);
                self.content_scroll = 0;
            }
            Action::Move { motion, count } if self.window == Window::Scope => {
                // Each pane keeps its own cursor, so switching panes does not
                // move the one you were not looking at.
                if self.scope.column == Column::Left {
                    let last = self.scopes.len().saturating_sub(1);
                    self.scope.scope_row = step_row(self.scope.scope_row, last, motion, count);
                    // The rules pane follows the highlighted scope, so its
                    // cursor cannot stay where it was.
                    self.scope.rule_row = 0;
                    self.refresh();
                } else {
                    let last = self.scope_rules.len().saturating_sub(1);
                    self.scope.rule_row = step_row(self.scope.rule_row, last, motion, count);
                }
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
            Action::ToggleScopeFilter => {
                let on = !self.scope_filter;
                self.set_scope_filter(on);
            }
            Action::CycleSeverity => self.cycle_finding(true),
            Action::CycleStatus => self.cycle_finding(false),
            Action::ScopeAddHost => self.scope_add_host(),
            Action::ScopeRemoveHost => self.scope_remove_host(),
            Action::NewSession => {
                self.repeater.open();
                self.content_scroll = 0;
                self.note(&format!(
                    "tab {} — <Space>s to load a flow",
                    self.repeater.active + 1
                ));
            }
            Action::CloseSession => {
                let closed = self.repeater.active + 1;
                self.repeater.close();
                self.content_scroll = 0;
                self.note(&format!("closed tab {closed}"));
            }
            Action::SelectSession(which) => match which {
                // 1-based on screen, so the count you type is the number you see.
                Some(n) => {
                    if self.repeater.select(n.saturating_sub(1)) {
                        self.content_scroll = 0;
                    } else {
                        self.note(&format!("no tab {n}"));
                    }
                }
                // Bare `gs` cycles, wrapping, so it stays useful with any
                // number of tabs and never needs a count for the common case.
                None => {
                    let next = (self.repeater.active + 1) % self.repeater.sessions.len();
                    self.repeater.select(next);
                    self.content_scroll = 0;
                    self.note(&format!("tab {}", next + 1));
                }
            },
            Action::History { forward } => {
                if self.repeater.step_history(forward) {
                    self.content_scroll = 0;
                    if let Some((nth, total)) = self.repeater.session().position() {
                        self.note(&format!("exchange {nth}/{total}"));
                    }
                } else {
                    self.note(if forward {
                        "already at the newest send"
                    } else {
                        "already at the oldest send"
                    });
                }
            }
            Action::ToggleView => {
                self.repeater.view = match self.repeater.view {
                    View::Raw => View::Pretty,
                    View::Pretty => View::Raw,
                };
                self.note(match self.repeater.view {
                    View::Pretty => "response: pretty (view only — the bytes are unchanged)",
                    View::Raw => "response: raw",
                });
            }
            Action::Insert(key) => self.edit(key),
            Action::Forward => self.answer_held(true),
            Action::Drop if self.window == Window::Findings => self.delete_finding(),
            Action::Drop if self.window == Window::Notes => self.delete_note(),
            Action::Drop if self.window == Window::Scope => self.scope_delete(),
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
            Action::ToggleHoldRequests => {
                let intercept = self.engine.intercept();
                let on = !intercept.holds_requests();
                let released = intercept.set_hold_requests(on);
                self.note(&leg_note("requests", on, released));
            }
            Action::ToggleHoldResponses => {
                let intercept = self.engine.intercept();
                let on = !intercept.holds_responses();
                let released = intercept.set_hold_responses(on);
                self.note(&leg_note("responses", on, released));
            }
            Action::Focus(column) if self.window == Window::Scope => {
                self.scope.column = column.unwrap_or_else(|| self.scope.column.flip());
                self.content_scroll = 0;
            }
            Action::Focus(column) => {
                self.intercept.focus = column.unwrap_or_else(|| self.intercept.focus.flip());
                // The two columns scroll independently; carrying an offset from
                // one into the other lands you somewhere arbitrary.
                self.content_scroll = 0;
            }
            Action::Toggle => self.toggle_fold(),
            Action::Enter if self.window == Window::Scope => self.scope_enter(),
            Action::Enter => self.enter_preview(),
            Action::ExternalEdit => self.request_external_edit(),
            Action::Vim(cmd) => self.run_vim(cmd),
            Action::Escape => self.leave_preview(),
            Action::Command(line) => self.run_command(&line),
            Action::Window(window) => self.show_window(window),
            Action::WindowStep(direction) => self.show_window(self.window.step(direction)),
            Action::Palette(key) => self.palette(key),
        }
    }

    // --- editing ---

    /// Step into the focused buffer, wherever the window keeps one.
    fn enter_preview(&mut self) {
        if self.window == Window::Repeater {
            if self.repeater.session().original.is_some() {
                // Editing always means editing the live request. Pinned to an
                // older exchange the pane is showing what was sent, and typing
                // into that view would put keystrokes somewhere they cannot go.
                if self.repeater.session_mut().viewing.take().is_some() {
                    self.note("back to the newest — editing the live request");
                } else {
                    self.note("editing — vim keys, <Esc> to leave");
                }
                self.repeater.focused = true;
            }
            return;
        }
        if self.window == Window::Notes {
            if self.notes.is_empty() {
                self.note("no notes yet — :note <title> starts one");
                return;
            }
            self.notes_view.focused = true;
            // Materialise now so the cursor is visible on arrival.
            self.note_buffer();
            self.note("editing — vim keys, ^g for $EDITOR, <Esc> saves and leaves");
            return;
        }
        if self.window == Window::Findings {
            if self.findings.is_empty() {
                self.note("nothing filed yet — <Space>f files the selected flow");
                return;
            }
            self.findings_view.focused = true;
            // Materialise now so the cursor is visible on arrival.
            self.write_up_buffer();
            self.note("editing the write-up — ## Reproduction / ## Impact / ## Remediation are sections, ^g for $EDITOR, <Esc> saves");
            return;
        }
        if self.window != Window::Intercept {
            return;
        }
        let requests = self.intercept.showing_requests();
        if self.held(requests).is_empty() {
            return;
        }
        self.intercept.pane = Pane::Preview;
        self.content_scroll = 0;
        // Materialise the buffer now so the cursor is visible on arrival.
        self.preview_buffer(requests);
        self.note("preview — ^g for $EDITOR, gq to format, i to insert, <Esc> back");
    }

    /// Step back out of a buffer, which is what makes window keys reachable
    /// again.
    fn leave_preview(&mut self) {
        match self.window {
            Window::Repeater => self.repeater.focused = false,
            Window::Intercept if self.intercept.pane == Pane::Preview => {
                self.intercept.pane = Pane::Table;
                self.content_scroll = 0;
            }
            // Stepping out of a note is the save point: there is no `:w`, so
            // the way out has to be the way it lands.
            Window::Notes if self.notes_view.focused => {
                self.save_note();
                self.notes_view.focused = false;
                self.content_scroll = 0;
            }
            Window::Findings if self.findings_view.focused => {
                self.save_write_up();
                self.findings_view.focused = false;
                self.content_scroll = 0;
            }
            _ => {}
        }
    }

    /// Move the cursor inside the focused preview buffer.
    fn move_in_preview(&mut self, motion: Motion, count: Option<usize>) {
        let requests = self.intercept.showing_requests();
        let Some(buffer) = self.preview_buffer(requests) else {
            return;
        };
        let step = count.unwrap_or(1);
        match motion {
            Motion::Down => (0..step).for_each(|_| buffer.down()),
            Motion::Up => (0..step).for_each(|_| buffer.up()),
            Motion::Top => match count {
                Some(n) => buffer.goto_line(n.saturating_sub(1)),
                None => buffer.top(),
            },
            Motion::Bottom => match count {
                Some(n) => buffer.goto_line(n.saturating_sub(1)),
                None => buffer.bottom(),
            },
            Motion::HalfPageDown | Motion::PageDown => (0..10 * step).for_each(|_| buffer.down()),
            Motion::HalfPageUp | Motion::PageUp => (0..10 * step).for_each(|_| buffer.up()),
            _ => {}
        }
    }

    /// Run a parsed vim command against the focused buffer.
    ///
    /// Everything routes through ranges: an operator resolves its target to a
    /// [`Range`](crate::editor::Range) and then deletes or yanks it. That is why
    /// adding a motion or a text object needs no new operator code.
    fn run_vim(&mut self, cmd: vim::Command) {
        use vim::{Command, Operator, Simple, Target};

        // Escape means "narrow the scope by one": drop the selection if there
        // is one, otherwise leave the buffer entirely. Handled before the
        // buffer borrow so the second case can touch the rest of the app.
        if matches!(cmd, Command::Escape) {
            let had_selection = self
                .active_buffer()
                .map(|b| b.has_selection())
                .unwrap_or(false);
            if !had_selection {
                self.leave_preview();
                self.input.set_vim_visual(false);
                return;
            }
        }

        // Cloned up front: the register lives on `self`, and pasting reads it
        // while the buffer is mutably borrowed out of the same struct.
        let register = self.yank.clone();
        let mut yanked = None;
        let mut selection_changed = false;
        // Only an explicit yank reaches the system clipboard. Deleting fills
        // the internal register too — that is what makes `dd` then `p` a move —
        // but having every `x` and `dw` clobber the clipboard would make it
        // useless for carrying a token to another window.
        let copies_out = matches!(
            cmd,
            Command::Operate {
                op: Operator::Yank,
                ..
            } | Command::VisualOperate(Operator::Yank)
        );

        // Handled before the buffer is borrowed, because reformatting reports
        // to the status line and that needs `self` back.
        if let Command::Simple {
            cmd: Simple::Format,
            ..
        } = cmd
        {
            self.format_buffer();
            return;
        }

        let Some(buffer) = self.active_buffer() else {
            return;
        };

        match cmd {
            Command::Move { motion, count } => {
                let target = buffer.motion_target(motion, count);
                buffer.set_cursor(target);
            }

            Command::Operate { op, target, count } => {
                let range = match target {
                    Target::Motion(motion) => Some(buffer.range_for_motion(motion, count)),
                    Target::Line => Some(buffer.range_for_lines(count)),
                    Target::Object(object) => buffer.range_for_object(object),
                };
                // `ci"` with the cursor outside any quotes finds no range. Doing
                // nothing is right; guessing at a nearby pair is not.
                let Some(range) = range else { return };

                match op {
                    Operator::Yank => yanked = Some(buffer.yank_range(range)),
                    Operator::Delete => yanked = Some(buffer.delete_range(range)),
                    Operator::Change => {
                        yanked = Some(buffer.delete_range(range));
                        // `cc` leaves an empty line to type on; `cw` leaves the
                        // cursor in the gap it just made.
                        if range.linewise {
                            buffer.open_above();
                        }
                    }
                }
            }

            Command::VisualOperate(op) => {
                let Some(range) = buffer.selection_range() else {
                    return;
                };
                match op {
                    Operator::Yank => {
                        yanked = Some(buffer.yank_range(range));
                        // Vim leaves the cursor at the start of a yanked
                        // selection rather than where it happened to end.
                        buffer.set_cursor(range.start);
                    }
                    Operator::Delete => yanked = Some(buffer.delete_range(range)),
                    Operator::Change => {
                        yanked = Some(buffer.delete_range(range));
                        if range.linewise {
                            buffer.open_above();
                        }
                    }
                }
                buffer.clear_selection();
                selection_changed = true;
            }

            Command::Visual { linewise } => {
                buffer.toggle_selection(linewise);
                selection_changed = true;
            }
            Command::VisualSwapEnds => buffer.swap_selection_ends(),
            Command::Escape => {
                buffer.clear_selection();
                selection_changed = true;
            }

            Command::Simple { cmd, count } => match cmd {
                Simple::DeleteChar => {
                    let range = buffer.range_for_motion(vim::Motion::Right, count);
                    yanked = Some(buffer.delete_range(range));
                }
                Simple::DeleteToEnd => {
                    let range = buffer.range_for_motion(vim::Motion::LineEnd, 1);
                    yanked = Some(buffer.delete_range(range));
                }
                Simple::ChangeToEnd => {
                    let range = buffer.range_for_motion(vim::Motion::LineEnd, 1);
                    yanked = Some(buffer.delete_range(range));
                }
                Simple::PasteAfter => buffer.paste(&register, true),
                Simple::PasteBefore => buffer.paste(&register, false),
                Simple::Undo => {
                    for _ in 0..count {
                        if !buffer.undo() {
                            break;
                        }
                    }
                }
                Simple::Redo => {
                    for _ in 0..count {
                        if !buffer.redo() {
                            break;
                        }
                    }
                }
                Simple::JoinLines => buffer.join_lines(count),
                Simple::Insert => buffer.checkpoint(),
                Simple::InsertLineStart => {
                    buffer.checkpoint();
                    buffer.first_non_blank();
                }
                Simple::Append => {
                    buffer.checkpoint();
                    buffer.append();
                }
                Simple::AppendLineEnd => {
                    buffer.checkpoint();
                    buffer.line_end();
                }
                Simple::OpenBelow => buffer.open_below(),
                Simple::OpenAbove => buffer.open_above(),
                // Dot-repeat needs a record of the last change, which this
                // subset does not keep. Saying so beats doing nothing silently.
                Simple::Repeat => {}
                // Taken above, before the buffer was borrowed.
                Simple::Format => unreachable!("handled before the buffer borrow"),
            },
        }

        let has_selection = buffer.has_selection();

        // An operator that found nothing leaves the register alone rather than
        // clearing it to an empty string.
        if let Some(yanked) = yanked {
            if !yanked.text.is_empty() {
                if copies_out {
                    self.copy_out(&yanked.text);
                }
                self.yank = yanked;
            }
        }
        if selection_changed {
            self.input.set_vim_visual(has_selection);
        }
        if matches!(
            cmd,
            vim::Command::Simple {
                cmd: Simple::Repeat,
                ..
            }
        ) {
            self.note("`.` repeat is not implemented — use ^g for $EDITOR");
        }
    }

    /// Pretty-print the body of the buffer under the cursor.
    ///
    /// One checkpoint, so `u` puts the body back exactly as it was — which is
    /// what makes this safe to try on a request you care about. Failures are
    /// reported with the reason rather than leaving the operator wondering
    /// whether the key registered.
    pub(super) fn format_buffer(&mut self) {
        let note = match self.active_buffer() {
            None => "nothing to format here".to_string(),
            Some(buffer) => {
                let current = buffer.text();
                match lockgate_core::pretty::pretty_message(&current) {
                    // Saying so beats a checkpoint and a no-op edit that makes
                    // the buffer look dirty for no reason.
                    Ok((formatted, _)) if formatted == current => "already formatted".to_string(),
                    Ok((formatted, language)) => {
                        buffer.checkpoint();
                        buffer.set_text(&formatted);
                        match language {
                            // Whitespace between HTML elements can render as a
                            // space, so this one is not purely cosmetic and the
                            // operator should know before forwarding it.
                            lockgate_core::http_text::Language::Html => {
                                "HTML reformatted — whitespace changed, u to undo".to_string()
                            }
                            _ => "body reformatted — u to undo".to_string(),
                        }
                    }
                    Err(e) => format!("cannot format: {e}"),
                }
            }
        };
        self.note(&note);
    }

    /// Put a yank on the system clipboard, reporting rather than failing.
    ///
    /// A clipboard that did not take is worth saying out loud: the text is
    /// still in our own register, so `p` works, and the operator would
    /// otherwise only discover it after switching windows to paste.
    fn copy_out(&self, text: &str) {
        let chars = text.chars().count();
        match crate::clipboard::copy(text) {
            Ok(()) => self.note(&format!("yanked {chars} char(s) → clipboard")),
            // Off a terminal there is no clipboard to reach and nothing went
            // wrong, so report the yank plainly rather than as a failure.
            Err(crate::clipboard::ClipboardError::NotATerminal) => {
                self.note(&format!("yanked {chars} char(s)"))
            }
            Err(e) => self.note(&format!("yanked {chars} char(s); clipboard failed: {e}")),
        }
    }

    /// Route a keystroke to whichever buffer the active window is editing.
    /// Windows with nothing editable swallow it, so `i` there is inert rather
    /// than scribbling into a buffer the operator cannot see.
    fn edit(&mut self, key: InsertKey) {
        // `i` from the queue means "edit this one", so open its preview rather
        // than leaving the operator in INSERT with nothing underneath the
        // cursor. `<CR>` is still the way to open one just to read it.
        if (self.window == Window::Intercept && self.intercept.pane == Pane::Table)
            || (self.window == Window::Repeater && !self.repeater.focused)
        {
            self.enter_preview();
        }
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
    pub(super) fn active_buffer(&mut self) -> Option<&mut TextBuffer> {
        match self.window {
            Window::Repeater => {
                let session = self.repeater.session_mut();
                session.original.is_some().then_some(&mut session.request)
            }
            Window::Intercept => self.preview_buffer(self.intercept.showing_requests()),
            Window::Notes => self.note_buffer(),
            Window::Findings => self.write_up_buffer(),
            _ => None,
        }
    }

    /// The buffer for the highlighted finding's write-up, created on first use.
    ///
    /// Forked from the rendered document rather than re-rendered every frame:
    /// once typing starts the buffer *is* the write-up, and re-rendering it from
    /// the columns under the cursor would throw away unsaved lines.
    pub(super) fn write_up_buffer(&mut self) -> Option<&mut TextBuffer> {
        let finding = self.findings.get(self.findings_view.row)?;
        let (id, text) = (finding.id, finding.write_up());
        if self.findings_view.edit.as_ref().map(|(i, _)| *i) != Some(id) {
            self.findings_view.edit = Some((id, TextBuffer::from_text(&text)));
        }
        self.findings_view.edit.as_mut().map(|(_, b)| b)
    }

    /// Split the open write-up back into the four prose columns, if it has been
    /// touched.
    ///
    /// Called on every way out of the buffer for the same reason `save_note` is:
    /// a write-up you have to remember to save is a write-up you lose.
    pub(super) fn save_write_up(&mut self) {
        let Some((id, buffer)) = &self.findings_view.edit else {
            return;
        };
        if !buffer.is_dirty() {
            return;
        }
        let (id, write_up) = (*id, lockgate_core::WriteUp::parse(&buffer.text()));
        if self.engine.set_finding_write_up(id, &write_up) == 0 {
            self.note(&format!("finding #{id} is gone; edit not saved"));
            return;
        }
        // Clean again, so leaving twice does not write twice. The buffer is left
        // as it is rather than re-rendered from the saved columns — normalising
        // the document under the cursor mid-edit would move text the operator is
        // still looking at.
        if let Some((_, buffer)) = &mut self.findings_view.edit {
            buffer.clear_dirty();
        }
        self.refresh();
        self.note(&format!("saved finding #{id}"));
    }

    /// The buffer for the highlighted note, created on first use.
    ///
    /// Forked from the stored body rather than re-read every frame: the buffer
    /// is the live document once typing starts, and reloading it from SQLite
    /// under the cursor would throw away unsaved lines.
    pub(super) fn note_buffer(&mut self) -> Option<&mut TextBuffer> {
        let note = self.notes.get(self.notes_view.row)?;
        let (id, body) = (note.id, note.body_md.clone());
        if self.notes_view.edit.as_ref().map(|(i, _)| *i) != Some(id) {
            self.notes_view.edit = Some((id, TextBuffer::from_text(&body)));
        }
        self.notes_view.edit.as_mut().map(|(_, b)| b)
    }

    /// Write the open note back if it has been touched.
    ///
    /// Called on every way out of the buffer — leaving it, moving to another
    /// note, changing window, quitting — because a note has no explicit save
    /// key. `:w` would be the vim answer, but a document you have to remember
    /// to save is a document you lose.
    pub(super) fn save_note(&mut self) {
        let Some((id, buffer)) = &self.notes_view.edit else {
            return;
        };
        if !buffer.is_dirty() {
            return;
        }
        let (id, body) = (*id, buffer.text());
        if self.engine.update_note(id, None, Some(&body)) == 0 {
            self.note(&format!("note #{id} is gone; edit not saved"));
            return;
        }
        // Clean again, so leaving twice does not write twice. The buffer itself
        // is kept as it is — rebuilding it from the saved text would send the
        // cursor back to the top of a note you are still in the middle of.
        if let Some((_, buffer)) = &mut self.notes_view.edit {
            buffer.clear_dirty();
        }
        self.refresh();
        self.note(&format!("saved note #{id}"));
    }

    /// The buffer backing one column's preview, created on first use.
    ///
    /// Both columns get one, responses included — it is what carries the cursor
    /// for reading. Whether typing into it is *allowed* is a separate question,
    /// answered in [`App::edit`].
    pub(super) fn preview_buffer(&mut self, requests: bool) -> Option<&mut TextBuffer> {
        let held = self.held(requests).get(self.intercept.row(requests))?;
        let ticket = held.ticket;
        let text = render_pending(&held.pending);
        let slot = self.intercept.edit(requests);
        if slot.as_ref().map(|(t, _)| *t) != Some(ticket) {
            *slot = Some((ticket, TextBuffer::from_text(&text)));
        }
        slot.as_mut().map(|(_, b)| b)
    }

    // --- intercept ---
}
