//! Reusable pieces of the interface: panes, the buffer view, and the
//! line builders the detail panes are made of.

use super::*;

/// How many of a socket's most recent frames the transcript keeps. A long-lived
/// connection carries thousands; rendering all of them every tick is the one
/// thing that would make the WebSocket window slow.
pub(super) const WS_FRAME_CAP: usize = 1_000;

/// A bordered, wrapping pane — the shared shell for Request and Response.
pub(super) fn pane(lines: Vec<Line<'static>>, title: impl Into<String>) -> Paragraph<'static> {
    Paragraph::new(lines)
        .block(Block::bordered().title(title.into()))
        .wrap(Wrap { trim: false })
}

/// A pane showing an editable buffer: a line-number gutter, syntax-highlighted
/// text, and a block cursor when the buffer has focus.
///
/// Renders itself rather than returning a `Paragraph`, because the gutter and
/// the text scroll differently — the text moves sideways on a long line while
/// the numbers must stay put. That needs two widgets in two sub-areas, which a
/// single `Paragraph` cannot express.
pub(super) struct BufferView<'a> {
    pub(super) buffer: &'a TextBuffer,
    /// Shared with the app so a body highlighted this frame is free the next.
    pub(super) cache: Option<&'a crate::highlighter::SharedCache>,
    pub(super) title: String,
    pub(super) focused: bool,
    pub(super) inserting: bool,
    pub(super) border: Style,
    /// Vertical offset to use when the buffer does *not* have focus, where
    /// scrolling is driven by the window's own `j`/`k` rather than a cursor.
    pub(super) scroll: u16,
}

impl BufferView<'_> {
    /// Width of the number gutter, including its trailing space.
    pub(super) fn gutter_width(&self) -> u16 {
        let digits = self.buffer.lines().len().to_string().len().max(2);
        digits as u16 + 2
    }

    /// How far down to scroll so the cursor stays on screen.
    ///
    /// The bug this fixes: `content_scroll` only ever moved on `j`/`k` in a
    /// window with no focused buffer, so once a buffer had focus — and
    /// especially after `gq` turned one line into forty — the cursor walked off
    /// the bottom and the view never followed.
    ///
    /// Stateless, and pinned to the last row rather than centred, matching how
    /// the queue list above it scrolls. Nothing is stored, so the offset cannot
    /// drift out of agreement with the cursor.
    pub(super) fn vertical_scroll(&self, rows: u16) -> u16 {
        if !self.focused {
            return self.scroll;
        }
        let visible = rows.max(1) as usize;
        self.buffer.cursor().line.saturating_sub(visible - 1) as u16
    }

    /// How far sideways, so the far end of a minified body is reachable.
    ///
    /// The companion to this pane's refusal to wrap: a wrapped line occupies
    /// more than one screen row, which would put the cursor somewhere other
    /// than where the buffer says it is, and a text editor whose cursor lies
    /// about its position is worse than one that scrolls. Short lines stay
    /// pinned at column zero so the view holds still until it must move.
    pub(super) fn horizontal_scroll(&self, cols: u16) -> u16 {
        // One column spare, so the cursor is never flush against the edge.
        let visible = cols.saturating_sub(1) as usize;
        self.buffer.cursor().col.saturating_sub(visible) as u16
    }

    /// Vim's hybrid gutter: distance from the cursor on every line, but the
    /// cursor's own line shows its absolute number — relative numbers are for
    /// counting a jump, and `0` would say nothing.
    ///
    /// Without focus there is no cursor and nothing to count *to*, so the
    /// numbers go absolute. A relative gutter in a pane you cannot move around
    /// in would be measuring from a cursor the operator cannot see.
    pub(super) fn gutter(&self, width: u16) -> Vec<Line<'static>> {
        let cursor = self.buffer.cursor().line;
        let width = width.saturating_sub(1) as usize;
        (0..self.buffer.lines().len())
            .map(|line| {
                if !self.focused {
                    return Line::styled(format!("{:>width$} ", line + 1), muted());
                }
                if line == cursor {
                    Line::styled(
                        format!("{:<width$} ", line + 1),
                        Style::new().fg(Color::Cyan),
                    )
                } else {
                    Line::styled(format!("{:>width$} ", line.abs_diff(cursor)), muted())
                }
            })
            .collect()
    }

    /// The text itself: syntax underneath, cursor and selection layered on top.
    fn body(&self) -> Vec<Line<'static>> {
        let cursor = self.buffer.cursor();
        // Layering this way keeps the two concerns apart: the highlighter never
        // has to know a cursor exists, and `patch` lets a selection shade the
        // background while leaving the token's own foreground colour intact.
        let syntax = crate::syntax::highlight_with(self.buffer.lines(), self.cache);
        // Two cursors, because they mean different things: white where the next
        // key inserts text, cyan where it only moves.
        let cursor_bg = if self.inserting {
            Color::White
        } else {
            Color::Cyan
        };
        let cursor_style = Style::new().fg(Color::Black).bg(cursor_bg);
        let selected = Style::new().bg(Color::Rgb(60, 60, 100));
        let has_selection = self.buffer.has_selection();

        self.buffer
            .lines()
            .iter()
            .zip(syntax)
            .enumerate()
            .map(|(line, (text, mut styles))| {
                if self.focused {
                    // Per-cell so the selection and the cursor can overlap: the
                    // cursor sits inside its own selection and must stay visible
                    // there.
                    for (col, style) in styles.iter_mut().enumerate() {
                        if line == cursor.line && col == cursor.col {
                            *style = style.patch(cursor_style);
                        } else if has_selection && self.buffer.in_selection(Cursor { line, col }) {
                            *style = style.patch(selected);
                        }
                    }
                }
                let mut spans = crate::syntax::coalesce(text, &styles);
                // Past the last character there is nothing to invert, so a
                // space stands in for the cell.
                if self.focused && line == cursor.line && cursor.col >= text.chars().count() {
                    spans.push(Span::styled(" ", cursor_style));
                }
                Line::from(spans)
            })
            .collect()
    }

    pub(super) fn render(self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .title(self.title.clone())
            .border_style(self.border);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let gutter_width = self.gutter_width();
        let [gutter_area, text_area] =
            Layout::horizontal([Constraint::Length(gutter_width), Constraint::Min(0)]).areas(inner);

        // One offset for both, or the numbers would slide out of step with the
        // lines they label.
        let vertical = self.vertical_scroll(inner.height);

        frame.render_widget(
            Paragraph::new(self.gutter(gutter_width)).scroll((vertical, 0)),
            gutter_area,
        );
        frame.render_widget(
            Paragraph::new(self.body()).scroll((vertical, self.horizontal_scroll(text_area.width))),
            text_area,
        );
    }
}

/// A bordered pane with a single muted message — used when a window has nothing
/// to show because no flow is selected.
pub(super) fn empty_pane(title: &'static str, message: &'static str) -> Paragraph<'static> {
    Paragraph::new(Line::styled(message, muted())).block(Block::bordered().title(title))
}

/// How a rule's host pattern should be read, for the rules list.
pub(super) fn kind_label(rule: &lockgate_core::scope::ScopeRule) -> &'static str {
    match rule.spec.host {
        Some((lockgate_core::scope::HostKind::Glob, _)) => "glob",
        Some((lockgate_core::scope::HostKind::Regex, _)) => "regex",
        Some((lockgate_core::scope::HostKind::Cidr, _)) => "cidr",
        None => "any",
    }
}

/// The rule as text: host, then the port and path constraints if it has them.
pub(super) fn rule_pattern(rule: &lockgate_core::scope::ScopeRule) -> String {
    let mut out = match &rule.spec.host {
        Some((_, pattern)) => pattern.clone(),
        None => "*".to_string(),
    };
    if let Some(port) = rule.spec.port {
        out.push_str(&format!(":{port}"));
    }
    if let Some(prefix) = &rule.spec.path_prefix {
        out.push_str(prefix);
    }
    out
}

/// A section header inside the Automate pane.
pub(super) fn section(lines: &mut Vec<Line<'static>>, title: &str) {
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(
        title.to_string(),
        Style::new().bold().fg(Color::Cyan),
    ));
}

/// A right-aligned label and its value, so fields line up in a column.
pub(super) fn field(lines: &mut Vec<Line<'static>>, label: &str, value: impl Into<String>) {
    lines.push(Line::from(vec![
        Span::styled(format!("{label:>13}  "), muted()),
        Span::raw(value.into()),
    ]));
}

/// Start line, then headers, then a blank line and the body preview.
pub(super) fn message_lines(
    start: Line<'static>,
    headers: &HeaderMap,
    body: &[u8],
) -> Vec<Line<'static>> {
    let header_text: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or("<binary>")))
        .collect();

    // Decoded for reading. The stored bytes are what arrived — see
    // `lockgate_core::encoding` — but compressed bytes on screen are noise, and
    // nothing downstream of here can highlight or format them.
    let raw = hudsucker::hyper::body::Bytes::copy_from_slice(body);
    let decoded = lockgate_core::encoding::decoded(headers, &raw);
    let was_decoded = decoded != raw;

    let body = if decoded.is_empty() {
        String::new()
    } else {
        preview(&decoded)
    };

    let mut lines = vec![start];
    lines.extend(crate::syntax::highlighted_head_and_body(
        &header_text,
        &body,
    ));
    if was_decoded {
        // Said out loud: the body on screen is not byte-for-byte what came off
        // the wire, and an operator comparing lengths deserves to know why.
        if let Some(coding) = lockgate_core::encoding::coding_of(headers) {
            lines.push(Line::styled(
                format!("(decoded {} for display)", coding.as_str()),
                muted(),
            ));
        }
    }
    lines
}

/// Bodies are arbitrary bytes; show a lossy, truncated preview.
pub(super) fn preview(body: &[u8]) -> String {
    const LIMIT: usize = 2_000;
    let text = String::from_utf8_lossy(&body[..body.len().min(LIMIT)]);
    if body.len() > LIMIT {
        format!("{text}\n… ({} bytes total)", body.len())
    } else {
        text.into_owned()
    }
}
