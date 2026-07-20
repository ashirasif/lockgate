//! A multiline text buffer with a cursor and the vim motions and operators that
//! are worth having in a pane.
//!
//! Motions, operators, text objects and visual mode, driven by the grammar in
//! [`crate::vim`]. Everything an operator does goes through a [`Range`], so a
//! new motion or text object costs one function here and works with every
//! operator and count automatically.
//!
//! Still a subset. Named registers, marks, macros, `.` repeat and blockwise
//! visual are not here, and `e` hands the buffer to the operator's real editor
//! for those. The line is drawn at what you reach for without thinking while
//! reading a request.
//!
//! Lines are stored split rather than as one string with offsets, because every
//! consumer (rendering, cursor math) wants lines, and an HTTP message is small
//! enough that the copying cost is irrelevant. Undo works the same way: whole
//! snapshots, because a few kilobytes of history per edit is free at this size
//! and a diff-based scheme would be the only fiddly part of the file.

use crate::vim::{Motion as VimMotion, ObjectKind, TextObject};

/// A cursor position. `col` is a character index within `line`, and may equal
/// the line's length — that is the position after the last character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub line: usize,
    pub col: usize,
}

/// Text taken out of a buffer, and how it should go back in.
///
/// `linewise` is the distinction between `yy` and `yw`: the first pastes as
/// whole lines above or below, the second inside the current one. Getting this
/// wrong is what makes a homegrown `p` feel broken.
#[derive(Debug, Clone, Default)]
pub struct Yank {
    pub text: String,
    pub linewise: bool,
}

/// A point-in-time copy of the buffer, for undo.
#[derive(Debug, Clone)]
struct Snapshot {
    lines: Vec<String>,
    cursor: Cursor,
}

#[derive(Debug, Clone, Default)]
pub struct TextBuffer {
    lines: Vec<String>,
    cursor: Cursor,
    /// Set by any mutation, cleared by the owner once it has acted on the change.
    /// Lets the Repeater know its parsed form is stale without diffing text.
    dirty: bool,
    undo: Vec<Snapshot>,
    redo: Vec<Snapshot>,
    /// Where a visual selection started, if one is up. The other end is the
    /// cursor, which is what makes motions extend the selection for free.
    anchor: Option<Cursor>,
    selection_linewise: bool,
}

impl TextBuffer {
    pub fn from_text(text: &str) -> Self {
        Self {
            lines: text.split('\n').map(str::to_string).collect(),
            cursor: Cursor::default(),
            dirty: false,
            undo: Vec::new(),
            redo: Vec::new(),
            anchor: None,
            selection_linewise: false,
        }
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Put the cursor somewhere, clamped into the buffer. Used by motions,
    /// which compute a destination rather than stepping to it.
    pub fn set_cursor(&mut self, at: Cursor) {
        self.cursor.line = at.line.min(self.lines.len().saturating_sub(1));
        self.cursor.col = at.col;
        self.clamp_col();
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Mark the buffer changed without going through an edit method — for text
    /// that came back altered from somewhere else, such as an external editor.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    // --- editing ---

    pub fn insert_char(&mut self, c: char) {
        let col = self.cursor.col;
        let line = self.line_mut();
        let at = byte_index(line, col);
        line.insert(at, c);
        self.cursor.col += 1;
        self.dirty = true;
    }

    /// Split the current line at the cursor.
    pub fn insert_newline(&mut self) {
        let col = self.cursor.col;
        let line = self.line_mut();
        let at = byte_index(line, col);
        let tail = line.split_off(at);
        self.lines.insert(self.cursor.line + 1, tail);
        self.cursor.line += 1;
        self.cursor.col = 0;
        self.dirty = true;
    }

    /// Delete the character before the cursor, joining lines at column 0.
    pub fn backspace(&mut self) {
        if self.cursor.col > 0 {
            let col = self.cursor.col;
            let line = self.line_mut();
            let at = byte_index(line, col - 1);
            line.remove(at);
            self.cursor.col -= 1;
            self.dirty = true;
            return;
        }
        // At column 0: join with the previous line, landing where the seam is.
        if self.cursor.line == 0 {
            return;
        }
        let tail = self.lines.remove(self.cursor.line);
        self.cursor.line -= 1;
        self.cursor.col = self.lines[self.cursor.line].chars().count();
        self.lines[self.cursor.line].push_str(&tail);
        self.dirty = true;
    }

    /// Delete the character under the cursor, joining the next line at line end.
    pub fn delete(&mut self) {
        let len = self.line_len();
        if self.cursor.col < len {
            let col = self.cursor.col;
            let line = self.line_mut();
            let at = byte_index(line, col);
            line.remove(at);
            self.dirty = true;
            return;
        }
        if self.cursor.line + 1 >= self.lines.len() {
            return;
        }
        let tail = self.lines.remove(self.cursor.line + 1);
        self.lines[self.cursor.line].push_str(&tail);
        self.dirty = true;
    }

    // --- movement ---
    //
    // Vertical movement clamps the column to the destination line rather than
    // remembering a "desired column". Remembering it is what a real editor does,
    // but it is surprising in a box this small, and clamping never loses data.

    pub fn left(&mut self) {
        if self.cursor.col > 0 {
            self.cursor.col -= 1;
        } else if self.cursor.line > 0 {
            self.cursor.line -= 1;
            self.cursor.col = self.line_len();
        }
    }

    pub fn right(&mut self) {
        if self.cursor.col < self.line_len() {
            self.cursor.col += 1;
        } else if self.cursor.line + 1 < self.lines.len() {
            self.cursor.line += 1;
            self.cursor.col = 0;
        }
    }

    pub fn up(&mut self) {
        if self.cursor.line > 0 {
            self.cursor.line -= 1;
            self.clamp_col();
        }
    }

    pub fn down(&mut self) {
        if self.cursor.line + 1 < self.lines.len() {
            self.cursor.line += 1;
            self.clamp_col();
        }
    }

    /// `gg` — first line, keeping the column where it fits.
    pub fn top(&mut self) {
        self.cursor.line = 0;
        self.clamp_col();
    }

    /// `G` — last line.
    pub fn bottom(&mut self) {
        self.cursor.line = self.lines.len().saturating_sub(1);
        self.clamp_col();
    }

    /// Jump to a zero-based line, clamped to the buffer.
    pub fn goto_line(&mut self, line: usize) {
        self.cursor.line = line.min(self.lines.len().saturating_sub(1));
        self.clamp_col();
    }

    pub fn line_start(&mut self) {
        self.cursor.col = 0;
    }

    pub fn line_end(&mut self) {
        self.cursor.col = self.line_len();
    }

    fn clamp_col(&mut self) {
        self.cursor.col = self.cursor.col.min(self.line_len());
    }

    fn line_len(&self) -> usize {
        self.lines
            .get(self.cursor.line)
            .map(|l| l.chars().count())
            .unwrap_or(0)
    }

    /// The current line, creating an empty buffer line if somehow absent so no
    /// edit path can panic on an out-of-range cursor.
    fn line_mut(&mut self) -> &mut String {
        if self.lines.is_empty() {
            self.lines.push(String::new());
        }
        let i = self.cursor.line.min(self.lines.len() - 1);
        self.cursor.line = i;
        &mut self.lines[i]
    }
}

/// A span of the buffer for an operator to work on.
///
/// `end` is exclusive, which is the only representation that lets `dw` (stop
/// before the next word) and `de` (take the last character) share one code path
/// — the inclusive motions simply push `end` one further before we get here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: Cursor,
    pub end: Cursor,
    pub linewise: bool,
}

impl TextBuffer {
    // --- selection ---

    /// Start a selection at the cursor, or drop it if one is already up.
    /// Returns whether a selection is now active.
    pub fn toggle_selection(&mut self, linewise: bool) -> bool {
        match self.anchor {
            // Switching v↔V keeps the anchor and changes the shape, as vim does.
            Some(_) if self.selection_linewise != linewise => {
                self.selection_linewise = linewise;
                true
            }
            Some(_) => {
                self.anchor = None;
                false
            }
            None => {
                self.anchor = Some(self.cursor);
                self.selection_linewise = linewise;
                true
            }
        }
    }

    pub fn clear_selection(&mut self) {
        self.anchor = None;
    }

    pub fn has_selection(&self) -> bool {
        self.anchor.is_some()
    }

    /// `o` — put the cursor on the other end of the selection.
    pub fn swap_selection_ends(&mut self) {
        if let Some(anchor) = self.anchor {
            self.anchor = Some(self.cursor);
            self.cursor = anchor;
            self.clamp_col();
        }
    }

    /// The selected span, ordered, with the cursor's character included —
    /// vim's visual mode selects *through* the cursor, not up to it.
    pub fn selection_range(&self) -> Option<Range> {
        let anchor = self.anchor?;
        let (start, end) = if (anchor.line, anchor.col) <= (self.cursor.line, self.cursor.col) {
            (anchor, self.cursor)
        } else {
            (self.cursor, anchor)
        };
        Some(Range {
            start,
            end: Cursor {
                line: end.line,
                col: end.col + 1,
            },
            linewise: self.selection_linewise,
        })
    }

    /// Whether a position falls inside the selection, for highlighting.
    pub fn in_selection(&self, at: Cursor) -> bool {
        let Some(range) = self.selection_range() else {
            return false;
        };
        if range.linewise {
            return at.line >= range.start.line && at.line <= range.end.line;
        }
        (at.line, at.col) >= (range.start.line, range.start.col)
            && (at.line, at.col) < (range.end.line, range.end.col)
    }

    // --- motions as positions ---

    /// Where `motion` would put the cursor, without moving it.
    ///
    /// Pure, because an operator needs the destination as a *range endpoint*
    /// rather than as a move — `dw` must not leave the cursor where `w` would.
    pub fn motion_target(&self, motion: VimMotion, count: usize) -> Cursor {
        let mut probe = self.clone();
        for _ in 0..count {
            match motion {
                VimMotion::Left => probe.left_in_line(),
                VimMotion::Right => probe.right_in_line(),
                VimMotion::Up => probe.up(),
                VimMotion::Down => probe.down(),
                VimMotion::WordForward { big } => probe.word_forward_impl(big),
                VimMotion::WordBackward { big } => probe.word_backward_impl(big),
                VimMotion::WordEnd { big } => probe.word_end_impl(big),
                VimMotion::LineStart => probe.line_start(),
                VimMotion::FirstNonBlank => probe.first_non_blank(),
                VimMotion::LineEnd => probe.line_end(),
                VimMotion::Top => probe.top(),
                VimMotion::Bottom => probe.bottom(),
                VimMotion::GotoLine(n) => probe.goto_line(n.saturating_sub(1)),
                VimMotion::Find { ch, backward, till } => probe.find_char(ch, backward, till),
            }
        }
        probe.cursor
    }

    /// `h`/`l` stop at the line's edges rather than wrapping, unlike the arrow
    /// keys used while inserting.
    fn left_in_line(&mut self) {
        self.cursor.col = self.cursor.col.saturating_sub(1);
    }

    fn right_in_line(&mut self) {
        self.cursor.col = (self.cursor.col + 1).min(self.line_len());
    }

    /// `f`/`F`/`t`/`T` — search within the current line only, as in vim.
    fn find_char(&mut self, ch: char, backward: bool, till: bool) {
        let line: Vec<char> = self
            .lines
            .get(self.cursor.line)
            .map(|l| l.chars().collect())
            .unwrap_or_default();
        let found = if backward {
            (0..self.cursor.col)
                .rev()
                .find(|&i| line.get(i) == Some(&ch))
        } else {
            (self.cursor.col + 1..line.len()).find(|&i| line.get(i) == Some(&ch))
        };
        if let Some(i) = found {
            // `t` stops one short, on the near side of the target.
            self.cursor.col = match (till, backward) {
                (true, false) => i.saturating_sub(1),
                (true, true) => i + 1,
                (false, _) => i,
            };
        }
    }

    // --- ranges ---

    /// The span an operator should act on for a motion from the cursor.
    pub fn range_for_motion(&self, motion: VimMotion, count: usize) -> Range {
        let target = self.motion_target(motion, count);
        let (mut start, mut end) =
            if (target.line, target.col) < (self.cursor.line, self.cursor.col) {
                (target, self.cursor)
            } else {
                (self.cursor, target)
            };

        if motion.linewise() {
            return Range {
                start: Cursor {
                    line: start.line,
                    col: 0,
                },
                end: Cursor {
                    line: end.line,
                    col: 0,
                },
                linewise: true,
            };
        }
        // An inclusive motion takes the character it landed on. Only extend the
        // forward end, or `dF(` would swallow a character behind the cursor.
        if motion.inclusive() && (target.line, target.col) >= (self.cursor.line, self.cursor.col) {
            end.col += 1;
        }
        // Backward motions leave the cursor's own character alone.
        if (target.line, target.col) < (self.cursor.line, self.cursor.col) {
            start = target;
        }
        Range {
            start,
            end,
            linewise: false,
        }
    }

    /// Whole lines under the cursor — `dd`, `cc`, `yy`.
    pub fn range_for_lines(&self, count: usize) -> Range {
        let last = self.lines.len().saturating_sub(1);
        Range {
            start: Cursor {
                line: self.cursor.line,
                col: 0,
            },
            end: Cursor {
                line: (self.cursor.line + count - 1).min(last),
                col: 0,
            },
            linewise: true,
        }
    }

    /// The span of a text object around the cursor, or `None` if the cursor is
    /// not inside one — `ci"` outside any quotes does nothing, rather than
    /// guessing at a nearby pair.
    pub fn range_for_object(&self, object: TextObject) -> Option<Range> {
        match object.kind {
            ObjectKind::Word { big } => self.word_object(big, object.around),
            ObjectKind::Quote(q) => self.pair_object(q, q, object.around),
            ObjectKind::Delim(open) => {
                let close = match open {
                    '(' => ')',
                    '[' => ']',
                    '{' => '}',
                    '<' => '>',
                    _ => return None,
                };
                self.pair_object(open, close, object.around)
            }
        }
    }

    /// `iw` / `aw`. `aw` takes the trailing whitespace, or the leading run if
    /// there is none — matching vim, and the reason `daw` between two words
    /// leaves exactly one space.
    fn word_object(&self, big: bool, around: bool) -> Option<Range> {
        let line: Vec<char> = self.lines.get(self.cursor.line)?.chars().collect();
        if line.is_empty() {
            return None;
        }
        let col = self.cursor.col.min(line.len() - 1);
        let class = |c: char| if big { big_class(c) } else { class_of(c) };
        let here = class(line[col]);

        let mut start = col;
        while start > 0 && class(line[start - 1]) == here {
            start -= 1;
        }
        let mut end = col + 1;
        while end < line.len() && class(line[end]) == here {
            end += 1;
        }

        if around {
            let after = end;
            while end < line.len() && class_of(line[end]) == CharClass::Space {
                end += 1;
            }
            // No trailing whitespace: take the leading run instead.
            if end == after {
                while start > 0 && class_of(line[start - 1]) == CharClass::Space {
                    start -= 1;
                }
            }
        }

        Some(Range {
            start: Cursor {
                line: self.cursor.line,
                col: start,
            },
            end: Cursor {
                line: self.cursor.line,
                col: end,
            },
            linewise: false,
        })
    }

    /// `i(` / `a"`. Bracket pairs nest and may span lines; quotes do neither,
    /// so they are matched within the line.
    fn pair_object(&self, open: char, close: char, around: bool) -> Option<Range> {
        if open == close {
            return self.quote_object(open, around);
        }

        // Scan back for an unmatched opener, then forward for its partner.
        let mut depth = 0i32;
        let mut at = self.cursor;
        let start = loop {
            let c = char_at(&self.lines, at);
            if c == Some(close) && at != self.cursor {
                depth += 1;
            } else if c == Some(open) {
                if depth == 0 {
                    break at;
                }
                depth -= 1;
            }
            at = retreat(&self.lines, at)?;
        };

        depth = 0;
        let mut at = advance(&self.lines, start)?;
        let end = loop {
            match char_at(&self.lines, at) {
                Some(c) if c == open => depth += 1,
                Some(c) if c == close => {
                    if depth == 0 {
                        break at;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            at = advance(&self.lines, at)?;
        };

        Some(if around {
            Range {
                start,
                end: Cursor {
                    line: end.line,
                    col: end.col + 1,
                },
                linewise: false,
            }
        } else {
            Range {
                start: advance(&self.lines, start)?,
                end,
                linewise: false,
            }
        })
    }

    /// Quotes have no nesting, so the pair is found by counting from the start
    /// of the line — the cursor is inside if an odd number precede it.
    fn quote_object(&self, quote: char, around: bool) -> Option<Range> {
        let line: Vec<char> = self.lines.get(self.cursor.line)?.chars().collect();
        let positions: Vec<usize> = line
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == quote)
            .map(|(i, _)| i)
            .collect();

        let pair = positions
            .chunks(2)
            .filter(|c| c.len() == 2)
            .find(|c| self.cursor.col <= c[1])?;
        let (open, close) = (pair[0], pair[1]);

        let (start, end) = if around {
            (open, close + 1)
        } else {
            (open + 1, close)
        };
        Some(Range {
            start: Cursor {
                line: self.cursor.line,
                col: start,
            },
            end: Cursor {
                line: self.cursor.line,
                col: end,
            },
            linewise: false,
        })
    }

    // --- acting on ranges ---

    /// Copy a range without changing the buffer.
    pub fn yank_range(&self, range: Range) -> Yank {
        if range.linewise {
            let last = self.lines.len().saturating_sub(1);
            let text = (range.start.line..=range.end.line.min(last))
                .filter_map(|i| self.lines.get(i).cloned())
                .collect::<Vec<_>>()
                .join("\n");
            return Yank {
                text,
                linewise: true,
            };
        }
        Yank {
            text: self.slice(range),
            linewise: false,
        }
    }

    /// Remove a range, returning what came out.
    pub fn delete_range(&mut self, range: Range) -> Yank {
        let taken = self.yank_range(range);
        if taken.text.is_empty() && !range.linewise {
            return taken;
        }
        self.checkpoint();
        self.dirty = true;

        if range.linewise {
            let last = self.lines.len().saturating_sub(1);
            let end = range.end.line.min(last);
            self.lines.drain(range.start.line..=end);
            if self.lines.is_empty() {
                self.lines.push(String::new());
            }
            self.cursor.line = range.start.line.min(self.lines.len() - 1);
            self.cursor.col = 0;
            self.clamp_col();
            return taken;
        }

        if range.start.line == range.end.line {
            let line = &mut self.lines[range.start.line];
            let from = byte_index(line, range.start.col);
            let to = byte_index(line, range.end.col);
            line.replace_range(from..to, "");
        } else {
            // Multi-line charwise: keep the head of the first line and the tail
            // of the last, and drop everything between.
            let tail = {
                let line = &self.lines[range.end.line];
                let at = byte_index(line, range.end.col);
                line[at..].to_string()
            };
            {
                let line = &mut self.lines[range.start.line];
                let at = byte_index(line, range.start.col);
                line.truncate(at);
                line.push_str(&tail);
            }
            self.lines.drain(range.start.line + 1..=range.end.line);
        }
        self.cursor = range.start;
        self.clamp_col();
        taken
    }

    /// The text a charwise range covers.
    fn slice(&self, range: Range) -> String {
        if range.start.line == range.end.line {
            let Some(line) = self.lines.get(range.start.line) else {
                return String::new();
            };
            return line
                .chars()
                .skip(range.start.col)
                .take(range.end.col.saturating_sub(range.start.col))
                .collect();
        }
        let mut out = String::new();
        for i in range.start.line..=range.end.line.min(self.lines.len().saturating_sub(1)) {
            let Some(line) = self.lines.get(i) else { break };
            if i == range.start.line {
                out.extend(line.chars().skip(range.start.col));
            } else if i == range.end.line {
                out.push('\n');
                out.extend(line.chars().take(range.end.col));
            } else {
                out.push('\n');
                out.push_str(line);
            }
        }
        out
    }

    /// `J` — join the following line onto this one, with a single space.
    pub fn join_lines(&mut self, count: usize) {
        for _ in 0..count.max(1) {
            if self.cursor.line + 1 >= self.lines.len() {
                return;
            }
            self.checkpoint();
            let next = self.lines.remove(self.cursor.line + 1);
            let line = &mut self.lines[self.cursor.line];
            self.cursor.col = line.chars().count();
            if !line.is_empty() && !next.is_empty() {
                line.push(' ');
            }
            line.push_str(next.trim_start());
            self.dirty = true;
        }
    }
}

/// `W`/`B`/`E` split on whitespace alone, so `api.example.com` is one big word.
fn big_class(c: char) -> CharClass {
    if c.is_whitespace() {
        CharClass::Space
    } else {
        CharClass::Word
    }
}

fn char_at(lines: &[String], at: Cursor) -> Option<char> {
    lines.get(at.line)?.chars().nth(at.col)
}

/// What kind of run a character belongs to, for word motions.
///
/// Vim's `w` treats a run of word characters and a run of punctuation as
/// separate words, which is why `foo.bar` is three of them. Collapsing the two
/// into "not whitespace" is the usual shortcut, and it is wrong in exactly the
/// place it matters here: URLs and header values are mostly punctuation.
#[derive(PartialEq, Eq, Clone, Copy)]
enum CharClass {
    Word,
    Punct,
    Space,
}

fn class_of(c: char) -> CharClass {
    if c.is_alphanumeric() || c == '_' {
        CharClass::Word
    } else if c.is_whitespace() {
        CharClass::Space
    } else {
        CharClass::Punct
    }
}

impl TextBuffer {
    // --- undo ---

    /// Record the current state as an undo point.
    ///
    /// Called before an operator, and once when entering insert — not per
    /// keystroke. That is what makes a whole insert session undo as one step,
    /// the way vim does it, rather than one character at a time.
    pub fn checkpoint(&mut self) {
        self.undo.push(Snapshot {
            lines: self.lines.clone(),
            cursor: self.cursor,
        });
        // A fresh edit invalidates anything that was undone: you cannot redo
        // onto a history that no longer happened.
        self.redo.clear();
    }

    /// `u`. Returns whether anything was undone.
    pub fn undo(&mut self) -> bool {
        let Some(previous) = self.undo.pop() else {
            return false;
        };
        self.redo.push(Snapshot {
            lines: self.lines.clone(),
            cursor: self.cursor,
        });
        self.restore(previous);
        true
    }

    /// `<C-r>`. Returns whether anything was redone.
    pub fn redo(&mut self) -> bool {
        let Some(next) = self.redo.pop() else {
            return false;
        };
        self.undo.push(Snapshot {
            lines: self.lines.clone(),
            cursor: self.cursor,
        });
        self.restore(next);
        true
    }

    fn restore(&mut self, snapshot: Snapshot) {
        self.lines = snapshot.lines;
        self.cursor = snapshot.cursor;
        self.clamp_col();
        // Undoing is still a change as far as the owner is concerned: the text
        // no longer matches what was last forwarded or sent.
        self.dirty = true;
    }

    // --- word motions ---

    fn word_forward_impl(&mut self, big: bool) {
        let start = class_at_of(&self.lines, self.cursor, big);
        let mut at = self.cursor;

        // Step off the current run...
        if start != Some(CharClass::Space) {
            while let Some(next) = advance(&self.lines, at) {
                at = next;
                if class_at_of(&self.lines, at, big) != start {
                    break;
                }
            }
        }
        // ...then over any whitespace to the next word's first character.
        while class_at_of(&self.lines, at, big) == Some(CharClass::Space) {
            match advance(&self.lines, at) {
                Some(next) => at = next,
                None => break,
            }
        }
        self.cursor = at;
        self.clamp_col();
    }

    fn word_backward_impl(&mut self, big: bool) {
        let mut at = self.cursor;
        // Step back one, then over whitespace.
        match retreat(&self.lines, at) {
            Some(previous) => at = previous,
            None => return,
        }
        while class_at_of(&self.lines, at, big) == Some(CharClass::Space) {
            match retreat(&self.lines, at) {
                Some(previous) => at = previous,
                None => break,
            }
        }
        // Then back to the first character of this run.
        let run = class_at_of(&self.lines, at, big);
        while let Some(previous) = retreat(&self.lines, at) {
            if class_at_of(&self.lines, previous, big) != run {
                break;
            }
            at = previous;
        }
        self.cursor = at;
        self.clamp_col();
    }

    fn word_end_impl(&mut self, big: bool) {
        let mut at = self.cursor;
        let Some(mut next) = advance(&self.lines, at) else {
            return;
        };
        // Skip whitespace to land on a word first.
        while class_at_of(&self.lines, next, big) == Some(CharClass::Space) {
            at = next;
            match advance(&self.lines, at) {
                Some(further) => next = further,
                None => break,
            }
        }
        at = next;
        let run = class_at_of(&self.lines, at, big);
        while let Some(further) = advance(&self.lines, at) {
            if class_at_of(&self.lines, further, big) != run {
                break;
            }
            at = further;
        }
        self.cursor = at;
        self.clamp_col();
    }

    /// `^` — first non-blank character of the line.
    pub fn first_non_blank(&mut self) {
        let line = self
            .lines
            .get(self.cursor.line)
            .cloned()
            .unwrap_or_default();
        let col = line
            .chars()
            .position(|c| !c.is_whitespace())
            .unwrap_or_else(|| line.chars().count());
        self.cursor.col = col;
    }

    // --- operators ---

    /// `p` / `P`. Linewise yanks land on their own line, charwise inside this
    /// one — which is the whole reason the register records which it was.
    pub fn paste(&mut self, yank: &Yank, after: bool) {
        if yank.text.is_empty() {
            return;
        }
        self.checkpoint();
        self.dirty = true;

        if yank.linewise {
            let at = if after {
                self.cursor.line + 1
            } else {
                self.cursor.line
            };
            let at = at.min(self.lines.len());
            for (i, line) in yank.text.split('\n').enumerate() {
                self.lines.insert(at + i, line.to_string());
            }
            self.cursor.line = at;
            self.cursor.col = 0;
            return;
        }

        let col = if after {
            (self.cursor.col + 1).min(self.line_len())
        } else {
            self.cursor.col
        };
        let line = self.line_mut();
        let at = byte_index(line, col);
        line.insert_str(at, &yank.text);
        self.cursor.col = col + yank.text.chars().count() - 1;
        self.clamp_col();
    }

    // --- insert entry points ---

    /// `a` — start inserting after the cursor.
    pub fn append(&mut self) {
        self.cursor.col = (self.cursor.col + 1).min(self.line_len());
    }

    /// `o` — open a line below and put the cursor on it.
    pub fn open_below(&mut self) {
        self.checkpoint();
        self.cursor.line = (self.cursor.line + 1).min(self.lines.len());
        self.lines.insert(self.cursor.line, String::new());
        self.cursor.col = 0;
        self.dirty = true;
    }

    /// `O` — open a line above.
    pub fn open_above(&mut self) {
        self.checkpoint();
        self.lines.insert(self.cursor.line, String::new());
        self.cursor.col = 0;
        self.dirty = true;
    }
}

/// The class of the character at `at`, or `None` past the end of the buffer.
/// A line end reads as whitespace, which is what makes `w` wrap.
fn class_at_of(lines: &[String], at: Cursor, big: bool) -> Option<CharClass> {
    let line = lines.get(at.line)?;
    match line.chars().nth(at.col) {
        Some(c) => Some(if big { big_class(c) } else { class_of(c) }),
        None => Some(CharClass::Space),
    }
}

/// The next position, or `None` at the end of the buffer.
fn advance(lines: &[String], at: Cursor) -> Option<Cursor> {
    let line = lines.get(at.line)?;
    if at.col < line.chars().count() {
        return Some(Cursor {
            line: at.line,
            col: at.col + 1,
        });
    }
    (at.line + 1 < lines.len()).then_some(Cursor {
        line: at.line + 1,
        col: 0,
    })
}

/// The previous position, or `None` at the start of the buffer.
fn retreat(lines: &[String], at: Cursor) -> Option<Cursor> {
    if at.col > 0 {
        return Some(Cursor {
            line: at.line,
            col: at.col - 1,
        });
    }
    let previous = at.line.checked_sub(1)?;
    Some(Cursor {
        line: previous,
        col: lines.get(previous).map(|l| l.chars().count()).unwrap_or(0),
    })
}

/// Character index to byte index. Every edit goes through this, so a multi-byte
/// character in a header value or body cannot split and corrupt the string.
fn byte_index(line: &str, col: usize) -> usize {
    line.char_indices()
        .nth(col)
        .map(|(i, _)| i)
        .unwrap_or(line.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(text: &str) -> TextBuffer {
        TextBuffer::from_text(text)
    }

    #[test]
    fn round_trips_text() {
        assert_eq!(buf("a\nb\nc").text(), "a\nb\nc");
        assert_eq!(buf("").text(), "");
    }

    #[test]
    fn insert_puts_characters_at_the_cursor() {
        let mut b = buf("bc");
        b.insert_char('a');
        assert_eq!(b.text(), "abc");
        assert_eq!(b.cursor(), Cursor { line: 0, col: 1 });
    }

    #[test]
    fn newline_splits_the_line_at_the_cursor() {
        let mut b = buf("abcd");
        b.right();
        b.right();
        b.insert_newline();
        assert_eq!(b.text(), "ab\ncd");
        assert_eq!(b.cursor(), Cursor { line: 1, col: 0 });
    }

    #[test]
    fn backspace_at_column_zero_joins_lines() {
        let mut b = buf("ab\ncd");
        b.down();
        b.line_start();
        b.backspace();
        assert_eq!(b.text(), "abcd");
        assert_eq!(
            b.cursor(),
            Cursor { line: 0, col: 2 },
            "cursor lands at the seam"
        );
    }

    #[test]
    fn backspace_at_the_very_start_is_a_no_op() {
        let mut b = buf("abc");
        b.backspace();
        assert_eq!(b.text(), "abc");
    }

    #[test]
    fn delete_at_line_end_joins_the_next_line() {
        let mut b = buf("ab\ncd");
        b.line_end();
        b.delete();
        assert_eq!(b.text(), "abcd");
    }

    #[test]
    fn vertical_movement_clamps_to_the_shorter_line() {
        let mut b = buf("longer\nab");
        b.line_end();
        assert_eq!(b.cursor().col, 6);
        b.down();
        assert_eq!(b.cursor(), Cursor { line: 1, col: 2 });
    }

    #[test]
    fn horizontal_movement_wraps_across_lines() {
        let mut b = buf("ab\ncd");
        b.line_end();
        b.right();
        assert_eq!(b.cursor(), Cursor { line: 1, col: 0 });
        b.left();
        assert_eq!(b.cursor(), Cursor { line: 0, col: 2 });
    }

    /// A cursor tracked in characters must convert to bytes before indexing, or
    /// editing next to a multi-byte character panics or corrupts the string.
    #[test]
    fn multibyte_characters_are_safe_to_edit_around() {
        let mut b = buf("héllo");
        b.right();
        b.right();
        b.insert_char('X');
        assert_eq!(b.text(), "héXllo");
        b.backspace();
        assert_eq!(b.text(), "héllo");
        b.backspace();
        assert_eq!(b.text(), "hllo");
    }

    #[test]
    fn dirty_tracks_mutations_only() {
        let mut b = buf("abc");
        assert!(!b.is_dirty());
        b.right();
        assert!(!b.is_dirty(), "movement is not a mutation");
        b.insert_char('x');
        assert!(b.is_dirty());
        b.clear_dirty();
        assert!(!b.is_dirty());
    }

    #[test]
    fn editing_an_empty_buffer_does_not_panic() {
        let mut b = TextBuffer::default();
        b.insert_char('a');
        b.delete();
        b.backspace();
        assert_eq!(b.text(), "");
    }
}

#[cfg(test)]
mod vim_tests {
    use super::*;
    use crate::vim::Motion as M;

    fn at(b: &TextBuffer) -> (usize, usize) {
        (b.cursor().line, b.cursor().col)
    }

    /// Step the cursor by a motion, the way a bare motion command does.
    fn step(b: &mut TextBuffer, motion: M) {
        let target = b.motion_target(motion, 1);
        b.set_cursor(target);
    }

    const W: M = M::WordForward { big: false };
    const B: M = M::WordBackward { big: false };
    const E: M = M::WordEnd { big: false };

    /// `w` treats a run of word characters and a run of punctuation as separate
    /// words. This is the case that a "skip to next whitespace" shortcut gets
    /// wrong, and header values are full of it.
    #[test]
    fn word_forward_splits_words_from_punctuation() {
        let mut b = TextBuffer::from_text("host: api.example.com");
        assert_eq!(at(&b), (0, 0));
        step(&mut b, W);
        assert_eq!(at(&b), (0, 4), "onto the colon");
        step(&mut b, W);
        assert_eq!(at(&b), (0, 6), "onto `api`");
        step(&mut b, W);
        assert_eq!(at(&b), (0, 9), "onto the dot");
    }

    #[test]
    fn word_motions_wrap_across_lines() {
        let mut b = TextBuffer::from_text("one\ntwo");
        b.line_end();
        step(&mut b, W);
        assert_eq!(at(&b), (1, 0), "w wraps to the next line");
        step(&mut b, B);
        assert_eq!(at(&b), (0, 0), "b wraps back");
    }

    #[test]
    fn word_backward_lands_on_word_starts() {
        let mut b = TextBuffer::from_text("alpha beta gamma");
        b.line_end();
        step(&mut b, B);
        assert_eq!(at(&b), (0, 11), "start of `gamma`");
        step(&mut b, B);
        assert_eq!(at(&b), (0, 6), "start of `beta`");
    }

    #[test]
    fn word_end_lands_on_the_last_character() {
        let mut b = TextBuffer::from_text("alpha beta");
        step(&mut b, E);
        assert_eq!(at(&b), (0, 4), "last char of `alpha`");
        step(&mut b, E);
        assert_eq!(at(&b), (0, 9), "last char of `beta`");
    }

    #[test]
    fn first_non_blank_skips_indentation() {
        let mut b = TextBuffer::from_text("    indented");
        b.line_end();
        b.first_non_blank();
        assert_eq!(at(&b), (0, 4));
    }

    /// A linewise yank pastes onto its own line; a charwise one pastes inside
    /// the current line. Conflating them is what makes a homegrown `p` feel
    /// broken.
    #[test]
    fn paste_respects_linewise_versus_charwise() {
        let mut b = TextBuffer::from_text("one\ntwo");
        let line = b.yank_range(b.range_for_lines(1));
        assert!(line.linewise);
        b.paste(&line, true);
        assert_eq!(b.text(), "one\none\ntwo");

        let mut b = TextBuffer::from_text("ac");
        let yank = Yank {
            text: "b".into(),
            linewise: false,
        };
        b.paste(&yank, true);
        assert_eq!(b.text(), "abc");
    }

    /// An insert session undoes as one step, not one character at a time —
    /// which is why checkpoints are explicit rather than per-mutation.
    #[test]
    fn undo_restores_the_last_checkpoint() {
        let mut b = TextBuffer::from_text("original");
        b.checkpoint();
        for c in "XY".chars() {
            b.insert_char(c);
        }
        assert_eq!(b.text(), "XYoriginal");

        assert!(b.undo());
        assert_eq!(
            b.text(),
            "original",
            "the whole session should undo at once"
        );
        assert!(b.redo());
        assert_eq!(b.text(), "XYoriginal");
    }

    #[test]
    fn undo_on_a_fresh_buffer_does_nothing() {
        let mut b = TextBuffer::from_text("abc");
        assert!(!b.undo());
        assert_eq!(b.text(), "abc");
    }

    /// A new edit after undoing invalidates the redo history: you cannot redo
    /// onto a branch that no longer happened.
    #[test]
    fn editing_after_undo_clears_redo() {
        let mut b = TextBuffer::from_text("a");
        b.checkpoint();
        b.insert_char('X');
        b.undo();
        b.checkpoint();
        b.insert_char('Z');
        assert!(!b.redo());
        assert_eq!(b.text(), "Za");
    }

    #[test]
    fn open_below_and_above_place_the_cursor_on_the_new_line() {
        let mut b = TextBuffer::from_text("one\ntwo");
        b.open_below();
        assert_eq!(at(&b), (1, 0));
        assert_eq!(b.text(), "one\n\ntwo");

        let mut b = TextBuffer::from_text("one");
        b.open_above();
        assert_eq!(at(&b), (0, 0));
        assert_eq!(b.text(), "\none");
    }

    #[test]
    fn append_moves_one_past_the_cursor() {
        let mut b = TextBuffer::from_text("ab");
        b.append();
        assert_eq!(at(&b), (0, 1));
        b.line_end();
        b.append();
        assert_eq!(at(&b), (0, 2), "clamped to the line end");
    }

    /// Word motions index by character, so a multi-byte line must not panic or
    /// land mid-character.
    #[test]
    fn word_motions_are_multibyte_safe() {
        let mut b = TextBuffer::from_text("héllo wörld");
        step(&mut b, W);
        assert_eq!(at(&b), (0, 6));
        let range = b.range_for_motion(W, 1);
        let taken = b.delete_range(range);
        assert_eq!(b.text(), "héllo ");
        assert_eq!(taken.text, "wörld");
    }
}

#[cfg(test)]
mod grammar_tests {
    use super::*;
    use crate::vim::{Motion as M, ObjectKind, TextObject};

    fn buf(text: &str) -> TextBuffer {
        TextBuffer::from_text(text)
    }

    fn obj(kind: ObjectKind, around: bool) -> TextObject {
        TextObject { kind, around }
    }

    /// `W` skips whole whitespace-delimited chunks where `w` stops at every
    /// punctuation boundary. This is the difference the user actually feels on
    /// a URL.
    #[test]
    fn big_word_motions_skip_punctuation() {
        let b = buf("host: api.example.com next");
        // `w` from 0 stops at the colon.
        assert_eq!(b.motion_target(M::WordForward { big: false }, 1).col, 4);
        // `W` from 0 jumps clean over `host:`.
        assert_eq!(b.motion_target(M::WordForward { big: true }, 1).col, 6);
        // And over the whole dotted host in one more step.
        assert_eq!(b.motion_target(M::WordForward { big: true }, 2).col, 22);
    }

    #[test]
    fn big_word_backward_and_end() {
        let b = buf("api.example.com tail");
        let mut at_end = b.clone();
        at_end.line_end();
        assert_eq!(
            at_end.motion_target(M::WordBackward { big: true }, 1).col,
            16
        );
        assert_eq!(b.motion_target(M::WordEnd { big: true }, 1).col, 14);
    }

    /// `f`/`t` search within the line, and `t` stops one short.
    #[test]
    fn find_char_motions() {
        let b = buf("GET /a/b?q=1 HTTP/1.1");
        let found = M::Find {
            ch: '?',
            backward: false,
            till: false,
        };
        assert_eq!(b.motion_target(found, 1).col, 8);
        let till = M::Find {
            ch: '?',
            backward: false,
            till: true,
        };
        assert_eq!(b.motion_target(till, 1).col, 7, "t stops before");

        // Backward from the end.
        let mut at_end = b.clone();
        at_end.line_end();
        let back = M::Find {
            ch: '?',
            backward: true,
            till: false,
        };
        assert_eq!(at_end.motion_target(back, 1).col, 8);
    }

    /// The inclusivity rule: `dw` leaves the next word, `de` eats to its end.
    #[test]
    fn dw_and_de_differ_by_one() {
        let mut b = buf("alpha beta");
        let range = b.range_for_motion(M::WordForward { big: false }, 1);
        assert_eq!(b.yank_range(range).text, "alpha ");

        let mut c = buf("alpha beta");
        let range = c.range_for_motion(M::WordEnd { big: false }, 1);
        assert_eq!(c.yank_range(range).text, "alpha", "de is inclusive");

        b.delete_range(b.range_for_motion(M::WordForward { big: false }, 1));
        assert_eq!(b.text(), "beta");
    }

    /// A count on the motion widens the range rather than repeating the delete.
    #[test]
    fn counted_motions_widen_the_range() {
        let mut b = buf("one two three four");
        let range = b.range_for_motion(M::WordForward { big: false }, 3);
        assert_eq!(b.yank_range(range).text, "one two three ");
        b.delete_range(range);
        assert_eq!(b.text(), "four");
    }

    #[test]
    fn linewise_motions_take_whole_lines() {
        let mut b = buf("one\ntwo\nthree");
        let range = b.range_for_motion(M::Down, 1);
        assert!(range.linewise);
        let taken = b.delete_range(range);
        assert_eq!(taken.text, "one\ntwo");
        assert_eq!(b.text(), "three");
    }

    #[test]
    fn inner_and_around_word_objects() {
        let mut b = buf("alpha beta gamma");
        b.goto_line(0);
        for _ in 0..7 {
            b.right();
        }
        // Cursor inside `beta`.
        let inner = b.range_for_object(obj(ObjectKind::Word { big: false }, false));
        assert_eq!(b.yank_range(inner.unwrap()).text, "beta");

        let around = b.range_for_object(obj(ObjectKind::Word { big: false }, true));
        assert_eq!(
            b.yank_range(around.unwrap()).text,
            "beta ",
            "aw takes the trailing space"
        );
    }

    /// `daw` between two words must leave exactly one space, which is why `aw`
    /// falls back to leading whitespace when there is no trailing run.
    #[test]
    fn around_word_falls_back_to_leading_space() {
        let mut b = buf("alpha beta");
        b.line_end();
        b.left();
        let around = b.range_for_object(obj(ObjectKind::Word { big: false }, true));
        assert_eq!(b.yank_range(around.unwrap()).text, " beta");
    }

    #[test]
    fn quote_objects() {
        let mut b = buf(r#"name="value" other"#);
        for _ in 0..7 {
            b.right();
        }
        let inner = b.range_for_object(obj(ObjectKind::Quote('"'), false));
        assert_eq!(b.yank_range(inner.unwrap()).text, "value");

        let around = b.range_for_object(obj(ObjectKind::Quote('"'), true));
        assert_eq!(b.yank_range(around.unwrap()).text, "\"value\"");
    }

    #[test]
    fn bracket_objects_nest() {
        let mut b = buf("f(a, g(b), c)");
        // Cursor on `b`, inside the inner pair.
        for _ in 0..7 {
            b.right();
        }
        let inner = b.range_for_object(obj(ObjectKind::Delim('('), false));
        assert_eq!(
            b.yank_range(inner.unwrap()).text,
            "b",
            "should pick the innermost pair"
        );

        // From the outer level, the whole argument list.
        let mut c = buf("f(a, g(b), c)");
        for _ in 0..2 {
            c.right();
        }
        let inner = c.range_for_object(obj(ObjectKind::Delim('('), false));
        assert_eq!(c.yank_range(inner.unwrap()).text, "a, g(b), c");
    }

    #[test]
    fn a_cursor_outside_any_pair_yields_no_object() {
        let b = buf("no brackets here");
        assert!(
            b.range_for_object(obj(ObjectKind::Delim('('), false))
                .is_none()
        );
        assert!(
            b.range_for_object(obj(ObjectKind::Quote('"'), false))
                .is_none()
        );
    }

    /// Bracket objects span lines, which is what makes `di{` useful on a JSON
    /// body.
    #[test]
    fn bracket_objects_span_lines() {
        let mut b = buf("{\n  \"a\": 1\n}");
        b.down();
        let inner = b.range_for_object(obj(ObjectKind::Delim('{'), false));
        let text = b.yank_range(inner.unwrap()).text;
        assert!(text.contains("\"a\": 1"), "got: {text:?}");

        b.delete_range(
            b.range_for_object(obj(ObjectKind::Delim('{'), false))
                .unwrap(),
        );
        assert_eq!(b.text(), "{}");
    }

    #[test]
    fn selection_tracks_the_cursor_and_includes_it() {
        let mut b = buf("abcdef");
        assert!(b.toggle_selection(false));
        b.right();
        b.right();
        let range = b.selection_range().unwrap();
        assert_eq!(b.yank_range(range).text, "abc", "selection includes cursor");

        assert!(!b.toggle_selection(false), "v again drops it");
        assert!(b.selection_range().is_none());
    }

    #[test]
    fn linewise_selection_takes_whole_lines() {
        let mut b = buf("one\ntwo\nthree");
        b.toggle_selection(true);
        b.down();
        let range = b.selection_range().unwrap();
        assert!(range.linewise);
        assert_eq!(b.yank_range(range).text, "one\ntwo");
    }

    #[test]
    fn swapping_selection_ends_moves_the_cursor() {
        let mut b = buf("abcdef");
        b.right();
        b.right();
        b.toggle_selection(false);
        b.right();
        assert_eq!(b.cursor().col, 3);
        b.swap_selection_ends();
        assert_eq!(b.cursor().col, 2, "cursor jumps to the anchor");
    }

    #[test]
    fn in_selection_reports_the_highlighted_cells() {
        let mut b = buf("abc");
        b.toggle_selection(false);
        b.right();
        assert!(b.in_selection(Cursor { line: 0, col: 0 }));
        assert!(b.in_selection(Cursor { line: 0, col: 1 }));
        assert!(!b.in_selection(Cursor { line: 0, col: 2 }));
    }

    #[test]
    fn multi_line_charwise_delete_joins_the_ends() {
        let mut b = buf("keep-one\ndrop\ntwo-keep");
        let range = Range {
            start: Cursor { line: 0, col: 4 },
            end: Cursor { line: 2, col: 3 },
            linewise: false,
        };
        b.delete_range(range);
        assert_eq!(b.text(), "keep-keep");
    }

    #[test]
    fn join_lines_inserts_one_space() {
        let mut b = buf("one\n   two");
        b.join_lines(1);
        assert_eq!(b.text(), "one two", "leading indent is dropped");
    }
}
