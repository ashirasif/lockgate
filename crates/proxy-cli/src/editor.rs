//! A multiline text buffer with a cursor and the vim motions and operators that
//! are worth having in a pane.
//!
//! Deliberately a subset. Anything beyond it — counts on operators, text
//! objects, registers by name, macros, visual mode — is what the `e` handoff to
//! the real editor is for. The line between them is drawn at "what you reach for
//! without thinking while reading a request": `w`/`b`, `dd`, `cw`, `x`, `p`,
//! `u`. Reimplementing more than that would be reimplementing vim badly.
//!
//! Lines are stored split rather than as one string with offsets, because every
//! consumer (rendering, cursor math) wants lines, and an HTTP message is small
//! enough that the copying cost is irrelevant. Undo works the same way: whole
//! snapshots, because a few kilobytes of history per edit is free at this size
//! and a diff-based scheme would be the only fiddly part of the file.

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
}

impl TextBuffer {
    pub fn from_text(text: &str) -> Self {
        Self {
            lines: text.split('\n').map(str::to_string).collect(),
            cursor: Cursor::default(),
            dirty: false,
            undo: Vec::new(),
            redo: Vec::new(),
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

    /// `w` — the start of the next word, wrapping across lines.
    pub fn word_forward(&mut self) {
        let start = class_at(&self.lines, self.cursor);
        let mut at = self.cursor;

        // Step off the current run...
        if start != Some(CharClass::Space) {
            while let Some(next) = advance(&self.lines, at) {
                at = next;
                if class_at(&self.lines, at) != start {
                    break;
                }
            }
        }
        // ...then over any whitespace to the next word's first character.
        while class_at(&self.lines, at) == Some(CharClass::Space) {
            match advance(&self.lines, at) {
                Some(next) => at = next,
                None => break,
            }
        }
        self.cursor = at;
        self.clamp_col();
    }

    /// `b` — the start of the previous word.
    pub fn word_backward(&mut self) {
        let mut at = self.cursor;
        // Step back one, then over whitespace.
        match retreat(&self.lines, at) {
            Some(previous) => at = previous,
            None => return,
        }
        while class_at(&self.lines, at) == Some(CharClass::Space) {
            match retreat(&self.lines, at) {
                Some(previous) => at = previous,
                None => break,
            }
        }
        // Then back to the first character of this run.
        let run = class_at(&self.lines, at);
        while let Some(previous) = retreat(&self.lines, at) {
            if class_at(&self.lines, previous) != run {
                break;
            }
            at = previous;
        }
        self.cursor = at;
        self.clamp_col();
    }

    /// `e` — the last character of the current or next word.
    pub fn word_end(&mut self) {
        let mut at = self.cursor;
        let Some(mut next) = advance(&self.lines, at) else {
            return;
        };
        // Skip whitespace to land on a word first.
        while class_at(&self.lines, next) == Some(CharClass::Space) {
            at = next;
            match advance(&self.lines, at) {
                Some(further) => next = further,
                None => break,
            }
        }
        at = next;
        let run = class_at(&self.lines, at);
        while let Some(further) = advance(&self.lines, at) {
            if class_at(&self.lines, further) != run {
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

    /// `x` — delete the character under the cursor, returning it.
    pub fn delete_char(&mut self) -> Yank {
        let taken = self
            .lines
            .get(self.cursor.line)
            .and_then(|l| l.chars().nth(self.cursor.col))
            .map(|c| c.to_string())
            .unwrap_or_default();
        if !taken.is_empty() {
            self.checkpoint();
            let col = self.cursor.col;
            let line = self.line_mut();
            let at = byte_index(line, col);
            line.remove(at);
            self.dirty = true;
            self.clamp_col();
        }
        Yank {
            text: taken,
            linewise: false,
        }
    }

    /// `dd` — delete the whole line.
    pub fn delete_line(&mut self) -> Yank {
        if self.lines.is_empty() {
            return Yank::default();
        }
        self.checkpoint();
        let line = self
            .lines
            .remove(self.cursor.line.min(self.lines.len() - 1));
        // Deleting the last line leaves an empty buffer, not no buffer — vim
        // always has at least one line to put the cursor on.
        if self.lines.is_empty() {
            self.lines.push(String::new());
        }
        self.cursor.line = self.cursor.line.min(self.lines.len() - 1);
        self.clamp_col();
        self.dirty = true;
        Yank {
            text: line,
            linewise: true,
        }
    }

    /// `D` — delete from the cursor to the end of the line.
    pub fn delete_to_end(&mut self) -> Yank {
        self.checkpoint();
        let col = self.cursor.col;
        let line = self.line_mut();
        let at = byte_index(line, col);
        let tail = line.split_off(at);
        self.dirty = true;
        self.clamp_col();
        Yank {
            text: tail,
            linewise: false,
        }
    }

    /// `dw` — delete from the cursor to the start of the next word.
    ///
    /// Bounded to the current line: vim's `dw` stops at the line end rather than
    /// pulling the next line up, which is the behaviour that would surprise
    /// someone editing a header.
    pub fn delete_word(&mut self) -> Yank {
        let from = self.cursor;
        let mut probe = self.clone();
        probe.word_forward();
        let to = if probe.cursor.line != from.line {
            Cursor {
                line: from.line,
                col: self.line_len(),
            }
        } else {
            probe.cursor
        };
        if to.col <= from.col {
            return Yank::default();
        }

        self.checkpoint();
        let line = self.line_mut();
        let start = byte_index(line, from.col);
        let end = byte_index(line, to.col);
        let taken: String = line[start..end].to_string();
        line.replace_range(start..end, "");
        self.dirty = true;
        self.clamp_col();
        Yank {
            text: taken,
            linewise: false,
        }
    }

    /// `yy` — copy the current line.
    pub fn yank_line(&self) -> Yank {
        Yank {
            text: self
                .lines
                .get(self.cursor.line)
                .cloned()
                .unwrap_or_default(),
            linewise: true,
        }
    }

    /// `yw` — copy from the cursor to the start of the next word.
    pub fn yank_word(&self) -> Yank {
        let mut probe = self.clone();
        probe.word_forward();
        let line = self
            .lines
            .get(self.cursor.line)
            .cloned()
            .unwrap_or_default();
        let end = if probe.cursor.line != self.cursor.line {
            line.chars().count()
        } else {
            probe.cursor.col
        };
        if end <= self.cursor.col {
            return Yank::default();
        }
        let text: String = line
            .chars()
            .skip(self.cursor.col)
            .take(end - self.cursor.col)
            .collect();
        Yank {
            text,
            linewise: false,
        }
    }

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
fn class_at(lines: &[String], at: Cursor) -> Option<CharClass> {
    let line = lines.get(at.line)?;
    match line.chars().nth(at.col) {
        Some(c) => Some(class_of(c)),
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

    fn at(b: &TextBuffer) -> (usize, usize) {
        (b.cursor().line, b.cursor().col)
    }

    /// `w` treats a run of word characters and a run of punctuation as separate
    /// words. This is the case that a "skip to next whitespace" shortcut gets
    /// wrong, and header values are full of it.
    #[test]
    fn word_forward_splits_words_from_punctuation() {
        let mut b = TextBuffer::from_text("host: api.example.com");
        assert_eq!(at(&b), (0, 0));
        b.word_forward();
        assert_eq!(at(&b), (0, 4), "onto the colon");
        b.word_forward();
        assert_eq!(at(&b), (0, 6), "onto `api`");
        b.word_forward();
        assert_eq!(at(&b), (0, 9), "onto the dot");
    }

    #[test]
    fn word_motions_wrap_across_lines() {
        let mut b = TextBuffer::from_text("one\ntwo");
        b.line_end();
        b.word_forward();
        assert_eq!(at(&b), (1, 0), "w wraps to the next line");
        b.word_backward();
        assert_eq!(at(&b), (0, 0), "b wraps back");
    }

    #[test]
    fn word_backward_lands_on_word_starts() {
        let mut b = TextBuffer::from_text("alpha beta gamma");
        b.line_end();
        b.word_backward();
        assert_eq!(at(&b), (0, 11), "start of `gamma`");
        b.word_backward();
        assert_eq!(at(&b), (0, 6), "start of `beta`");
    }

    #[test]
    fn word_end_lands_on_the_last_character() {
        let mut b = TextBuffer::from_text("alpha beta");
        b.word_end();
        assert_eq!(at(&b), (0, 4), "last char of `alpha`");
        b.word_end();
        assert_eq!(at(&b), (0, 9), "last char of `beta`");
    }

    #[test]
    fn first_non_blank_skips_indentation() {
        let mut b = TextBuffer::from_text("    indented");
        b.line_end();
        b.first_non_blank();
        assert_eq!(at(&b), (0, 4));
    }

    #[test]
    fn x_deletes_under_the_cursor() {
        let mut b = TextBuffer::from_text("abc");
        let yanked = b.delete_char();
        assert_eq!(b.text(), "bc");
        assert_eq!(yanked.text, "a");
        assert!(!yanked.linewise);
    }

    #[test]
    fn dd_removes_the_line_and_yanks_it_linewise() {
        let mut b = TextBuffer::from_text("one\ntwo\nthree");
        b.down();
        let yanked = b.delete_line();
        assert_eq!(b.text(), "one\nthree");
        assert_eq!(yanked.text, "two");
        assert!(yanked.linewise);
    }

    /// Deleting the last line must leave a line to stand on, not an empty
    /// buffer with a cursor pointing at nothing.
    #[test]
    fn dd_on_the_only_line_leaves_an_empty_line() {
        let mut b = TextBuffer::from_text("only");
        b.delete_line();
        assert_eq!(b.text(), "");
        assert_eq!(b.lines().len(), 1);
    }

    #[test]
    fn dw_stops_at_the_end_of_the_line() {
        let mut b = TextBuffer::from_text("delete me\nnext line");
        let yanked = b.delete_word();
        assert_eq!(b.text(), "me\nnext line");
        assert_eq!(yanked.text, "delete ");

        // At the last word, dw must not pull the following line up.
        let mut b = TextBuffer::from_text("tail\nnext");
        b.delete_word();
        assert_eq!(b.text(), "\nnext");
    }

    #[test]
    fn capital_d_deletes_to_end_of_line() {
        let mut b = TextBuffer::from_text("keep drop");
        for _ in 0..5 {
            b.right();
        }
        let yanked = b.delete_to_end();
        assert_eq!(b.text(), "keep ");
        assert_eq!(yanked.text, "drop");
    }

    /// A linewise yank pastes onto its own line; a charwise one pastes inside
    /// the current line. Conflating them is what makes a homegrown `p` feel
    /// broken.
    #[test]
    fn paste_respects_linewise_versus_charwise() {
        let mut b = TextBuffer::from_text("one\ntwo");
        let line = b.yank_line();
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

    #[test]
    fn yank_word_takes_up_to_the_next_word() {
        let b = TextBuffer::from_text("alpha beta");
        assert_eq!(b.yank_word().text, "alpha ");
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
        b.word_forward();
        assert_eq!(at(&b), (0, 6));
        let yanked = b.delete_word();
        assert_eq!(b.text(), "héllo ");
        assert_eq!(yanked.text, "wörld");
    }
}
