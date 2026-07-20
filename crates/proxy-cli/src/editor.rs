//! A minimal multiline text buffer with a cursor.
//!
//! Everything the TUI edited before this was a single `String` pushed and popped
//! from the end (the `:` line, the palette filter). An HTTP message needs more:
//! a cursor that moves in two dimensions, insertion anywhere, and a notion of
//! "the line I am on". This is that, and no more — no undo, no selection, no
//! word motions. It is a text box, not vim.
//!
//! Lines are stored split rather than as one string with offsets, because every
//! consumer (rendering, cursor math) wants lines, and an HTTP message is small
//! enough that the copying cost is irrelevant.

/// A cursor position. `col` is a character index within `line`, and may equal
/// the line's length — that is the position after the last character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, Default)]
pub struct TextBuffer {
    lines: Vec<String>,
    cursor: Cursor,
    /// Set by any mutation, cleared by the owner once it has acted on the change.
    /// Lets the Repeater know its parsed form is stale without diffing text.
    dirty: bool,
}

impl TextBuffer {
    pub fn from_text(text: &str) -> Self {
        Self {
            lines: text.split('\n').map(str::to_string).collect(),
            cursor: Cursor::default(),
            dirty: false,
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
