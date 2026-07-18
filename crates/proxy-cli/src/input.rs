//! The modal input core: keys in, [`Action`]s out.
//!
//! This is deliberately independent of the UI. It knows nothing about flows,
//! panes or the engine — it only turns a stream of key events into intents,
//! the same way vim's input layer is separate from its buffers.
//!
//! The design rule for this file is *fidelity*: if a key does something in
//! vim, it must not do something different here. That is why `q` does not
//! quit (it records a macro) and `r` does not resend (it replaces a char).
//! Application-specific verbs live behind the leader key or on `:`.

use std::fmt::Write as _;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Which mode the editor is in. Drives both key resolution and the statusline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Normal,
    /// Linewise selection. A table row is a line, so `v` and `V` are the same.
    Visual,
    /// Typing into the `:` / `/` / `?` prompt at the bottom of the screen.
    Command,
}

impl Mode {
    /// Short label for the statusline indicator.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Normal => "NORMAL",
            Mode::Visual => "VISUAL",
            Mode::Command => "COMMAND",
        }
    }
}

/// A cursor movement. Interpretation (how far is a "page"?) is up to the
/// buffer that receives it, which is why these carry no resolved line numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motion {
    Down,
    Up,
    Top,
    Bottom,
    HalfPageDown,
    HalfPageUp,
    PageDown,
    PageUp,
    ScreenTop,
    ScreenMiddle,
    ScreenBottom,
    /// `}` / `{` — next or previous group of related rows (same host).
    GroupForward,
    GroupBackward,
    /// `n` / `N` — next or previous search match.
    MatchForward,
    MatchBackward,
}

/// How to reposition the viewport around the cursor without moving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scroll {
    Center,
    Top,
    Bottom,
}

/// What the input layer decided the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `count` is `None` when the user typed no count, which matters: bare `G`
    /// goes to the last line, but `12G` goes to line 12.
    Move { motion: Motion, count: Option<usize> },
    Scroll(Scroll),
    SetMark(char),
    GotoMark(char),
    /// `<C-o>` / `<C-i>` — walk the jumplist.
    JumpBack,
    JumpForward,
    ModeChange(Mode),
    /// A completed `:` line, without the leading colon.
    Command(String),
    /// A completed `/` or `?` line, without the leading slash.
    Search { pattern: String, backward: bool },
    /// `<Space>r` — replay the selection through the Repeater.
    Resend,
}

/// One entry in the keymap. Kept free of counts and arguments so the table can
/// stay a `const` — the resolver attaches those when a sequence completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bind {
    Move(Motion),
    Scroll(Scroll),
    /// Takes the following keystroke as a literal argument, e.g. `m{char}`.
    SetMark,
    GotoMark,
    JumpBack,
    JumpForward,
    Mode(Mode),
    /// Opens the bottom prompt in `Command` mode, seeded with this character.
    Prompt(char),
    Resend,
}

/// The keymap is data, not control flow, so that `:map` can later rewrite it
/// and so the resolver can answer "is this a prefix of something?" generically.
///
/// `{char}` marks a binding that swallows the next keystroke as an argument.
const NORMAL_MAP: &[(&str, Bind)] = &[
    // Motions.
    ("j", Bind::Move(Motion::Down)),
    ("<Down>", Bind::Move(Motion::Down)),
    ("k", Bind::Move(Motion::Up)),
    ("<Up>", Bind::Move(Motion::Up)),
    ("gg", Bind::Move(Motion::Top)),
    ("G", Bind::Move(Motion::Bottom)),
    ("<C-d>", Bind::Move(Motion::HalfPageDown)),
    ("<C-u>", Bind::Move(Motion::HalfPageUp)),
    ("<C-f>", Bind::Move(Motion::PageDown)),
    ("<C-b>", Bind::Move(Motion::PageUp)),
    ("H", Bind::Move(Motion::ScreenTop)),
    ("M", Bind::Move(Motion::ScreenMiddle)),
    ("L", Bind::Move(Motion::ScreenBottom)),
    ("}", Bind::Move(Motion::GroupForward)),
    ("{", Bind::Move(Motion::GroupBackward)),
    ("n", Bind::Move(Motion::MatchForward)),
    ("N", Bind::Move(Motion::MatchBackward)),
    // Viewport.
    ("zz", Bind::Scroll(Scroll::Center)),
    ("zt", Bind::Scroll(Scroll::Top)),
    ("zb", Bind::Scroll(Scroll::Bottom)),
    // Marks and the jumplist.
    ("m{char}", Bind::SetMark),
    ("'{char}", Bind::GotoMark),
    ("`{char}", Bind::GotoMark),
    ("<C-o>", Bind::JumpBack),
    ("<C-i>", Bind::JumpForward),
    // Modes and prompts.
    ("v", Bind::Mode(Mode::Visual)),
    ("V", Bind::Mode(Mode::Visual)),
    (":", Bind::Prompt(':')),
    ("/", Bind::Prompt('/')),
    ("?", Bind::Prompt('?')),
    // Leader. Application verbs live here so they never shadow vim's own keys.
    ("<Space>r", Bind::Resend),
    // `ZZ` quits; `q` is left free because vim spends it on macro recording.
    ("ZZ", Bind::Prompt('\0')),
];

/// The modal state machine. Feed it keys; take [`Action`]s out.
#[derive(Debug, Default)]
pub struct Input {
    mode: Mode,
    /// Digits typed before a command, as text so `10` and `1` `0` differ.
    count: String,
    /// Tokens of the sequence typed so far, e.g. `["g"]` while `gg` is half done.
    pending: Vec<String>,
    /// The `:`/`/`/`?` line being typed, including its leading character.
    cmdline: String,
}

impl Input {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The in-progress `:` or `/` line, for the UI to render at the bottom.
    pub fn cmdline(&self) -> Option<&str> {
        (self.mode == Mode::Command).then_some(self.cmdline.as_str())
    }

    /// Half-typed input, shown bottom-right the way vim shows `d2` mid-command.
    pub fn pending_display(&self) -> String {
        let mut out = self.count.clone();
        for token in &self.pending {
            let _ = write!(out, "{token}");
        }
        out
    }

    /// Feed one key press. Returns an action once a sequence resolves.
    pub fn feed(&mut self, key: KeyEvent) -> Option<Action> {
        match self.mode {
            Mode::Command => self.feed_command(key),
            Mode::Normal | Mode::Visual => self.feed_normal(key),
        }
    }

    // --- normal / visual ---

    fn feed_normal(&mut self, key: KeyEvent) -> Option<Action> {
        let token = encode(key)?;

        if token == "<Esc>" {
            self.reset();
            // Escape leaves Visual for Normal; in Normal it just clears pending.
            return (self.mode == Mode::Visual).then(|| {
                self.mode = Mode::Normal;
                Action::ModeChange(Mode::Normal)
            });
        }

        // A count is digits typed before a command — but a leading `0` is the
        // "first column" motion, not the start of a number.
        if self.pending.is_empty() && is_count_digit(&token, self.count.is_empty()) {
            self.count.push_str(&token);
            return None;
        }

        self.pending.push(token);
        match resolve(&self.pending) {
            Resolution::Partial => None,
            Resolution::None => {
                self.reset();
                None
            }
            Resolution::Match(bind, arg) => {
                let count = self.count.parse().ok();
                self.reset();
                self.apply(bind, arg, count)
            }
        }
    }

    /// Turn a resolved binding into an action, applying count and argument.
    fn apply(&mut self, bind: Bind, arg: Option<char>, count: Option<usize>) -> Option<Action> {
        Some(match bind {
            Bind::Move(motion) => Action::Move { motion, count },
            Bind::Scroll(scroll) => Action::Scroll(scroll),
            Bind::SetMark => Action::SetMark(arg?),
            Bind::GotoMark => Action::GotoMark(arg?),
            Bind::JumpBack => Action::JumpBack,
            Bind::JumpForward => Action::JumpForward,
            Bind::Mode(mode) => {
                // `v` in Visual mode toggles back out, as in vim.
                let next = if self.mode == mode { Mode::Normal } else { mode };
                self.mode = next;
                Action::ModeChange(next)
            }
            // `ZZ` is spelled as a prompt with a NUL seed purely so it can live
            // in the table; it means "run `:q` without making the user type it".
            Bind::Prompt('\0') => Action::Command("q".into()),
            Bind::Prompt(seed) => {
                self.mode = Mode::Command;
                self.cmdline = seed.to_string();
                return None;
            }
            Bind::Resend => Action::Resend,
        })
    }

    // --- command line ---

    fn feed_command(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.cmdline.clear();
                None
            }
            KeyCode::Backspace => {
                self.cmdline.pop();
                // Backspacing over the leading `:` abandons the prompt.
                if self.cmdline.is_empty() {
                    self.mode = Mode::Normal;
                }
                None
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                let line = std::mem::take(&mut self.cmdline);
                let mut chars = line.chars();
                let kind = chars.next()?;
                let rest = chars.as_str().to_string();
                Some(match kind {
                    ':' => Action::Command(rest),
                    _ => Action::Search { pattern: rest, backward: kind == '?' },
                })
            }
            KeyCode::Char(c) => {
                self.cmdline.push(c);
                None
            }
            _ => None,
        }
    }

    fn reset(&mut self) {
        self.count.clear();
        self.pending.clear();
    }
}

/// Whether this token continues a count. `0` only counts once digits precede it.
fn is_count_digit(token: &str, count_empty: bool) -> bool {
    match token.parse::<u8>() {
        Ok(0) => !count_empty,
        Ok(_) => token.len() == 1,
        Err(_) => false,
    }
}

enum Resolution {
    /// A complete binding, with the literal argument if it takes one.
    Match(Bind, Option<char>),
    /// A prefix of at least one binding — keep collecting keys.
    Partial,
    None,
}

/// Look a typed sequence up in the keymap.
fn resolve(pending: &[String]) -> Resolution {
    let typed = pending.concat();
    let mut partial = false;

    for (sequence, bind) in NORMAL_MAP {
        if let Some(prefix) = sequence.strip_suffix("{char}") {
            // e.g. `m{char}`: match once the argument key has arrived.
            if let Some(arg) = typed.strip_prefix(prefix) {
                match single_char(arg) {
                    Some(c) => return Resolution::Match(*bind, Some(c)),
                    None if arg.is_empty() => partial = true,
                    None => {}
                }
            }
            continue;
        }
        if *sequence == typed {
            return Resolution::Match(*bind, None);
        }
        partial |= sequence.starts_with(&typed);
    }

    if partial { Resolution::Partial } else { Resolution::None }
}

/// A mark argument must be one plain character — `ma`, never `m<C-d>`.
fn single_char(token: &str) -> Option<char> {
    let mut chars = token.chars();
    let c = chars.next()?;
    chars.next().is_none().then_some(c)
}

/// Render a key event as a keymap token. Returns `None` for keys we don't map,
/// so modifiers like a bare Shift press don't disturb a pending sequence.
fn encode(key: KeyEvent) -> Option<String> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char(' ') if !ctrl => "<Space>".into(),
        KeyCode::Char(c) if ctrl => format!("<C-{}>", c.to_ascii_lowercase()),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Esc => "<Esc>".into(),
        KeyCode::Enter => "<CR>".into(),
        KeyCode::Tab if ctrl => "<C-i>".into(),
        KeyCode::Up => "<Up>".into(),
        KeyCode::Down => "<Down>".into(),
        KeyCode::Left => "<Left>".into(),
        KeyCode::Right => "<Right>".into(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type a literal string of plain keys, returning every action produced.
    fn feed(input: &mut Input, keys: &str) -> Vec<Action> {
        keys.chars()
            .filter_map(|c| input.feed(KeyEvent::from(KeyCode::Char(c))))
            .collect()
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn last(keys: &str) -> Action {
        let mut input = Input::new();
        feed(&mut input, keys).pop().expect("no action from {keys}")
    }

    #[test]
    fn plain_motion_carries_no_count() {
        assert_eq!(last("j"), Action::Move { motion: Motion::Down, count: None });
    }

    #[test]
    fn digits_accumulate_into_a_count() {
        assert_eq!(last("12j"), Action::Move { motion: Motion::Down, count: Some(12) });
    }

    /// Bare `G` means "last line" but `12G` means "line 12" — so the absence of
    /// a count has to survive as `None` rather than collapsing to 1.
    #[test]
    fn count_presence_is_distinguishable() {
        assert_eq!(last("G"), Action::Move { motion: Motion::Bottom, count: None });
        assert_eq!(last("12G"), Action::Move { motion: Motion::Bottom, count: Some(12) });
    }

    /// A leading `0` is a motion in vim, not the start of a number.
    #[test]
    fn leading_zero_is_not_a_count() {
        let mut input = Input::new();
        assert!(feed(&mut input, "0").is_empty());
        assert_eq!(input.pending_display(), "", "0 should not be buffered as a count");
        assert_eq!(last("10j"), Action::Move { motion: Motion::Down, count: Some(10) });
    }

    #[test]
    fn multi_key_sequences_wait_for_completion() {
        let mut input = Input::new();
        assert!(input.feed(KeyEvent::from(KeyCode::Char('g'))).is_none());
        assert_eq!(input.pending_display(), "g", "half-typed keys should be visible");
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('g'))),
            Some(Action::Move { motion: Motion::Top, count: None })
        );
        assert_eq!(input.pending_display(), "");
    }

    #[test]
    fn unmapped_sequence_is_discarded_not_reinterpreted() {
        let mut input = Input::new();
        // `gx` is not bound; the `x` must not then be handled on its own.
        assert!(feed(&mut input, "gx").is_empty());
        assert_eq!(input.pending_display(), "");
    }

    #[test]
    fn marks_take_the_next_key_literally() {
        assert_eq!(last("ma"), Action::SetMark('a'));
        assert_eq!(last("'a"), Action::GotoMark('a'));
        // `j` after `m` is a mark name, not a motion.
        assert_eq!(last("mj"), Action::SetMark('j'));
    }

    #[test]
    fn escape_clears_a_partial_sequence() {
        let mut input = Input::new();
        feed(&mut input, "12g");
        assert!(input.feed(KeyEvent::from(KeyCode::Esc)).is_none());
        assert_eq!(input.pending_display(), "");
    }

    #[test]
    fn visual_mode_toggles_and_escape_exits() {
        let mut input = Input::new();
        assert_eq!(input.feed(KeyEvent::from(KeyCode::Char('v'))), Some(Action::ModeChange(Mode::Visual)));
        assert_eq!(input.mode(), Mode::Visual);
        assert_eq!(input.feed(KeyEvent::from(KeyCode::Esc)), Some(Action::ModeChange(Mode::Normal)));
        assert_eq!(input.mode(), Mode::Normal);
    }

    /// Motions must keep working while a visual selection is active.
    #[test]
    fn visual_mode_still_moves() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('v')));
        assert_eq!(last("j"), Action::Move { motion: Motion::Down, count: None });
        assert_eq!(input.mode(), Mode::Visual);
    }

    #[test]
    fn colon_opens_a_command_line_and_enter_submits_it() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char(':')));
        assert_eq!(input.mode(), Mode::Command);
        feed(&mut input, "resend");
        assert_eq!(input.cmdline(), Some(":resend"));
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Command("resend".into()))
        );
        assert_eq!(input.mode(), Mode::Normal);
    }

    #[test]
    fn search_prompts_record_their_direction() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('/')));
        feed(&mut input, "admin");
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Search { pattern: "admin".into(), backward: false })
        );

        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('?')));
        feed(&mut input, "admin");
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Search { pattern: "admin".into(), backward: true })
        );
    }

    #[test]
    fn backspacing_past_the_prompt_character_cancels() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char(':')));
        input.feed(KeyEvent::from(KeyCode::Char('q')));
        input.feed(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(input.mode(), Mode::Command);
        input.feed(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(input.mode(), Mode::Normal, "erasing the ':' should abandon the prompt");
    }

    #[test]
    fn control_keys_map_to_scroll_and_jumps() {
        let mut input = Input::new();
        assert_eq!(
            input.feed(ctrl('d')),
            Some(Action::Move { motion: Motion::HalfPageDown, count: None })
        );
        assert_eq!(input.feed(ctrl('o')), Some(Action::JumpBack));
    }

    /// The leader keeps application verbs out of vim's namespace.
    #[test]
    fn leader_sequence_triggers_resend() {
        let mut input = Input::new();
        assert!(input.feed(KeyEvent::from(KeyCode::Char(' '))).is_none());
        assert_eq!(input.feed(KeyEvent::from(KeyCode::Char('r'))), Some(Action::Resend));
    }

    /// The keys vim reserves must stay reserved, or muscle memory starts lying.
    #[test]
    fn vim_reserved_keys_are_unbound() {
        for key in ["q", "r", "i", "x", "d", "c", "y", "p"] {
            let mut input = Input::new();
            assert!(feed(&mut input, key).is_empty(), "{key} should not be bound yet");
        }
    }

    #[test]
    fn zz_quits_without_shadowing_z_motions() {
        assert_eq!(last("ZZ"), Action::Command("q".into()));
        assert_eq!(last("zz"), Action::Scroll(Scroll::Center));
    }
}
