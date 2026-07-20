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
    /// The Cmd-K command palette is open: keys filter and pick from a list
    /// instead of moving a cursor.
    Palette,
    /// Typing into an editable message buffer (a Repeater request, a held
    /// item). Every printable key is text, as in vim.
    Insert,
}

impl Mode {
    /// Short label for the statusline indicator.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Normal => "NORMAL",
            Mode::Visual => "VISUAL",
            Mode::Command => "COMMAND",
            Mode::Palette => "PALETTE",
            Mode::Insert => "INSERT",
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

/// A top-level window. Vim would call these tabs; Burp calls them tools. Only
/// one is on screen at a time, and the tab strip across the top shows the rest.
///
/// The interpretation of every other key still belongs to the window that
/// receives it — this enum only names the window, it carries no behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Window {
    /// The HTTP history and its request/response detail. The home window.
    #[default]
    Proxy,
    /// Replay a single request and read the fresh response.
    Repeater,
    Scope,
    Findings,
    /// Traffic held in flight, awaiting forward or drop.
    Intercept,
    /// The tree of what has been seen: host, then path.
    Sitemap,
    /// Batch and automation scaffolding built on top of a base request set.
    Automate,
}

impl Window {
    /// Left-to-right tab order, and the set `gt` / `gT` cycle through.
    pub const ALL: [Window; 7] = [
        Window::Proxy,
        Window::Intercept,
        Window::Repeater,
        Window::Scope,
        Window::Findings,
        Window::Sitemap,
        Window::Automate,
    ];

    /// The name shown in the tab strip.
    pub fn label(self) -> &'static str {
        match self {
            Window::Proxy => "Proxy",
            Window::Intercept => "Intercept",
            Window::Repeater => "Repeater",
            Window::Scope => "Scope",
            Window::Findings => "Findings",
            Window::Sitemap => "Sitemap",
            Window::Automate => "Automate",
        }
    }

    /// The single key that jumps straight here, shown in the tab strip.
    ///
    /// Uppercase `I` is free for Intercept because vim only spends the
    /// *lowercase* `i` on insert.
    pub fn key(self) -> char {
        match self {
            Window::Proxy => 'P',
            Window::Intercept => 'I',
            Window::Repeater => 'R',
            Window::Scope => 'C',
            Window::Findings => 'T',
            Window::Sitemap => 'S',
            Window::Automate => 'A',
        }
    }

    /// The next / previous window in tab order, wrapping — `gt` / `gT`.
    pub fn step(self, direction: isize) -> Window {
        let i = Self::ALL.iter().position(|&w| w == self).unwrap_or(0) as isize;
        let len = Self::ALL.len() as isize;
        Self::ALL[(i + direction).rem_euclid(len) as usize]
    }
}

/// A keystroke while the command palette is open. The palette's *contents* are
/// the app's business — this layer only reports what the user did to it, the
/// same way it reports a motion without knowing what a "line" is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteKey {
    /// The palette just opened; the app should reset its query and selection.
    Open,
    /// A character typed into the filter.
    Char(char),
    Backspace,
    /// Move the highlight up / down the filtered list.
    Up,
    Down,
    /// Run the highlighted command.
    Accept,
    /// Dismiss without running anything.
    Cancel,
}

/// Which side of a split window has focus. The Intercept window shows the two
/// legs of an exchange side by side, each with its own queue and preview, and
/// keys act on whichever column is focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Column {
    #[default]
    Left,
    Right,
}

impl Column {
    pub fn flip(self) -> Column {
        match self {
            Column::Left => Column::Right,
            Column::Right => Column::Left,
        }
    }
}

/// A keystroke while an editable buffer has focus. Like [`PaletteKey`], this
/// reports the gesture without knowing what is being edited — the buffer itself
/// is the app's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertKey {
    Char(char),
    Backspace,
    Delete,
    Newline,
    Left,
    Right,
    Up,
    Down,
    LineStart,
    LineEnd,
}

/// What the input layer decided the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `count` is `None` when the user typed no count, which matters: bare `G`
    /// goes to the last line, but `12G` goes to line 12.
    Move {
        motion: Motion,
        count: Option<usize>,
    },
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
    Search {
        pattern: String,
        backward: bool,
    },
    /// `<Space>r` — replay the selection through the Repeater.
    Resend,
    /// `P` / `R` / `I` / `A` — jump straight to a named window.
    Window(Window),
    /// `gt` / `gT` — cycle to the next / previous window in tab order.
    WindowStep(isize),
    /// Something happened to the Cmd-K palette (opened, filtered, picked…).
    Palette(PaletteKey),
    /// A keystroke into the focused editable buffer.
    Insert(InsertKey),
    /// `<Space>f` / `<Space>d` — answer the selected held item.
    Forward,
    Drop,
    /// `<Space>F` / `<Space>D` — answer every held item at once.
    ForwardAll,
    DropAll,
    /// `<Space>i` — turn interception on or off.
    ToggleIntercept,
    /// `<Space>s` — snapshot the selection into the Repeater for editing.
    SendToRepeater,
    /// `<CR>` on a sitemap row — fold or unfold it.
    Toggle,
    /// `<CR>` on a queue row — step into the preview for that item.
    Enter,
    /// `e` — open the focused buffer in the operator's own editor.
    ExternalEdit,
    /// A parsed vim command aimed at the focused buffer.
    Vim(crate::vim::Command),
    /// Escape with nothing half-typed: step back out of wherever you are.
    Escape,
    /// `<C-w>h` / `<C-w>l` / `<C-w>w` — move focus between split panes.
    Focus(Option<Column>),
    /// `<Space>1` / `<Space>2` — choose which legs of an exchange hold.
    ToggleHoldRequests,
    ToggleHoldResponses,
    ScopeAddHost,
    ScopeRemoveHost,
    ToggleScopeFilter,
    CycleSeverity,
    CycleStatus,
    NewSession,
    CloseSession,
    /// Repeater: switch sessions. `Some(n)` picks the nth, 1-based as the tab
    /// strip shows it; `None` cycles to the next, which is what a bare `gs`
    /// means.
    SelectSession(Option<usize>),
    History {
        forward: bool,
    },
    ToggleView,
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
    /// Opens the prompt pre-filled with a whole command, so a key can offer a
    /// verb while leaving its argument to be typed. Scope patterns are free
    /// text; a keybinding per pattern is not a thing.
    PromptSeeded(&'static str),
    Resend,
    Window(Window),
    /// Cycle windows by `+1` (`gt`) or `-1` (`gT`).
    WindowStep(isize),
    /// Open the Cmd-K command palette.
    Palette,
    Forward,
    Drop,
    ForwardAll,
    DropAll,
    ToggleIntercept,
    SendToRepeater,
    Toggle,
    Enter,
    ExternalEdit,
    /// `None` cycles to the other pane; `Some(c)` focuses that side.
    Focus(Option<Column>),
    ToggleHoldRequests,
    ToggleHoldResponses,
    ScopeAddHost,
    ScopeRemoveHost,
    ToggleScopeFilter,
    CycleSeverity,
    CycleStatus,
    NewSession,
    CloseSession,
    SelectSession,
    History {
        forward: bool,
    },
    ToggleView,
}

/// Bindings that only apply inside one window, checked before [`NORMAL_MAP`].
///
/// This is the escape hatch from the fidelity rule. `f` and `d` are find-char
/// and the delete operator in vim, and shadowing them globally would be exactly
/// the sort of lie this file exists to prevent. But inside Intercept there is no
/// line to find a character on and nothing to delete — there is a queue, and the
/// two things you do to it are forward and drop. A key that is unambiguous in
/// one window can be spent there without costing anything anywhere else.
const WINDOW_MAP: &[(Window, &str, Bind)] = &[
    // Hand the buffer to the operator's real editor. `<C-g>` rather than `e`:
    // the preview panes grew real vim motions, and `e` is end-of-word there. A
    // key that means "jump a word" inside the buffer and "launch nvim" one
    // keystroke outside it is a trap, so external edit moved somewhere no
    // motion can claim — and the same chord now works in both places.
    (Window::Intercept, "<C-g>", Bind::ExternalEdit),
    (Window::Repeater, "<C-g>", Bind::ExternalEdit),
    (Window::Intercept, "f", Bind::Forward),
    (Window::Intercept, "d", Bind::Drop),
    (Window::Intercept, "F", Bind::ForwardAll),
    (Window::Intercept, "D", Bind::DropAll),
    // Step into the preview for the highlighted item.
    (Window::Intercept, "<CR>", Bind::Enter),
    (Window::Repeater, "<CR>", Bind::Enter),
    // Session tabs. Only reachable with the buffer unfocused, where these keys
    // are otherwise idle — inside the buffer `n` and `x` are vim's own.
    (Window::Repeater, "n", Bind::NewSession),
    (Window::Repeater, "x", Bind::CloseSession),
    (Window::Repeater, "[", Bind::History { forward: false }),
    (Window::Repeater, "]", Bind::History { forward: true }),
    (Window::Repeater, "p", Bind::ToggleView),
    // `{count}gs` selects a session, bare `gs` cycles — exactly how vim's own
    // `{count}gt` works on tabs. Binding the digits directly cannot work: a
    // bare digit is a *count*, consumed before the keymap is consulted, so
    // `1` would never reach here. Leader-prefixed is taken too — `<Space>1`
    // and `<Space>2` are the hold toggles.
    (Window::Repeater, "gs", Bind::SelectSession),
    (Window::Sitemap, "<CR>", Bind::Toggle),
    // Sitemap: put the highlighted host in scope, or take it out again.
    (Window::Sitemap, "a", Bind::ScopeAddHost),
    (Window::Sitemap, "d", Bind::ScopeRemoveHost),
    // Scope: `<CR>` activates a scope or toggles a rule, depending on which
    // pane has the keys — the same "act on what is highlighted" shape the
    // other windows use. Patterns are free text, so the keys that need one
    // open a pre-filled prompt rather than pretending to be a form.
    (Window::Scope, "<CR>", Bind::Enter),
    (Window::Scope, "a", Bind::PromptSeeded(":scope add ")),
    (Window::Scope, "x", Bind::PromptSeeded(":scope exclude ")),
    (Window::Scope, "n", Bind::PromptSeeded(":scope new ")),
    (Window::Scope, "d", Bind::Drop),
    (Window::Scope, "<C-w>", Bind::Focus(None)),
    // Findings: triage is the whole job, so severity and status are single keys
    // rather than a form.
    (Window::Findings, "d", Bind::Drop),
    (Window::Findings, "s", Bind::CycleSeverity),
    (Window::Findings, "c", Bind::CycleStatus),
];

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
    ("<Space>s", Bind::SendToRepeater),
    // Bypass scope filtering from wherever you noticed something missing —
    // the same reason the intercept toggle is global rather than window-bound.
    ("<Space>c", Bind::ToggleScopeFilter),
    // File the selected flow as a finding, from wherever you noticed it.
    ("<Space>f", Bind::PromptSeeded(":finding ")),
    // Intercept verdicts live in `WINDOW_MAP` as bare `f`/`d`, since that is
    // where they are unambiguous. Toggling *whether* we hold is global, though:
    // you reach for it from wherever you noticed traffic was stalling.
    ("<Space>i", Bind::ToggleIntercept),
    // Which legs hold, numbered left-to-right the way the panes are laid out.
    ("<Space>1", Bind::ToggleHoldRequests),
    ("<Space>2", Bind::ToggleHoldResponses),
    // Vim's window motions, for a window that is genuinely split.
    ("<C-w>h", Bind::Focus(Some(Column::Left))),
    ("<C-w>l", Bind::Focus(Some(Column::Right))),
    ("<C-w>w", Bind::Focus(None)),
    // `i` starts insert, exactly as in vim — there is something to edit now.
    ("i", Bind::Mode(Mode::Insert)),
    // Windows. In a text editor these uppercase keys are Replace / Insert /
    // Append — but jumping between tools is the navigation a proxy needs
    // constantly, so they are spent here. `gt` / `gT` still cycle the way vim
    // cycles tabs. Lowercase `i` stays vim's insert, which is why Intercept
    // takes `C`.
    ("P", Bind::Window(Window::Proxy)),
    ("I", Bind::Window(Window::Intercept)),
    ("R", Bind::Window(Window::Repeater)),
    // `C` for sCope: `S` is Sitemap and moving it would break muscle memory
    // for the sake of a mnemonic.
    ("C", Bind::Window(Window::Scope)),
    // `T` for triage: `F` would read better but Intercept already spends it on
    // forward-all, and a window key you cannot press from every window is worse
    // than one with a duller mnemonic.
    ("T", Bind::Window(Window::Findings)),
    ("S", Bind::Window(Window::Sitemap)),
    ("A", Bind::Window(Window::Automate)),
    ("gt", Bind::WindowStep(1)),
    ("gT", Bind::WindowStep(-1)),
    // Command palette. `<D-k>` is Cmd-K, which most terminals swallow before it
    // reaches us, so `<C-k>` is bound as the one that works everywhere.
    ("<D-k>", Bind::Palette),
    ("<C-k>", Bind::Palette),
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
    /// Which window is on screen, so [`WINDOW_MAP`] can be consulted. The app
    /// keeps this in step; the input layer never changes it itself.
    window: Window,
    /// Whether a text buffer has focus, which routes keys to the vim grammar
    /// instead of the window keymap. Set by the app.
    buffer_focus: bool,
    /// The vim grammar, used only while a buffer has focus.
    vim: crate::vim::VimParser,
}

impl Input {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Tell the input layer which window is active, so window-scoped bindings
    /// resolve against the right one.
    pub fn set_window(&mut self, window: Window) {
        self.window = window;
    }

    /// Tell the input layer whether a text buffer has focus. While it does,
    /// keys are parsed as vim commands against that buffer.
    pub fn set_buffer_focus(&mut self, focused: bool) {
        self.buffer_focus = focused;
    }

    /// Keep the grammar's idea of visual mode in step with the buffer's, so an
    /// operator knows whether it needs a target or already has a selection.
    pub fn set_vim_visual(&mut self, visual: bool) {
        self.vim.set_visual(visual);
    }

    /// The in-progress `:` or `/` line, for the UI to render at the bottom.
    pub fn cmdline(&self) -> Option<&str> {
        (self.mode == Mode::Command).then_some(self.cmdline.as_str())
    }

    /// Half-typed input, shown bottom-right the way vim shows `d2` mid-command.
    pub fn pending_display(&self) -> String {
        if self.buffer_focus {
            return self.vim.pending();
        }
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
            Mode::Palette => self.feed_palette(key),
            Mode::Insert => self.feed_insert(key),
            // A focused buffer takes every key: inside it these are vim
            // commands, and falling through to the window map would let `d`
            // drop a request halfway through typing `diw`.
            _ if self.buffer_focus => self.feed_vim(key),
            Mode::Normal | Mode::Visual => self.feed_normal(key),
        }
    }

    // --- vim grammar ---

    fn feed_vim(&mut self, key: KeyEvent) -> Option<Action> {
        use crate::vim::Parsed;

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let parsed = match key.code {
            KeyCode::Esc => self.vim.feed_escape(),
            KeyCode::Char('r') if ctrl => self.vim.feed_redo(),
            // Escape hatch to the real editor, from inside the buffer. The
            // grammar never sees it: a focused buffer takes every key, so
            // without this arm there would be no way to reach `$EDITOR` short
            // of leaving the preview first.
            KeyCode::Char('g') if ctrl => return Some(Action::ExternalEdit),
            KeyCode::Char(c) if !ctrl => self.vim.feed(c),
            // Arrows are the same motions by another name.
            KeyCode::Left => self.vim.feed('h'),
            KeyCode::Right => self.vim.feed('l'),
            KeyCode::Up => self.vim.feed('k'),
            KeyCode::Down => self.vim.feed('j'),
            KeyCode::Enter => self.vim.feed('j'),
            _ => return None,
        };

        match parsed {
            Parsed::Command(cmd) => {
                if cmd.enters_insert() {
                    self.mode = Mode::Insert;
                }
                Some(Action::Vim(cmd))
            }
            Parsed::Pending | Parsed::Invalid => None,
        }
    }

    // --- insert ---

    /// While a buffer is being edited every printable key is text. Only Escape
    /// leaves, which is the whole contract vim muscle memory expects.
    fn feed_insert(&mut self, key: KeyEvent) -> Option<Action> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let gesture = match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                return Some(Action::ModeChange(Mode::Normal));
            }
            KeyCode::Backspace => InsertKey::Backspace,
            KeyCode::Delete => InsertKey::Delete,
            KeyCode::Enter => InsertKey::Newline,
            KeyCode::Left => InsertKey::Left,
            KeyCode::Right => InsertKey::Right,
            KeyCode::Up => InsertKey::Up,
            KeyCode::Down => InsertKey::Down,
            KeyCode::Home => InsertKey::LineStart,
            KeyCode::End => InsertKey::LineEnd,
            // Readline's line motions, the two that are worth having in a box
            // with no word motions.
            KeyCode::Char('a') if ctrl => InsertKey::LineStart,
            KeyCode::Char('e') if ctrl => InsertKey::LineEnd,
            KeyCode::Tab => InsertKey::Char('\t'),
            KeyCode::Char(c) if !ctrl => InsertKey::Char(c),
            _ => return None,
        };
        Some(Action::Insert(gesture))
    }

    // --- command palette ---

    /// While the palette is open every key is a palette gesture: printable keys
    /// filter, `<C-n>`/`<C-p>` (or the arrows, or `<C-j>`/`<C-k>`) move, Enter
    /// runs, Escape dismisses. The app owns the list; we only report the gesture.
    fn feed_palette(&mut self, key: KeyEvent) -> Option<Action> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let gesture = match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                PaletteKey::Cancel
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                PaletteKey::Accept
            }
            KeyCode::Backspace => PaletteKey::Backspace,
            KeyCode::Up => PaletteKey::Up,
            KeyCode::Down => PaletteKey::Down,
            // Telescope's motions: Ctrl holds them apart from typed letters.
            KeyCode::Char('n' | 'j') if ctrl => PaletteKey::Down,
            KeyCode::Char('p' | 'k') if ctrl => PaletteKey::Up,
            KeyCode::Char(c) if !ctrl => PaletteKey::Char(c),
            _ => return None,
        };
        Some(Action::Palette(gesture))
    }

    // --- normal / visual ---

    fn feed_normal(&mut self, key: KeyEvent) -> Option<Action> {
        let token = encode(key)?;

        if token == "<Esc>" {
            let had_pending = !self.pending.is_empty() || !self.count.is_empty();
            self.reset();
            if self.mode == Mode::Visual {
                self.mode = Mode::Normal;
                return Some(Action::ModeChange(Mode::Normal));
            }
            // With something half-typed, Escape's job was to discard it and
            // nothing more. Otherwise it means "back out", which is the window's
            // to interpret.
            return (!had_pending).then_some(Action::Escape);
        }

        // A count is digits typed before a command — but a leading `0` is the
        // "first column" motion, not the start of a number.
        if self.pending.is_empty() && is_count_digit(&token, self.count.is_empty()) {
            self.count.push_str(&token);
            return None;
        }

        self.pending.push(token);
        match resolve(&self.pending, self.window) {
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
                let next = if self.mode == mode {
                    Mode::Normal
                } else {
                    mode
                };
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
            Bind::PromptSeeded(seed) => {
                self.mode = Mode::Command;
                seed.clone_into(&mut self.cmdline);
                return None;
            }
            Bind::Resend => Action::Resend,
            Bind::Forward => Action::Forward,
            Bind::Drop => Action::Drop,
            Bind::ForwardAll => Action::ForwardAll,
            Bind::DropAll => Action::DropAll,
            Bind::ToggleIntercept => Action::ToggleIntercept,
            Bind::SendToRepeater => Action::SendToRepeater,
            Bind::ToggleScopeFilter => Action::ToggleScopeFilter,
            Bind::CycleSeverity => Action::CycleSeverity,
            Bind::CycleStatus => Action::CycleStatus,
            Bind::ScopeAddHost => Action::ScopeAddHost,
            Bind::ScopeRemoveHost => Action::ScopeRemoveHost,
            Bind::NewSession => Action::NewSession,
            Bind::CloseSession => Action::CloseSession,
            Bind::SelectSession => Action::SelectSession(count),
            Bind::History { forward } => Action::History { forward },
            Bind::ToggleView => Action::ToggleView,
            Bind::Toggle => Action::Toggle,
            Bind::Enter => Action::Enter,
            Bind::ExternalEdit => Action::ExternalEdit,
            Bind::Focus(column) => Action::Focus(column),
            Bind::ToggleHoldRequests => Action::ToggleHoldRequests,
            Bind::ToggleHoldResponses => Action::ToggleHoldResponses,
            Bind::Window(window) => Action::Window(window),
            Bind::WindowStep(direction) => Action::WindowStep(direction),
            // Enter palette mode and tell the app to start with a clean filter.
            Bind::Palette => {
                self.mode = Mode::Palette;
                Action::Palette(PaletteKey::Open)
            }
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
                    _ => Action::Search {
                        pattern: rest,
                        backward: kind == '?',
                    },
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
///
/// Window-scoped bindings win over global ones, so a window can claim a key
/// without the global map having to know that any window exists.
fn resolve(pending: &[String], window: Window) -> Resolution {
    let typed = pending.concat();
    let mut partial = false;

    for (scope, sequence, bind) in WINDOW_MAP {
        if *scope != window {
            continue;
        }
        if *sequence == typed {
            return Resolution::Match(*bind, None);
        }
        partial |= sequence.starts_with(&typed);
    }

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

    if partial {
        Resolution::Partial
    } else {
        Resolution::None
    }
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
    // Cmd on macOS. vim spells it `<D-…>`; whether it ever arrives is up to the
    // terminal, but if it does we want it to mean the same as the fallback.
    let cmd = key.modifiers.contains(KeyModifiers::SUPER);
    Some(match key.code {
        KeyCode::Char(' ') if !ctrl => "<Space>".into(),
        KeyCode::Char(c) if cmd => format!("<D-{}>", c.to_ascii_lowercase()),
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

    /// Like `last`, but the sequence opens with a key `feed` cannot spell.
    fn last_with(first: KeyEvent, rest: &str) -> Action {
        let mut input = Input::new();
        input.feed(first);
        feed(&mut input, rest).pop().expect("no action")
    }

    #[test]
    fn plain_motion_carries_no_count() {
        assert_eq!(
            last("j"),
            Action::Move {
                motion: Motion::Down,
                count: None
            }
        );
    }

    #[test]
    fn digits_accumulate_into_a_count() {
        assert_eq!(
            last("12j"),
            Action::Move {
                motion: Motion::Down,
                count: Some(12)
            }
        );
    }

    /// Bare `G` means "last line" but `12G` means "line 12" — so the absence of
    /// a count has to survive as `None` rather than collapsing to 1.
    #[test]
    fn count_presence_is_distinguishable() {
        assert_eq!(
            last("G"),
            Action::Move {
                motion: Motion::Bottom,
                count: None
            }
        );
        assert_eq!(
            last("12G"),
            Action::Move {
                motion: Motion::Bottom,
                count: Some(12)
            }
        );
    }

    /// A leading `0` is a motion in vim, not the start of a number.
    #[test]
    fn leading_zero_is_not_a_count() {
        let mut input = Input::new();
        assert!(feed(&mut input, "0").is_empty());
        assert_eq!(
            input.pending_display(),
            "",
            "0 should not be buffered as a count"
        );
        assert_eq!(
            last("10j"),
            Action::Move {
                motion: Motion::Down,
                count: Some(10)
            }
        );
    }

    #[test]
    fn multi_key_sequences_wait_for_completion() {
        let mut input = Input::new();
        assert!(input.feed(KeyEvent::from(KeyCode::Char('g'))).is_none());
        assert_eq!(
            input.pending_display(),
            "g",
            "half-typed keys should be visible"
        );
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('g'))),
            Some(Action::Move {
                motion: Motion::Top,
                count: None
            })
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
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('v'))),
            Some(Action::ModeChange(Mode::Visual))
        );
        assert_eq!(input.mode(), Mode::Visual);
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Esc)),
            Some(Action::ModeChange(Mode::Normal))
        );
        assert_eq!(input.mode(), Mode::Normal);
    }

    /// Motions must keep working while a visual selection is active.
    #[test]
    fn visual_mode_still_moves() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('v')));
        assert_eq!(
            last("j"),
            Action::Move {
                motion: Motion::Down,
                count: None
            }
        );
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
            Some(Action::Search {
                pattern: "admin".into(),
                backward: false
            })
        );

        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('?')));
        feed(&mut input, "admin");
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Search {
                pattern: "admin".into(),
                backward: true
            })
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
        assert_eq!(
            input.mode(),
            Mode::Normal,
            "erasing the ':' should abandon the prompt"
        );
    }

    #[test]
    fn control_keys_map_to_scroll_and_jumps() {
        let mut input = Input::new();
        assert_eq!(
            input.feed(ctrl('d')),
            Some(Action::Move {
                motion: Motion::HalfPageDown,
                count: None
            })
        );
        assert_eq!(input.feed(ctrl('o')), Some(Action::JumpBack));
    }

    /// The leader keeps application verbs out of vim's namespace.
    #[test]
    fn leader_sequence_triggers_resend() {
        let mut input = Input::new();
        assert!(input.feed(KeyEvent::from(KeyCode::Char(' '))).is_none());
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('r'))),
            Some(Action::Resend)
        );
    }

    /// The keys vim reserves must stay reserved, or muscle memory starts lying.
    /// `i` has left this list: there are editable buffers now, and it does in
    /// here exactly what it does in vim.
    #[test]
    fn vim_reserved_keys_are_unbound() {
        for key in ["q", "r", "x", "d", "c", "y", "p"] {
            let mut input = Input::new();
            assert!(
                feed(&mut input, key).is_empty(),
                "{key} should not be bound yet"
            );
        }
    }

    #[test]
    fn zz_quits_without_shadowing_z_motions() {
        assert_eq!(last("ZZ"), Action::Command("q".into()));
        assert_eq!(last("zz"), Action::Scroll(Scroll::Center));
    }

    #[test]
    fn uppercase_keys_jump_to_windows() {
        assert_eq!(last("P"), Action::Window(Window::Proxy));
        assert_eq!(last("I"), Action::Window(Window::Intercept));
        assert_eq!(last("R"), Action::Window(Window::Repeater));
        assert_eq!(last("S"), Action::Window(Window::Sitemap));
        assert_eq!(last("A"), Action::Window(Window::Automate));
    }

    /// Uppercase `I` jumps to Intercept while lowercase `i` still starts insert.
    /// Only the lowercase key is vim's, so the pair does not conflict.
    #[test]
    fn i_enters_insert_mode_and_escape_leaves() {
        let mut input = Input::new();
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('I'))),
            Some(Action::Window(Window::Intercept)),
            "uppercase I is the window jump"
        );
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('i'))),
            Some(Action::ModeChange(Mode::Insert))
        );
        assert_eq!(input.mode(), Mode::Insert);
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Esc)),
            Some(Action::ModeChange(Mode::Normal))
        );
        assert_eq!(input.mode(), Mode::Normal);
    }

    /// In Insert mode the keymap stops applying: `j` is a letter, not a motion.
    #[test]
    fn insert_mode_takes_printable_keys_as_text() {
        let mut input = Input::new();
        input.feed(KeyEvent::from(KeyCode::Char('i')));
        for c in ['j', 'G', ':', ' '] {
            assert_eq!(
                input.feed(KeyEvent::from(KeyCode::Char(c))),
                Some(Action::Insert(InsertKey::Char(c))),
                "{c} should be text in insert mode"
            );
        }
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Insert(InsertKey::Newline))
        );
    }

    /// `<C-w>` window motions, for the split Intercept window.
    #[test]
    fn ctrl_w_moves_focus_between_panes() {
        let mut input = Input::new();
        assert!(
            input.feed(ctrl('w')).is_none(),
            "should wait for a direction"
        );
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('l'))),
            Some(Action::Focus(Some(Column::Right)))
        );
        assert_eq!(last_with(ctrl('w'), "h"), Action::Focus(Some(Column::Left)));
        assert_eq!(last_with(ctrl('w'), "w"), Action::Focus(None));
    }

    /// A digit after the leader is an argument, not a count — the count rule
    /// only applies to digits typed before a sequence starts.
    #[test]
    fn leader_digits_choose_which_legs_hold() {
        assert_eq!(last(" 1"), Action::ToggleHoldRequests);
        assert_eq!(last(" 2"), Action::ToggleHoldResponses);
    }

    #[test]
    fn leader_verbs_are_global() {
        assert_eq!(last(" i"), Action::ToggleIntercept);
        assert_eq!(last(" s"), Action::SendToRepeater);
    }

    /// In Intercept, bare `f`/`d` answer the queue. This is the one place the
    /// fidelity rule bends, and it must bend *only* there.
    #[test]
    fn intercept_claims_bare_f_and_d() {
        let mut input = Input::new();
        input.set_window(Window::Intercept);
        assert_eq!(feed(&mut input, "f").pop(), Some(Action::Forward));
        assert_eq!(feed(&mut input, "d").pop(), Some(Action::Drop));
        assert_eq!(feed(&mut input, "F").pop(), Some(Action::ForwardAll));
        assert_eq!(feed(&mut input, "D").pop(), Some(Action::DropAll));
        assert_eq!(feed(&mut input, "\r").pop(), None, "CR is not a Char key");
    }

    /// Bare digits are vim counts, consumed before the keymap is consulted, so
    /// a window binding on `1` can never fire. Tab selection is leader-prefixed
    /// for that reason — this pins the conflict so it cannot come back.
    #[test]
    fn digits_stay_counts_and_tab_selection_is_leader_prefixed() {
        let mut input = Input::new();
        input.set_window(Window::Repeater);
        assert!(
            feed(&mut input, "2").is_empty(),
            "a bare digit must stay a count"
        );

        // `{count}gs` is how you pick one, using the count rather than fighting
        // it. Leader-prefixed digits are not free either: `<Space>1` and
        // `<Space>2` are the hold toggles.
        let mut input = Input::new();
        input.set_window(Window::Repeater);
        assert_eq!(
            feed(&mut input, "2gs"),
            vec![Action::SelectSession(Some(2))]
        );

        // Bare `gs` cycles, as vim's bare `gt` does.
        let mut input = Input::new();
        input.set_window(Window::Repeater);
        assert_eq!(feed(&mut input, "gs"), vec![Action::SelectSession(None)]);
    }

    #[test]
    fn f_and_d_stay_free_in_other_windows() {
        // Proxy and Repeater can both put a text buffer under the cursor, so
        // `d` there has to stay the delete operator.
        for window in [Window::Proxy, Window::Repeater] {
            let mut input = Input::new();
            input.set_window(window);
            assert!(
                feed(&mut input, "f").is_empty(),
                "f should be unbound in {window:?}"
            );
            assert!(
                feed(&mut input, "d").is_empty(),
                "d should be unbound in {window:?}"
            );
        }

        // Sitemap and Scope have no buffer and no line to operate on, which is
        // the same reason Intercept gets to spend `d` on a verdict. `f` stays
        // free in both: there is still nothing to find a character on, but
        // nothing worth binding it to either.
        for window in [Window::Sitemap, Window::Scope] {
            let mut input = Input::new();
            input.set_window(window);
            assert!(
                feed(&mut input, "f").is_empty(),
                "f should be unbound in {window:?}"
            );
        }

        let mut input = Input::new();
        input.set_window(Window::Sitemap);
        assert_eq!(
            feed(&mut input, "d"),
            vec![Action::ScopeRemoveHost],
            "Sitemap spends `d` on taking a host out of scope"
        );
    }

    /// `<CR>` means different things in different windows, which is exactly
    /// what window scoping is for.
    #[test]
    fn cr_is_scoped_to_the_window() {
        let cr = KeyEvent::from(KeyCode::Enter);

        let mut input = Input::new();
        input.set_window(Window::Intercept);
        assert_eq!(input.feed(cr), Some(Action::Enter));

        let mut input = Input::new();
        input.set_window(Window::Sitemap);
        assert_eq!(input.feed(cr), Some(Action::Toggle));

        let mut input = Input::new();
        input.set_window(Window::Proxy);
        assert_eq!(input.feed(cr), None, "unbound elsewhere");
    }

    /// Escape with nothing half-typed is a "back out" the window interprets;
    /// with a partial sequence it only discards that.
    #[test]
    fn escape_reports_only_when_nothing_is_pending() {
        let mut input = Input::new();
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Esc)),
            Some(Action::Escape)
        );

        let mut input = Input::new();
        feed(&mut input, "12g");
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Esc)),
            None,
            "should have discarded the partial sequence instead"
        );
    }

    /// `gt` / `gT` cycle tabs, and must not disturb `gg`, whose prefix they share.
    #[test]
    fn gt_cycles_windows_without_shadowing_gg() {
        assert_eq!(last("gt"), Action::WindowStep(1));
        assert_eq!(last("gT"), Action::WindowStep(-1));
        assert_eq!(
            last("gg"),
            Action::Move {
                motion: Motion::Top,
                count: None
            }
        );
    }

    #[test]
    fn windows_cycle_and_wrap_in_tab_order() {
        assert_eq!(Window::Proxy.step(1), Window::Intercept);
        assert_eq!(
            Window::Automate.step(1),
            Window::Proxy,
            "last wraps to first"
        );
        assert_eq!(
            Window::Proxy.step(-1),
            Window::Automate,
            "first wraps to last"
        );
    }

    /// Both Cmd-K and the Ctrl-K fallback open the palette and enter its mode.
    #[test]
    fn cmd_k_and_ctrl_k_open_the_palette() {
        for key in [
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::SUPER),
            ctrl('k'),
        ] {
            let mut input = Input::new();
            assert_eq!(input.feed(key), Some(Action::Palette(PaletteKey::Open)));
            assert_eq!(input.mode(), Mode::Palette);
        }
    }

    /// Once open, printable keys filter and Enter runs the highlighted command.
    #[test]
    fn palette_filters_then_accepts() {
        let mut input = Input::new();
        input.feed(ctrl('k'));
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Char('r'))),
            Some(Action::Palette(PaletteKey::Char('r')))
        );
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Enter)),
            Some(Action::Palette(PaletteKey::Accept))
        );
        assert_eq!(input.mode(), Mode::Normal, "Enter closes the palette");
    }

    #[test]
    fn palette_navigates_with_ctrl_and_arrows_and_escapes() {
        let mut input = Input::new();
        input.feed(ctrl('k'));
        assert_eq!(
            input.feed(ctrl('n')),
            Some(Action::Palette(PaletteKey::Down))
        );
        assert_eq!(input.feed(ctrl('p')), Some(Action::Palette(PaletteKey::Up)));
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Down)),
            Some(Action::Palette(PaletteKey::Down))
        );
        assert_eq!(
            input.feed(KeyEvent::from(KeyCode::Esc)),
            Some(Action::Palette(PaletteKey::Cancel))
        );
        assert_eq!(input.mode(), Mode::Normal);
    }
}
