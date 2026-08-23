//! A vim command grammar: keys in, parsed commands out.
//!
//! The flat key→action table this replaces could express `dd` and `dw` only
//! because each was written out by hand. It had no way to say `d2aw`, and every
//! new motion had to be multiplied by every operator to stay usable.
//!
//! Vim's grammar is
//!
//! ```text
//! [count] operator [count] (motion | text-object)
//! ```
//!
//! so that is what this parses. Adding `W` means adding one motion and it works
//! after every operator; adding `aw` means adding one text object and it works
//! with every count. That is the whole reason for the rewrite.
//!
//! This module is pure: it knows keys and grammar, never buffers or screens.
//! Resolving a [`Motion`] to a position is [`crate::editor`]'s job, because only
//! the buffer knows where the words are.

/// What to do to a range of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Delete,
    Change,
    Yank,
}

/// A cursor movement. Doubles as the range for an operator: `dw` is "delete
/// from here to where `w` would go".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motion {
    Left,
    Right,
    Up,
    Down,
    /// `w` / `W`. A "big" word is delimited by whitespace only, which is why
    /// `W` steps over `api.example.com` in one go where `w` takes five.
    WordForward {
        big: bool,
    },
    WordBackward {
        big: bool,
    },
    WordEnd {
        big: bool,
    },
    LineStart,
    FirstNonBlank,
    LineEnd,
    Top,
    Bottom,
    GotoLine(usize),
    /// `f` / `F` / `t` / `T`. `till` stops one short of the character.
    Find {
        ch: char,
        backward: bool,
        till: bool,
    },
}

impl Motion {
    /// Whether an operator over this motion works on whole lines. `dj` takes
    /// two lines; `dw` takes part of one.
    pub fn linewise(self) -> bool {
        matches!(
            self,
            Motion::Up | Motion::Down | Motion::Top | Motion::Bottom | Motion::GotoLine(_)
        )
    }

    /// Whether the character at the destination is part of the range.
    ///
    /// This is the distinction between `dw` and `de`: both end at the end of a
    /// word, but only `de` takes the last character with it. Getting it wrong
    /// is the classic off-by-one in a homegrown vim.
    pub fn inclusive(self) -> bool {
        match self {
            Motion::WordEnd { .. } | Motion::LineEnd => true,
            // Forward finds include their target; backward ones stop before it.
            Motion::Find { backward, .. } => !backward,
            _ => false,
        }
    }
}

/// The `iw` / `a"` family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Word {
        big: bool,
    },
    /// A quoted run, e.g. `i"`.
    Quote(char),
    /// A bracketed run, given its opening character, e.g. `i(`.
    Delim(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextObject {
    pub kind: ObjectKind,
    /// `a` rather than `i`: take the delimiters or trailing whitespace too.
    pub around: bool,
}

/// What an operator applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Motion(Motion),
    Object(TextObject),
    /// The doubled operator — `dd`, `cc`, `yy` — meaning whole lines.
    Line,
}

/// Commands that take no target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Simple {
    DeleteChar,
    DeleteToEnd,
    ChangeToEnd,
    PasteAfter,
    PasteBefore,
    Undo,
    Redo,
    Insert,
    InsertLineStart,
    Append,
    AppendLineEnd,
    OpenBelow,
    OpenAbove,
    /// `.`
    Repeat,
    JoinLines,
    /// `gq` — pretty-print the message body.
    ///
    /// Vim's `gq` is an operator that takes a motion, but there is only one
    /// sensible scope here: a JSON body is a single syntactic unit, and
    /// reformatting half of one produces garbage. So this is a simple command
    /// over the whole body rather than an operator, and `gqq`/`gqip` are not
    /// accepted — better to not offer a motion than to accept one and ignore it.
    Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Move {
        motion: Motion,
        count: usize,
    },
    Operate {
        op: Operator,
        target: Target,
        count: usize,
    },
    Simple {
        cmd: Simple,
        count: usize,
    },
    /// `v` / `V` — start (or leave) a selection.
    Visual {
        linewise: bool,
    },
    /// An operator pressed while a selection is up: it applies to the selection
    /// and there is no target to wait for.
    VisualOperate(Operator),
    /// `o` in visual mode — swap which end of the selection moves.
    VisualSwapEnds,
    /// Leave visual mode / cancel a half-typed command.
    Escape,
}

impl Command {
    /// Whether running this leaves the buffer in insert mode. The input layer
    /// needs to know before the buffer has acted, so it can switch modes in the
    /// same keystroke.
    pub fn enters_insert(self) -> bool {
        match self {
            Command::Operate { op, .. } => op == Operator::Change,
            Command::VisualOperate(op) => op == Operator::Change,
            Command::Simple { cmd, .. } => matches!(
                cmd,
                Simple::Insert
                    | Simple::InsertLineStart
                    | Simple::Append
                    | Simple::AppendLineEnd
                    | Simple::OpenBelow
                    | Simple::OpenAbove
                    | Simple::ChangeToEnd
            ),
            _ => false,
        }
    }
}

/// What a fed key produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    Command(Command),
    /// A valid prefix — keep feeding.
    Pending,
    /// Not a command. The caller should discard what it has.
    Invalid,
}

/// What the parser is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Wait {
    #[default]
    Start,
    /// After `g`, which is a prefix of `gg`.
    G,
    /// After `f`/`F`/`t`/`T`, swallowing the next key as a literal.
    Find { backward: bool, till: bool },
    /// After `i`/`a` in operator-pending or visual: the object type follows.
    Object { around: bool },
}

/// The grammar's state machine.
#[derive(Debug, Default)]
pub struct VimParser {
    /// Digits before the operator, and digits between operator and motion.
    /// Vim multiplies them: `2d3w` deletes six words.
    count1: String,
    count2: String,
    operator: Option<Operator>,
    wait: Wait,
    /// A selection is up, which changes what an operator means: it applies
    /// immediately instead of waiting for a target.
    visual: bool,
}

impl VimParser {
    /// Tell the parser a selection was started or ended elsewhere (leaving the
    /// pane, say), so `d` does not keep meaning "operate on the selection".
    pub fn set_visual(&mut self, visual: bool) {
        self.visual = visual;
        self.reset();
    }

    /// Whether anything is half-typed, for the pending-keys display.
    pub fn pending(&self) -> String {
        let mut out = self.count1.clone();
        if let Some(op) = self.operator {
            out.push(match op {
                Operator::Delete => 'd',
                Operator::Change => 'c',
                Operator::Yank => 'y',
            });
        }
        out.push_str(&self.count2);
        match self.wait {
            Wait::G => out.push('g'),
            Wait::Find { backward, till } => out.push(match (backward, till) {
                (false, false) => 'f',
                (true, false) => 'F',
                (false, true) => 't',
                (true, true) => 'T',
            }),
            Wait::Object { around } => out.push(if around { 'a' } else { 'i' }),
            Wait::Start => {}
        }
        out
    }

    fn reset(&mut self) {
        self.count1.clear();
        self.count2.clear();
        self.operator = None;
        self.wait = Wait::Start;
    }

    /// The effective count: the two counts multiplied, at least 1.
    fn count(&self) -> usize {
        let a: usize = self.count1.parse().unwrap_or(1).max(1);
        let b: usize = self.count2.parse().unwrap_or(1).max(1);
        a.saturating_mul(b).clamp(1, 10_000)
    }

    /// Feed one character. Non-character keys (Escape, arrows) are the caller's
    /// to translate first.
    pub fn feed(&mut self, c: char) -> Parsed {
        match self.wait {
            Wait::Find { backward, till } => {
                let motion = Motion::Find {
                    ch: c,
                    backward,
                    till,
                };
                return self.finish_motion(motion);
            }
            Wait::Object { around } => {
                let Some(kind) = object_kind(c) else {
                    self.reset();
                    return Parsed::Invalid;
                };
                return self.finish_object(TextObject { kind, around });
            }
            Wait::G => {
                self.wait = Wait::Start;
                return match c {
                    'g' => self.finish_motion(Motion::Top),
                    // `gq` is a command, not a motion, so it cannot be an
                    // operator's target. This arm returns before the general
                    // operator-pending guard below, so `dgq` has to be rejected
                    // here or it would silently format instead.
                    'q' if self.operator.is_none() => self.finish_simple(Simple::Format),
                    _ => {
                        self.reset();
                        Parsed::Invalid
                    }
                };
            }
            Wait::Start => {}
        }

        // Counts. A leading `0` is the line-start motion, not a digit — but a
        // `0` after other digits is.
        if c.is_ascii_digit() && !(c == '0' && self.current_count().is_empty()) {
            self.current_count_mut().push(c);
            return Parsed::Pending;
        }

        match c {
            // Operators. Doubling one means whole lines; in visual mode it
            // applies to the selection at once.
            'd' | 'c' | 'y' => {
                let op = match c {
                    'd' => Operator::Delete,
                    'c' => Operator::Change,
                    _ => Operator::Yank,
                };
                if self.visual {
                    self.reset();
                    return Parsed::Command(Command::VisualOperate(op));
                }
                match self.operator {
                    Some(existing) if existing == op => {
                        let count = self.count();
                        self.reset();
                        Parsed::Command(Command::Operate {
                            op,
                            target: Target::Line,
                            count,
                        })
                    }
                    // A different operator replaces a half-typed one, matching
                    // vim's tolerance for `dc…`.
                    _ => {
                        self.operator = Some(op);
                        Parsed::Pending
                    }
                }
            }

            // Text-object prefixes only mean anything with an operator pending
            // or a selection up; otherwise `i` and `a` enter insert.
            'i' | 'a' if self.operator.is_some() || self.visual => {
                self.wait = Wait::Object { around: c == 'a' };
                Parsed::Pending
            }

            // Motions.
            'h' => self.finish_motion(Motion::Left),
            'l' | ' ' => self.finish_motion(Motion::Right),
            'k' => self.finish_motion(Motion::Up),
            'j' => self.finish_motion(Motion::Down),
            'w' => self.finish_motion(Motion::WordForward { big: false }),
            'W' => self.finish_motion(Motion::WordForward { big: true }),
            'b' => self.finish_motion(Motion::WordBackward { big: false }),
            'B' => self.finish_motion(Motion::WordBackward { big: true }),
            'e' => self.finish_motion(Motion::WordEnd { big: false }),
            'E' => self.finish_motion(Motion::WordEnd { big: true }),
            '0' => self.finish_motion(Motion::LineStart),
            '^' => self.finish_motion(Motion::FirstNonBlank),
            '$' => self.finish_motion(Motion::LineEnd),
            'G' => {
                // `5G` is line 5; bare `G` is the last line.
                let motion = match self.count1.parse::<usize>() {
                    Ok(n) => Motion::GotoLine(n),
                    Err(_) => Motion::Bottom,
                };
                self.finish_motion(motion)
            }
            'g' => {
                self.wait = Wait::G;
                Parsed::Pending
            }
            'f' | 'F' | 't' | 'T' => {
                self.wait = Wait::Find {
                    backward: c.is_uppercase(),
                    till: c.eq_ignore_ascii_case(&'t'),
                };
                Parsed::Pending
            }

            // Everything below is only a command on its own — an operator
            // waiting for a target cannot use it.
            _ if self.operator.is_some() => {
                self.reset();
                Parsed::Invalid
            }

            'v' => {
                self.reset();
                Parsed::Command(Command::Visual { linewise: false })
            }
            'V' => {
                self.reset();
                Parsed::Command(Command::Visual { linewise: true })
            }
            'o' if self.visual => {
                self.reset();
                Parsed::Command(Command::VisualSwapEnds)
            }

            // In visual mode these act on the selection rather than a count.
            'x' if self.visual => {
                self.reset();
                Parsed::Command(Command::VisualOperate(Operator::Delete))
            }
            's' if self.visual => {
                self.reset();
                Parsed::Command(Command::VisualOperate(Operator::Change))
            }

            'x' => self.finish_simple(Simple::DeleteChar),
            'D' => self.finish_simple(Simple::DeleteToEnd),
            'C' => self.finish_simple(Simple::ChangeToEnd),
            'p' => self.finish_simple(Simple::PasteAfter),
            'P' => self.finish_simple(Simple::PasteBefore),
            'u' => self.finish_simple(Simple::Undo),
            'J' => self.finish_simple(Simple::JoinLines),
            '.' => self.finish_simple(Simple::Repeat),
            'i' => self.finish_simple(Simple::Insert),
            'I' => self.finish_simple(Simple::InsertLineStart),
            'a' => self.finish_simple(Simple::Append),
            'A' => self.finish_simple(Simple::AppendLineEnd),
            'o' => self.finish_simple(Simple::OpenBelow),
            'O' => self.finish_simple(Simple::OpenAbove),

            _ => {
                self.reset();
                Parsed::Invalid
            }
        }
    }

    /// `<C-r>` and friends arrive as named keys rather than characters.
    pub fn feed_redo(&mut self) -> Parsed {
        self.finish_simple(Simple::Redo)
    }

    pub fn feed_escape(&mut self) -> Parsed {
        let had_pending = !self.pending().is_empty();
        self.reset();
        // Escape's first job is to cancel a half-typed command; only once there
        // is nothing pending does it leave visual mode.
        if had_pending {
            Parsed::Pending
        } else {
            Parsed::Command(Command::Escape)
        }
    }

    fn current_count(&self) -> &str {
        if self.operator.is_some() {
            &self.count2
        } else {
            &self.count1
        }
    }

    fn current_count_mut(&mut self) -> &mut String {
        if self.operator.is_some() {
            &mut self.count2
        } else {
            &mut self.count1
        }
    }

    fn finish_motion(&mut self, motion: Motion) -> Parsed {
        let count = self.count();
        let op = self.operator;
        self.reset();
        Parsed::Command(match op {
            Some(op) => Command::Operate {
                op,
                target: Target::Motion(motion),
                count,
            },
            None => Command::Move { motion, count },
        })
    }

    fn finish_object(&mut self, object: TextObject) -> Parsed {
        let count = self.count();
        let op = self.operator;
        self.reset();
        match op {
            Some(op) => Parsed::Command(Command::Operate {
                op,
                target: Target::Object(object),
                count,
            }),
            // `viw` with no operator extends the selection over the object.
            None if self.visual => Parsed::Command(Command::Operate {
                op: Operator::Yank,
                target: Target::Object(object),
                count,
            }),
            None => Parsed::Invalid,
        }
    }

    fn finish_simple(&mut self, cmd: Simple) -> Parsed {
        let count = self.count();
        self.reset();
        Parsed::Command(Command::Simple { cmd, count })
    }
}

/// The object a key names after `i`/`a`. Both halves of a bracket pair select
/// the same object, so `i(` and `i)` are the same thing, as in vim.
fn object_kind(c: char) -> Option<ObjectKind> {
    Some(match c {
        'w' => ObjectKind::Word { big: false },
        'W' => ObjectKind::Word { big: true },
        '"' | '\'' | '`' => ObjectKind::Quote(c),
        '(' | ')' | 'b' => ObjectKind::Delim('('),
        '[' | ']' => ObjectKind::Delim('['),
        '{' | '}' | 'B' => ObjectKind::Delim('{'),
        '<' | '>' => ObjectKind::Delim('<'),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole sequence, returning what the last key produced.
    fn parse(keys: &str) -> Parsed {
        let mut p = VimParser::default();
        let mut last = Parsed::Pending;
        for c in keys.chars() {
            last = p.feed(c);
        }
        last
    }

    /// `gq` is a whole-body command, not a motion, so it must not be usable as
    /// an operator target — `dgq` is a typo, and formatting instead of erroring
    /// would be a surprising thing to do to someone's request.
    #[test]
    fn gq_formats_and_cannot_be_an_operator_target() {
        assert_eq!(
            parse("gq"),
            Parsed::Command(Command::Simple {
                cmd: Simple::Format,
                count: 1
            })
        );
        assert_eq!(parse("dgq"), Parsed::Invalid);
        assert_eq!(parse("ygq"), Parsed::Invalid);
        // `gg` must still work — `gq` shares its prefix.
        assert_eq!(
            parse("gg"),
            Parsed::Command(Command::Move {
                motion: Motion::Top,
                count: 1
            })
        );
    }

    fn visual(keys: &str) -> Parsed {
        let mut p = VimParser::default();
        p.set_visual(true);
        let mut last = Parsed::Pending;
        for c in keys.chars() {
            last = p.feed(c);
        }
        last
    }

    #[test]
    fn bare_motions_move() {
        assert_eq!(
            parse("w"),
            Parsed::Command(Command::Move {
                motion: Motion::WordForward { big: false },
                count: 1
            })
        );
        assert_eq!(
            parse("W"),
            Parsed::Command(Command::Move {
                motion: Motion::WordForward { big: true },
                count: 1
            })
        );
        assert_eq!(
            parse("B"),
            Parsed::Command(Command::Move {
                motion: Motion::WordBackward { big: true },
                count: 1
            })
        );
        assert_eq!(
            parse("E"),
            Parsed::Command(Command::Move {
                motion: Motion::WordEnd { big: true },
                count: 1
            })
        );
    }

    #[test]
    fn counts_attach_to_motions() {
        assert_eq!(
            parse("12j"),
            Parsed::Command(Command::Move {
                motion: Motion::Down,
                count: 12
            })
        );
    }

    /// A leading `0` is the line-start motion; a later `0` is a digit.
    #[test]
    fn zero_is_a_motion_until_it_is_a_digit() {
        assert_eq!(
            parse("0"),
            Parsed::Command(Command::Move {
                motion: Motion::LineStart,
                count: 1
            })
        );
        assert_eq!(
            parse("10j"),
            Parsed::Command(Command::Move {
                motion: Motion::Down,
                count: 10
            })
        );
    }

    #[test]
    fn operators_take_motions() {
        assert_eq!(
            parse("dw"),
            Parsed::Command(Command::Operate {
                op: Operator::Delete,
                target: Target::Motion(Motion::WordForward { big: false }),
                count: 1
            })
        );
        assert_eq!(
            parse("cE"),
            Parsed::Command(Command::Operate {
                op: Operator::Change,
                target: Target::Motion(Motion::WordEnd { big: true }),
                count: 1
            })
        );
    }

    /// A doubled operator is linewise: `dd`, `cc`, `yy`.
    #[test]
    fn doubled_operators_are_linewise() {
        for (keys, op) in [
            ("dd", Operator::Delete),
            ("cc", Operator::Change),
            ("yy", Operator::Yank),
        ] {
            assert_eq!(
                parse(keys),
                Parsed::Command(Command::Operate {
                    op,
                    target: Target::Line,
                    count: 1
                })
            );
        }
    }

    /// Both counts multiply, which is the rule that a flat keymap cannot
    /// express at all: `2d3w` deletes six words.
    #[test]
    fn counts_multiply_across_the_operator() {
        assert_eq!(
            parse("2d3w"),
            Parsed::Command(Command::Operate {
                op: Operator::Delete,
                target: Target::Motion(Motion::WordForward { big: false }),
                count: 6
            })
        );
        assert_eq!(
            parse("3dd"),
            Parsed::Command(Command::Operate {
                op: Operator::Delete,
                target: Target::Line,
                count: 3
            })
        );
    }

    #[test]
    fn text_objects_parse_after_an_operator() {
        assert_eq!(
            parse("ciw"),
            Parsed::Command(Command::Operate {
                op: Operator::Change,
                target: Target::Object(TextObject {
                    kind: ObjectKind::Word { big: false },
                    around: false
                }),
                count: 1
            })
        );
        assert_eq!(
            parse("da\""),
            Parsed::Command(Command::Operate {
                op: Operator::Delete,
                target: Target::Object(TextObject {
                    kind: ObjectKind::Quote('"'),
                    around: true
                }),
                count: 1
            })
        );
        assert_eq!(
            parse("yi("),
            Parsed::Command(Command::Operate {
                op: Operator::Yank,
                target: Target::Object(TextObject {
                    kind: ObjectKind::Delim('('),
                    around: false
                }),
                count: 1
            })
        );
    }

    /// Either half of a bracket pair names the same object.
    #[test]
    fn both_brackets_name_the_same_object() {
        assert_eq!(parse("di("), parse("di)"));
        assert_eq!(parse("di{"), parse("diB"));
    }

    /// Without an operator, `i` and `a` are insert commands, not object
    /// prefixes — the same keys meaning different things by context is exactly
    /// what a grammar buys over a table.
    #[test]
    fn i_and_a_are_insert_commands_on_their_own() {
        assert_eq!(
            parse("i"),
            Parsed::Command(Command::Simple {
                cmd: Simple::Insert,
                count: 1
            })
        );
        assert_eq!(
            parse("a"),
            Parsed::Command(Command::Simple {
                cmd: Simple::Append,
                count: 1
            })
        );
    }

    #[test]
    fn find_swallows_the_next_key() {
        assert_eq!(
            parse("f;"),
            Parsed::Command(Command::Move {
                motion: Motion::Find {
                    ch: ';',
                    backward: false,
                    till: false
                },
                count: 1
            })
        );
        assert_eq!(
            parse("dT/"),
            Parsed::Command(Command::Operate {
                op: Operator::Delete,
                target: Target::Motion(Motion::Find {
                    ch: '/',
                    backward: true,
                    till: true
                }),
                count: 1
            })
        );
        // A motion key used as a find argument is taken literally.
        assert_eq!(
            parse("fw"),
            Parsed::Command(Command::Move {
                motion: Motion::Find {
                    ch: 'w',
                    backward: false,
                    till: false
                },
                count: 1
            })
        );
    }

    #[test]
    fn gg_and_goto_line() {
        assert_eq!(
            parse("gg"),
            Parsed::Command(Command::Move {
                motion: Motion::Top,
                count: 1
            })
        );
        assert_eq!(
            parse("5G"),
            Parsed::Command(Command::Move {
                motion: Motion::GotoLine(5),
                count: 5
            })
        );
        assert_eq!(
            parse("G"),
            Parsed::Command(Command::Move {
                motion: Motion::Bottom,
                count: 1
            })
        );
    }

    #[test]
    fn visual_mode_starts_and_operators_apply_at_once() {
        assert_eq!(
            parse("v"),
            Parsed::Command(Command::Visual { linewise: false })
        );
        assert_eq!(
            parse("V"),
            Parsed::Command(Command::Visual { linewise: true })
        );
        // With a selection up, `d` needs no target.
        assert_eq!(
            visual("d"),
            Parsed::Command(Command::VisualOperate(Operator::Delete))
        );
        assert_eq!(
            visual("x"),
            Parsed::Command(Command::VisualOperate(Operator::Delete))
        );
        assert_eq!(
            visual("y"),
            Parsed::Command(Command::VisualOperate(Operator::Yank))
        );
    }

    /// In visual mode a text object extends the selection instead of needing an
    /// operator first.
    #[test]
    fn visual_text_objects_need_no_operator() {
        assert!(matches!(
            visual("iw"),
            Parsed::Command(Command::Operate {
                target: Target::Object(_),
                ..
            })
        ));
    }

    #[test]
    fn partial_sequences_report_pending() {
        let mut p = VimParser::default();
        assert_eq!(p.feed('2'), Parsed::Pending);
        assert_eq!(p.feed('d'), Parsed::Pending);
        assert_eq!(p.feed('i'), Parsed::Pending);
        assert_eq!(p.pending(), "2di");
        assert!(matches!(p.feed('w'), Parsed::Command(_)));
        assert_eq!(p.pending(), "", "a finished command clears");
    }

    #[test]
    fn nonsense_after_an_operator_is_discarded() {
        let mut p = VimParser::default();
        p.feed('d');
        assert_eq!(p.feed('z'), Parsed::Invalid);
        assert_eq!(p.pending(), "", "and does not linger");
    }

    /// Escape cancels a half-typed command first, and only then leaves visual
    /// mode — pressing it once mid-command must not drop the selection.
    #[test]
    fn escape_cancels_before_it_leaves() {
        // A half-typed operator: the first Escape discards it, the second is a
        // real Escape for the caller to act on.
        let mut p = VimParser::default();
        p.feed('2');
        p.feed('d');
        assert_eq!(p.pending(), "2d");
        assert_eq!(p.feed_escape(), Parsed::Pending, "cancels the command");
        assert_eq!(p.feed_escape(), Parsed::Command(Command::Escape));
    }

    /// In visual mode an operator fires immediately, so there is nothing
    /// half-typed for Escape to cancel.
    #[test]
    fn visual_operators_leave_nothing_pending() {
        let mut p = VimParser::default();
        p.set_visual(true);
        assert!(matches!(
            p.feed('d'),
            Parsed::Command(Command::VisualOperate(_))
        ));
        assert_eq!(p.pending(), "");
    }

    /// Motion metadata drives the off-by-one that separates `dw` from `de`.
    #[test]
    fn inclusivity_and_linewise_are_marked() {
        assert!(!Motion::WordForward { big: false }.inclusive());
        assert!(Motion::WordEnd { big: false }.inclusive());
        assert!(
            Motion::Find {
                ch: 'x',
                backward: false,
                till: false
            }
            .inclusive()
        );
        assert!(
            !Motion::Find {
                ch: 'x',
                backward: true,
                till: false
            }
            .inclusive()
        );

        assert!(Motion::Down.linewise());
        assert!(Motion::Top.linewise());
        assert!(!Motion::WordForward { big: false }.linewise());
    }
}
