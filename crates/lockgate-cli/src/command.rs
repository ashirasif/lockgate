//! The `:` command line.
//!
//! Parsing lives here, execution lives in the UI. Commands are the escape
//! valve that stops us inventing forty keybindings: anything niche gets a
//! name on `:` instead of a chord.

/// A parsed `:` command. Unknown names become [`Command::Unknown`] so the UI
/// can echo vim's own error rather than silently doing nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Quit,
    /// `:resend` — replay the selection, same as `<Space>r`.
    Resend,
    /// `:set rnu`, `:set nornu`, … — a boolean option and its new value.
    Set {
        option: String,
        value: bool,
    },
    /// `:12` — a bare line number jumps to that flow.
    Goto(usize),
    /// `:pretty` — reformat the body of the message being edited. The same
    /// thing `gq` does, reachable when the buffer does not have focus.
    Pretty,
    /// `:finding <title>` — file the selected flow as a draft finding.
    Finding(String),
    /// `:finding! <title>` — retitle the highlighted finding. Same bang rule as
    /// `:note!`: without it you always get a new one.
    RenameFinding(String),
    /// `:note <title>` — start a project note and open it for editing.
    Note(String),
    /// `:note! <title>` — retitle the highlighted note. The `!` is vim's own
    /// "and mean it" suffix: `:note` with no bang always makes a new one, so
    /// the destructive reading of a bare title is never the accidental one.
    RenameNote(String),
    /// `:scope <verb> [argument]` — scope management. Patterns are free text,
    /// so they arrive as a command rather than as forty keybindings.
    Scope {
        verb: String,
        argument: String,
    },
    /// `:unhide` — bring back everything `d` removed from the histories.
    /// Listed because undoing a thing you can do blind needs a name, not a
    /// chord nobody remembers.
    Unhide,
    Help,
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        let (name, rest) = match line.split_once(char::is_whitespace) {
            Some((name, rest)) => (name, rest.trim()),
            None => (line, ""),
        };
        if name.is_empty() {
            return None;
        }
        // `:42` — vim's bare-line-number jump.
        if let Ok(line_number) = name.parse::<usize>() {
            return Some(Command::Goto(line_number));
        }
        Some(match name {
            "q" | "quit" => Command::Quit,
            "resend" | "rep" | "repeat" => Command::Resend,
            "h" | "help" => Command::Help,
            "pretty" | "pp" | "format" => Command::Pretty,
            "finding" | "fi" => Command::Finding(rest.to_string()),
            "finding!" | "fi!" => Command::RenameFinding(rest.to_string()),
            "note" | "nt" => Command::Note(rest.to_string()),
            "note!" | "nt!" => Command::RenameNote(rest.to_string()),
            "scope" | "sc" => {
                let (verb, argument) = match rest.split_once(char::is_whitespace) {
                    Some((verb, argument)) => (verb.to_string(), argument.trim().to_string()),
                    None => (rest.to_string(), String::new()),
                };
                Command::Scope { verb, argument }
            }
            "set" => parse_set(rest),
            "unhide" | "uh" => Command::Unhide,
            _ => Command::Unknown(name.to_string()),
        })
    }
}

/// `:set foo` turns an option on, `:set nofoo` turns it off.
fn parse_set(rest: &str) -> Command {
    match rest.strip_prefix("no") {
        Some(option) if !option.is_empty() => Command::Set {
            option: option.to_string(),
            value: false,
        },
        _ => Command::Set {
            option: rest.to_string(),
            value: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abbreviations_resolve_to_the_same_command() {
        assert_eq!(Command::parse("q"), Some(Command::Quit));
        assert_eq!(Command::parse("quit"), Some(Command::Quit));
        assert_eq!(Command::parse("resend"), Some(Command::Resend));
        assert_eq!(Command::parse("rep"), Some(Command::Resend));
    }

    #[test]
    fn unhide_parses_with_its_abbreviation() {
        assert_eq!(Command::parse("unhide"), Some(Command::Unhide));
        assert_eq!(Command::parse("uh"), Some(Command::Unhide));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(Command::parse("  quit  "), Some(Command::Quit));
    }

    #[test]
    fn empty_line_is_not_a_command() {
        assert_eq!(Command::parse(""), None);
        assert_eq!(Command::parse("   "), None);
    }

    /// `:42` is vim's jump-to-line, and the history table is a list of lines.
    #[test]
    fn bare_number_is_a_jump() {
        assert_eq!(Command::parse("42"), Some(Command::Goto(42)));
    }

    #[test]
    fn set_toggles_on_the_no_prefix() {
        assert_eq!(
            Command::parse("set rnu"),
            Some(Command::Set {
                option: "rnu".into(),
                value: true
            })
        );
        assert_eq!(
            Command::parse("set nornu"),
            Some(Command::Set {
                option: "rnu".into(),
                value: false
            })
        );
    }

    /// The bang is what separates "new note" from "rename this one", so the two
    /// must not collapse into each other. `:finding` reads the same way.
    #[test]
    fn the_bang_distinguishes_a_new_note_from_a_rename() {
        assert_eq!(
            Command::parse("note auth teardown"),
            Some(Command::Note("auth teardown".into()))
        );
        assert_eq!(
            Command::parse("note! auth teardown"),
            Some(Command::RenameNote("auth teardown".into()))
        );
        assert_eq!(
            Command::parse("finding auth bypass"),
            Some(Command::Finding("auth bypass".into()))
        );
        assert_eq!(
            Command::parse("finding! auth bypass"),
            Some(Command::RenameFinding("auth bypass".into()))
        );
        assert_eq!(
            Command::parse("fi! auth bypass"),
            Some(Command::RenameFinding("auth bypass".into()))
        );
    }

    #[test]
    fn unknown_commands_are_reported_not_swallowed() {
        assert_eq!(
            Command::parse("frobnicate"),
            Some(Command::Unknown("frobnicate".into()))
        );
    }
}
