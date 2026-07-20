//! Re-indenting JSON bodies inside an HTTP message.
//!
//! Hand-rolled rather than routed through `serde_json`, for two reasons that
//! both matter specifically in a security tool:
//!
//! - **Key order is preserved.** `serde_json`'s default map is a `BTreeMap`,
//!   which sorts keys. Reordering the body of a request changes what you are
//!   testing — server-side parsers disagree about duplicate and out-of-order
//!   keys, and that disagreement is often the whole point of the request.
//! - **Numbers survive verbatim.** Round-tripping through `f64` would rewrite
//!   `10000000000000000001` and `1.0`. Here the digits are copied as written,
//!   so a body that was crafted to sit on a precision boundary still does.
//!
//! Nothing is re-encoded: strings are copied through byte for byte, escapes
//! included. The only thing that changes is whitespace *between* tokens, which
//! JSON does not ascribe meaning to — so a pretty-printed body is still the
//! same request.

/// Why a body could not be pretty-printed.
#[derive(Debug, PartialEq, Eq)]
pub enum PrettyError {
    /// No blank line, so there is no body to format.
    NoBody,
    /// The body is empty or whitespace.
    EmptyBody,
    /// The body is not JSON. Carries what went wrong, so the status line can
    /// say *why* rather than just failing.
    NotJson(String),
}

impl std::fmt::Display for PrettyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrettyError::NoBody => write!(f, "no body to format"),
            PrettyError::EmptyBody => write!(f, "body is empty"),
            PrettyError::NotJson(why) => write!(f, "not JSON: {why}"),
        }
    }
}

const INDENT: &str = "  ";

/// Pretty-print the body of an HTTP message, leaving the head alone.
///
/// The start line and headers are untouched — reformatting those would change
/// the request rather than just its presentation. `Content-Length`, if present,
/// is corrected to the new body length: leaving a stale value behind would
/// silently truncate or hang the very next send, and that failure is miserable
/// to diagnose from the far end.
pub fn pretty_message(text: &str) -> Result<String, PrettyError> {
    let (head, body) = split(text).ok_or(PrettyError::NoBody)?;
    if body.trim().is_empty() {
        return Err(PrettyError::EmptyBody);
    }

    let formatted = pretty_json(body)?;
    let head = retarget_content_length(head, formatted.len());
    Ok(format!("{head}\n\n{formatted}"))
}

/// Split at the first blank line, into head and body.
fn split(text: &str) -> Option<(&str, &str)> {
    // Only LF: the buffer holds LF-separated text, CRLF is applied on the way
    // out by the renderer.
    let at = text.find("\n\n")?;
    Some((&text[..at], &text[at + 2..]))
}

/// Rewrite an existing `Content-Length` to `len`; add nothing if absent.
///
/// Absent means the message did not declare one, and inventing one could change
/// how the far end frames the request.
fn retarget_content_length(head: &str, len: usize) -> String {
    head.split('\n')
        .map(|line| match line.split_once(':') {
            Some((name, _)) if name.trim().eq_ignore_ascii_case("content-length") => {
                format!("{}: {len}", name.trim())
            }
            _ => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Re-indent a JSON document.
///
/// Rejects trailing content rather than formatting a prefix: a body that is
/// JSON followed by junk is a body you want to know about, not one you want
/// silently truncated.
pub fn pretty_json(src: &str) -> Result<String, PrettyError> {
    let chars: Vec<char> = src.chars().collect();
    let mut parser = Parser {
        chars: &chars,
        at: 0,
        out: String::with_capacity(src.len() + src.len() / 4),
    };
    parser.skip_whitespace();
    parser.value(0)?;
    parser.skip_whitespace();
    if parser.at < parser.chars.len() {
        return Err(PrettyError::NotJson(format!(
            "unexpected trailing input at character {}",
            parser.at
        )));
    }
    Ok(parser.out)
}

struct Parser<'a> {
    chars: &'a [char],
    at: usize,
    out: String,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.at += 1;
        }
    }

    fn newline(&mut self, depth: usize) {
        self.out.push('\n');
        for _ in 0..depth {
            self.out.push_str(INDENT);
        }
    }

    fn expected(&self, what: &str) -> PrettyError {
        match self.peek() {
            Some(c) => PrettyError::NotJson(format!(
                "expected {what} at character {}, found {c:?}",
                self.at
            )),
            None => PrettyError::NotJson(format!("expected {what}, found end of input")),
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), PrettyError> {
        match self.peek() {
            Some('{') => self.container(depth, true),
            Some('[') => self.container(depth, false),
            Some('"') => self.string(),
            Some(c) if c.is_ascii_digit() || c == '-' => self.number(),
            Some(c) if c.is_ascii_alphabetic() => self.literal(),
            _ => Err(self.expected("a value")),
        }
    }

    /// Objects and arrays differ only in their brackets and in whether entries
    /// carry a `"key":` — so they share one loop rather than two that drift.
    fn container(&mut self, depth: usize, object: bool) -> Result<(), PrettyError> {
        let (open, close) = if object { ('{', '}') } else { ('[', ']') };
        self.at += 1;
        self.out.push(open);
        self.skip_whitespace();

        // Empty containers stay on one line: `{}` reads better than a `{`, a
        // blank line and a `}`.
        if self.peek() == Some(close) {
            self.at += 1;
            self.out.push(close);
            return Ok(());
        }

        loop {
            self.newline(depth + 1);
            if object {
                if self.peek() != Some('"') {
                    return Err(self.expected("a quoted key"));
                }
                self.string()?;
                self.skip_whitespace();
                if self.peek() != Some(':') {
                    return Err(self.expected("':'"));
                }
                self.at += 1;
                self.out.push_str(": ");
                self.skip_whitespace();
            }
            self.value(depth + 1)?;
            self.skip_whitespace();

            match self.peek() {
                Some(',') => {
                    self.at += 1;
                    self.out.push(',');
                    self.skip_whitespace();
                    // A trailing comma before the closing bracket is not JSON.
                    if self.peek() == Some(close) {
                        return Err(self.expected("another entry after ','"));
                    }
                }
                Some(c) if c == close => {
                    self.at += 1;
                    self.newline(depth);
                    self.out.push(close);
                    return Ok(());
                }
                _ => return Err(self.expected("',' or a closing bracket")),
            }
        }
    }

    /// Copied through verbatim, escapes and all — re-encoding a string is a
    /// chance to change it, and there is nothing to gain by taking that chance.
    fn string(&mut self) -> Result<(), PrettyError> {
        let start = self.at;
        self.at += 1;
        loop {
            match self.peek() {
                Some('\\') => self.at += 2,
                Some('"') => {
                    self.at += 1;
                    self.out.extend(&self.chars[start..self.at]);
                    return Ok(());
                }
                // A raw newline inside a string is invalid JSON, and letting it
                // through would produce output that no longer parses.
                Some('\n') | None => {
                    return Err(PrettyError::NotJson(format!(
                        "unterminated string starting at character {start}"
                    )));
                }
                Some(_) => self.at += 1,
            }
        }
    }

    /// Digits are copied as written: no parse, no re-format, no lost precision.
    fn number(&mut self) -> Result<(), PrettyError> {
        let start = self.at;
        if self.peek() == Some('-') {
            self.at += 1;
        }
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        {
            self.at += 1;
        }
        if self.at == start || !self.chars[start..self.at].iter().any(char::is_ascii_digit) {
            return Err(self.expected("a number"));
        }
        self.out.extend(&self.chars[start..self.at]);
        Ok(())
    }

    fn literal(&mut self) -> Result<(), PrettyError> {
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.at += 1;
        }
        let word: String = self.chars[start..self.at].iter().collect();
        if !matches!(word.as_str(), "true" | "false" | "null") {
            return Err(PrettyError::NotJson(format!("unknown literal {word:?}")));
        }
        self.out.push_str(&word);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_structures_are_indented() {
        let out = pretty_json(r#"{"a":{"b":[1,2]}}"#).unwrap();
        assert_eq!(
            out,
            "{\n  \"a\": {\n    \"b\": [\n      1,\n      2\n    ]\n  }\n}"
        );
    }

    /// Sorting keys would change what the request tests. Encounter order wins.
    #[test]
    fn key_order_is_preserved() {
        let out = pretty_json(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        let keys: Vec<&str> = out
            .lines()
            .filter_map(|l| l.trim().split(':').next())
            .filter(|k| k.starts_with('"'))
            .collect();
        assert_eq!(keys, ["\"z\"", "\"a\"", "\"m\""]);
    }

    /// A float round-trip would rewrite both of these. They must come out byte
    /// for byte as they went in.
    #[test]
    fn number_precision_survives() {
        let src = r#"{"big":10000000000000000001,"exact":1.0,"exp":1e400,"neg":-0.5}"#;
        let out = pretty_json(src).unwrap();
        for literal in ["10000000000000000001", "1.0", "1e400", "-0.5"] {
            assert!(out.contains(literal), "{literal} missing from {out}");
        }
    }

    #[test]
    fn strings_are_copied_verbatim_including_escapes() {
        let src = r#"{"s":"a\"b\\cé\n"}"#;
        let out = pretty_json(src).unwrap();
        assert!(out.contains(r#""a\"b\\cé\n""#), "{out}");
    }

    /// A colon or bracket inside a string must not be read as structure.
    #[test]
    fn punctuation_inside_strings_is_not_structure() {
        let out = pretty_json(r#"{"u":"http://a.test/x?y={z}"}"#).unwrap();
        assert_eq!(out, "{\n  \"u\": \"http://a.test/x?y={z}\"\n}");
    }

    #[test]
    fn empty_containers_stay_on_one_line() {
        assert_eq!(pretty_json("{}").unwrap(), "{}");
        assert_eq!(pretty_json("[]").unwrap(), "[]");
        assert_eq!(
            pretty_json(r#"{"a":{},"b":[]}"#).unwrap(),
            "{\n  \"a\": {},\n  \"b\": []\n}"
        );
    }

    /// Running it twice must not keep adding indentation.
    #[test]
    fn formatting_is_idempotent() {
        let once = pretty_json(r#"{"a":[1,{"b":null}]}"#).unwrap();
        assert_eq!(pretty_json(&once).unwrap(), once);
    }

    #[test]
    fn scalars_and_literals_at_the_top_level_are_valid_json() {
        assert_eq!(pretty_json("true").unwrap(), "true");
        assert_eq!(pretty_json(" null ").unwrap(), "null");
        assert_eq!(pretty_json(r#""hi""#).unwrap(), r#""hi""#);
        assert_eq!(pretty_json("42").unwrap(), "42");
    }

    #[test]
    fn malformed_json_is_reported_rather_than_mangled() {
        for bad in [
            r#"{"a":}"#,
            r#"{"a":1,}"#,
            r#"{a:1}"#,
            r#"{"a":1"#,
            r#"{"a":1} trailing"#,
            r#"{"a":tru}"#,
            "",
            "not json",
        ] {
            assert!(
                pretty_json(bad).is_err(),
                "should have rejected {bad:?}, got {:?}",
                pretty_json(bad)
            );
        }
    }

    /// The head is presentation-neutral: reformatting it would change the
    /// request, not just how it looks.
    #[test]
    fn the_head_is_left_alone() {
        let msg = "POST /a HTTP/1.1\nHost: x.test\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap();
        assert!(
            out.starts_with("POST /a HTTP/1.1\nHost: x.test\n\n"),
            "{out}"
        );
        assert!(out.ends_with("{\n  \"a\": 1\n}"), "{out}");
    }

    /// A stale Content-Length silently truncates the next send. It must track
    /// the body it actually describes.
    #[test]
    fn content_length_follows_the_new_body() {
        let msg = "POST /a HTTP/1.1\nContent-Length: 7\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap();
        let body = out.split_once("\n\n").unwrap().1;
        assert!(
            out.contains(&format!("Content-Length: {}", body.len())),
            "{out}"
        );
    }

    #[test]
    fn content_length_is_matched_case_insensitively() {
        let msg = "POST /a HTTP/1.1\ncontent-length: 7\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap();
        assert!(out.contains("content-length: 12"), "{out}");
    }

    /// Absent means the sender chose not to declare one; inventing one changes
    /// how the far end frames the message.
    #[test]
    fn a_missing_content_length_is_not_invented() {
        let msg = "POST /a HTTP/1.1\nHost: x\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap();
        assert!(
            !out.to_ascii_lowercase().contains("content-length"),
            "{out}"
        );
    }

    #[test]
    fn messages_without_a_usable_body_are_reported() {
        assert_eq!(
            pretty_message("GET / HTTP/1.1\nHost: x"),
            Err(PrettyError::NoBody)
        );
        assert_eq!(
            pretty_message("GET / HTTP/1.1\nHost: x\n\n"),
            Err(PrettyError::EmptyBody)
        );
        assert!(matches!(
            pretty_message("GET / HTTP/1.1\n\nnot json"),
            Err(PrettyError::NotJson(_))
        ));
    }

    /// A body containing a blank line must not be split at the wrong place.
    #[test]
    fn only_the_first_blank_line_separates() {
        let msg = "POST / HTTP/1.1\nHost: x\n\n{\n\n\"a\":1}";
        let out = pretty_message(msg).unwrap();
        assert!(out.ends_with("{\n  \"a\": 1\n}"), "{out}");
    }
}
