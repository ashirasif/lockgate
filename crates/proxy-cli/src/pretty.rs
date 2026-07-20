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

use crate::syntax::Language;

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
    /// The body is a language we do not reformat.
    Unsupported,
}

impl std::fmt::Display for PrettyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrettyError::NoBody => write!(f, "no body to format"),
            PrettyError::EmptyBody => write!(f, "body is empty"),
            PrettyError::NotJson(why) => write!(f, "not JSON: {why}"),
            PrettyError::Unsupported => write!(f, "body is not JSON or HTML"),
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
pub fn pretty_message(text: &str) -> Result<(String, Language), PrettyError> {
    let (head, body) = split(text).ok_or(PrettyError::NoBody)?;
    if body.trim().is_empty() {
        return Err(PrettyError::EmptyBody);
    }

    // The same detection the highlighter uses, so `gq` can never reformat as
    // JSON something the pane is colouring as HTML.
    let headers: Vec<String> = head.split('\n').skip(1).map(str::to_string).collect();
    let body_lines: Vec<String> = body.split('\n').map(str::to_string).collect();

    let language = crate::syntax::detect_body(&headers, &body_lines);
    let formatted = match language {
        Language::Json => pretty_json(body)?,
        Language::Html => pretty_html(body)?,
        Language::Form | Language::Plain => return Err(PrettyError::Unsupported),
    };
    let head = retarget_content_length(head, formatted.len());
    Ok((format!("{head}\n\n{formatted}"), language))
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

/// Elements with no closing tag, which must not open an indent level.
const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Elements whose contents are text rather than markup.
const RAW: &[&str] = &["script", "style", "pre", "textarea"];

/// Break minified HTML onto one line per node.
///
/// **This changes whitespace between elements, and in HTML that is not always
/// cosmetic** — whitespace between inline elements renders as a space, so a
/// reformatted body is not guaranteed to render identically to the original.
/// That is an acceptable trade for reading a 559-byte single-line response, but
/// it is why the status line says the body was rewritten, and why `u` restores
/// it exactly. `<pre>`, `<textarea>`, `<script>` and `<style>` are copied
/// verbatim, since for those the whitespace is unambiguously content.
pub fn pretty_html(src: &str) -> Result<String, PrettyError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut depth: usize = 0;
    let mut saw_tag = false;
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '<' {
            // A text node runs to the next tag. Trimmed, because the whitespace
            // around it is exactly what we are replacing with indentation.
            let start = i;
            while i < chars.len() && chars[i] != '<' {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            let text = text.trim();
            if !text.is_empty() {
                out.push(indent(depth) + text);
            }
            continue;
        }

        if starts_with(&chars, i, "<!--") {
            let end = find(&chars, i, "-->").map_or(chars.len(), |e| e + 3);
            out.push(indent(depth) + &collect(&chars, i, end));
            i = end;
            continue;
        }

        let Some(close) = tag_end(&chars, i) else {
            // An unterminated tag is the rest of the document; emitting it as
            // text beats dropping it.
            out.push(indent(depth) + collect(&chars, i, chars.len()).trim());
            break;
        };
        let tag = collect(&chars, i, close + 1);
        let name = tag_name(&tag);
        saw_tag = true;

        if tag.starts_with("<!") || tag.starts_with("<?") {
            out.push(indent(depth) + &tag);
            i = close + 1;
            continue;
        }

        if tag.starts_with("</") {
            depth = depth.saturating_sub(1);
            out.push(indent(depth) + &tag);
            i = close + 1;
            continue;
        }

        out.push(indent(depth) + &tag);
        i = close + 1;

        let self_closing = tag.ends_with("/>");
        if self_closing || VOID.iter().any(|v| name.eq_ignore_ascii_case(v)) {
            continue;
        }

        if RAW.iter().any(|r| name.eq_ignore_ascii_case(r)) {
            // Verbatim: inside these elements whitespace is content, so
            // re-indenting it would change what the page says.
            let closing = format!("</{name}");
            let end = find_ignore_case(&chars, i, &closing).unwrap_or(chars.len());
            let body = collect(&chars, i, end);
            if !body.trim().is_empty() {
                out.push(body);
            }
            i = end;
            continue;
        }

        depth += 1;
    }

    if !saw_tag {
        return Err(PrettyError::Unsupported);
    }
    Ok(out.join("\n"))
}

fn indent(depth: usize) -> String {
    INDENT.repeat(depth)
}

fn collect(chars: &[char], from: usize, to: usize) -> String {
    chars[from..to.min(chars.len())].iter().collect()
}

/// The `>` closing the tag opening at `from`, skipping any inside attribute
/// values — `<a title="a>b">` is one tag, not two.
fn tag_end(chars: &[char], from: usize) -> Option<usize> {
    let mut i = from + 1;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        match (quote, chars[i]) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, c @ ('"' | '\'')) => quote = Some(c),
            (None, '>') => return Some(i),
            (None, _) => {}
        }
        i += 1;
    }
    None
}

fn tag_name(tag: &str) -> String {
    tag.trim_start_matches(['<', '/', '!', '?'])
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ':'))
        .collect()
}

fn starts_with(chars: &[char], at: usize, needle: &str) -> bool {
    needle
        .chars()
        .enumerate()
        .all(|(k, c)| chars.get(at + k) == Some(&c))
}

fn find(chars: &[char], from: usize, needle: &str) -> Option<usize> {
    (from..chars.len()).find(|&i| starts_with(chars, i, needle))
}

/// Tag names are case-insensitive in HTML, so `</SCRIPT>` closes `<script>`.
fn find_ignore_case(chars: &[char], from: usize, needle: &str) -> Option<usize> {
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    find(&lower, from, &needle.to_ascii_lowercase())
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
        let out = pretty_message(msg).unwrap().0;
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
        let out = pretty_message(msg).unwrap().0;
        let body = out.split_once("\n\n").unwrap().1;
        assert!(
            out.contains(&format!("Content-Length: {}", body.len())),
            "{out}"
        );
    }

    #[test]
    fn content_length_is_matched_case_insensitively() {
        let msg = "POST /a HTTP/1.1\ncontent-length: 7\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap().0;
        assert!(out.contains("content-length: 12"), "{out}");
    }

    /// Absent means the sender chose not to declare one; inventing one changes
    /// how the far end frames the message.
    #[test]
    fn a_missing_content_length_is_not_invented() {
        let msg = "POST /a HTTP/1.1\nHost: x\n\n{\"a\":1}";
        let out = pretty_message(msg).unwrap().0;
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
        // Unstructured text has no formatter, so it is unsupported rather
        // than a JSON parse failure.
        assert_eq!(
            pretty_message("GET / HTTP/1.1\n\nnot json"),
            Err(PrettyError::Unsupported)
        );
        // A body that announces itself as JSON and then is not still reports
        // the parse error, so the reason stays specific.
        assert!(matches!(
            pretty_message("GET / HTTP/1.1\n\n{oops}"),
            Err(PrettyError::NotJson(_))
        ));
    }

    /// The case from the screenshot: a minified response body on one line.
    #[test]
    fn minified_html_is_broken_onto_lines() {
        let out = pretty_html(
            r#"<!doctype html><html lang="en"><head><title>Example Domain</title></head></html>"#,
        )
        .unwrap();
        assert_eq!(
            out,
            "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <title>\n      Example Domain\n    </title>\n  </head>\n</html>"
        );
    }

    #[test]
    fn void_elements_do_not_open_an_indent_level() {
        let out = pretty_html("<div><br><img src=\"x\"><p>hi</p></div>").unwrap();
        let depths: Vec<usize> = out
            .lines()
            .map(|l| l.len() - l.trim_start().len())
            .collect();
        // div=0, br=2, img=2, p=2, text=4, /p=2, /div=0 — br and img must not
        // push everything after them one level deeper.
        assert_eq!(depths, [0, 2, 2, 2, 4, 2, 0], "{out}");
    }

    #[test]
    fn self_closing_tags_do_not_open_an_indent_level() {
        let out = pretty_html("<a><b/><c/></a>").unwrap();
        assert_eq!(out, "<a>\n  <b/>\n  <c/>\n</a>");
    }

    /// Inside these, whitespace is content — re-indenting would change what the
    /// page actually says.
    #[test]
    fn raw_elements_are_copied_verbatim() {
        let src = "<pre>  keep\n   this  </pre>";
        let out = pretty_html(src).unwrap();
        assert!(out.contains("  keep\n   this  "), "{out}");

        let script = "<script>if (a<b) { x(); }</script>";
        let out = pretty_html(script).unwrap();
        assert!(out.contains("if (a<b) { x(); }"), "{out}");
    }

    /// `</SCRIPT>` closes `<script>`: HTML tag names are case-insensitive.
    #[test]
    fn a_raw_block_closes_case_insensitively() {
        let out = pretty_html("<SCRIPT>var a=1;</SCRIPT><p>after</p>").unwrap();
        assert!(out.contains("after"), "the block must end: {out}");
    }

    /// `>` inside an attribute value does not end the tag.
    #[test]
    fn a_bracket_inside_an_attribute_does_not_split_the_tag() {
        let out = pretty_html(r#"<a title="a>b">x</a>"#).unwrap();
        assert_eq!(out, "<a title=\"a>b\">\n  x\n</a>");
    }

    #[test]
    fn comments_survive_and_do_not_swallow_the_document() {
        let out = pretty_html("<div><!-- note --><p>x</p></div>").unwrap();
        assert!(out.contains("<!-- note -->"), "{out}");
        assert!(out.contains("<p>"), "the comment must end: {out}");
    }

    /// Malformed markup must not lose content or hang.
    #[test]
    fn unterminated_markup_is_kept_rather_than_dropped() {
        let out = pretty_html("<div><p>text<span").unwrap();
        assert!(out.contains("text"), "{out}");
        assert!(out.contains("<span"), "{out}");
    }

    #[test]
    fn text_with_no_tags_at_all_is_not_html() {
        assert_eq!(pretty_html("just words"), Err(PrettyError::Unsupported));
    }

    /// The message-level path must pick HTML for an HTML body, and must not try
    /// to parse it as JSON.
    #[test]
    fn an_html_response_body_is_formatted_as_html() {
        let msg = "HTTP/1.1 200 OK\ncontent-type: text/html\n\n<html><body>hi</body></html>";
        let out = pretty_message(msg).unwrap().0;
        assert!(
            out.starts_with("HTTP/1.1 200 OK\ncontent-type: text/html\n\n"),
            "{out}"
        );
        assert!(
            out.ends_with("<html>\n  <body>\n    hi\n  </body>\n</html>"),
            "{out}"
        );
    }

    /// Bodies we have no formatter for are reported rather than mangled.
    #[test]
    fn a_plain_text_body_is_unsupported() {
        let msg = "HTTP/1.1 200 OK\ncontent-type: text/plain\n\nnothing structured here";
        assert_eq!(pretty_message(msg), Err(PrettyError::Unsupported));
    }

    /// A body containing a blank line must not be split at the wrong place.
    #[test]
    fn only_the_first_blank_line_separates() {
        let msg = "POST / HTTP/1.1\nHost: x\n\n{\n\n\"a\":1}";
        let out = pretty_message(msg).unwrap().0;
        assert!(out.ends_with("{\n  \"a\": 1\n}"), "{out}");
    }
}
