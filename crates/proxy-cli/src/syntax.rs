//! Syntax highlighting for HTTP wire text.
//!
//! Not tree-sitter, and deliberately so. Tree-sitter earns its keep on languages
//! with recursive structure and error recovery worth doing properly; an HTTP
//! message is three flat regions — start line, headers, body — separated by the
//! first blank line. A grammar, a parser generator and a C dependency would buy
//! nothing here that thirty lines of scanning does not.
//!
//! The one place real nesting appears is a JSON body, and even there the useful
//! property is that **a JSON string cannot contain a literal newline**. That
//! makes tokenising one line at a time correct rather than merely convenient: a
//! line can only end mid-string if the document is already invalid.
//!
//! Highlighting is *presentational only*. It never edits the buffer and never
//! refuses to render — malformed input is a normal case in a proxy, and text
//! that fails to parse must still be readable. Every path degrades to plain
//! text rather than erroring.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Whether the buffer holds a request or a response.
///
/// Inferred rather than passed in, so the read-only preview panes and the
/// editable ones share one code path — and so an edit that turns one into the
/// other re-colours immediately instead of lying until the pane is rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Request,
    Response,
}

/// What language a message body is written in.
///
/// Public and shared with [`crate::pretty`] on purpose: the highlighter and the
/// formatter must never disagree about what a body is, or `gq` would reformat
/// something as JSON that the pane is colouring as HTML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Json,
    Html,
    Form,
    Plain,
}

// --- palette -------------------------------------------------------------
//
// Punctuation uses DIM rather than a named grey, for the same reason `muted()`
// in the UI does: a fixed dark colour vanishes against a transparent or light
// terminal background, while DIM is relative to whatever foreground the user
// actually has.

fn plain() -> Style {
    Style::new()
}
fn punct() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}
fn method() -> Style {
    Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD)
}
fn target() -> Style {
    Style::new().fg(Color::Cyan)
}
fn header_name() -> Style {
    Style::new().fg(Color::Blue)
}
fn json_key() -> Style {
    Style::new().fg(Color::Cyan)
}
fn json_string() -> Style {
    Style::new().fg(Color::Green)
}
fn json_number() -> Style {
    Style::new().fg(Color::Magenta)
}
fn json_literal() -> Style {
    Style::new().fg(Color::Yellow)
}
fn tag_name() -> Style {
    Style::new().fg(Color::Blue)
}
fn attr_name() -> Style {
    Style::new().fg(Color::Cyan)
}
fn attr_value() -> Style {
    Style::new().fg(Color::Green)
}
fn comment() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

/// Status colouring by class, which is the thing an operator actually scans for.
fn status(code: &str) -> Style {
    let colour = match code.as_bytes().first() {
        Some(b'2') => Color::Green,
        Some(b'3') => Color::Cyan,
        Some(b'4') => Color::Yellow,
        Some(b'5') => Color::Red,
        _ => return plain(),
    };
    Style::new().fg(colour).add_modifier(Modifier::BOLD)
}

/// Style every character of every line.
///
/// Returns one `Style` per character, so callers can overlay their own
/// per-cell decoration — a cursor, a visual selection — on top without the
/// highlighter needing to know those exist.
pub fn highlight(lines: &[String]) -> Vec<Vec<Style>> {
    let kind = match lines.first() {
        Some(first) if first.starts_with("HTTP/") => Kind::Response,
        _ => Kind::Request,
    };

    // The first blank line ends the headers. No blank line means the whole
    // buffer is head and there is no body — matching how `http_text` splits it.
    let separator = lines
        .iter()
        .position(|l| l.trim_end_matches('\r').is_empty());
    let body_start = separator.map(|i| i + 1);

    let body = match separator {
        // `1.min(sep)` because the separator can be line 0 — a buffer whose
        // very first line is blank has no start line and no headers, and
        // `1..0` would panic rather than yielding nothing.
        Some(sep) => detect_body(&lines[1.min(sep)..sep], &lines[sep + 1..]),
        None => Language::Plain,
    };

    // HTML is the one body language that needs state carried between lines: a
    // comment, a tag or a <script> block can all straddle a newline, and JSON's
    // "strings cannot span lines" guarantee has no HTML equivalent. Threading it
    // through the fold keeps the highlighter a single pass.
    let mut html = HtmlState::Text;

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let chars: Vec<char> = line.chars().collect();
            match (i, body_start) {
                (0, _) => start_line(&chars, kind),
                (_, Some(start)) if i >= start => match body {
                    Language::Json => json_line(&chars),
                    Language::Html => html_line(&chars, &mut html),
                    Language::Form => form_line(&chars),
                    Language::Plain => vec![plain(); chars.len()],
                },
                _ if Some(i) == separator => Vec::new(),
                _ => header_line(&chars),
            }
        })
        .collect()
}

/// Pick a body language.
///
/// `Content-Type` is consulted first, but a body that *looks* like JSON is
/// treated as JSON regardless of what the header claims. Mislabelled bodies are
/// routine in this line of work — `text/plain` wrapping JSON is common enough
/// that trusting the header would make the feature useless exactly when someone
/// is looking hardest.
pub fn detect_body(headers: &[String], body: &[String]) -> Language {
    let content_type = headers
        .iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_ascii_lowercase())
        })
        .unwrap_or_default();

    if content_type.contains("json") {
        return Language::Json;
    }
    if content_type.contains("x-www-form-urlencoded") {
        return Language::Form;
    }
    if content_type.contains("html") || content_type.contains("xml") {
        return Language::Html;
    }
    match body
        .iter()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| l.trim_start().chars().next())
    {
        Some('{' | '[') => Language::Json,
        Some('<') => Language::Html,
        _ => Language::Plain,
    }
}

/// `METHOD target HTTP/1.1` or `HTTP/1.1 200 Reason`.
fn start_line(chars: &[char], kind: Kind) -> Vec<Style> {
    let mut styles = vec![plain(); chars.len()];
    for (index, (start, end)) in words(chars).into_iter().enumerate() {
        let style = match (kind, index) {
            (Kind::Request, 0) => method(),
            (Kind::Request, 1) => target(),
            (Kind::Request, _) => punct(),
            (Kind::Response, 0) => punct(),
            (Kind::Response, 1) => status(&chars[start..end].iter().collect::<String>()),
            // The reason phrase is several words; colour them like the status
            // but without the weight, so the code stays the thing that pops.
            (Kind::Response, _) => {
                let code: String = words(chars)
                    .get(1)
                    .map(|&(s, e)| chars[s..e].iter().collect())
                    .unwrap_or_default();
                status(&code).remove_modifier(Modifier::BOLD)
            }
        };
        styles[start..end].fill(style);
    }
    styles
}

/// `Name: value`. Everything up to the first colon is the name.
fn header_line(chars: &[char]) -> Vec<Style> {
    let mut styles = vec![plain(); chars.len()];
    // No colon is malformed, but it is also what a half-typed line looks like,
    // so it stays plain rather than being flagged mid-keystroke.
    if let Some(colon) = chars.iter().position(|&c| c == ':') {
        styles[..colon].fill(header_name());
        styles[colon] = punct();
    }
    styles
}

/// One line of JSON.
///
/// Correct line-locally because JSON strings cannot span lines; a line that ends
/// inside a string is already invalid, and the worst outcome is mis-colouring
/// text that was never going to parse.
fn json_line(chars: &[char]) -> Vec<Style> {
    let mut styles = vec![plain(); chars.len()];
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '"' => {
                let end = string_end(chars, i);
                // A string is a key if the next thing that is not whitespace is
                // a colon. That lookahead is the whole key/value distinction.
                let is_key = chars[end..]
                    .iter()
                    .find(|c| !c.is_whitespace())
                    .is_some_and(|&c| c == ':');
                styles[i..end].fill(if is_key { json_key() } else { json_string() });
                i = end;
            }
            '{' | '}' | '[' | ']' | ',' | ':' => {
                styles[i] = punct();
                i += 1;
            }
            c if c.is_ascii_digit() || c == '-' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_digit()
                        || matches!(chars[i], '-' | '+' | '.' | 'e' | 'E'))
                {
                    i += 1;
                }
                styles[start..i].fill(json_number());
            }
            c if c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if matches!(word.as_str(), "true" | "false" | "null") {
                    styles[start..i].fill(json_literal());
                }
            }
            _ => i += 1,
        }
    }
    styles
}

/// Where a JSON string ends, one past its closing quote.
///
/// `\\` escapes the next character, so a `\"` inside the string does not close
/// it. An unterminated string runs to end of line.
fn string_end(chars: &[char], open: usize) -> usize {
    let mut i = open + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    chars.len()
}

/// Where the HTML scanner is, between lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlState {
    Text,
    /// Inside `<…>`. Carries the raw-text block to enter once the tag closes,
    /// because `<script` and its content are decided one after the other.
    InTag {
        raw: Option<&'static str>,
    },
    InComment,
    /// Inside `<script>`/`<style>`/`<pre>`/`<textarea>`, whose contents are not
    /// markup and must not be scanned for tags.
    InRaw(&'static str),
}

/// Tags whose contents are text, not markup.
fn raw_tag(name: &str) -> Option<&'static str> {
    ["script", "style", "pre", "textarea"]
        .into_iter()
        .find(|t| name.eq_ignore_ascii_case(t))
}

/// One line of HTML, resuming from `state` and leaving it where the line ends.
fn html_line(chars: &[char], state: &mut HtmlState) -> Vec<Style> {
    let mut styles = vec![plain(); chars.len()];
    let mut i = 0;

    while i < chars.len() {
        match *state {
            HtmlState::InComment => {
                let end = find(chars, i, "-->");
                let stop = end.map_or(chars.len(), |e| e + 3);
                styles[i..stop].fill(comment());
                i = stop;
                if end.is_some() {
                    *state = HtmlState::Text;
                }
            }
            HtmlState::InRaw(tag) => {
                // Raw content stays plain; only the closing tag ends the block.
                let end = find(chars, i, &format!("</{tag}"));
                i = end.unwrap_or(chars.len());
                if end.is_some() {
                    *state = HtmlState::Text;
                }
            }
            HtmlState::InTag { raw } => {
                match chars[i] {
                    '>' => {
                        styles[i] = punct();
                        i += 1;
                        // `<script/>` never enters raw text; `<script>` does.
                        *state = match raw {
                            Some(tag) if chars.get(i.wrapping_sub(2)) != Some(&'/') => {
                                HtmlState::InRaw(tag)
                            }
                            _ => HtmlState::Text,
                        };
                    }
                    '/' | '=' => {
                        styles[i] = punct();
                        i += 1;
                    }
                    '"' | '\'' => {
                        let quote = chars[i];
                        let mut end = i + 1;
                        while end < chars.len() && chars[end] != quote {
                            end += 1;
                        }
                        let stop = (end + 1).min(chars.len());
                        styles[i..stop].fill(attr_value());
                        i = stop;
                    }
                    c if c.is_whitespace() => i += 1,
                    _ => {
                        let start = i;
                        while i < chars.len()
                            && !chars[i].is_whitespace()
                            && !matches!(chars[i], '>' | '=' | '/' | '"' | '\'')
                        {
                            i += 1;
                        }
                        styles[start..i].fill(attr_name());
                    }
                }
            }
            HtmlState::Text => {
                let Some(open) = chars[i..].iter().position(|&c| c == '<').map(|p| p + i) else {
                    break;
                };
                i = open;

                if starts_with(chars, i, "<!--") {
                    *state = HtmlState::InComment;
                    continue;
                }

                styles[i] = punct();
                i += 1;
                // `<!doctype`, `<?xml` and `</` all lead with punctuation before
                // the name.
                while i < chars.len() && matches!(chars[i], '/' | '!' | '?') {
                    styles[i] = punct();
                    i += 1;
                }

                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || matches!(chars[i], '-' | '_' | ':'))
                {
                    i += 1;
                }
                styles[start..i].fill(tag_name());

                let name: String = chars[start..i].iter().collect();
                let closing = chars.get(start.wrapping_sub(1)) == Some(&'/');
                *state = HtmlState::InTag {
                    raw: if closing { None } else { raw_tag(&name) },
                };
            }
        }
    }
    styles
}

/// Whether `needle` begins at `at`.
fn starts_with(chars: &[char], at: usize, needle: &str) -> bool {
    needle
        .chars()
        .enumerate()
        .all(|(k, c)| chars.get(at + k) == Some(&c))
}

/// The next occurrence of `needle` at or after `from`.
fn find(chars: &[char], from: usize, needle: &str) -> Option<usize> {
    (from..chars.len()).find(|&i| starts_with(chars, i, needle))
}

/// `a=1&b=2` — colour the names, dim the separators.
fn form_line(chars: &[char]) -> Vec<Style> {
    let mut styles = vec![plain(); chars.len()];
    let mut name = true;
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '&' => {
                styles[i] = punct();
                name = true;
            }
            '=' => {
                styles[i] = punct();
                name = false;
            }
            _ if name => styles[i] = json_key(),
            _ => {}
        }
    }
    styles
}

/// Whitespace-separated runs, as `(start, end)` character offsets.
fn words(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        out.push((start, i));
    }
    out
}

/// Build display lines for a read-only pane, coalescing equal adjacent styles
/// into single spans so we hand ratatui a handful of spans per line rather than
/// one per character.
pub fn highlighted_lines(text: &str) -> Vec<Line<'static>> {
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let styles = highlight(&lines);
    lines
        .iter()
        .zip(styles)
        .map(|(line, styles)| Line::from(coalesce(line, &styles)))
        .collect()
}

/// Highlight headers and a body for a pane that renders its own start line.
///
/// The Proxy detail panes show `METHOD https://host/path` — the full URI, not
/// the origin-form target that goes on the wire — so their first line is built
/// separately. Rather than duplicate the header scan and the body sniff here,
/// this stitches a synthetic message together, highlights it whole, and drops
/// the placeholder line. Content-type detection then behaves identically in
/// both panes, because it is literally the same code.
pub fn highlighted_head_and_body(headers: &[String], body: &str) -> Vec<Line<'static>> {
    let mut lines = vec![String::new()];
    lines.extend(headers.iter().cloned());
    lines.push(String::new());
    lines.extend(body.lines().map(str::to_string));

    let styles = highlight(&lines);
    lines
        .iter()
        .zip(styles)
        .skip(1)
        .map(|(line, styles)| Line::from(coalesce(line, &styles)))
        .collect()
}

/// Merge runs of identical style into one span each.
pub fn coalesce(line: &str, styles: &[Style]) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut current = String::new();
    let mut current_style: Option<Style> = None;

    for (i, c) in line.chars().enumerate() {
        let style = styles.get(i).copied().unwrap_or_else(plain);
        if current_style != Some(style) {
            if let Some(previous) = current_style {
                spans.push(Span::styled(std::mem::take(&mut current), previous));
            }
            current_style = Some(style);
        }
        current.push(c);
    }
    if let Some(style) = current_style {
        spans.push(Span::styled(current, style));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The style at a character offset, for asserting without hand-counting.
    fn style_at(lines: &[&str], line: usize, needle: &str) -> Style {
        let owned: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        let styles = highlight(&owned);
        let col = owned[line].find(needle).expect("needle not in line");
        let col = owned[line][..col].chars().count();
        styles[line][col]
    }

    #[test]
    fn request_start_line_separates_method_from_target() {
        let lines = ["POST /a/b?q=1 HTTP/1.1"];
        assert_eq!(style_at(&lines, 0, "POST"), method());
        assert_eq!(style_at(&lines, 0, "/a/b"), target());
        assert_eq!(style_at(&lines, 0, "HTTP/1.1"), punct());
    }

    /// Status class is the thing you scan a response list for, so it must be
    /// the thing that is coloured.
    #[test]
    fn status_codes_are_coloured_by_class() {
        for (line, colour) in [
            ("HTTP/1.1 200 OK", Color::Green),
            ("HTTP/1.1 301 Moved", Color::Cyan),
            ("HTTP/1.1 404 Not Found", Color::Yellow),
            ("HTTP/1.1 500 Oops", Color::Red),
        ] {
            let code = &line[9..12];
            assert_eq!(
                style_at(&[line], 0, code).fg,
                Some(colour),
                "wrong colour for {line}"
            );
        }
    }

    #[test]
    fn a_response_is_told_apart_from_a_request_by_its_first_line() {
        // "HTTP/1.1" leads a response; anything else is a request, so the first
        // word must not be read as a method.
        assert_eq!(style_at(&["HTTP/1.1 200 OK"], 0, "HTTP/1.1"), punct());
        assert_eq!(style_at(&["GET / HTTP/1.1"], 0, "GET"), method());
    }

    #[test]
    fn header_names_are_coloured_and_values_are_not() {
        let lines = ["GET / HTTP/1.1", "Host: example.com"];
        assert_eq!(style_at(&lines, 1, "Host"), header_name());
        assert_eq!(style_at(&lines, 1, ":"), punct());
        assert_eq!(style_at(&lines, 1, "example.com"), plain());
    }

    /// A value containing a colon must not steal colouring from the name: only
    /// the *first* colon separates.
    #[test]
    fn only_the_first_colon_splits_a_header() {
        let lines = ["GET / HTTP/1.1", "Referer: https://a.test/x"];
        assert_eq!(style_at(&lines, 1, "Referer"), header_name());
        assert_eq!(style_at(&lines, 1, "https"), plain());
    }

    #[test]
    fn json_bodies_distinguish_keys_from_string_values() {
        let lines = [
            "POST / HTTP/1.1",
            "Content-Type: application/json",
            "",
            r#"{"name": "value", "n": 42, "ok": true}"#,
        ];
        assert_eq!(style_at(&lines, 3, r#""name""#), json_key());
        assert_eq!(style_at(&lines, 3, r#""value""#), json_string());
        assert_eq!(style_at(&lines, 3, "42"), json_number());
        assert_eq!(style_at(&lines, 3, "true"), json_literal());
        assert_eq!(style_at(&lines, 3, "{"), punct());
    }

    /// The header is routinely wrong or missing; a body that looks like JSON is
    /// treated as JSON anyway, because that is when highlighting helps most.
    #[test]
    fn a_json_body_is_detected_even_when_mislabelled() {
        let lines = [
            "POST / HTTP/1.1",
            "Content-Type: text/plain",
            "",
            r#"{"a": 1}"#,
        ];
        assert_eq!(style_at(&lines, 3, r#""a""#), json_key());
    }

    #[test]
    fn a_plain_body_stays_plain() {
        let lines = ["POST / HTTP/1.1", "Content-Type: text/plain", "", "hello"];
        assert_eq!(style_at(&lines, 3, "hello"), plain());
    }

    /// An escaped quote does not close the string — otherwise everything after
    /// it colours as if it were structure.
    #[test]
    fn escaped_quotes_do_not_end_a_string() {
        let lines = ["POST / HTTP/1.1", "", r#"{"a": "x\"y", "b": 1}"#];
        assert_eq!(style_at(&lines, 2, r#""b""#), json_key());
        assert_eq!(style_at(&lines, 2, "1"), json_number());
    }

    /// A colon inside a string value must not make the *next* string look like
    /// a key.
    #[test]
    fn a_colon_inside_a_string_is_not_a_key_separator() {
        let lines = ["POST / HTTP/1.1", "", r#"{"url": "http://a.test"}"#];
        assert_eq!(style_at(&lines, 2, r#""http://a.test""#), json_string());
    }

    #[test]
    fn form_bodies_colour_parameter_names() {
        let lines = [
            "POST / HTTP/1.1",
            "Content-Type: application/x-www-form-urlencoded",
            "",
            "user=admin&pass=hunter2",
        ];
        assert_eq!(style_at(&lines, 3, "user"), json_key());
        assert_eq!(style_at(&lines, 3, "admin"), plain());
        assert_eq!(style_at(&lines, 3, "&"), punct());
    }

    /// The pane must render whatever is in the buffer, including things that
    /// are not valid HTTP at all. Highlighting is decoration, never a gate.
    #[test]
    fn malformed_input_still_produces_one_style_per_character() {
        for text in ["", "\n", "not http at all", "GET", ":::", "{{{{"] {
            let lines: Vec<String> = text.lines().map(str::to_string).collect();
            let styles = highlight(&lines);
            assert_eq!(styles.len(), lines.len(), "line count for {text:?}");
            for (line, styles) in lines.iter().zip(&styles) {
                assert_eq!(
                    styles.len(),
                    line.chars().count(),
                    "style count for {line:?}"
                );
            }
        }
    }

    /// Multi-byte characters must be indexed by character, not byte, or the
    /// styles slide out of alignment with the text.
    #[test]
    fn multibyte_text_keeps_styles_aligned() {
        let lines = vec!["GET /café HTTP/1.1".to_string()];
        let styles = highlight(&lines);
        assert_eq!(styles[0].len(), lines[0].chars().count());
        // "HTTP/1.1" starts at character 10 once é counts as one.
        assert_eq!(styles[0][10], punct());
    }

    #[test]
    fn coalescing_preserves_the_text_exactly() {
        let text = "POST /a HTTP/1.1\nHost: x\n\n{\"k\": 1}";
        let rendered: String = highlighted_lines(text)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(rendered, text);
    }

    #[test]
    fn coalescing_merges_adjacent_equal_styles() {
        let line = "Host: example.com";
        let styles = header_line(&line.chars().collect::<Vec<_>>());
        let spans = coalesce(line, &styles);
        // name / colon / value — three runs, not seventeen.
        assert_eq!(spans.len(), 3, "{spans:?}");
        assert_eq!(spans[0].content.as_ref(), "Host");
    }

    #[test]
    fn html_bodies_colour_tags_and_attributes() {
        let lines = [
            "HTTP/1.1 200 OK",
            "content-type: text/html",
            "",
            r#"<a href="/x" class=y>text</a>"#,
        ];
        assert_eq!(style_at(&lines, 3, "a"), tag_name());
        assert_eq!(style_at(&lines, 3, "href"), attr_name());
        assert_eq!(style_at(&lines, 3, r#""/x""#), attr_value());
        assert_eq!(style_at(&lines, 3, "text"), plain());
        assert_eq!(style_at(&lines, 3, "<"), punct());
    }

    /// The screenshot's case: `text/html` must not fall through to plain.
    #[test]
    fn a_minified_html_body_is_highlighted() {
        let lines = [
            "HTTP/1.1 200 OK",
            "content-type: text/html",
            "",
            "<!doctype html><html lang=\"en\"><head><title>Example Domain</title></head>",
        ];
        assert_eq!(style_at(&lines, 3, "html lang"), tag_name());
        assert_eq!(style_at(&lines, 3, "title"), tag_name());
        assert_eq!(style_at(&lines, 3, "Example Domain"), plain());
    }

    /// Unlike JSON, HTML constructs really do span lines, so the scanner has to
    /// carry state — a comment must not stop colouring at the newline.
    #[test]
    fn html_comments_span_lines() {
        let lines = [
            "HTTP/1.1 200 OK",
            "content-type: text/html",
            "",
            "<p><!-- start",
            "still comment",
            "end --><b>after</b>",
        ];
        assert_eq!(style_at(&lines, 4, "still comment"), comment());
        assert_eq!(
            style_at(&lines, 5, "b"),
            tag_name(),
            "the comment must end at -->"
        );
        assert_eq!(style_at(&lines, 5, "after"), plain());
    }

    /// `<` inside a script is an operator, not a tag — scanning it as markup
    /// would mis-colour the rest of the document.
    #[test]
    fn script_contents_are_not_scanned_as_markup() {
        let lines = [
            "HTTP/1.1 200 OK",
            "content-type: text/html",
            "",
            "<script>if (a<b) x();</script><p>after</p>",
        ];
        assert_eq!(style_at(&lines, 3, "if (a<b)"), plain());
        assert_eq!(
            style_at(&lines, 3, "p"),
            tag_name(),
            "the raw block must end at </script>"
        );
    }
}
