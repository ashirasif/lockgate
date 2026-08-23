//! Body highlighting via syntect, with a memo in front of it.
//!
//! The hand-rolled scanners in [`crate::syntax`] cover the shapes we care most
//! about — JSON, HTML, form-urlencoded — and they are cheap, line-local and
//! incapable of failing. This module adds the long tail: XML, GraphQL, protobuf,
//! JavaScript inside `<script>`, CSS, SQL, YAML and the rest of bat's syntax
//! set, which is worth having in a proxy precisely because you do not get to
//! choose what a server sends you.
//!
//! Two properties of syntect shape everything here:
//!
//! - **It is stateful across lines.** Highlighting line 3000 correctly means
//!   parsing from line 0, so there is no such thing as highlighting only the
//!   viewport. A full pass over a 4000-line body costs ~77ms, which is far too
//!   slow to repeat every frame — hence [`SyntaxCache`], which memoises the last
//!   few results, and [`MAX_BYTES`], which declines the job outright on bodies
//!   where even one pass would be felt.
//! - **It cannot fail.** It is a regex lexer with no parse tree, so malformed
//!   input degrades to plainly-styled text rather than erroring. That is what
//!   makes it usable here at all: a proxy must render whatever bytes arrived,
//!   and a highlighter that refuses invalid JSON would be useless exactly when
//!   you are looking hardest.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use ratatui::style::{Color, Style};
use syntect::easy::HighlightLines;
use syntect::highlighting::Theme;
use syntect::parsing::{SyntaxReference, SyntaxSet};

/// Bodies past this size are left to the hand-rolled scanners.
///
/// Measured, not guessed: a ~44KB JSON body costs 26ms for a full pass in a
/// release build — about 0.6ms per KB. Since a cache miss happens on *every
/// keystroke* while editing, the ceiling has to sit where one pass is
/// imperceptible rather than merely tolerable, which puts 64 KiB at roughly
/// 40ms worst case. Typical API bodies are 1–20KB, so this bites almost never.
///
/// Past the cap nothing is lost that matters most: JSON and HTML still get the
/// hand-rolled scanners, which are line-local and effectively free. It is only
/// the long tail — XML, GraphQL, embedded JS — that falls back to plain on a
/// very large body.
const MAX_BYTES: usize = 64 * 1024;

/// How many highlighted bodies to keep. Four covers the request and response
/// previews in Intercept plus the Repeater's two, which is every buffer that
/// can be on screen at once.
const CACHE_ENTRIES: usize = 4;

/// Lazily-loaded syntax and theme data, plus the memo.
///
/// Loading costs a few milliseconds and ~3.4MB of syntax dumps, so it happens
/// on first use rather than at startup: someone who only ever looks at the flow
/// table never pays for it.
pub struct SyntaxCache {
    loaded: Option<Loaded>,
    entries: Vec<Entry>,
}

struct Loaded {
    syntaxes: SyntaxSet,
    theme: Theme,
}

struct Entry {
    key: u64,
    styles: Vec<Vec<Style>>,
}

impl Default for SyntaxCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntaxCache {
    pub const fn new() -> Self {
        Self {
            loaded: None,
            entries: Vec::new(),
        }
    }

    /// Highlight `lines` as `syntax_name`, or `None` if this body is not one
    /// syntect should handle — no matching syntax, or too big to be worth a
    /// pass. `None` means "fall back", never "render nothing".
    pub fn highlight(&mut self, lines: &[String], syntax_name: &str) -> Option<Vec<Vec<Style>>> {
        let bytes: usize = lines.iter().map(|l| l.len() + 1).sum();
        if bytes > MAX_BYTES {
            return None;
        }

        let key = key_for(lines, syntax_name);
        if let Some(hit) = self.entries.iter().find(|e| e.key == key) {
            return Some(hit.styles.clone());
        }

        let loaded = self.loaded.get_or_insert_with(Loaded::load);
        let syntax = loaded.syntaxes.find_syntax_by_name(syntax_name)?;
        let styles = highlight_body(lines, syntax, &loaded.syntaxes, &loaded.theme);

        // Newest first, so the two buffers on screen stay resident while an
        // older one falls off the end.
        self.entries.insert(
            0,
            Entry {
                key,
                styles: styles.clone(),
            },
        );
        self.entries.truncate(CACHE_ENTRIES);
        Some(styles)
    }
}

impl Loaded {
    fn load() -> Self {
        Self {
            // two-face rather than syntect's own defaults: the bundled 75 have
            // no GraphQL, protobuf, TOML or INI, and those are exactly the
            // bodies you meet on an API you are testing.
            syntaxes: two_face::syntax::extra_newlines(),
            theme: two_face::theme::extra()
                .get(two_face::theme::EmbeddedThemeName::Base16OceanDark)
                .clone(),
        }
    }
}

/// One style per character, matching what the rest of the UI expects so the
/// cursor and selection can be patched over the top.
fn highlight_body(
    lines: &[String],
    syntax: &SyntaxReference,
    syntaxes: &SyntaxSet,
    theme: &Theme,
) -> Vec<Vec<Style>> {
    let mut highlighter = HighlightLines::new(syntax, theme);
    lines
        .iter()
        .map(|line| {
            // A failure here is a malformed *syntax definition*, not malformed
            // input — but there is still nothing useful to do about it mid-draw,
            // so the line falls back to unstyled rather than taking the pane
            // down with it.
            let Ok(regions) = highlighter.highlight_line(line, syntaxes) else {
                return vec![Style::new(); line.chars().count()];
            };
            let mut styles = Vec::with_capacity(line.chars().count());
            for (style, text) in regions {
                let converted = convert(style);
                styles.extend(std::iter::repeat_n(converted, text.chars().count()));
            }
            // syntect appends the trailing newline it was given; we hand it
            // lines without one, but guard the length anyway so a style vector
            // can never disagree with the text it decorates.
            styles.truncate(line.chars().count());
            styles.resize(line.chars().count(), Style::new());
            styles
        })
        .collect()
}

/// syntect's 24-bit colour to a ratatui one.
///
/// Foreground only. syntect themes also carry a background per token, but
/// painting it would fight the pane's own background and, more to the point,
/// the selection and cursor highlights that get patched over this.
fn convert(style: syntect::highlighting::Style) -> Style {
    let fg = style.foreground;
    Style::new().fg(Color::Rgb(fg.r, fg.g, fg.b))
}

/// Cache key: the body's content and the syntax it is being read as.
///
/// Hashing the text each frame is O(n) but tens of microseconds where a miss is
/// tens of milliseconds. Keying on content rather than on a revision counter
/// means the cache cannot go stale — a buffer that edits back to a previous
/// state simply hits again.
fn key_for(lines: &[String], syntax_name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    syntax_name.hash(&mut hasher);
    lines.len().hash(&mut hasher);
    for line in lines {
        line.hash(&mut hasher);
    }
    hasher.finish()
}

/// Shared handle, so the draw path can memoise through a `&self` borrow.
pub type SharedCache = RefCell<SyntaxCache>;

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    fn colours(styles: &[Vec<Style>]) -> Vec<Color> {
        styles.iter().flatten().filter_map(|s| s.fg).collect()
    }

    #[test]
    fn json_bodies_get_more_than_one_colour() {
        let mut cache = SyntaxCache::new();
        let styles = cache
            .highlight(&lines(r#"{"a": 1, "b": "x", "c": true}"#), "JSON")
            .expect("JSON is a known syntax");
        let distinct: std::collections::HashSet<_> = colours(&styles).into_iter().collect();
        assert!(
            distinct.len() > 1,
            "expected varied colours, got {distinct:?}"
        );
    }

    /// The reason for reaching past our own scanners at all.
    #[test]
    fn graphql_is_supported() {
        let mut cache = SyntaxCache::new();
        let styles = cache
            .highlight(
                &lines("query GetUser($id: ID!) { user { name } }"),
                "GraphQL",
            )
            .expect("GraphQL must be available via two-face");
        assert!(colours(&styles).len() > 1);
    }

    #[test]
    fn the_long_tail_of_syntaxes_is_present() {
        let mut cache = SyntaxCache::new();
        for name in ["XML", "JavaScript", "CSS", "SQL", "YAML", "Protocol Buffer"] {
            assert!(
                cache.highlight(&lines("x"), name).is_some(),
                "{name} should be a known syntax"
            );
        }
    }

    /// A syntax we do not have must fall back, not panic or render nothing.
    #[test]
    fn an_unknown_syntax_falls_back() {
        let mut cache = SyntaxCache::new();
        assert!(
            cache
                .highlight(&lines("x=1"), "Nonexistent Language")
                .is_none()
        );
    }

    /// The constraint that makes this usable in a proxy at all: whatever
    /// arrived must render.
    #[test]
    fn malformed_input_still_produces_one_style_per_character() {
        let mut cache = SyntaxCache::new();
        for (text, syntax) in [
            (r#"{"a": 1,"#, "JSON"),
            ("}}}}]]]]", "JSON"),
            ("<div class=\"x><script>var y = {", "HTML"),
            ("query { unclosed", "GraphQL"),
            ("", "JSON"),
            ("\u{0}\u{feff}binary\u{202e}", "JSON"),
        ] {
            let body = lines(text);
            let styles = cache
                .highlight(&body, syntax)
                .unwrap_or_else(|| panic!("{syntax} should be known"));
            assert_eq!(styles.len(), body.len(), "line count for {text:?}");
            for (line, styles) in body.iter().zip(&styles) {
                assert_eq!(
                    styles.len(),
                    line.chars().count(),
                    "style count for {line:?}"
                );
            }
        }
    }

    /// Multi-byte text must stay aligned, or styles slide off the characters
    /// they belong to.
    #[test]
    fn multibyte_text_keeps_styles_aligned() {
        let mut cache = SyntaxCache::new();
        let body = lines(r#"{"city": "café", "emoji": "🔥"}"#);
        let styles = cache.highlight(&body, "JSON").unwrap();
        assert_eq!(styles[0].len(), body[0].chars().count());
    }

    /// A body big enough that one pass would be felt is declined outright.
    #[test]
    fn oversized_bodies_are_declined_rather_than_highlighted_slowly() {
        let mut cache = SyntaxCache::new();
        let big = lines(&"x".repeat(MAX_BYTES + 1));
        assert!(cache.highlight(&big, "JSON").is_none());
        // Just under is still served.
        let ok = lines(&"x".repeat(MAX_BYTES - 1));
        assert!(cache.highlight(&ok, "JSON").is_some());
    }

    #[test]
    fn repeated_highlights_hit_the_cache() {
        let mut cache = SyntaxCache::new();
        let body = lines(r#"{"a": 1}"#);
        let first = cache.highlight(&body, "JSON").unwrap();
        let second = cache.highlight(&body, "JSON").unwrap();
        assert_eq!(first, second);
        assert_eq!(
            cache.entries.len(),
            1,
            "the same body must not be re-entered"
        );
    }

    /// Editing invalidates by content, so the cache cannot serve a stale body.
    #[test]
    fn an_edit_misses_the_cache() {
        let mut cache = SyntaxCache::new();
        cache.highlight(&lines(r#"{"a": 1}"#), "JSON").unwrap();
        cache.highlight(&lines(r#"{"a": 2}"#), "JSON").unwrap();
        assert_eq!(cache.entries.len(), 2);
    }

    /// The same text read as two languages is two different results.
    #[test]
    fn the_syntax_is_part_of_the_key() {
        let mut cache = SyntaxCache::new();
        cache.highlight(&lines("<a>1</a>"), "HTML").unwrap();
        cache.highlight(&lines("<a>1</a>"), "XML").unwrap();
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn the_cache_is_bounded() {
        let mut cache = SyntaxCache::new();
        for i in 0..CACHE_ENTRIES * 3 {
            cache.highlight(&lines(&format!("{{\"n\": {i}}}")), "JSON");
        }
        assert_eq!(cache.entries.len(), CACHE_ENTRIES);
    }

    /// Not an assertion about wall-clock, which varies by machine — an
    /// assertion that the memo is doing its job, since a miss on every frame
    /// is the difference between usable and unusable.
    #[test]
    fn the_cache_turns_a_repeat_pass_into_a_cheap_one() {
        let mut cache = SyntaxCache::new();
        let body: Vec<String> = (0..2000)
            .map(|i| format!("{{\"key{i}\": \"value{i}\"}},"))
            .collect();

        let start = std::time::Instant::now();
        cache.highlight(&body, "JSON").unwrap();
        let cold = start.elapsed();

        let start = std::time::Instant::now();
        cache.highlight(&body, "JSON").unwrap();
        let warm = start.elapsed();

        println!(
            "cold {cold:?}  warm {warm:?}  ({}x)",
            cold.as_nanos() / warm.as_nanos().max(1)
        );
        assert!(warm < cold / 10, "cold {cold:?} warm {warm:?}");
    }
}
