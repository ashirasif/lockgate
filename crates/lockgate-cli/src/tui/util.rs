//! Small helpers with no state of their own.

use super::*;

/// Shown by `:help`. Deliberately lists only what differs from plain vim.
pub(super) const HELP: &str = "^k palette · P/W/I/R/C/T/K/S/A windows, gt/gT cycle · <CR> edit: vim motions w/W b/B e ^ $ f{c}, operators d/c/y + motion|iw|aw|i\"|i(, v/V visual, counts (2d3w), u/^r · gq format body · ^g $EDITOR · Histories (P/W): d hide row from view (V+d range), :unhide restores · Repeater: n new tab, x close, {count}gs switch, [ ] history, p raw/pretty · Intercept: <Space>i hold, ^w pane, f/d answer · Scope (C): n new, a include, x exclude, d delete, <CR> activate, <Space>c bypass; Sitemap: a/d scope host · Findings (T): <CR> write up (## Reproduction/Impact/Remediation are sections), s severity, c status, r retitle, d delete, <Space>f file · Notes (K): n new, <CR> edit, r retitle, d delete, <Space>n new from anywhere · :q";

/// Move a row cursor by a motion, clamped to `last`. The row-cursor windows
/// (Intercept, Sitemap) have no jumplist or search, so this is the whole of
/// their movement — `move_cursor` stays specific to the flow table.
pub(super) fn step_row(current: usize, last: usize, motion: Motion, count: Option<usize>) -> usize {
    let step = count.unwrap_or(1) as isize;
    let target = match motion {
        Motion::Down => current as isize + step,
        Motion::Up => current as isize - step,
        Motion::Top => count.map_or(0, |n| n.saturating_sub(1)) as isize,
        Motion::Bottom => count.map_or(last as isize, |n| n.saturating_sub(1) as isize),
        Motion::HalfPageDown => current as isize + step * 10,
        Motion::HalfPageUp => current as isize - step * 10,
        Motion::PageDown => current as isize + step * 20,
        Motion::PageUp => current as isize - step * 20,
        _ => current as isize,
    };
    target.clamp(0, last as isize) as usize
}

/// Render a held item as wire text, whichever leg it is.
pub(super) fn render_pending(pending: &Pending) -> String {
    match pending {
        Pending::Request(r) => http_text::render_request_decoded(r),
        Pending::Response(r) => http_text::render_response_decoded(r),
    }
}

/// Forget an edit buffer whose item is no longer held. Without this, edits made
/// to an answered item would silently attach to whatever took its place.
pub(super) fn drop_stale_edit(slot: &mut Option<(TicketId, TextBuffer)>, held: &[Held]) {
    if let Some((ticket, _)) = slot {
        if !held.iter().any(|h| h.ticket == *ticket) {
            *slot = None;
        }
    }
}

pub(super) fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Reparse edited text as the same kind of message it started as. The queue
/// entry's direction is what decides, never the text — otherwise a mangled
/// start line could turn a held response into a request.
pub(super) fn reparse(original: &Pending, text: &str) -> Result<Pending, http_text::ParseError> {
    Ok(match original {
        Pending::Request(r) => Pending::Request(http_text::parse_request(text, r)?),
        Pending::Response(r) => Pending::Response(http_text::parse_response(text, r)?),
    })
}

/// Rebuild the sitemap tree from the flat node list and flatten it back into
/// display rows, skipping anything under a fold.
///
/// Nodes whose parent fell outside the fetched page are treated as roots rather
/// than dropped: an orphan is a paging artefact, and silently hiding a path an
/// operator has actually seen is worse than showing it one level too shallow.
pub(super) fn build_sitemap_rows(
    nodes: &[SitemapNode],
    collapsed: &HashSet<String>,
) -> Vec<SitemapRow> {
    let present: HashSet<i64> = nodes.iter().map(|n| n.id).collect();
    let mut children: HashMap<i64, Vec<&SitemapNode>> = HashMap::new();
    let mut roots: HashMap<&str, Vec<&SitemapNode>> = HashMap::new();

    for node in nodes {
        match node.parent_id {
            Some(parent) if present.contains(&parent) => {
                children.entry(parent).or_default().push(node)
            }
            _ => roots.entry(node.host.as_str()).or_default().push(node),
        }
    }

    let mut hosts: Vec<&str> = roots.keys().copied().collect();
    hosts.sort_unstable();

    let mut rows = Vec::new();
    for host in hosts {
        let host_key = format!("host:{host}");
        let host_roots = roots.get(host).map(Vec::as_slice).unwrap_or(&[]);
        let folded = collapsed.contains(&host_key);
        rows.push(SitemapRow {
            depth: 0,
            label: host.to_string(),
            key: host_key,
            // A host's count is the traffic across everything beneath it.
            flow_count: host_roots.iter().map(|n| n.flow_count).sum(),
            has_children: !host_roots.is_empty(),
            host: host.to_string(),
        });
        if folded {
            continue;
        }
        let mut sorted = host_roots.to_vec();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        for node in sorted {
            push_sitemap_node(&mut rows, node, &children, collapsed, 1);
        }
    }
    rows
}

pub(super) fn push_sitemap_node(
    rows: &mut Vec<SitemapRow>,
    node: &SitemapNode,
    children: &HashMap<i64, Vec<&SitemapNode>>,
    collapsed: &HashSet<String>,
    depth: usize,
) {
    let key = format!("node:{}", node.id);
    let kids = children.get(&node.id).map(Vec::as_slice).unwrap_or(&[]);
    let folded = collapsed.contains(&key);
    rows.push(SitemapRow {
        depth,
        label: node.name.clone(),
        key,
        flow_count: node.flow_count,
        has_children: !kids.is_empty(),
        host: node.host.clone(),
    });
    if folded {
        return;
    }
    let mut sorted = kids.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for kid in sorted {
        push_sitemap_node(rows, kid, children, collapsed, depth + 1);
    }
}

/// Score how well `query` fuzzy-matches `text`, or `None` if it doesn't. Every
/// query char must appear in order; contiguous runs and an early first hit score
/// higher, so "grep" ranks "Go to Repeater" above a scattered coincidence. An
/// empty query matches everything with a neutral score.
pub(super) fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let haystack: Vec<char> = text.to_lowercase().chars().collect();
    let mut score = 0;
    let mut from = 0;
    let mut previous: Option<usize> = None;
    for needle in query.to_lowercase().chars() {
        let found = haystack[from..].iter().position(|&c| c == needle)? + from;
        // Reward adjacency (a real substring) and matching near the start.
        score += if previous == Some(found.saturating_sub(1)) {
            8
        } else {
            1
        };
        score -= found as i32 / 4;
        previous = Some(found);
        from = found + 1;
    }
    Some(score)
}

/// A rectangle `pct_x` × `pct_y` percent of `area`, centred within it.
pub(super) fn centered_rect(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let width = area.width * pct_x / 100;
    let height = area.height * pct_y / 100;
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// The command that opens `path` in the operator's editor.
///
/// `$VISUAL` before `$EDITOR` (the former means "full-screen editor", which is
/// exactly what we are handing the terminal to), then `nvim`, then `vi` — which
/// POSIX requires to exist.
///
/// The variable is split on whitespace so settings like `code -w` or
/// `nvim --clean` work. That is not a shell parse: an editor path containing
/// spaces will not resolve. Running it through a shell instead would make the
/// variable's contents executable code, which is a much worse trade for a
/// setting this rarely exotic.
pub(super) fn editor_command(path: &std::path::Path) -> tokio::process::Command {
    let configured = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_default();
    editor_command_from(&configured, path)
}

/// The half of [`editor_command`] that does not read the environment.
///
/// Split out to be testable: mutating `VISUAL`/`EDITOR` to test the real thing
/// would be process-global, and unsound alongside parallel test threads.
pub(super) fn editor_command_from(
    configured: &str,
    path: &std::path::Path,
) -> tokio::process::Command {
    let mut parts = configured.split_whitespace();

    let program = parts.next().unwrap_or("").to_string();
    let program = if program.is_empty() {
        if which("nvim") { "nvim" } else { "vi" }.to_string()
    } else {
        program
    };

    let mut command = tokio::process::Command::new(program);
    command.args(parts).arg(path);
    command
}

/// Whether a program is on `PATH`. Only used to prefer `nvim` over the `vi`
/// fallback, so a false negative costs nothing worse than a plainer editor.
pub(super) fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
}

/// Capture time as a wall clock, in the operator's own timezone.
///
/// Local rather than UTC: the point of the column is to line traffic up against
/// what you were doing when it fired, and you were doing it in local time. Falls
/// back to `--:--:--` for a timestamp that will not convert, which beats
/// rendering a misleading epoch.
pub(super) fn clock_time(micros: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_micros(micros) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => "--:--:--".to_string(),
    }
}

// --- theme ---
//
// Secondary text is defined here and nowhere else. It was `Color::DarkGray`
// inline at sixteen call sites, which made it both invisible on some terminals
// and tedious to change.

/// The slice of a table's rows that is actually on screen, given where the last
/// frame was scrolled to and where the cursor is now.
///
/// The tables are backed by the whole capture — a long session runs to tens of
/// thousands of flows — but a table only ever shows `height` of them. Building a
/// `Row` for every flow on every frame (six heap strings and a timezone
/// conversion apiece) put an idle TUI at 45% of a core; building them for the
/// visible slice makes a frame cost what the terminal is, not what the capture
/// is.
///
/// Scrolling is ours now rather than ratatui's, because ratatui's runs on the
/// rows it was handed and we hand it the answer. The rule is vim's: the window
/// moves only as far as it must to keep the cursor inside it.
pub(super) fn visible_window(
    offset: usize,
    cursor: usize,
    len: usize,
    height: usize,
) -> std::ops::Range<usize> {
    if len == 0 || height == 0 {
        return 0..0;
    }
    let cursor = cursor.min(len - 1);
    let mut start = offset.min(len - 1);
    if cursor < start {
        start = cursor;
    } else if cursor >= start + height {
        start = cursor + 1 - height;
    }
    // Never leave blank rows below a list long enough to fill them — which can
    // happen when the terminal grows, or when a scope filter shortens the list
    // under a window that was scrolled past what is left.
    start = start.min(len.saturating_sub(height));
    start..(start + height).min(len)
}
