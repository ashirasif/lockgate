//! The status page: every target at a glance, from a phone.
//!
//! The TUI needs a terminal; an agent run needs watching from anywhere. This
//! serves read-only HTML on the same listener as the MCP (`/status`): a
//! sidebar naming every target the server runs, an overview table across all
//! of them, and a drill-down per target — the leads ledger, findings, the
//! agent's tagged sends, and its notes, which is where its reasoning lives
//! (notes are the one document agent and operator share).
//!
//! Read-only by construction (GET handlers over engine reads), loopback-bound
//! by default, and token-gated when `--status-token` is set — set one before
//! ever binding this beyond 127.0.0.1. The token arrives as `?token=` or an
//! `X-Status-Token` header (which is how app proxies that inject headers keep
//! the phone from typing it); when set, every link this page renders carries
//! it along, so navigation never dead-ends on a 401. Rendered by hand: one
//! page, no framework, no build step.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use lockgate_core::Engine;

use crate::dto::FlowDto;

pub struct StatusState {
    pub targets: Arc<crate::Targets>,
    pub token: Option<String>,
}

pub fn router(targets: Arc<crate::Targets>, token: Option<String>) -> axum::Router {
    let state = Arc::new(StatusState { targets, token });
    axum::Router::new()
        .route(
            "/status",
            axum::routing::get(dashboard).with_state(state.clone()),
        )
        .route(
            "/status/",
            axum::routing::get(dashboard).with_state(state.clone()),
        )
        .route(
            "/status/report",
            axum::routing::get(report).with_state(state),
        )
}

#[derive(Deserialize)]
pub(crate) struct PageQuery {
    pub(crate) token: Option<String>,
    /// Which target's drill-down to show. Absent = the overview.
    pub(crate) t: Option<String>,
}

/// The one gate both pages share: a configured token must arrive as `?token=`
/// or an `X-Status-Token` header. The header is how app proxies that inject
/// headers server-side keep the phone from typing a token.
fn check_token(
    state: &StatusState,
    q: &PageQuery,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, &'static str)> {
    if let Some(expected) = &state.token {
        let given = q
            .token
            .as_deref()
            .or_else(|| headers.get("x-status-token").and_then(|v| v.to_str().ok()));
        if given != Some(expected.as_str()) {
            return Err((StatusCode::UNAUTHORIZED, "bad token"));
        }
    }
    Ok(())
}

fn link_suffix(state: &StatusState, q: &PageQuery) -> String {
    match (&state.token, &q.token) {
        (Some(t), _) => format!("?token={t}"),
        (None, _) => String::new(),
    }
}

async fn dashboard(
    State(state): State<Arc<StatusState>>,
    Query(q): Query<PageQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    check_token(&state, &q, &headers)?;
    let selected =
        q.t.as_deref()
            .and_then(|t| state.targets.get(t).map(|_| t.to_string()));
    Ok(Html(render_page(
        &state.targets,
        selected.as_deref(),
        &state,
        &q,
    )))
}

/// The report as HTML-escaped markdown in a `<pre>` — readable on a phone
/// without pulling a markdown renderer into the tree. Reports the selected
/// target, or every target back to back when none is chosen.
async fn report(
    State(state): State<Arc<StatusState>>,
    Query(q): Query<PageQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    check_token(&state, &q, &headers)?;
    let mut md = String::new();
    let selected =
        q.t.as_deref()
            .and_then(|t| state.targets.get(t).map(|_| t.to_string()));
    match selected {
        Some(name) => {
            let engine = state.targets.get(&name).expect("checked above");
            md = engine.generate_report().unwrap_or_default();
        }
        None => {
            for (name, engine) in &state.targets.engines {
                md.push_str(&format!("# Target: {name}\n\n"));
                md.push_str(&engine.generate_report().unwrap_or_default());
                md.push_str("\n\n");
            }
        }
    }
    let mut out = String::with_capacity(md.len() + 512);
    out.push_str("<!doctype html><html><head><meta charset=utf-8>");
    out.push_str("<meta name=viewport content='width=device-width, initial-scale=1'>");
    out.push_str("<title>lockgate — report</title><style>");
    out.push_str("body{background:#0d1117;color:#e6edf3;font-family:-apple-system,sans-serif;margin:0;padding:12px;max-width:680px;margin-inline:auto}");
    out.push_str(
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.82rem;line-height:1.45}",
    );
    out.push_str("</style></head><body><h1>Report</h1><pre>");
    out.push_str(&esc(&md));
    out.push_str("</pre><p><a style='color:#79c0ff' href='status'>← status</a></p></body></html>");
    Ok(Html(out))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The whole page: sidebar (every target), then the overview or one target's
/// drill-down. `selected: None` is the overview.
fn render_page(
    targets: &Arc<crate::Targets>,
    selected: Option<&str>,
    state: &StatusState,
    q: &PageQuery,
) -> String {
    let suffix = link_suffix(state, q);
    let mut out = String::with_capacity(48 * 1024);
    out.push_str("<!doctype html><html><head><meta charset=utf-8>");
    out.push_str("<meta name=viewport content='width=device-width, initial-scale=1'>");
    // A meta refresh beats websockets here: works with any proxy, no JS, and a
    // phone lock/unload cannot break it.
    out.push_str("<meta http-equiv=refresh content=5>");
    out.push_str("<title>lockgate — status</title><style>");
    out.push_str("body{background:#0d1117;color:#e6edf3;font-family:-apple-system,sans-serif;margin:0;padding:12px;font-size:15px}");
    out.push_str("h1{font-size:1.2rem;margin:0 0 4px}h2{font-size:1rem;color:#9da7b3;border-bottom:1px solid #21283b;padding-bottom:4px;margin-top:1.4rem}");
    out.push_str("table{width:100%;border-collapse:collapse;font-size:.85rem}td,th{padding:4px 6px;text-align:left;border-bottom:1px solid #1c2333;vertical-align:top}");
    out.push_str(".sev-critical,.sev-high{color:#ff6b6b;font-weight:600}.sev-medium{color:#ffb347}.sev-low{color:#8fa3bf}.sev-info{color:#6e7b8b}");
    out.push_str(".st-verified{color:#3fb950;font-weight:600}.st-refuted{color:#8b949e}.st-proposed,.st-verifying{color:#d29922}");
    out.push_str(".ruling-admissible{color:#3fb950}.ruling-refuted{color:#8b949e}");
    out.push_str(".card{background:#161b27;border:1px solid #21283b;border-radius:8px;padding:10px;margin:8px 0;overflow-wrap:anywhere}");
    out.push_str(".muted{color:#6e7b8b}.tag{color:#79c0ff;font-family:ui-monospace,monospace}");
    out.push_str("pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem}");
    out.push_str("a{color:#79c0ff;text-decoration:none}");
    // Sidebar on wide screens; a wrapping row of chips on a phone.
    out.push_str(".wrap{display:flex;gap:16px;flex-wrap:wrap}nav{min-width:150px;flex:0 0 auto}main{flex:1 1 380px;min-width:0}");
    out.push_str(
        "nav a{display:block;padding:5px 10px;border-radius:6px;margin:2px 0;font-size:.9rem}",
    );
    out.push_str("nav a.here{background:#1c2a3f;font-weight:600}nav a:hover{background:#161b27}");
    out.push_str("nav .cnt{float:right;color:#6e7b8b}");
    out.push_str("</style></head><body>");

    // --- sidebar: every target, plus the overview ---
    out.push_str("<div class=wrap><nav><h1>lockgate</h1>");
    out.push_str(&format!(
        "<a class='{}' href='status{suffix}'>overview</a>",
        if selected.is_none() { "here" } else { "" },
    ));
    for (name, engine) in &targets.engines {
        let open = engine
            .leads(None)
            .into_iter()
            .filter(|l| matches!(l.status.as_str(), "proposed" | "verifying"))
            .count();
        let here = selected.map(|s| s == name).unwrap_or(false);
        out.push_str(&format!(
            "<a class='{}' href='status?t={}{}'>{}<span class=cnt>{}</span></a>",
            if here { "here" } else { "" },
            esc(name),
            suffix,
            esc(name),
            open,
        ));
    }
    let suffix_report = if suffix.is_empty() {
        match selected {
            Some(name) => format!("?t={}", esc(name)),
            None => String::new(),
        }
    } else {
        let t = match selected {
            Some(name) => format!("&t={}", esc(name)),
            None => String::new(),
        };
        format!("{suffix}{t}")
    };
    out.push_str(&format!(
        "<a href='report{suffix_report}'>full report</a></nav><main>"
    ));

    match selected {
        Some(name) => {
            let engine = targets
                .get(name)
                .expect("selected was resolved through targets");
            out.push_str(&format!("<h1>{}</h1>", esc(name)));
            out.push_str(&render_target(&engine));
        }
        None => {
            out.push_str("<h1>Overview</h1>");
            out.push_str(&render_overview(targets));
        }
    }

    out.push_str("</main></div>");
    out.push_str("<p class=muted>refreshes every 5s</p></body></html>");
    out
}

/// Per-target counts for the overview table, computed once per engine.
struct TargetCounts {
    findings: usize,
    critical: usize,
    high: usize,
    open_leads: usize,
    last_activity: Option<i64>,
}

fn counts(engine: &Arc<Engine>) -> TargetCounts {
    let findings = engine.list_findings();
    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let open_leads = engine
        .leads(None)
        .into_iter()
        .filter(|l| matches!(l.status.as_str(), "proposed" | "verifying"))
        .count();
    let last_activity = engine
        .query_flows(&lockgate_core::FlowQuery::default(), 0, 1)
        .first()
        .map(|f| f.started_at);
    TargetCounts {
        findings: findings.len(),
        critical,
        high,
        open_leads,
        last_activity,
    }
}

fn render_overview(targets: &Arc<crate::Targets>) -> String {
    let mut out = String::from(
        "<table><tr><th>target</th><th>findings</th><th>high/crit</th><th>open leads</th><th>last activity</th></tr>",
    );
    let mut any = false;
    for (name, engine) in &targets.engines {
        any = true;
        let c = counts(engine);
        let name_e = esc(name);
        out.push_str(&format!(
            "<tr><td><a href='status?t={name_e}'>{name_e}</a></td><td>{}</td><td class='{}'>{}/{}<td>{}</td><td>{}</td></tr>",
            c.findings,
            if c.critical > 0 { "sev-critical" } else { "sev-info" },
            c.high,
            c.critical,
            c.open_leads,
            c.last_activity.map(fmt_age).unwrap_or_else(|| "never".into()),
        ));
    }
    if !any {
        out.push_str(
            "<tr><td colspan=5 class=muted>no targets — start lockgate with --targets</td></tr>",
        );
    }
    out.push_str("</table>");
    out
}

/// The drill-down sections for one target: leads, findings, agent sends, and
/// the agent's notes.
fn render_target(engine: &Arc<Engine>) -> String {
    let findings = engine.list_findings();
    let leads = engine.leads(None);
    let notes = engine.list_notes();
    let identities = engine.identities();
    let policy = engine.policy();
    let policy_rules = engine.policy_rules();

    // The agent's activity: sends carrying a tag are planned work, not
    // browsing. Newest first, bounded — a phone reads the last page, not all.
    let tagged: Vec<FlowDto> = engine
        .query_flows(&lockgate_core::FlowQuery::default(), 0, 200)
        .into_iter()
        .filter(|f| f.tag.is_some())
        .take(20)
        .map(FlowDto::from)
        .collect();

    let criticals = findings.iter().filter(|f| f.severity == "critical").count();
    let highs = findings.iter().filter(|f| f.severity == "high").count();
    let open_leads = leads
        .iter()
        .filter(|l| matches!(l.status.as_str(), "proposed" | "verifying"))
        .count();
    let mut out = format!(
        "<p class=muted>{} findings ({} high, {} critical) · {} leads ({} open) · {} identities · policy: {} / {} rules</p>",
        findings.len(),
        highs,
        criticals,
        leads.len(),
        open_leads,
        identities.len(),
        policy
            .rate_per_sec
            .map(|r| format!("{r}/s per host"))
            .unwrap_or_else(|| "no rate limit".into()),
        policy_rules.len(),
    );

    // --- leads: the epistemics ---
    out.push_str("<h2>Leads</h2>");
    if leads.is_empty() {
        out.push_str("<p class=muted>none yet</p>");
    }
    out.push_str("<table><tr><th>#</th><th>lead</th><th>status</th><th>ruling</th></tr>");
    for l in leads.iter().take(20) {
        let ruling = esc(l.ruling.as_deref().unwrap_or("—"));
        out.push_str(&format!(
            "<tr><td>{}</td><td><b>{}</b><br><span class=muted>{}</span></td><td class='st-{}'>{}</td><td class='ruling-{}'>{}</td></tr>",
            l.id,
            esc(&l.title),
            esc(l.endpoint.as_deref().unwrap_or(&l.kind)),
            esc(&l.status),
            esc(&l.status),
            ruling,
            ruling,
        ));
    }
    out.push_str("</table>");

    // --- findings ---
    out.push_str("<h2>Findings</h2>");
    if findings.is_empty() {
        out.push_str("<p class=muted>none yet</p>");
    }
    out.push_str("<table><tr><th>sev</th><th>title</th><th>status</th></tr>");
    for f in findings.iter().take(20) {
        out.push_str(&format!(
            "<tr><td class='sev-{}'>{}</td><td>{}<br><span class=muted>{}</span></td><td>{}</td></tr>",
            esc(&f.severity),
            esc(&f.severity),
            esc(&f.title),
            esc(f.host.as_deref().unwrap_or("")),
            esc(&f.status),
        ));
    }
    out.push_str("</table>");

    // --- the agent's planned work ---
    out.push_str("<h2>Agent sends</h2>");
    if tagged.is_empty() {
        out.push_str("<p class=muted>no tagged sends — the agent has not started probing</p>");
    }
    out.push_str("<table><tr><th>tag</th><th>request</th><th>status</th></tr>");
    for f in &tagged {
        out.push_str(&format!(
            "<tr><td class=tag>{}</td><td>{} {}<br><span class=muted>{}</span></td><td>{}</td></tr>",
            esc(f.tag.as_deref().unwrap_or("")),
            esc(&f.method),
            esc(&f.uri),
            esc(&f.host),
            f.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "…".into()),
        ));
    }
    out.push_str("</table>");

    // --- the reasoning: notes are the agent's working memory ---
    out.push_str("<h2>Notes (agent reasoning)</h2>");
    if notes.is_empty() {
        out.push_str("<p class=muted>no notes — an agent that files none is working blind; the skill tells it to keep one</p>");
    }
    for n in notes.iter().take(3) {
        out.push_str(&format!(
            "<div class=card><b>{}</b> <span class=muted>· {}</span><pre>{}</pre></div>",
            esc(&n.title),
            esc(&fmt_age(n.updated_at)),
            esc(truncate(&n.body_md, 2500)),
        ));
    }
    out
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn fmt_age(micros: i64) -> String {
    let secs = (lockgate_core::model::now_micros() - micros) / 1_000_000;
    match secs {
        s if s < 60 => "just now".into(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn two_targets() -> Arc<crate::Targets> {
        let a = Engine::new();
        let b = Engine::new();
        a.create_lead(&lockgate_core::NewLead {
            kind: "idor".into(),
            title: "Booking ids <script>alert(1)</script>".into(),
            rationale_md: "sequential ids".into(),
            endpoint: None,
            flow_id: None,
        })
        .unwrap();
        b.create_finding(lockgate_core::NewFinding {
            title: "CORS wildcard".into(),
            severity: "medium".into(),
            status: "draft".into(),
            cvss_vector: None,
            cvss_score: None,
            cvss_version: None,
            cwe: Some("942".into()),
            description_md: "wildcard".into(),
            repro_md: None,
            impact_md: None,
            remediation_md: None,
            host: Some("b.com".into()),
            path: None,
            evidence: vec![],
            origin: "workflow".into(),
        })
        .await
        .unwrap();
        Arc::new(crate::Targets {
            engines: vec![("a".into(), a), ("b".into(), b)],
        })
    }

    #[tokio::test]
    async fn overview_and_drilldown_render_all_targets() {
        let targets = two_targets().await;

        let page = render_page(&targets, None, &state_without_token(), &no_query());
        // The sidebar names both targets.
        assert!(page.contains(">a</a>") && page.contains(">b</a>"), "{page}");
        // The overview shows b's finding count without leaking a's lead into it.
        assert!(page.contains("Overview"));
        assert!(page.contains("<th>open leads</th>"));

        // Drill-down on a: its lead, escaped; on b: its finding.
        let a_page = render_page(&targets, Some("a"), &state_without_token(), &no_query());
        assert!(a_page.contains("Booking ids &lt;script&gt;"), "{a_page}");
        assert!(!a_page.contains("<script>alert"), "no raw html from data");
        assert!(
            !a_page.contains("CORS wildcard"),
            "a's page must not show b's findings"
        );

        let b_page = render_page(&targets, Some("b"), &state_without_token(), &no_query());
        assert!(b_page.contains("CORS wildcard"));
        assert!(
            !b_page.contains("Booking ids"),
            "b's page must not show a's leads"
        );
    }

    #[tokio::test]
    async fn the_token_gate_refuses_without_it_and_links_carry_it() {
        let targets = two_targets().await;
        let state = StatusState {
            targets,
            token: Some("sekrit".into()),
        };
        let no_headers = axum::http::HeaderMap::new();

        // No token: refused. Wrong token: refused.
        let err = dashboard(
            State(Arc::new(clone_state(&state))),
            Query(PageQuery {
                token: None,
                t: None,
            }),
            no_headers.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        // Right token via query: the page renders, and its nav links carry
        // the token so clicking a sidebar target never dead-ends on a 401.
        let ok = dashboard(
            State(Arc::new(clone_state(&state))),
            Query(PageQuery {
                token: Some("sekrit".into()),
                t: Some("a".into()),
            }),
            no_headers.clone(),
        )
        .await
        .unwrap();
        assert!(
            ok.0.contains("token=sekrit"),
            "links carry the token: {}",
            ok.0
        );

        // The header form — what a proxy that injects headers uses — also passes.
        let mut injected = axum::http::HeaderMap::new();
        injected.insert("x-status-token", "sekrit".parse().unwrap());
        let ok = dashboard(
            State(Arc::new(clone_state(&state))),
            Query(PageQuery {
                token: None,
                t: None,
            }),
            injected,
        )
        .await
        .unwrap();
        assert!(ok.0.contains("Overview"));
    }

    fn state_without_token() -> StatusState {
        StatusState {
            // Stand-in engine is irrelevant for render-only paths that name
            // their target; two_targets() builds its own per test.
            targets: two_targets_nowait(),
            token: None,
        }
    }

    fn two_targets_nowait() -> Arc<crate::Targets> {
        let mut engines = Vec::new();
        for name in ["a", "b"] {
            engines.push((name.to_string(), Engine::new()));
        }
        Arc::new(crate::Targets { engines })
    }

    fn no_query() -> PageQuery {
        PageQuery {
            token: None,
            t: None,
        }
    }

    fn clone_state(state: &StatusState) -> StatusState {
        StatusState {
            targets: state.targets.clone(),
            token: state.token.clone(),
        }
    }
}
