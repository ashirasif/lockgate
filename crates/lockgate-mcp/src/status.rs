//! The status page: the engagement at a glance, from a phone.
//!
//! The TUI needs a terminal; an agent run needs watching from anywhere. This
//! serves read-only HTML on the same listener as the MCP (`/status`), showing
//! what an autonomous run is *doing* and *thinking*: the leads ledger, the
//! findings, the agent's tagged sends, and its notes — which is where its
//! reasoning lives, since notes are the one document agent and operator share.
//!
//! Read-only by construction (GET handlers over engine reads), loopback-bound
//! by default, and token-gated when `--status-token` is set — set one before
//! ever binding this beyond 127.0.0.1. Rendered by hand: one page, no
//! framework, no build step.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use serde::Deserialize;

use lockgate_core::Engine;

use crate::dto::FlowDto;

pub struct StatusState {
    pub engine: Arc<Engine>,
    pub token: Option<String>,
}

pub fn router(engine: Arc<Engine>, token: Option<String>) -> axum::Router {
    let state = Arc::new(StatusState { engine, token });
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
pub(crate) struct TokenQuery {
    pub(crate) token: Option<String>,
}

/// The one gate both pages share: a configured token must arrive as `?token=`
/// or an `X-Status-Token` header. The header is how Teleport-style app
/// proxies inject it server-side — the phone never types a token.
fn check_token(
    state: &StatusState,
    q: &TokenQuery,
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

async fn dashboard(
    State(state): State<Arc<StatusState>>,
    Query(q): Query<TokenQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    check_token(&state, &q, &headers)?;
    Ok(Html(render(&state.engine)))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render(engine: &Arc<Engine>) -> String {
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

    let mut out = String::with_capacity(32 * 1024);
    out.push_str("<!doctype html><html><head><meta charset=utf-8>");
    out.push_str("<meta name=viewport content='width=device-width, initial-scale=1'>");
    // A meta refresh beats websockets here: works with any proxy, no JS, and a
    // phone lock/unload cannot break it.
    out.push_str("<meta http-equiv=refresh content=5>");
    out.push_str("<title>lockgate — status</title><style>");
    out.push_str(
        "body{background:#0d1117;color:#e6edf3;font-family:-apple-system,sans-serif;margin:0;padding:12px;max-width:680px;margin-inline:auto;font-size:15px}",
        );
    out.push_str("h1{font-size:1.2rem}h2{font-size:1rem;color:#9da7b3;border-bottom:1px solid #21283b;padding-bottom:4px;margin-top:1.4rem}");
    out.push_str("table{width:100%;border-collapse:collapse;font-size:.85rem}td,th{padding:4px 6px;text-align:left;border-bottom:1px solid #1c2333;vertical-align:top}");
    out.push_str(".sev-critical,.sev-high{color:#ff6b6b;font-weight:600}.sev-medium{color:#ffb347}.sev-low{color:#8fa3bf}.sev-info{color:#6e7b8b}");
    out.push_str(".st-verified{color:#3fb950;font-weight:600}.st-refuted{color:#8b949e}.st-proposed,.st-verifying{color:#d29922}");
    out.push_str(".ruling-admissible{color:#3fb950}.ruling-refuted{color:#8b949e}");
    out.push_str(".card{background:#161b27;border:1px solid #21283b;border-radius:8px;padding:10px;margin:8px 0;overflow-wrap:anywhere}");
    out.push_str(".muted{color:#6e7b8b}.tag{color:#79c0ff;font-family:ui-monospace,monospace}");
    out.push_str("pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem}");
    out.push_str("</style></head><body>");

    let criticals = findings.iter().filter(|f| f.severity == "critical").count();
    let highs = findings.iter().filter(|f| f.severity == "high").count();
    let open_leads = leads
        .iter()
        .filter(|l| matches!(l.status.as_str(), "proposed" | "verifying"))
        .count();
    out.push_str(&format!(
        "<h1>lockgate</h1><p class=muted>{} findings ({} high, {} critical) · {} leads ({} open) · {} identities · policy: {} / {} rules</p>",
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
    ));
    out.push_str("<p class=muted><a style='color:#79c0ff' href='report'>full report</a> · refreshes every 5s</p>");

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
            f.status.map(|s| s.to_string()).unwrap_or_else(|| "…".into()),
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

    out.push_str("</body></html>");
    out
}

/// The report as HTML-escaped markdown in a `<pre>` — readable on a phone
/// without pulling a markdown renderer into the tree.
pub async fn report(
    State(state): State<Arc<StatusState>>,
    Query(q): Query<TokenQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    check_token(&state, &q, &headers)?;
    let md = state
        .engine
        .generate_report()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "report failed"))?;
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

    #[tokio::test]
    async fn renders_the_engagement_readably_and_escapes_it() {
        let engine = Engine::new();
        engine
            .create_lead(&lockgate_core::NewLead {
                kind: "idor".into(),
                title: "Booking ids <script>alert(1)</script>".into(),
                rationale_md: "sequential ids".into(),
                endpoint: Some("https://t.com/b/{id}".into()),
                flow_id: None,
            })
            .unwrap();
        let id = engine
            .create_finding(lockgate_core::NewFinding {
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
                host: Some("t.com".into()),
                path: None,
                evidence: vec![],
                origin: "workflow".into(),
            })
            .await
            .unwrap();
        let _ = id;

        let html = render(&engine);
        assert!(
            html.contains("Booking ids &lt;script&gt;"),
            "data must be escaped: {html}"
        );
        assert!(!html.contains("<script>alert"), "no raw html from data");
        assert!(html.contains("Findings"));
        assert!(html.contains("Leads"));
        assert!(html.contains("Notes"));
        assert!(
            html.contains("st-proposed"),
            "status colours key off classes"
        );
    }

    #[tokio::test]
    async fn the_token_gate_refuses_without_the_query_param() {
        let state = Arc::new(StatusState {
            engine: Engine::new(),
            token: Some("sekrit".into()),
        });
        // No token: refused.
        let err = dashboard(State(state.clone()), Query(TokenQuery { token: None }))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        // Wrong token: refused. Right token: the page.
        let err = dashboard(
            State(state.clone()),
            Query(TokenQuery {
                token: Some("nope".into()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        let ok = dashboard(
            State(state),
            Query(TokenQuery {
                token: Some("sekrit".into()),
            }),
        )
        .await
        .unwrap();
        assert!(ok.0.contains("lockgate"));
    }
}
