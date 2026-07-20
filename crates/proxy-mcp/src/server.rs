//! The MCP server: recon over captured traffic, live interception, scope
//! management and request sending — plus the `flow://` resources that carry
//! full request/response bodies on demand.
//!
//! Every tool is a thin shell over an `Engine` verb. Reads go straight to the
//! engine's database-backed queries; the two writes (annotate, create finding)
//! go through the engine too, which funnels them to the single writer task —
//! this server never opens a database of its own.
//!
//! The intercept tools are the exception to "reads go to the database": a held
//! item is a live connection parked on a channel, not history. They share the
//! engine's `Intercept` with the TUI, so an agent and an operator work the same
//! queue, and share `http_text` so both see byte-identical wire text.
//!
//! `send_request` is the Repeater for agents. The TUI's Repeater keeps tabs and
//! per-session history, which is view state and lives there; what is shared is
//! the part that matters — take wire text, send it, record a flow.

use std::sync::Arc;

use proxy_core::{Engine, FlowQuery, Held, NewFinding, Pending, ResendError, Side, http_text};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    ErrorData, ListResourceTemplatesResult, PaginatedRequestParams, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResult, ResourceContents, ResourceTemplate,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::dto::{
    BodyPreview, FindingDto, FlowDetailDto, FlowDto, SitemapNodeDto, detail_headers, encode_bytes,
};

/// Default and ceiling on how many rows a listing returns. A ceiling matters
/// because history reaches millions of flows and an agent will happily ask for
/// all of them.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Default and ceiling on a body *preview* window in `get_flow`. Full bodies are
/// fetched through the `flow://` resource instead, so the preview stays small.
const DEFAULT_BODY_LIMIT: i64 = 64 * 1024;
const MAX_BODY_LIMIT: i64 = 1024 * 1024;

/// Ceiling on a single resource read. Bodies can be hundreds of MB; a resource
/// returns at most this much and callers page the rest via `get_flow`.
const MAX_RESOURCE_BYTES: i64 = 10 * 1024 * 1024;

/// The finding vocabularies, mirroring the values `db.rs` documents for the
/// `finding` table. The columns are free text with no CHECK, so the tool is the
/// only guard against a typo persisting and skewing later filters.
const SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];
const STATUSES: &[&str] = &[
    "draft",
    "confirmed",
    "false_positive",
    "reported",
    "fixed",
    "wont_fix",
];

// --- intercept ---

/// One held item, as listed. The payload is summarised rather than inlined:
/// `intercept_get` returns the full wire text for the one ticket being worked
/// on, so listing a deep queue does not drag every body through the context.
#[derive(Serialize, schemars::JsonSchema)]
pub struct HeldDto {
    /// Answer this with intercept_forward / intercept_drop.
    pub ticket: i64,
    /// The flow this belongs to. One flow can be held twice — once each way —
    /// so a flow id does not identify a hold.
    pub flow_id: i64,
    /// "request" or "response".
    pub leg: String,
    /// Unix microseconds. Held traffic is a live connection waiting on you.
    pub held_at: i64,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub status: Option<u16>,
    pub body_len: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct InterceptStatusResult {
    pub enabled: bool,
    pub holds_requests: bool,
    pub holds_responses: bool,
    pub queued_requests: i64,
    pub queued_responses: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct InterceptSetParams {
    /// Master switch. Turning it off releases everything currently held.
    pub enabled: Option<bool>,
    /// Hold outbound requests.
    pub hold_requests: Option<bool>,
    /// Hold inbound responses.
    pub hold_responses: Option<bool>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct InterceptSetResult {
    /// How many held items this change released.
    pub released: i64,
    pub enabled: bool,
    pub holds_requests: bool,
    pub holds_responses: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct InterceptQueueParams {
    /// "request", "response", or omitted for both.
    pub leg: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct InterceptQueueResult {
    pub held: Vec<HeldDto>,
    pub count: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct TicketParams {
    pub ticket: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct InterceptGetResult {
    pub ticket: i64,
    pub flow_id: i64,
    pub leg: String,
    /// The message exactly as it will go on the wire. Edit this text and hand
    /// it back to intercept_forward.
    pub text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct InterceptForwardParams {
    pub ticket: i64,
    /// Replacement wire text, in the form intercept_get returned. Omit to
    /// forward unchanged. Re-parsed before sending, so a malformed edit is
    /// rejected rather than put on the wire.
    pub edited: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AnsweredResult {
    /// False if the ticket was unknown — already answered, or never existed.
    pub answered: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct InterceptAnswerAllParams {
    /// "forward" or "drop".
    pub verdict: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AnsweredAllResult {
    pub answered: i64,
}

// --- scope ---

#[derive(Serialize, schemars::JsonSchema)]
pub struct ScopeDto {
    pub id: i64,
    pub name: String,
    /// Only one scope is active, and it is the active one that narrows
    /// list_flows when in_scope is set.
    pub is_active: bool,
    pub rule_count: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ScopeRuleDto {
    pub id: i64,
    /// "include" or "exclude". Excludes always beat includes, so the result
    /// does not depend on rule order.
    pub action: String,
    /// "glob", "regex", "cidr", or "any" when the rule does not constrain host.
    pub host_kind: String,
    pub host_pattern: Option<String>,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
    pub enabled: bool,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListScopesResult {
    pub scopes: Vec<ScopeDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateScopeParams {
    pub name: String,
    /// Make it the active scope straight away. A scope nobody activated
    /// narrows nothing.
    pub activate: Option<bool>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ScopeIdResult {
    pub id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ScopeIdParams {
    pub scope_id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListScopeRulesParams {
    /// Omit for the active scope.
    pub scope_id: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListScopeRulesResult {
    pub scope_id: i64,
    pub rules: Vec<ScopeRuleDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AddScopeRuleParams {
    /// Omit for the active scope.
    pub scope_id: Option<i64>,
    /// "include" (default) or "exclude".
    pub action: Option<String>,
    /// Host pattern. Note `*.example.com` does NOT match the apex
    /// `example.com` — add both if you mean the site and its subdomains.
    pub host: Option<String>,
    /// "glob" (default), "regex", or "cidr". Prefer glob: a regex here is
    /// matched unanchored, so `example\.com` also matches
    /// `evil-example.com.attacker.net`.
    pub host_kind: Option<String>,
    pub port: Option<u16>,
    /// Matched on path segments, so `/api` covers `/api/v1` but not `/apikeys`.
    pub path_prefix: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RuleIdParams {
    pub rule_id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SetRuleEnabledParams {
    pub rule_id: i64,
    pub enabled: bool,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct OkResult {
    pub ok: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CheckScopeParams {
    /// Absolute URL to test, e.g. "https://api.example.com/v1/users".
    pub url: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct CheckScopeResult {
    pub in_scope: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    /// The scope that decided, or null when none is active (everything is in
    /// scope).
    pub scope: Option<String>,
}

// --- request sending ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SendRequestParams {
    /// The request as raw wire text: start line, headers, blank line, body —
    /// the same shape intercept_get returns.
    pub text: String,
    /// A flow to resolve scheme and authority against, for when the start line
    /// carries an origin-form target like `/path`. Omit only if the start line
    /// has an absolute URL or the text has a Host header.
    pub base_flow_id: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct SendRequestResult {
    /// The new flow this send was recorded as.
    pub flow_id: i64,
    pub status: u16,
    /// The response as wire text.
    pub text: String,
    pub response_len: i64,
    pub millis: i64,
}

// --- formatting ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct FormatMessageParams {
    /// An HTTP message as wire text.
    pub text: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct FormatMessageResult {
    pub text: String,
    /// "json" or "html" — what the body was read as.
    pub language: String,
}

/// The MCP frontend. Holds only an `Engine` handle and its tool table; a fresh
/// one is built per session by the transport's service factory.
#[derive(Clone)]
pub struct ProxyServer {
    engine: Arc<Engine>,
    tool_router: ToolRouter<ProxyServer>,
}

// --- tool parameter and result shapes ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListFlowsParams {
    /// Substring match on host (case-insensitive).
    pub host: Option<String>,
    /// Exact HTTP method (matched case-insensitively).
    pub method: Option<String>,
    /// Exact source: proxy | repeater | automate | import.
    pub source: Option<String>,
    /// Substring match on the request URI.
    pub uri_contains: Option<String>,
    /// Only flows whose response has this status code.
    pub status: Option<u16>,
    /// Include Automate/Intruder-generated flows, which are hidden by default so
    /// a survey shows real traffic, not tool output. Ignored when `source` is set
    /// (an explicit source wins). Default false.
    pub include_automate: Option<bool>,
    /// Rows to skip, for paging. Default 0.
    pub offset: Option<i64>,
    /// Max rows to return. Default 100, capped at 500.
    pub limit: Option<i64>,
    /// Narrow to the active scope. Off by default, so a survey shows everything
    /// captured rather than silently hiding traffic.
    pub in_scope: Option<bool>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListFlowsResult {
    pub flows: Vec<FlowDto>,
    pub offset: i64,
    pub limit: i64,
    pub returned: usize,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct GetFlowParams {
    pub id: i64,
    /// Byte offset into each body for the preview window. Default 0.
    pub body_offset: Option<i64>,
    /// Preview bytes per body. Default 64 KiB, capped at 1 MiB. Use the
    /// `flow://{id}/request|response` resource for the full body.
    pub body_limit: Option<i64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct GetSitemapParams {
    /// Restrict to one host. Omit for the whole tree.
    pub host: Option<String>,
    pub offset: Option<i64>,
    /// Default 100, capped at 500.
    pub limit: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct GetSitemapResult {
    pub nodes: Vec<SitemapNodeDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ResendFlowParams {
    /// The flow to replay. Its request is sent straight at the target and the
    /// fresh response is summarised here; the replay is recorded as a new flow.
    pub id: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ResendFlowResult {
    /// The id of the new flow this replay was recorded as (parented to the
    /// original). Fetch it with get_flow to see the full replayed exchange.
    pub replay_flow_id: i64,
    pub status: u16,
    pub http_version: String,
    pub response_len: i64,
    pub mime: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AnnotateFlowParams {
    pub id: i64,
    /// Set the triage comment. Omit to leave unchanged; empty string clears it.
    pub comment: Option<String>,
    /// Set the highlight colour/label. Omit to leave unchanged.
    pub highlight: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AnnotateFlowResult {
    /// 0 means no flow with that id.
    pub rows_changed: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct EvidenceInput {
    pub flow_id: i64,
    pub label: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateFindingParams {
    pub title: String,
    /// info | low | medium | high | critical.
    pub severity: String,
    /// draft | confirmed | false_positive | reported | fixed | wont_fix.
    /// Defaults to "draft".
    pub status: Option<String>,
    pub description_md: String,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cwe: Option<String>,
    pub repro_md: Option<String>,
    pub impact_md: Option<String>,
    pub remediation_md: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    /// Captured flows that demonstrate the issue.
    pub evidence: Option<Vec<EvidenceInput>>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct CreateFindingResult {
    pub id: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListFindingsResult {
    pub findings: Vec<FindingDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct GetFindingParams {
    pub id: i64,
}

#[tool_router]
impl ProxyServer {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List captured HTTP flows (metadata only, no bodies), newest first. \
                       Filter by host, method, source, URI substring, or status, and page \
                       with offset/limit, and narrow to the active scope with in_scope. \
                       Use get_flow for headers and body previews."
    )]
    async fn list_flows(
        &self,
        Parameters(p): Parameters<ListFlowsParams>,
    ) -> Result<Json<ListFlowsResult>, ErrorData> {
        let offset = p.offset.unwrap_or(0).max(0);
        let limit = clamp_limit(p.limit, DEFAULT_LIMIT, MAX_LIMIT);
        let query = FlowQuery {
            host: p.host,
            method: p.method,
            source: p.source,
            uri_contains: p.uri_contains,
            status: p.status,
            include_automate: p.include_automate.unwrap_or(false),
        };
        // Scope cannot be pushed into SQL — the patterns are globs, regexes and
        // CIDR blocks — so the scoped path filters in Rust and pages the
        // results it keeps.
        let rows = if p.in_scope.unwrap_or(false) {
            self.engine.query_flows_in_scope(&query, offset, limit)
        } else {
            self.engine.query_flows(&query, offset, limit)
        };
        let flows: Vec<FlowDto> = rows.into_iter().map(FlowDto::from).collect();
        Ok(Json(ListFlowsResult {
            offset,
            limit,
            returned: flows.len(),
            flows,
        }))
    }

    #[tool(
        description = "Get one flow in full: metadata, request/response headers, and a bounded \
                       preview of each body. Bodies beyond the preview are read from the \
                       flow://{id}/request and flow://{id}/response resources."
    )]
    async fn get_flow(
        &self,
        Parameters(p): Parameters<GetFlowParams>,
    ) -> Result<Json<FlowDetailDto>, ErrorData> {
        let detail = self
            .engine
            .flow_detail(p.id)
            .ok_or_else(|| ErrorData::resource_not_found(format!("no flow #{}", p.id), None))?;

        let offset = p.body_offset.unwrap_or(0).max(0);
        let limit = clamp_limit(p.body_limit, DEFAULT_BODY_LIMIT, MAX_BODY_LIMIT);
        let (request_headers, response_headers) = detail_headers(&detail);

        let request_body = self.body_preview(
            p.id,
            Side::Request,
            offset,
            limit,
            coding_of_pairs(&detail.req_headers),
        );
        let response_body = self.body_preview(
            p.id,
            Side::Response,
            offset,
            limit,
            coding_of_pairs(&detail.resp_headers),
        );

        Ok(Json(FlowDetailDto {
            flow: FlowDto::from(detail.row),
            http_version: detail.http_version,
            parent_id: detail.parent_id,
            request_headers,
            response_headers,
            request_body,
            response_body,
        }))
    }

    #[tool(
        description = "Get the sitemap: the host → directory → leaf tree materialised from \
                       captured traffic. Returns flat nodes with parent_id; reconstruct the \
                       tree from that. Filter to one host with `host`."
    )]
    async fn get_sitemap(
        &self,
        Parameters(p): Parameters<GetSitemapParams>,
    ) -> Result<Json<GetSitemapResult>, ErrorData> {
        let offset = p.offset.unwrap_or(0).max(0);
        let limit = clamp_limit(p.limit, DEFAULT_LIMIT, MAX_LIMIT);
        let nodes = self
            .engine
            .sitemap(p.host.as_deref(), offset, limit)
            .into_iter()
            .map(SitemapNodeDto::from)
            .collect();
        Ok(Json(GetSitemapResult { nodes }))
    }

    #[tool(
        description = "Replay a captured request straight at its target (Burp-Repeater style) \
                       and return the fresh response summary. The replay is recorded as a new \
                       flow. Refused if the target is outside the active scope."
    )]
    async fn resend_flow(
        &self,
        Parameters(p): Parameters<ResendFlowParams>,
    ) -> Result<Json<ResendFlowResult>, ErrorData> {
        let resent = self
            .engine
            .resend(p.id as u64)
            .await
            .map_err(resend_error)?;
        let response = &resent.response;
        // "text/html; charset=utf-8" -> "text/html", matching how capture stores mime.
        let mime = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());
        Ok(Json(ResendFlowResult {
            replay_flow_id: resent.replay_id as i64,
            status: response.status.as_u16(),
            http_version: format!("{:?}", response.version),
            response_len: response.body.len() as i64,
            mime,
        }))
    }

    /// The scope a call means: the one named, else the active one.
    fn resolve_scope(&self, given: Option<i64>) -> Result<i64, ErrorData> {
        if let Some(id) = given {
            return Ok(id);
        }
        self.engine.active_scope().map(|s| s.id).ok_or_else(|| {
            ErrorData::invalid_params(
                "no active scope — pass scope_id, or create one with create_scope",
                None,
            )
        })
    }

    // --- scope ---
    //
    // Scope is a *view* filter, not a capture filter: nothing is dropped on the
    // wire, so narrowing it hides rows rather than losing them, and widening it
    // brings them straight back.

    #[tool(
        description = "List scopes. Exactly one is active, and it is the active one that \
                       list_flows narrows to when in_scope is set."
    )]
    async fn list_scopes(&self) -> Result<Json<ListScopesResult>, ErrorData> {
        let scopes = self
            .engine
            .scopes()
            .into_iter()
            .map(|s| ScopeDto {
                rule_count: self.engine.scope_rules(s.id).len() as i64,
                id: s.id,
                name: s.name,
                is_active: s.is_active,
            })
            .collect();
        Ok(Json(ListScopesResult { scopes }))
    }

    #[tool(description = "Create a scope. Pass activate=true to make it the active one.")]
    async fn create_scope(
        &self,
        Parameters(p): Parameters<CreateScopeParams>,
    ) -> Result<Json<ScopeIdResult>, ErrorData> {
        let name = p.name.trim();
        if name.is_empty() {
            return Err(ErrorData::invalid_params("name must not be empty", None));
        }
        let id = self.engine.create_scope(name).map_err(scope_error)?;
        if p.activate.unwrap_or(false) {
            self.engine.set_active_scope(id).map_err(scope_error)?;
        }
        Ok(Json(ScopeIdResult { id }))
    }

    #[tool(
        description = "Delete a scope and its rules. Deleting the active scope leaves none \
                       active, which means everything is in scope."
    )]
    async fn delete_scope(
        &self,
        Parameters(p): Parameters<ScopeIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine.delete_scope(p.scope_id).map_err(scope_error)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Make a scope the active one.")]
    async fn set_active_scope(
        &self,
        Parameters(p): Parameters<ScopeIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine
            .set_active_scope(p.scope_id)
            .map_err(scope_error)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "List a scope's rules. Omit scope_id for the active scope.")]
    async fn list_scope_rules(
        &self,
        Parameters(p): Parameters<ListScopeRulesParams>,
    ) -> Result<Json<ListScopeRulesResult>, ErrorData> {
        let scope_id = self.resolve_scope(p.scope_id)?;
        let rules = self
            .engine
            .scope_rules(scope_id)
            .iter()
            .map(rule_dto)
            .collect();
        Ok(Json(ListScopeRulesResult { scope_id, rules }))
    }

    #[tool(
        description = "Add a rule to a scope. Defaults to an include with a glob host \
                       pattern. Excludes always beat includes. The pattern is validated \
                       here, so a bad regex or CIDR is refused rather than breaking the \
                       matcher later."
    )]
    async fn add_scope_rule(
        &self,
        Parameters(p): Parameters<AddScopeRuleParams>,
    ) -> Result<Json<ScopeIdResult>, ErrorData> {
        let scope_id = self.resolve_scope(p.scope_id)?;
        let action = match p.action.as_deref().unwrap_or("include") {
            "include" => proxy_core::scope::Action::Include,
            "exclude" => proxy_core::scope::Action::Exclude,
            other => {
                return Err(ErrorData::invalid_params(
                    format!("action must be \"include\" or \"exclude\", got {other:?}"),
                    None,
                ));
            }
        };

        let mut spec = match &p.host {
            Some(host) => {
                let kind = match p.host_kind.as_deref().unwrap_or("glob") {
                    "glob" => proxy_core::scope::HostKind::Glob,
                    "regex" => proxy_core::scope::HostKind::Regex,
                    "cidr" => proxy_core::scope::HostKind::Cidr,
                    other => {
                        return Err(ErrorData::invalid_params(
                            format!("host_kind must be glob|regex|cidr, got {other:?}"),
                            None,
                        ));
                    }
                };
                proxy_core::scope::RuleSpec::host(kind, host.clone())
            }
            None => proxy_core::scope::RuleSpec::default(),
        };
        if let Some(port) = p.port {
            spec = spec.with_port(port);
        }
        if let Some(prefix) = &p.path_prefix {
            spec = spec.with_path_prefix(prefix.clone());
        }

        let id = self
            .engine
            .add_scope_rule(scope_id, action, &spec)
            .map_err(scope_error)?;
        Ok(Json(ScopeIdResult { id }))
    }

    #[tool(description = "Delete one scope rule.")]
    async fn delete_scope_rule(
        &self,
        Parameters(p): Parameters<RuleIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine
            .delete_scope_rule(p.rule_id)
            .map_err(scope_error)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Turn a rule off or on without deleting it — useful for checking \
                       whether a rule is why something is missing."
    )]
    async fn set_scope_rule_enabled(
        &self,
        Parameters(p): Parameters<SetRuleEnabledParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine
            .set_scope_rule_enabled(p.rule_id, p.enabled)
            .map_err(scope_error)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Test whether a URL is in the active scope. Use this before acting on \
                       a target rather than guessing from the rules."
    )]
    async fn check_scope(
        &self,
        Parameters(p): Parameters<CheckScopeParams>,
    ) -> Result<Json<CheckScopeResult>, ErrorData> {
        let uri: hudsucker::hyper::Uri = p
            .url
            .parse()
            .map_err(|_| ErrorData::invalid_params(format!("not a URL: {:?}", p.url), None))?;
        let host = uri.host().unwrap_or_default().to_string();
        // Resolved the same way capture resolves it, so a port rule means the
        // same thing whether or not the caller wrote the port out.
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            Some("http") => 80,
            _ => 443,
        });
        let path = uri.path().to_string();

        let in_scope = self
            .engine
            .scope_matcher()
            .matches(&proxy_core::scope::Target {
                host: &host,
                port,
                path: &path,
            });
        Ok(Json(CheckScopeResult {
            in_scope,
            host,
            port,
            path,
            scope: self.engine.active_scope().map(|s| s.name),
        }))
    }

    // --- sending ---

    #[tool(
        description = "Send an edited request and return the response (the Repeater, for \
                       agents). Takes raw wire text, so any part of the message can be \
                       changed. Recorded as a new flow. Use resend_flow instead to replay \
                       a captured request unchanged."
    )]
    async fn send_request(
        &self,
        Parameters(p): Parameters<SendRequestParams>,
    ) -> Result<Json<SendRequestResult>, ErrorData> {
        // The original supplies what origin-form wire text cannot: scheme and
        // authority. Without a base flow we synthesize one, which works as long
        // as the text carries an absolute target or a Host header.
        let base = match p.base_flow_id {
            Some(id) => {
                let flow = self
                    .engine
                    .get_flow(id as u64)
                    .ok_or_else(|| ErrorData::resource_not_found(format!("no flow #{id}"), None))?;
                flow.request
            }
            None => placeholder_request(),
        };

        let request = http_text::parse_request(&p.text, &base)
            .map_err(|e| ErrorData::invalid_params(format!("request does not parse: {e}"), None))?;

        // `parse_request` falls back to the original's authority when the text
        // supplies none — so with no base flow, the placeholder's host is
        // exactly the signal that the caller gave no host at all. Checking for
        // `None` would never fire, and the send would go out aimed at the
        // placeholder.
        let unnamed = p.base_flow_id.is_none() && request.uri.host() == Some(PLACEHOLDER_HOST);
        if unnamed || request.uri.host().is_none() {
            return Err(ErrorData::invalid_params(
                "no host: give an absolute URL in the start line, a Host header, or a \
                 base_flow_id to resolve against",
                None,
            ));
        }

        let started = std::time::Instant::now();
        let sent = self
            .engine
            .send_request(request, p.base_flow_id.map(|id| id as u64))
            .await
            .map_err(resend_error)?;
        let millis = started.elapsed().as_millis() as i64;

        Ok(Json(SendRequestResult {
            flow_id: sent.replay_id as i64,
            status: sent.response.status.as_u16(),
            response_len: sent.response.body.len() as i64,
            text: http_text::render_response_decoded(&sent.response),
            millis,
        }))
    }

    #[tool(
        description = "Pretty-print the body of an HTTP message for reading. JSON and HTML \
                       only. Key order and number text are preserved exactly, so a \
                       reformatted request is still the same request; an existing \
                       Content-Length is corrected to match."
    )]
    async fn format_message(
        &self,
        Parameters(p): Parameters<FormatMessageParams>,
    ) -> Result<Json<FormatMessageResult>, ErrorData> {
        let (text, language) = proxy_core::pretty::pretty_message(&p.text)
            .map_err(|e| ErrorData::invalid_params(format!("cannot format: {e}"), None))?;
        Ok(Json(FormatMessageResult {
            text,
            language: format!("{language:?}").to_ascii_lowercase(),
        }))
    }

    // --- intercept ---
    //
    // Held traffic is a *live connection* parked on a channel, unlike every
    // other tool here, which reads history. Nothing times out — matching Burp
    // and Caido — so anything left in the queue stays parked until it is
    // answered or interception is turned off. Check intercept_queue after
    // enabling, and answer what you find.

    #[tool(
        description = "Get interception state: whether it is on, which legs are held, and how \
                       many items are waiting. Held items are live connections parked until \
                       answered — nothing times out."
    )]
    async fn intercept_status(&self) -> Result<Json<InterceptStatusResult>, ErrorData> {
        let i = self.engine.intercept();
        Ok(Json(InterceptStatusResult {
            enabled: i.is_enabled(),
            holds_requests: i.holds_requests(),
            holds_responses: i.holds_responses(),
            queued_requests: i.queue_of(true).len() as i64,
            queued_responses: i.queue_of(false).len() as i64,
        }))
    }

    #[tool(
        description = "Turn interception on/off, or choose which legs are held. Omit a field to \
                       leave it unchanged. Turning something off releases whatever it was \
                       holding, unmodified. Returns how many items that released."
    )]
    async fn intercept_set(
        &self,
        Parameters(p): Parameters<InterceptSetParams>,
    ) -> Result<Json<InterceptSetResult>, ErrorData> {
        let i = self.engine.intercept();
        let mut released = 0usize;
        if let Some(on) = p.hold_requests {
            released += i.set_hold_requests(on);
        }
        if let Some(on) = p.hold_responses {
            released += i.set_hold_responses(on);
        }
        // Applied last: the master switch should win over a leg toggle sent in
        // the same call, rather than being silently re-enabled by one.
        if let Some(on) = p.enabled {
            released += i.set_enabled(on);
        }
        Ok(Json(InterceptSetResult {
            released: released as i64,
            enabled: i.is_enabled(),
            holds_requests: i.holds_requests(),
            holds_responses: i.holds_responses(),
        }))
    }

    #[tool(
        description = "List held items awaiting a verdict, oldest first. Summaries only — use \
                       intercept_get for one item's full text. Filter with leg=request|response."
    )]
    async fn intercept_queue(
        &self,
        Parameters(p): Parameters<InterceptQueueParams>,
    ) -> Result<Json<InterceptQueueResult>, ErrorData> {
        let i = self.engine.intercept();
        let held = match p.leg.as_deref() {
            None => i.queue(),
            Some(leg) => match parse_leg(leg)? {
                true => i.queue_of(true),
                false => i.queue_of(false),
            },
        };
        let held: Vec<HeldDto> = held.iter().map(held_dto).collect();
        Ok(Json(InterceptQueueResult {
            count: held.len() as i64,
            held,
        }))
    }

    #[tool(
        description = "Get one held item as raw HTTP wire text — start line, headers, blank \
                       line, body. This is the exact text to edit and hand back to \
                       intercept_forward."
    )]
    async fn intercept_get(
        &self,
        Parameters(p): Parameters<TicketParams>,
    ) -> Result<Json<InterceptGetResult>, ErrorData> {
        let held = self
            .engine
            .intercept()
            .get(p.ticket as u64)
            .ok_or_else(|| unknown_ticket(p.ticket))?;
        Ok(Json(InterceptGetResult {
            ticket: held.ticket as i64,
            flow_id: held.flow_id as i64,
            leg: leg_name(&held.pending).to_string(),
            text: render_pending(&held.pending),
        }))
    }

    #[tool(
        description = "Release one held item, optionally replacing it with edited wire text in \
                       the form intercept_get returned. A malformed edit is rejected and the \
                       item stays held, so a bad edit never reaches the wire."
    )]
    async fn intercept_forward(
        &self,
        Parameters(p): Parameters<InterceptForwardParams>,
    ) -> Result<Json<AnsweredResult>, ErrorData> {
        let ticket = p.ticket as u64;
        let edited = match p.edited {
            None => None,
            Some(text) => {
                // Reparsed against the original, which supplies what wire text
                // cannot: the absolute URI behind an origin-form target.
                let held = self
                    .engine
                    .intercept()
                    .get(ticket)
                    .ok_or_else(|| unknown_ticket(p.ticket))?;
                Some(reparse(&held.pending, &text).map_err(|e| {
                    ErrorData::invalid_params(format!("edited message does not parse: {e}"), None)
                })?)
            }
        };
        Ok(Json(AnsweredResult {
            answered: self.engine.intercept().forward(ticket, edited),
        }))
    }

    #[tool(
        description = "Drop one held item. The client gets a 502 rather than a hung socket. \
                       Returns answered=false if the ticket is unknown."
    )]
    async fn intercept_drop(
        &self,
        Parameters(p): Parameters<TicketParams>,
    ) -> Result<Json<AnsweredResult>, ErrorData> {
        Ok(Json(AnsweredResult {
            answered: self.engine.intercept().discard(p.ticket as u64),
        }))
    }

    #[tool(
        description = "Answer everything currently held at once with verdict=forward or \
                       verdict=drop. Use this to clear a queue you no longer intend to work \
                       through — held connections wait indefinitely."
    )]
    async fn intercept_answer_all(
        &self,
        Parameters(p): Parameters<InterceptAnswerAllParams>,
    ) -> Result<Json<AnsweredAllResult>, ErrorData> {
        let i = self.engine.intercept();
        let answered = match p.verdict.to_ascii_lowercase().as_str() {
            "forward" => i.forward_all(),
            "drop" => i.discard_all(),
            other => {
                return Err(ErrorData::invalid_params(
                    format!("verdict must be \"forward\" or \"drop\", got {other:?}"),
                    None,
                ));
            }
        };
        Ok(Json(AnsweredAllResult {
            answered: answered as i64,
        }))
    }

    #[tool(
        description = "Set a flow's triage comment and/or highlight. Omit a field to leave it \
                       unchanged; pass an empty string to clear it. Returns rows_changed (0 if \
                       no such flow)."
    )]
    async fn annotate_flow(
        &self,
        Parameters(p): Parameters<AnnotateFlowParams>,
    ) -> Result<Json<AnnotateFlowResult>, ErrorData> {
        // Both omitted is a no-op that would report rows_changed:0 and read as
        // "no such flow" — almost always a caller mistake, so reject it plainly.
        if p.comment.is_none() && p.highlight.is_none() {
            return Err(ErrorData::invalid_params(
                "annotate_flow needs a comment or a highlight".to_string(),
                None,
            ));
        }
        let rows = self
            .engine
            .annotate_flow(p.id as u64, p.comment, p.highlight)
            .await
            .map_err(write_error)?;
        Ok(Json(AnnotateFlowResult { rows_changed: rows }))
    }

    #[tool(
        description = "Author a security finding with severity, status, markdown write-up, \
                       optional CVSS/CWE, and evidence flows. Returns the new finding id."
    )]
    async fn create_finding(
        &self,
        Parameters(p): Parameters<CreateFindingParams>,
    ) -> Result<Json<CreateFindingResult>, ErrorData> {
        // Validate up front: the columns are free text with no DB CHECK, so a
        // typo'd severity would persist silently and skew every later filter.
        let severity = validate_one("severity", &p.severity, SEVERITIES)?;
        let status = match &p.status {
            Some(s) => validate_one("status", s, STATUSES)?,
            None => "draft".to_string(),
        };

        // A bad evidence id would only surface as an opaque foreign-key failure
        // ("the write did not commit"); check existence first for a clear error.
        let evidence = p.evidence.unwrap_or_default();
        for e in &evidence {
            if self.engine.flow_detail(e.flow_id).is_none() {
                return Err(ErrorData::invalid_params(
                    format!("evidence flow #{} does not exist", e.flow_id),
                    None,
                ));
            }
        }

        let finding = NewFinding {
            title: p.title,
            severity,
            status,
            cvss_vector: p.cvss_vector,
            cvss_score: p.cvss_score,
            cvss_version: p.cvss_version,
            cwe: p.cwe,
            description_md: p.description_md,
            repro_md: p.repro_md,
            impact_md: p.impact_md,
            remediation_md: p.remediation_md,
            host: p.host,
            path: p.path,
            evidence: evidence.into_iter().map(|e| (e.flow_id, e.label)).collect(),
        };
        let id = self
            .engine
            .create_finding(finding)
            .await
            .map_err(write_error)?;
        Ok(Json(CreateFindingResult { id }))
    }

    #[tool(description = "List every finding recorded in this project, newest first.")]
    async fn list_findings(&self) -> Result<Json<ListFindingsResult>, ErrorData> {
        let findings = self
            .engine
            .list_findings()
            .into_iter()
            .map(FindingDto::from)
            .collect();
        Ok(Json(ListFindingsResult { findings }))
    }

    #[tool(description = "Get one finding by id, with its full write-up and evidence flows.")]
    async fn get_finding(
        &self,
        Parameters(p): Parameters<GetFindingParams>,
    ) -> Result<Json<FindingDto>, ErrorData> {
        self.engine
            .get_finding(p.id)
            .map(|f| Json(FindingDto::from(f)))
            .ok_or_else(|| ErrorData::resource_not_found(format!("no finding #{}", p.id), None))
    }

    /// Read a bounded window of one body and shape it for JSON.
    fn body_preview(
        &self,
        id: i64,
        side: Side,
        offset: i64,
        limit: i64,
        coding: Option<proxy_core::encoding::Coding>,
    ) -> BodyPreview {
        let side_name = match side {
            Side::Request => "request",
            Side::Response => "response",
        };
        let resource_uri = format!("flow://{id}/{side_name}");

        match self.engine.body_slice(id, side, offset, limit) {
            Some(slice) => {
                let returned = slice.bytes.len() as i64;
                let truncated = offset + returned < slice.total_len;

                // A compressed stream can only be decoded from its start and in
                // full; decoding a window would produce plausible-looking
                // garbage, which is worse than handing back the bytes.
                let whole = offset == 0 && !truncated;
                let raw = hudsucker::hyper::body::Bytes::copy_from_slice(&slice.bytes);
                let decoded_bytes = match (whole, coding) {
                    (true, Some(coding)) => proxy_core::encoding::decode_body(coding, &raw),
                    _ => raw.clone(),
                };
                let decoded = decoded_bytes != raw;

                let (text, base64) = encode_bytes(&decoded_bytes);
                BodyPreview {
                    truncated,
                    total_len: slice.total_len,
                    storage: slice.storage,
                    offset,
                    text,
                    base64,
                    content_encoding: coding.map(|c| c.as_str().to_string()),
                    decoded,
                    resource_uri,
                }
            }
            // No body on this side (or an in-memory engine): report it as empty.
            None => BodyPreview {
                total_len: 0,
                storage: "none".to_string(),
                offset,
                truncated: false,
                text: None,
                base64: None,
                content_encoding: None,
                decoded: false,
                resource_uri,
            },
        }
    }

    /// Resolve a `flow://{id}/request|response` URI to its full body, as text
    /// when the bytes are valid UTF-8 and base64 otherwise. Context-free so the
    /// resource logic is testable without a live session.
    fn read_flow_resource(&self, uri: &str) -> Result<ReadResourceResult, ErrorData> {
        let (id, side) = parse_flow_uri(uri).ok_or_else(|| {
            ErrorData::invalid_params(format!("unrecognised resource uri: {uri}"), None)
        })?;

        let slice = self
            .engine
            .body_slice(id, side, 0, MAX_RESOURCE_BYTES)
            .ok_or_else(|| ErrorData::resource_not_found(format!("no flow #{id}"), None))?;

        // Response mime comes from the stored row; requests carry none.
        let mime = match side {
            Side::Response => self.engine.flow_detail(id).and_then(|d| d.row.mime),
            Side::Request => None,
        };

        let contents = match std::str::from_utf8(&slice.bytes) {
            Ok(text) => ResourceContents::text(text, uri),
            Err(_) => {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&slice.bytes);
                ResourceContents::blob(encoded, uri)
            }
        };
        let contents = match mime {
            Some(m) => contents.with_mime_type(m),
            None => contents,
        };
        Ok(ReadResourceResult::new(vec![contents]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProxyServer {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo`/`Implementation` are `#[non_exhaustive]`, so build from
        // the default and set fields rather than a struct literal. The default's
        // `server_info` names rmcp, not us, so overwrite it.
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::LATEST;
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        info.server_info.name = "proxy-mcp".to_string();
        info.server_info.title = Some("Proxy — captured traffic".to_string());
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.server_info.description = Some(
            "Recon over an intercepting proxy's captured HTTP traffic: list and inspect flows, \
             walk the sitemap, replay requests, annotate, and record findings."
                .to_string(),
        );
        info.instructions = Some(
            "Start with list_flows to survey traffic and get_flow for detail. Full request and \
             response bodies are resources at flow://{id}/request and flow://{id}/response. \
             resend_flow replays a request (scope-gated). Record what you find with \
             create_finding; list_findings shows them all."
                .to_string(),
        );
        info
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(
            resource_templates(),
        ))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        self.read_flow_resource(&request.uri)
    }
}

/// The two body resources this server exposes. Free-standing so it can be tested
/// without a live session's `RequestContext`.
fn resource_templates() -> Vec<ResourceTemplate> {
    vec![
        ResourceTemplate::new("flow://{id}/request", "flow-request-body")
            .with_description("The full request body of flow {id}."),
        ResourceTemplate::new("flow://{id}/response", "flow-response-body")
            .with_description("The full response body of flow {id}."),
    ]
}

/// Parse `flow://{id}/request` or `flow://{id}/response`.
fn parse_flow_uri(uri: &str) -> Option<(i64, Side)> {
    let rest = uri.strip_prefix("flow://")?;
    let (id, side) = rest.split_once('/')?;
    let id: i64 = id.parse().ok()?;
    let side = match side {
        "request" => Side::Request,
        "response" => Side::Response,
        _ => return None,
    };
    Some((id, side))
}

/// The declared coding, from headers stored as name/value pairs.
fn coding_of_pairs(headers: &[(String, String)]) -> Option<proxy_core::encoding::Coding> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .and_then(|(_, value)| proxy_core::encoding::Coding::from_header_value(value))
}

// --- scope helpers ---

fn scope_error(e: proxy_core::scope::ScopeError) -> ErrorData {
    ErrorData::invalid_params(format!("{e:?}"), None)
}

fn rule_dto(rule: &proxy_core::scope::ScopeRule) -> ScopeRuleDto {
    let (host_kind, host_pattern) = match &rule.spec.host {
        Some((kind, pattern)) => (
            match kind {
                proxy_core::scope::HostKind::Glob => "glob",
                proxy_core::scope::HostKind::Regex => "regex",
                proxy_core::scope::HostKind::Cidr => "cidr",
            },
            Some(pattern.clone()),
        ),
        None => ("any", None),
    };
    ScopeRuleDto {
        id: rule.id,
        action: match rule.action {
            proxy_core::scope::Action::Include => "include".into(),
            proxy_core::scope::Action::Exclude => "exclude".into(),
        },
        host_kind: host_kind.into(),
        host_pattern,
        port: rule.spec.port,
        path_prefix: rule.spec.path_prefix.clone(),
        enabled: rule.enabled,
    }
}

/// A stand-in request for sends that carry their own absolute target.
///
/// `parse_request` needs an original to recover scheme and authority from. When
/// the caller gave no base flow, this supplies the scheme so a `Host` header is
/// enough — and if there is no Host either, the send is refused rather than
/// aimed at this placeholder.
/// Reserved by RFC 2606 and guaranteed never to resolve, which is what makes it
/// safe to use as "the caller named no host" — if this ever reached the wire it
/// could not hit anything real.
const PLACEHOLDER_HOST: &str = "invalid.invalid";

fn placeholder_request() -> proxy_core::CapturedRequest {
    proxy_core::CapturedRequest {
        method: hudsucker::hyper::Method::GET,
        uri: hudsucker::hyper::Uri::from_static("https://invalid.invalid/"),
        version: hudsucker::hyper::Version::HTTP_11,
        headers: hudsucker::hyper::HeaderMap::new(),
        body: hudsucker::hyper::body::Bytes::new(),
    }
}

// --- intercept helpers ---

fn leg_name(pending: &Pending) -> &'static str {
    if pending.is_request() {
        "request"
    } else {
        "response"
    }
}

/// `"request"` / `"response"` to the boolean the engine takes.
fn parse_leg(leg: &str) -> Result<bool, ErrorData> {
    match leg.to_ascii_lowercase().as_str() {
        "request" | "requests" => Ok(true),
        "response" | "responses" => Ok(false),
        other => Err(ErrorData::invalid_params(
            format!("leg must be \"request\" or \"response\", got {other:?}"),
            None,
        )),
    }
}

fn unknown_ticket(ticket: i64) -> ErrorData {
    ErrorData::resource_not_found(
        format!("no held item with ticket {ticket} (already answered, or never existed)"),
        None,
    )
}

fn held_dto(held: &Held) -> HeldDto {
    let (method, uri, status, body_len) = match &held.pending {
        Pending::Request(r) => (
            Some(r.method.to_string()),
            Some(r.uri.to_string()),
            None,
            r.body.len(),
        ),
        Pending::Response(r) => (None, None, Some(r.status.as_u16()), r.body.len()),
    };
    HeldDto {
        ticket: held.ticket as i64,
        flow_id: held.flow_id as i64,
        leg: leg_name(&held.pending).to_string(),
        held_at: held.held_at,
        method,
        uri,
        status,
        body_len: body_len as i64,
    }
}

/// A held item as editable wire text — the same rendering the TUI shows, from
/// the same codec, so an agent and an operator are looking at the same bytes.
fn render_pending(pending: &Pending) -> String {
    match pending {
        Pending::Request(r) => http_text::render_request_decoded(r),
        Pending::Response(r) => http_text::render_response_decoded(r),
    }
}

/// Parse edited text back into the same kind of message it started as. The
/// original supplies what wire text cannot carry: the absolute URI behind an
/// origin-form target, and the version if the edit dropped it.
fn reparse(original: &Pending, text: &str) -> Result<Pending, http_text::ParseError> {
    Ok(match original {
        Pending::Request(r) => Pending::Request(http_text::parse_request(text, r)?),
        Pending::Response(r) => Pending::Response(http_text::parse_response(text, r)?),
    })
}

fn clamp_limit(requested: Option<i64>, default: i64, max: i64) -> i64 {
    requested.unwrap_or(default).clamp(1, max)
}

/// Accept `value` only if it is one of `allowed`, returning it owned; otherwise
/// an `invalid_params` naming the field and the allowed set.
fn validate_one(field: &str, value: &str, allowed: &[&str]) -> Result<String, ErrorData> {
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(ErrorData::invalid_params(
            format!(
                "invalid {field} {value:?}; expected one of {}",
                allowed.join(", ")
            ),
            None,
        ))
    }
}

fn resend_error(e: ResendError) -> ErrorData {
    match e {
        ResendError::NotFound(id) => ErrorData::resource_not_found(format!("no flow #{id}"), None),
        ResendError::NoTarget => {
            ErrorData::invalid_params("flow has no absolute URL to resend to".to_string(), None)
        }
        ResendError::OutOfScope => {
            ErrorData::invalid_request("target is outside the active scope".to_string(), None)
        }
        ResendError::Http(e) => ErrorData::internal_error(format!("resend failed: {e}"), None),
    }
}

fn write_error(e: proxy_core::engine::WriteError) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

#[cfg(test)]
mod tests {
    //! Drives the tool methods and resource helpers in-process against an
    //! in-memory `Engine` (synchronous, so a recorded flow is readable at once).
    //! This is the level worth pinning: parameter clamping, DTO mapping, the
    //! validation guards, and the `flow://` resolution — everything but the HTTP
    //! transport, which rmcp owns and tests itself.

    use super::*;
    use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version, body::Bytes};
    use proxy_core::{CapturedRequest, CapturedResponse, Engine};
    use rmcp::model::ResourceContents;
    use std::sync::Arc;

    fn setup() -> (Arc<Engine>, ProxyServer) {
        let engine = Engine::new();
        let server = ProxyServer::new(engine.clone());
        (engine, server)
    }

    /// Record a proxy request+response and return the flow id.
    fn record(engine: &Engine, uri: &str, body: &str) -> i64 {
        let mut req_headers = HeaderMap::new();
        req_headers.insert("host", "example.com".parse().unwrap());
        let id = engine.record_request(CapturedRequest {
            method: Method::GET,
            uri: uri.parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers: req_headers,
            body: Bytes::new(),
        });

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
        engine.record_response(
            id,
            CapturedResponse {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: resp_headers,
                body: Bytes::from(body.to_string()),
            },
        );
        id as i64
    }

    // --- scope ---

    #[tokio::test]
    async fn scopes_round_trip_and_only_one_is_active() {
        let (_engine, server) = setup();

        let a = server
            .create_scope(Parameters(CreateScopeParams {
                name: "linear".into(),
                activate: Some(true),
            }))
            .await
            .unwrap()
            .0
            .id;
        let b = server
            .create_scope(Parameters(CreateScopeParams {
                name: "google".into(),
                activate: Some(true),
            }))
            .await
            .unwrap()
            .0
            .id;
        assert_ne!(a, b);

        let listed = server.list_scopes().await.unwrap().0.scopes;
        assert_eq!(listed.len(), 2);
        let active: Vec<&ScopeDto> = listed.iter().filter(|s| s.is_active).collect();
        assert_eq!(active.len(), 1, "exactly one scope may be active");
        assert_eq!(active[0].name, "google", "the later activation wins");
    }

    #[tokio::test]
    async fn rules_are_added_listed_disabled_and_deleted() {
        let (_engine, server) = setup();
        server
            .create_scope(Parameters(CreateScopeParams {
                name: "s".into(),
                activate: Some(true),
            }))
            .await
            .unwrap();

        let rule_id = server
            .add_scope_rule(Parameters(AddScopeRuleParams {
                scope_id: None,
                action: None,
                host: Some("*.linear.app".into()),
                host_kind: None,
                port: None,
                path_prefix: None,
            }))
            .await
            .unwrap()
            .0
            .id;

        let listed = server
            .list_scope_rules(Parameters(ListScopeRulesParams { scope_id: None }))
            .await
            .unwrap()
            .0;
        assert_eq!(listed.rules.len(), 1);
        assert_eq!(listed.rules[0].action, "include", "include is the default");
        assert_eq!(listed.rules[0].host_kind, "glob", "glob is the default");
        assert!(listed.rules[0].enabled);

        server
            .set_scope_rule_enabled(Parameters(SetRuleEnabledParams {
                rule_id,
                enabled: false,
            }))
            .await
            .unwrap();
        let listed = server
            .list_scope_rules(Parameters(ListScopeRulesParams { scope_id: None }))
            .await
            .unwrap()
            .0;
        assert!(!listed.rules[0].enabled, "disabled but still present");

        server
            .delete_scope_rule(Parameters(RuleIdParams { rule_id }))
            .await
            .unwrap();
        let listed = server
            .list_scope_rules(Parameters(ListScopeRulesParams { scope_id: None }))
            .await
            .unwrap()
            .0;
        assert!(listed.rules.is_empty());
    }

    /// A pattern that will not compile must be refused when it is added, not
    /// silently dropped later — a dropped *exclude* would widen scope.
    #[tokio::test]
    async fn a_bad_pattern_is_refused() {
        let (_engine, server) = setup();
        server
            .create_scope(Parameters(CreateScopeParams {
                name: "s".into(),
                activate: Some(true),
            }))
            .await
            .unwrap();

        for (host, kind) in [("[unclosed", "regex"), ("not-a-network", "cidr")] {
            let result = server
                .add_scope_rule(Parameters(AddScopeRuleParams {
                    scope_id: None,
                    action: None,
                    host: Some(host.into()),
                    host_kind: Some(kind.into()),
                    port: None,
                    path_prefix: None,
                }))
                .await;
            assert!(result.is_err(), "{kind} {host:?} should be refused");
        }

        let bad_action = server
            .add_scope_rule(Parameters(AddScopeRuleParams {
                scope_id: None,
                action: Some("maybe".into()),
                host: Some("x.test".into()),
                host_kind: None,
                port: None,
                path_prefix: None,
            }))
            .await;
        assert!(bad_action.is_err());
    }

    #[tokio::test]
    async fn check_scope_answers_for_a_url() {
        let (_engine, server) = setup();
        server
            .create_scope(Parameters(CreateScopeParams {
                name: "s".into(),
                activate: Some(true),
            }))
            .await
            .unwrap();
        server
            .add_scope_rule(Parameters(AddScopeRuleParams {
                scope_id: None,
                action: None,
                host: Some("*.linear.app".into()),
                host_kind: None,
                port: None,
                path_prefix: None,
            }))
            .await
            .unwrap();

        let inside = server
            .check_scope(Parameters(CheckScopeParams {
                url: "https://api.linear.app/graphql".into(),
            }))
            .await
            .unwrap()
            .0;
        assert!(inside.in_scope);
        assert_eq!(inside.host, "api.linear.app");
        assert_eq!(inside.port, 443, "the scheme default is resolved");
        assert_eq!(inside.scope.as_deref(), Some("s"));

        let outside = server
            .check_scope(Parameters(CheckScopeParams {
                url: "http://evil.test/".into(),
            }))
            .await
            .unwrap()
            .0;
        assert!(!outside.in_scope);
        assert_eq!(outside.port, 80);
    }

    /// An unanchored regex is the trap the glob default exists to avoid; the
    /// tool has to at least report it truthfully.
    #[tokio::test]
    async fn a_regex_rule_matches_unanchored() {
        let (_engine, server) = setup();
        server
            .create_scope(Parameters(CreateScopeParams {
                name: "s".into(),
                activate: Some(true),
            }))
            .await
            .unwrap();
        server
            .add_scope_rule(Parameters(AddScopeRuleParams {
                scope_id: None,
                action: None,
                host: Some(r"linear\.app".into()),
                host_kind: Some("regex".into()),
                port: None,
                path_prefix: None,
            }))
            .await
            .unwrap();

        let sneaky = server
            .check_scope(Parameters(CheckScopeParams {
                url: "https://evil-linear.app.attacker.test/".into(),
            }))
            .await
            .unwrap()
            .0;
        assert!(
            sneaky.in_scope,
            "documents today's behaviour: regex host rules are not anchored"
        );
    }

    #[tokio::test]
    async fn listing_can_be_narrowed_to_scope() {
        let (engine, server) = setup();
        record(&engine, "https://in.test/a", "x");
        record(&engine, "https://out.test/b", "y");

        let all = server
            .list_flows(Parameters(list_params()))
            .await
            .unwrap()
            .0;
        assert_eq!(all.returned, 2);

        server
            .create_scope(Parameters(CreateScopeParams {
                name: "s".into(),
                activate: Some(true),
            }))
            .await
            .unwrap();
        server
            .add_scope_rule(Parameters(AddScopeRuleParams {
                scope_id: None,
                action: None,
                host: Some("in.test".into()),
                host_kind: None,
                port: None,
                path_prefix: None,
            }))
            .await
            .unwrap();

        // Off by default: a survey must not silently hide traffic.
        let unfiltered = server
            .list_flows(Parameters(list_params()))
            .await
            .unwrap()
            .0;
        assert_eq!(unfiltered.returned, 2);

        let scoped = server
            .list_flows(Parameters(ListFlowsParams {
                in_scope: Some(true),
                ..list_params()
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(scoped.returned, 1);
        assert!(scoped.flows[0].uri.contains("in.test"));
    }

    /// Scope tools with no active scope should say so rather than guessing.
    #[tokio::test]
    async fn scope_calls_without_an_active_scope_are_reported() {
        let (_engine, server) = setup();
        assert!(
            server
                .list_scope_rules(Parameters(ListScopeRulesParams { scope_id: None }))
                .await
                .is_err()
        );
    }

    // --- sending ---

    #[tokio::test]
    async fn send_request_refuses_a_message_with_no_host() {
        let (_engine, server) = setup();
        let result = server
            .send_request(Parameters(SendRequestParams {
                text: "GET /nowhere HTTP/1.1\n\n".into(),
                base_flow_id: None,
            }))
            .await;
        let message = format!("{:?}", result.err().expect("should refuse"));
        assert!(message.contains("no host"), "{message}");
    }

    #[tokio::test]
    async fn send_request_refuses_malformed_text() {
        let (_engine, server) = setup();
        let result = server
            .send_request(Parameters(SendRequestParams {
                text: "GET / HTTP/1.1\nnot-a-header\n\n".into(),
                base_flow_id: None,
            }))
            .await;
        let message = format!("{:?}", result.err().expect("should refuse"));
        assert!(message.contains("does not parse"), "{message}");
    }

    #[tokio::test]
    async fn send_request_reports_an_unknown_base_flow() {
        let (_engine, server) = setup();
        let result = server
            .send_request(Parameters(SendRequestParams {
                text: "GET /a HTTP/1.1\n\n".into(),
                base_flow_id: Some(999),
            }))
            .await;
        assert!(result.is_err());
    }

    // --- formatting ---

    #[tokio::test]
    async fn format_message_indents_a_json_body() {
        let (_engine, server) = setup();
        let out = server
            .format_message(Parameters(FormatMessageParams {
                text: "HTTP/1.1 200 OK\ncontent-type: application/json\n\n{\"b\":1,\"a\":2}".into(),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(out.language, "json");
        assert!(
            out.text.ends_with("{\n  \"b\": 1,\n  \"a\": 2\n}"),
            "{}",
            out.text
        );
        assert!(
            out.text.starts_with("HTTP/1.1 200 OK\n"),
            "the head is left alone: {}",
            out.text
        );
    }

    #[tokio::test]
    async fn format_message_reports_what_it_cannot_format() {
        let (_engine, server) = setup();
        let result = server
            .format_message(Parameters(FormatMessageParams {
                text: "HTTP/1.1 200 OK\n\nplain words".into(),
            }))
            .await;
        assert!(result.is_err());
    }

    /// Park a request on the intercept queue the way the proxy handler does,
    /// and return its ticket. The hold is awaited on a spawned task, so the
    /// queue is populated while the test drives the tools.
    ///
    /// `async`, and yielding through tokio rather than the thread: `#[tokio::test]`
    /// runs a current-thread runtime, so a synchronous spin here would block the
    /// executor the spawned hold needs and deadlock rather than ever seeing it.
    async fn hold_a_request(engine: &Arc<Engine>, uri: &str) -> (u64, tokio::task::JoinHandle<()>) {
        engine.intercept().set_enabled(true);
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        let request = CapturedRequest {
            method: Method::GET,
            uri: uri.parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers,
            body: Bytes::from_static(b"original"),
        };

        let e = engine.clone();
        let task = tokio::spawn(async move {
            let _ = e.intercept().hold_request(1, request).await;
        });
        // Spin until the hold lands rather than sleeping a fixed amount.
        let ticket = loop {
            if let Some(held) = engine.intercept().queue().first() {
                break held.ticket;
            }
            tokio::task::yield_now().await;
        };
        (ticket, task)
    }

    #[tokio::test]
    async fn status_and_set_report_the_intercept_state() {
        let (engine, server) = setup();

        let before = server.intercept_status().await.unwrap().0;
        assert!(!before.enabled, "interception starts off");

        let set = server
            .intercept_set(Parameters(InterceptSetParams {
                enabled: Some(true),
                hold_requests: None,
                hold_responses: None,
            }))
            .await
            .unwrap()
            .0;
        assert!(set.enabled);
        assert!(
            engine.intercept().is_enabled(),
            "engine is the source of truth"
        );

        let off = server
            .intercept_set(Parameters(InterceptSetParams {
                enabled: None,
                hold_responses: Some(false),
                hold_requests: None,
            }))
            .await
            .unwrap()
            .0;
        assert!(!off.holds_responses);
        assert!(off.holds_requests, "the other leg is untouched");
    }

    #[tokio::test]
    async fn a_held_request_is_listed_and_readable_as_wire_text() {
        let (engine, server) = setup();
        let (ticket, task) = hold_a_request(&engine, "https://example.com/a?q=1").await;

        let queue = server
            .intercept_queue(Parameters(InterceptQueueParams { leg: None }))
            .await
            .unwrap()
            .0;
        assert_eq!(queue.count, 1);
        assert_eq!(queue.held[0].leg, "request");
        assert_eq!(queue.held[0].method.as_deref(), Some("GET"));

        let got = server
            .intercept_get(Parameters(TicketParams {
                ticket: ticket as i64,
            }))
            .await
            .unwrap()
            .0;
        assert!(got.text.starts_with("GET /a?q=1 HTTP/1.1"), "{}", got.text);
        assert!(got.text.ends_with("\n\noriginal"), "{}", got.text);

        server
            .intercept_forward(Parameters(InterceptForwardParams {
                ticket: ticket as i64,
                edited: None,
            }))
            .await
            .unwrap();
        task.await.unwrap();
    }

    /// The point of the whole exercise: an agent edits the text and the edit
    /// reaches the wire.
    #[tokio::test]
    async fn an_edited_forward_replaces_the_message() {
        let (engine, server) = setup();
        let (ticket, task) = hold_a_request(&engine, "https://example.com/a").await;

        let answered = server
            .intercept_forward(Parameters(InterceptForwardParams {
                ticket: ticket as i64,
                edited: Some(
                    "POST /changed HTTP/1.1\nhost: example.com\n\nedited body".to_string(),
                ),
            }))
            .await
            .unwrap()
            .0;
        assert!(answered.answered);
        task.await.unwrap();
        assert!(engine.intercept().is_empty());
    }

    /// A malformed edit must be refused *and* leave the item held, so a bad
    /// edit can be retried rather than having silently gone out or been lost.
    #[tokio::test]
    async fn a_malformed_edit_is_rejected_and_the_item_stays_held() {
        let (engine, server) = setup();
        let (ticket, task) = hold_a_request(&engine, "https://example.com/a").await;

        let result = server
            .intercept_forward(Parameters(InterceptForwardParams {
                ticket: ticket as i64,
                edited: Some("GET /x HTTP/1.1\nthis-is-not-a-header\n\n".to_string()),
            }))
            .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a bad edit must not be forwarded"),
        };
        assert!(
            format!("{err:?}").contains("does not parse"),
            "should say why: {err:?}"
        );
        assert_eq!(engine.intercept().len(), 1, "the item must still be held");

        server
            .intercept_forward(Parameters(InterceptForwardParams {
                ticket: ticket as i64,
                edited: None,
            }))
            .await
            .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn an_unknown_ticket_is_reported_rather_than_silently_ignored() {
        let (_engine, server) = setup();

        assert!(
            server
                .intercept_get(Parameters(TicketParams { ticket: 999 }))
                .await
                .is_err()
        );
        // Dropping an unknown ticket is not an error, but it must not claim to
        // have answered something.
        let dropped = server
            .intercept_drop(Parameters(TicketParams { ticket: 999 }))
            .await
            .unwrap()
            .0;
        assert!(!dropped.answered);
    }

    #[tokio::test]
    async fn answer_all_clears_the_queue_and_validates_its_verdict() {
        let (engine, server) = setup();
        let (_t1, task1) = hold_a_request(&engine, "https://example.com/one").await;

        let bad = server
            .intercept_answer_all(Parameters(InterceptAnswerAllParams {
                verdict: "sideways".to_string(),
            }))
            .await;
        assert!(bad.is_err(), "an unknown verdict must not silently forward");
        assert_eq!(engine.intercept().len(), 1, "nothing answered on error");

        let all = server
            .intercept_answer_all(Parameters(InterceptAnswerAllParams {
                verdict: "forward".to_string(),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(all.answered, 1);
        task1.await.unwrap();
    }

    /// An agent and an operator share one queue; a leg filter must not invent
    /// a second view of it.
    #[tokio::test]
    async fn the_leg_filter_is_validated() {
        let (_engine, server) = setup();
        assert!(
            server
                .intercept_queue(Parameters(InterceptQueueParams {
                    leg: Some("sideways".into())
                }))
                .await
                .is_err()
        );
    }

    fn list_params() -> ListFlowsParams {
        ListFlowsParams {
            host: None,
            method: None,
            source: None,
            uri_contains: None,
            status: None,
            include_automate: None,
            offset: None,
            limit: None,
            in_scope: None,
        }
    }

    fn finding_params() -> CreateFindingParams {
        CreateFindingParams {
            title: "t".into(),
            severity: "low".into(),
            status: None,
            description_md: "d".into(),
            cvss_vector: None,
            cvss_score: None,
            cvss_version: None,
            cwe: None,
            repro_md: None,
            impact_md: None,
            remediation_md: None,
            host: None,
            path: None,
            evidence: None,
        }
    }

    #[tokio::test]
    async fn list_flows_hides_automate_unless_asked() {
        let (engine, server) = setup();
        let a = record(&engine, "http://example.com/a", "A");
        let b = record(&engine, "http://example.com/b", "B");
        // Fabricate an Automate-source flow — there is no capture verb for one.
        engine.with_db(|c| {
            c.execute("UPDATE flow SET source = 'automate' WHERE id = ?1", [b])
                .unwrap();
        });

        // Default: automate is hidden.
        let r = server
            .list_flows(Parameters(list_params()))
            .await
            .unwrap()
            .0;
        assert_eq!(r.returned, 1);
        assert_eq!(r.flows[0].id, a);

        // Opt in: both show.
        let mut p = list_params();
        p.include_automate = Some(true);
        assert_eq!(
            server.list_flows(Parameters(p)).await.unwrap().0.returned,
            2
        );

        // Explicit source wins over the default hide.
        let mut p = list_params();
        p.source = Some("automate".into());
        let r = server.list_flows(Parameters(p)).await.unwrap().0;
        assert_eq!(r.returned, 1);
        assert_eq!(r.flows[0].id, b);
    }

    #[tokio::test]
    async fn list_flows_filters_and_clamps() {
        let (engine, server) = setup();
        record(&engine, "http://example.com/keep", "1");
        record(&engine, "http://other.test/skip", "2");

        let mut p = list_params();
        p.uri_contains = Some("keep".into());
        let r = server.list_flows(Parameters(p)).await.unwrap().0;
        assert_eq!(r.returned, 1);
        assert!(r.flows[0].uri.contains("keep"));

        // Over-large limit is clamped, not honoured verbatim.
        let mut p = list_params();
        p.limit = Some(100_000);
        assert_eq!(
            server.list_flows(Parameters(p)).await.unwrap().0.limit,
            MAX_LIMIT
        );
    }

    #[tokio::test]
    async fn get_flow_and_body_resource() {
        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/page", "<h1>hi</h1>");

        let d = server
            .get_flow(Parameters(GetFlowParams {
                id,
                body_offset: None,
                body_limit: None,
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(d.flow.status, Some(200));
        assert!(d.request_headers.iter().any(|h| h.name == "host"));
        assert_eq!(d.response_body.total_len, "<h1>hi</h1>".len() as i64);
        assert_eq!(d.response_body.text.as_deref(), Some("<h1>hi</h1>"));
        assert!(!d.response_body.truncated);

        // Full body as a resource, with mime stripped of the charset.
        let rr = server
            .read_flow_resource(&format!("flow://{id}/response"))
            .unwrap();
        match &rr.contents[0] {
            ResourceContents::TextResourceContents {
                text, mime_type, ..
            } => {
                assert_eq!(text, "<h1>hi</h1>");
                assert_eq!(mime_type.as_deref(), Some("text/html"));
            }
            other => panic!("expected text contents, got {other:?}"),
        }

        // A malformed uri and an unknown flow both error rather than panic.
        assert!(server.read_flow_resource("flow://nope").is_err());
        assert!(server.read_flow_resource("flow://9999/response").is_err());
    }

    #[tokio::test]
    async fn get_flow_missing_is_not_found() {
        let (_engine, server) = setup();
        let err = server
            .get_flow(Parameters(GetFlowParams {
                id: 4242,
                body_offset: None,
                body_limit: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("4242"));
    }

    #[tokio::test]
    async fn annotate_round_trips_and_rejects_empty() {
        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/a", "A");

        let res = server
            .annotate_flow(Parameters(AnnotateFlowParams {
                id,
                comment: Some("look here".into()),
                highlight: Some("red".into()),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(res.rows_changed, 1);

        let r = server
            .list_flows(Parameters(list_params()))
            .await
            .unwrap()
            .0;
        let f = r.flows.iter().find(|f| f.id == id).unwrap();
        assert_eq!(f.comment.as_deref(), Some("look here"));
        assert_eq!(f.highlight.as_deref(), Some("red"));

        // Nothing to set is a caller error, not a silent 0-row no-op.
        let err = server
            .annotate_flow(Parameters(AnnotateFlowParams {
                id,
                comment: None,
                highlight: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("comment or a highlight"));
    }

    #[tokio::test]
    async fn create_finding_round_trips_with_evidence() {
        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/vuln", "boom");

        let mut p = finding_params();
        p.title = "Reflected XSS".into();
        p.severity = "high".into();
        p.evidence = Some(vec![EvidenceInput {
            flow_id: id,
            label: Some("poc".into()),
        }]);
        let out = server.create_finding(Parameters(p)).await.unwrap().0;

        let g = server
            .get_finding(Parameters(GetFindingParams { id: out.id }))
            .await
            .unwrap()
            .0;
        assert_eq!(g.title, "Reflected XSS");
        assert_eq!(g.severity, "high");
        assert_eq!(g.status, "draft"); // defaulted
        assert_eq!(g.evidence.len(), 1);
        assert_eq!(g.evidence[0].flow_id, id);

        assert_eq!(server.list_findings().await.unwrap().0.findings.len(), 1);
    }

    #[tokio::test]
    async fn create_finding_validates_inputs() {
        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/a", "A");

        let mut bad_sev = finding_params();
        bad_sev.severity = "spicy".into();
        let err = server
            .create_finding(Parameters(bad_sev))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("invalid severity"));

        let mut bad_status = finding_params();
        bad_status.status = Some("vibing".into());
        let err = server
            .create_finding(Parameters(bad_status))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("invalid status"));

        // A dangling evidence id is caught up front, not as an opaque write error.
        let mut bad_ev = finding_params();
        bad_ev.evidence = Some(vec![EvidenceInput {
            flow_id: id + 999,
            label: None,
        }]);
        let err = server
            .create_finding(Parameters(bad_ev))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("does not exist"));

        // Nothing was written by the rejected calls.
        assert!(server.list_findings().await.unwrap().0.findings.is_empty());
    }

    #[tokio::test]
    async fn resend_refuses_out_of_scope() {
        use proxy_core::scope::{self, Action, HostKind, RuleSpec};

        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/x", "x");

        // Active scope includes only other.com, so example.com is out of scope.
        engine.with_db(|c| {
            let sid = scope::create_scope(c, "s").unwrap();
            scope::add_rule(
                c,
                sid,
                Action::Include,
                &RuleSpec::host(HostKind::Glob, "other.com"),
                None,
            )
            .unwrap();
            scope::set_active(c, sid).unwrap();
        });

        let err = server
            .resend_flow(Parameters(ResendFlowParams { id }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.message.contains("scope"),
            "message was: {}",
            err.message
        );
    }

    #[test]
    fn server_info_advertises_tools_and_resources() {
        let (_engine, server) = setup();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "proxy-mcp");
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_some());

        let templates = resource_templates();
        assert_eq!(templates.len(), 2);
        assert!(
            templates
                .iter()
                .any(|t| t.uri_template == "flow://{id}/request")
        );
    }
}
