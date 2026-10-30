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

use lockgate_core::{
    Engine, FlowQuery, Held, NewFinding, NewIdentity, Pending, ResendError, Side, http_text,
};
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
    BodyPreview, FindingDto, FlowDetailDto, FlowDto, IdentityDto, LeadDto, MaterialisedFileDto,
    NoteDto, SitemapNodeDto, detail_headers, encode_bytes,
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

// --- websockets ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct FlowIdParams {
    pub flow_id: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct WsMessageDto {
    /// Order on the socket, from 0.
    pub seq: i64,
    /// "c2s" (client to server) or "s2c".
    pub direction: String,
    /// "text", "binary", "ping", "pong" or "close".
    pub opcode: String,
    pub sent_at: i64,
    pub len: i64,
    /// The payload as text when it is valid UTF-8, base64 otherwise.
    pub text: Option<String>,
    pub base64: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListWsMessagesResult {
    pub flow_id: i64,
    pub count: i64,
    pub messages: Vec<WsMessageDto>,
}

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
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    /// The request as raw wire text: start line, headers, blank line, body —
    /// the same shape intercept_get returns.
    pub text: String,
    /// A flow to resolve scheme and authority against, for when the start line
    /// carries an origin-form target like `/path`. Omit only if the start line
    /// has an absolute URL or the text has a Host header.
    pub base_flow_id: Option<i64>,
    /// Send *as* an identity: that identity's cookie jar replaces whatever
    /// Cookie header the text carries. Scope still gates the send.
    pub as_identity: Option<i64>,
    /// Label the recorded flow with what this send was *for* — the lead or
    /// question it answers. list_flows filters on it exactly.
    pub tag: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct SendRequestResult {
    /// The target this send hit.
    pub target: String,
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
/// Every target this server instance runs: a name and its live engine. One
/// process serves all of them; each keeps its own project database, scope,
/// policy and identity set, so a target's floor never leaks into another's.
#[derive(Clone)]
pub struct Targets {
    pub engines: Vec<(String, Arc<Engine>)>,
}

impl Targets {
    /// The single-target shape every pre-multi-target caller means.
    pub fn single(name: &str, engine: Arc<Engine>) -> Arc<Self> {
        Arc::new(Self {
            engines: vec![(name.to_string(), engine)],
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<Engine>> {
        self.engines
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.clone())
    }

    pub fn first(&self) -> (String, Arc<Engine>) {
        self.engines[0].clone()
    }

    pub fn names(&self) -> Vec<String> {
        self.engines.iter().map(|(n, _)| n.clone()).collect()
    }
}

pub struct ProxyServer {
    targets: Arc<Targets>,
    /// This *session's* target. Per session, not global: two agents driving
    /// the same MCP server can work two targets at once without stomping
    /// each other. Defaults to the first target.
    selected: std::sync::Mutex<String>,
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
    /// Exact tag match — the label a send carried (`lead:idor-3`). This is how
    /// agent traffic is grouped by the question that produced it.
    pub tag: Option<String>,
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
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    /// The flow to replay. Its request is sent straight at the target and the
    /// fresh response is summarised here; the replay is recorded as a new flow.
    pub id: i64,
    /// Send it *as* an identity: that identity's cookie jar replaces the
    /// request's, so the replay is what that session would have sent — the
    /// access-control primitive. Replay the same request under two identities
    /// and diff the answers. Scope still gates the send.
    pub as_identity: Option<i64>,
    /// Label this replay with what it was *for* — `lead:idor-3`, `verify-cors`.
    /// list_flows filters on it exactly, so evidence can be grouped by the
    /// question that produced it.
    pub tag: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ResendFlowResult {
    /// The target this replay hit.
    pub target: String,
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
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
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
    pub target: String,
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

/// A revision to an existing finding. Every field is optional; omitting one
/// leaves that column exactly as it is.
///
/// Clearing is by empty string rather than by `null`, deliberately: a client
/// that serialises absent fields as `null` — plenty do — would otherwise wipe
/// every column it did not mention. `""` can only be sent on purpose.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct UpdateFindingParams {
    pub id: i64,
    /// Omit to leave the title alone. Must not be empty.
    pub title: Option<String>,
    /// info | low | medium | high | critical.
    pub severity: Option<String>,
    /// draft | confirmed | false_positive | reported | fixed | wont_fix.
    pub status: Option<String>,
    /// Replaces the whole description when given — get_finding first if you
    /// mean to append.
    pub description_md: Option<String>,
    /// Empty string clears the section.
    pub repro_md: Option<String>,
    /// Empty string clears the section.
    pub impact_md: Option<String>,
    /// Empty string clears the section.
    pub remediation_md: Option<String>,
    /// Empty string clears the CVSS vector *and* its score and version — a
    /// score without the vector it was computed from is not a rating anyone can
    /// check.
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    /// Empty string clears it.
    pub cwe: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateNoteParams {
    pub title: String,
    /// Markdown. May be empty — a note often starts as a title and grows.
    pub body_md: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct CreateNoteResult {
    pub id: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListNotesResult {
    pub notes: Vec<NoteDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct NoteIdParams {
    pub id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct UpdateNoteParams {
    pub id: i64,
    /// Omit to leave the title as it is.
    pub title: Option<String>,
    /// Omit to leave the body as it is. Replaces the whole body when given —
    /// read the note first if you mean to append.
    pub body_md: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct RowsChangedResult {
    /// 0 means nothing with that id.
    pub rows_changed: u64,
}

// --- identities ---

/// One cookie supplied to create/update an identity. Values are accepted here
/// (how else would a jar be built) and never reported back — reads return
/// names, scopes and lengths only.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct CookieInput {
    pub name: String,
    pub value: String,
    /// The host (or parent domain) the cookie applies to. Defaults to the
    /// identity's host when omitted there too — a jar then scoped entirely by
    /// the host column.
    pub domain: Option<String>,
    /// Default "/".
    pub path: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateIdentityParams {
    /// A unique name — what `as_identity` takes. Name it for the role, not the
    /// target: "admin", "user", "acme-user".
    pub name: String,
    /// The host the session belongs to. When set, replays are only offered the
    /// jar for that host (per-cookie domains still scope the individual
    /// cookies).
    pub host: Option<String>,
    #[serde(default)]
    pub cookies: Vec<CookieInput>,
    /// A base32 TOTP seed, when the login demands one — the code the agent
    /// would need to re-derive at re-login. Store the *secret*, not a code.
    pub totp_secret: Option<String>,
    pub note: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct IdentityIdParams {
    pub identity_id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct UpdateIdentityParams {
    pub identity_id: i64,
    /// Omit to leave as is. Must stay unique.
    pub name: Option<String>,
    /// Omit to leave as is; "" clears the host binding.
    pub host: Option<String>,
    /// Omit to leave as is; "" clears the secret.
    pub totp_secret: Option<String>,
    /// Omit to leave as is; "" clears it.
    pub note: Option<String>,
    /// When given, replaces the whole jar. Omit to leave it alone.
    pub cookies: Option<Vec<CookieInput>>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AdoptSessionParams {
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    /// A flow that shows the session — ideally one captured right after login,
    /// so the response's Set-Cookie headers are on it.
    pub flow_id: i64,
    /// Name for the new identity.
    pub name: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListIdentitiesResult {
    pub identities: Vec<IdentityDto>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct IdentityIdResult {
    pub identity_id: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct AdoptSessionResult {
    pub target: String,
    pub identity_id: i64,
    pub cookie_count: i64,
    /// The host the session was captured on — now the identity's binding.
    pub host: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct BrowserEnsureResult {
    /// The endpoint a browser client attaches to, e.g. http://127.0.0.1:9222.
    pub cdp_url: String,
    /// True when this call launched Chrome; false when one already listened.
    pub spawned: bool,
    /// The user-data-dir the browser carries its sessions in.
    pub profile: String,
    pub binary: String,
    /// Headless (a VPS, or explicitly asked) — pages render, no window shows.
    pub headless: bool,
}

// --- policy ---

#[derive(Serialize, schemars::JsonSchema)]
pub struct PolicyRuleDto {
    pub id: i64,
    /// Today only `forbid_url_regex`.
    pub kind: String,
    pub pattern: String,
    pub note: Option<String>,
    pub enabled: bool,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct GetPolicyResult {
    /// Max sends per second per host on the replay path. Null = unlimited.
    pub rate_per_sec: Option<f64>,
    pub note: Option<String>,
    pub rules: Vec<PolicyRuleDto>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SetRateLimitParams {
    /// Max sends per second per host on the replay path — the pace an agent's
    /// fuzz loop may hold. `0` lifts the ceiling. Applies to every send path:
    /// TUI, resend_flow, send_request.
    pub per_host_per_sec: f64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AddPolicyRuleParams {
    /// Only `forbid_url_regex` today. The pattern is matched unanchored —
    /// write `^…$` when you mean exact.
    pub kind: Option<String>,
    /// URLs matching this are refused before anything leaves, in every send
    /// path. This is the out-of-bounds list: r"^https://target\.com/pay",
    /// r"tenant_b\.".
    pub pattern: String,
    /// Why it exists — future-you reads this.
    pub note: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct PolicyIdResult {
    pub rule_id: i64,
}

// --- leads ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateLeadParams {
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    /// idor | authz | ratelimit | injection | logic | config | exposure | other
    pub kind: String,
    pub title: String,
    /// Why this looks worth a probe: the observation, the mechanism you
    /// suspect, what an attacker with the stated position could do.
    pub rationale_md: String,
    /// The URL the lead concerns.
    pub endpoint: Option<String>,
    /// The flow that inspired it, when there is one.
    pub flow_id: Option<i64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListLeadsParams {
    /// Only leads in this status. Omit for all.
    pub status: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListLeadsResult {
    pub leads: Vec<LeadDto>,
}

/// A lead mutation's echo: which target was hit, and the lead after the write
/// — so a transcript is self-describing about both.
#[derive(Serialize, schemars::JsonSchema)]
pub struct LeadMutationResult {
    pub target: String,
    #[serde(flatten)]
    pub lead: LeadDto,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct LeadIdResult {
    pub target: String,
    pub lead_id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct LeadIdParams {
    pub lead_id: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct UpdateLeadParams {
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    pub lead_id: i64,
    /// proposed | verifying | verified | refuted | reported. Settling on
    /// verified/refuted requires the verdict and control below — a conclusion
    /// without the discriminating check is refused, in code.
    pub status: Option<String>,
    /// What actually happened when you probed it.
    pub verdict: Option<String>,
    /// The baseline-vs-exploit check that discriminates bug from intended
    /// behaviour ("same request, tenant B's id: 200 vs 403").
    pub control: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AdjudicateLeadParams {
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    pub lead_id: i64,
    /// admissible | refuted
    pub ruling: String,
    /// Why — a ruling without its why is a vote.
    pub ruling_reason: String,
}

// --- targets ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct TargetNameParams {
    /// Exact target name, as list_targets shows.
    pub name: String,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct TargetDto {
    pub name: String,
    /// True for this session's target.
    pub active: bool,
    pub findings: i64,
    pub critical: i64,
    pub high: i64,
    /// Leads in proposed/verifying — work in flight.
    pub open_leads: i64,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ListTargetsResult {
    pub targets: Vec<TargetDto>,
}

// --- materialise / report / scan ---

#[derive(Deserialize, schemars::JsonSchema)]
pub struct MaterialiseParams {
    /// Directory to write the index into. Created if absent; the files it
    /// owns are replaced. Relative paths resolve against the process cwd.
    pub dir: String,
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct MaterialiseResult {
    pub dir: String,
    pub files: Vec<MaterialisedFileDto>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ReportResult {
    /// The full engagement as one markdown document: findings by severity
    /// with their evidence, then the leads ledger with verdicts and rulings.
    pub markdown: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ScanFlowsParams {
    /// Which target this call acts on. Wins over this session's set_target;
    /// omit to use the session's selection. The result echoes the target hit.
    pub target: Option<String>,
    /// How many of the most recent flows to scan. Default 500, capped 5000.
    pub limit: Option<i64>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ScanResult {
    pub target: String,
    pub scanned: i64,
    /// New draft findings filed (deduplicated per rule+host).
    pub filed: i64,
}

#[tool_router]
impl ProxyServer {
    pub fn new(targets: Arc<Targets>) -> Self {
        let selected = targets.first().0;
        Self {
            targets,
            selected: std::sync::Mutex::new(selected),
            tool_router: Self::tool_router(),
        }
    }

    /// The engine this session is currently working on. A missing selection
    /// (a target deleted out from under a long session) falls back to the
    /// first target rather than erroring mid-run.
    fn engine(&self) -> Arc<Engine> {
        let name = self.selected.lock().unwrap().clone();
        self.targets
            .get(&name)
            .or_else(|| self.targets.get(&self.targets.first().0))
            .expect("targets is never empty")
    }

    fn target_name(&self) -> String {
        self.selected.lock().unwrap().clone()
    }

    /// Which target a call lands on: an explicit `target` argument wins, else
    /// this session's `set_target` selection. Every action tool resolves
    /// through here and echoes the resolved name in its result, so a
    /// transcript always says what hit what.
    fn resolve(&self, explicit: Option<&str>) -> Result<(String, Arc<Engine>), ErrorData> {
        match explicit {
            Some(name) => self
                .targets
                .get(name)
                .map(|e| (name.to_string(), e))
                .ok_or_else(|| {
                    ErrorData::resource_not_found(
                        format!(
                            "no target \u{201c}{name}\u{201d} — list_targets shows what \
                             this server runs"
                        ),
                        None,
                    )
                }),
            None => {
                let name = self.target_name();
                let engine = self.engine();
                Ok((name, engine))
            }
        }
    }

    #[tool(
        description = "List the targets this lockgate server runs, with per-target counts.                        One is marked active — the one this session's tools operate on.                        Switch with set_target."
    )]
    async fn list_targets(&self) -> Result<Json<ListTargetsResult>, ErrorData> {
        let active = self.target_name();
        let targets = self
            .targets
            .engines
            .iter()
            .map(|(name, engine)| {
                let findings = engine.list_findings();
                let (critical, high) = findings.iter().fold((0, 0), |(c, h), f| {
                    (
                        c + (f.severity == "critical") as i64,
                        h + (f.severity == "high") as i64,
                    )
                });
                TargetDto {
                    name: name.clone(),
                    active: name == &active,
                    findings: findings.len() as i64,
                    critical,
                    high,
                    open_leads: engine
                        .leads(None)
                        .into_iter()
                        .filter(|l| matches!(l.status.as_str(), "proposed" | "verifying"))
                        .count() as i64,
                }
            })
            .collect();
        Ok(Json(ListTargetsResult { targets }))
    }

    #[tool(
        description = "Point this session's tools at a target. Per session: another agent                        driving the same server keeps its own selection. The switch is                        remembered for list_flows, send, leads, findings, notes — everything."
    )]
    async fn set_target(
        &self,
        Parameters(p): Parameters<TargetNameParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        if self.targets.get(&p.name).is_none() {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no target “{}” — list_targets shows what this server runs",
                    p.name
                ),
                None,
            ));
        }
        *self.selected.lock().unwrap() = p.name;
        Ok(Json(OkResult { ok: true }))
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
            tag: p.tag,
            include_automate: p.include_automate.unwrap_or(false),
        };
        // Scope cannot be pushed into SQL — the patterns are globs, regexes and
        // CIDR blocks — so the scoped path filters in Rust and pages the
        // results it keeps.
        let rows = if p.in_scope.unwrap_or(false) {
            self.engine().query_flows_in_scope(&query, offset, limit)
        } else {
            self.engine().query_flows(&query, offset, limit)
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
            .engine()
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
            .engine()
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
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let resent = engine
            .resend_as(p.id as u64, p.as_identity, p.tag)
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
            target,
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
        self.engine().active_scope().map(|s| s.id).ok_or_else(|| {
            ErrorData::invalid_params(
                "no active scope — pass scope_id, or create one with create_scope",
                None,
            )
        })
    }

    #[tool(
        description = "List the WebSocket frames on a flow, oldest first. A flow is a \
                       WebSocket if its status is 101; the frames are the conversation \
                       that followed the upgrade. Frames are observed, not intercepted."
    )]
    async fn list_ws_messages(
        &self,
        Parameters(p): Parameters<FlowIdParams>,
    ) -> Result<Json<ListWsMessagesResult>, ErrorData> {
        let messages: Vec<WsMessageDto> = self
            .engine()
            .ws_messages(p.flow_id as u64)
            .into_iter()
            .map(|m| {
                let (text, base64) = encode_bytes(&m.payload);
                WsMessageDto {
                    seq: m.seq,
                    direction: m.direction,
                    opcode: m.opcode,
                    sent_at: m.sent_at,
                    len: m.payload.len() as i64,
                    text,
                    base64,
                }
            })
            .collect();
        Ok(Json(ListWsMessagesResult {
            flow_id: p.flow_id,
            count: messages.len() as i64,
            messages,
        }))
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
            .engine()
            .scopes()
            .into_iter()
            .map(|s| ScopeDto {
                rule_count: self.engine().scope_rules(s.id).len() as i64,
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
        let id = self.engine().create_scope(name).map_err(scope_error)?;
        if p.activate.unwrap_or(false) {
            self.engine().set_active_scope(id).map_err(scope_error)?;
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
        self.engine()
            .delete_scope(p.scope_id)
            .map_err(scope_error)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Make a scope the active one.")]
    async fn set_active_scope(
        &self,
        Parameters(p): Parameters<ScopeIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine()
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
            .engine()
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
            "include" => lockgate_core::scope::Action::Include,
            "exclude" => lockgate_core::scope::Action::Exclude,
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
                    "glob" => lockgate_core::scope::HostKind::Glob,
                    "regex" => lockgate_core::scope::HostKind::Regex,
                    "cidr" => lockgate_core::scope::HostKind::Cidr,
                    other => {
                        return Err(ErrorData::invalid_params(
                            format!("host_kind must be glob|regex|cidr, got {other:?}"),
                            None,
                        ));
                    }
                };
                lockgate_core::scope::RuleSpec::host(kind, host.clone())
            }
            None => lockgate_core::scope::RuleSpec::default(),
        };
        if let Some(port) = p.port {
            spec = spec.with_port(port);
        }
        if let Some(prefix) = &p.path_prefix {
            spec = spec.with_path_prefix(prefix.clone());
        }

        let id = self
            .engine()
            .add_scope_rule(scope_id, action, &spec)
            .map_err(scope_error)?;
        Ok(Json(ScopeIdResult { id }))
    }

    #[tool(description = "Delete one scope rule.")]
    async fn delete_scope_rule(
        &self,
        Parameters(p): Parameters<RuleIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.engine()
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
        self.engine()
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
            .engine()
            .scope_matcher()
            .matches(&lockgate_core::scope::Target {
                host: &host,
                port,
                path: &path,
            });
        Ok(Json(CheckScopeResult {
            in_scope,
            host,
            port,
            path,
            scope: self.engine().active_scope().map(|s| s.name),
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
                    .engine()
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

        let (target, engine) = self.resolve(p.target.as_deref())?;
        let started = std::time::Instant::now();
        let sent = engine
            .send_request(
                request,
                p.base_flow_id.map(|id| id as u64),
                p.as_identity,
                p.tag,
            )
            .await
            .map_err(resend_error)?;
        let millis = started.elapsed().as_millis() as i64;

        Ok(Json(SendRequestResult {
            target,
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
        let (text, language) = lockgate_core::pretty::pretty_message(&p.text)
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
        let engine = self.engine();
        let i = engine.intercept();
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
        let engine = self.engine();
        let i = engine.intercept();
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
        let engine = self.engine();
        let i = engine.intercept();
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
            .engine()
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
                    .engine()
                    .intercept()
                    .get(ticket)
                    .ok_or_else(|| unknown_ticket(p.ticket))?;
                Some(reparse(&held.pending, &text).map_err(|e| {
                    ErrorData::invalid_params(format!("edited message does not parse: {e}"), None)
                })?)
            }
        };
        Ok(Json(AnsweredResult {
            answered: self.engine().intercept().forward(ticket, edited),
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
            answered: self.engine().intercept().discard(p.ticket as u64),
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
        let engine = self.engine();
        let i = engine.intercept();
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
            .engine()
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
            if self.engine().flow_detail(e.flow_id).is_none() {
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
            // A tool-filed finding is the operator's (or agent's) word —
            // `workflow` is reserved for what the passive scanner raises.
            origin: "manual".to_string(),
        };
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let id = engine.create_finding(finding).await.map_err(write_error)?;
        Ok(Json(CreateFindingResult { id, target }))
    }

    #[tool(description = "List every finding recorded in this project, newest first.")]
    async fn list_findings(&self) -> Result<Json<ListFindingsResult>, ErrorData> {
        let findings = self
            .engine()
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
        self.engine()
            .get_finding(p.id)
            .map(|f| Json(FindingDto::from(f)))
            .ok_or_else(|| ErrorData::resource_not_found(format!("no finding #{}", p.id), None))
    }

    #[tool(
        description = "Revise a finding: triage it, or rewrite any part of the write-up as you \
                       learn more. Omitted fields are left alone; a given markdown field replaces \
                       that whole section, so get_finding first if you mean to append. Pass an \
                       empty string to clear an optional field. Evidence flows cannot be changed \
                       here — file the finding with the evidence it needs."
    )]
    async fn update_finding(
        &self,
        Parameters(p): Parameters<UpdateFindingParams>,
    ) -> Result<Json<RowsChangedResult>, ErrorData> {
        // Same vocabularies as create_finding, and validated for the same
        // reason: the columns are free text with no DB CHECK, so a typo'd
        // severity persists silently and skews every later filter.
        let severity = p
            .severity
            .as_deref()
            .map(|s| validate_one("severity", s, SEVERITIES))
            .transpose()?;
        let status = p
            .status
            .as_deref()
            .map(|s| validate_one("status", s, STATUSES))
            .transpose()?;
        if p.title.as_deref().is_some_and(|t| t.trim().is_empty()) {
            return Err(ErrorData::invalid_params("title must not be empty", None));
        }

        // Empty means clear; anything else is the new value.
        let clearable = |field: Option<String>| field.map(|v| (!v.is_empty()).then_some(v));

        // The score and version describe the vector, so clearing it clears
        // them. Without this a finding could keep a 9.8 whose vector is gone.
        let cleared_cvss = p.cvss_vector.as_deref() == Some("");
        let cvss_score = match (cleared_cvss, p.cvss_score) {
            (true, _) => Some(None),
            (false, score) => score.map(Some),
        };
        let cvss_version = if cleared_cvss {
            Some(None)
        } else {
            clearable(p.cvss_version)
        };

        let edit = lockgate_core::FindingEdit {
            title: p.title,
            severity,
            status,
            description_md: p.description_md,
            repro_md: clearable(p.repro_md),
            impact_md: clearable(p.impact_md),
            remediation_md: clearable(p.remediation_md),
            cvss_vector: clearable(p.cvss_vector),
            cvss_score,
            cvss_version,
            cwe: clearable(p.cwe),
        };
        if edit.is_empty() {
            return Err(ErrorData::invalid_params(
                "give at least one field to change",
                None,
            ));
        }

        let rows = self.engine().update_finding(p.id, &edit);
        Ok(Json(RowsChangedResult {
            rows_changed: rows as u64,
        }))
    }

    #[tool(
        description = "Start a project note: a free markdown document (how the auth flow works, \
                       what to try next). For a scribble on one flow use annotate_flow instead. \
                       Returns the new note id."
    )]
    async fn create_note(
        &self,
        Parameters(p): Parameters<CreateNoteParams>,
    ) -> Result<Json<CreateNoteResult>, ErrorData> {
        let title = p.title.trim();
        if title.is_empty() {
            return Err(ErrorData::invalid_params("title must not be empty", None));
        }
        let id = self
            .engine()
            .create_note(lockgate_core::NewNote {
                title: title.to_string(),
                body_md: p.body_md.unwrap_or_default(),
            })
            .await
            .map_err(write_error)?;
        Ok(Json(CreateNoteResult { id }))
    }

    #[tool(description = "List every note in this project, newest first, with full bodies.")]
    async fn list_notes(&self) -> Result<Json<ListNotesResult>, ErrorData> {
        let notes = self
            .engine()
            .list_notes()
            .into_iter()
            .map(NoteDto::from)
            .collect();
        Ok(Json(ListNotesResult { notes }))
    }

    #[tool(description = "Get one note by id.")]
    async fn get_note(
        &self,
        Parameters(p): Parameters<NoteIdParams>,
    ) -> Result<Json<NoteDto>, ErrorData> {
        self.engine()
            .get_note(p.id)
            .map(|n| Json(NoteDto::from(n)))
            .ok_or_else(|| ErrorData::resource_not_found(format!("no note #{}", p.id), None))
    }

    #[tool(
        description = "Edit a note. Omitted fields are left alone; a given body_md replaces the \
                       whole body, so read the note first if you mean to append."
    )]
    async fn update_note(
        &self,
        Parameters(p): Parameters<UpdateNoteParams>,
    ) -> Result<Json<RowsChangedResult>, ErrorData> {
        if p.title.is_none() && p.body_md.is_none() {
            return Err(ErrorData::invalid_params(
                "give at least one of title or body_md",
                None,
            ));
        }
        if p.title.as_deref().is_some_and(|t| t.trim().is_empty()) {
            return Err(ErrorData::invalid_params("title must not be empty", None));
        }
        let rows = self
            .engine()
            .update_note(p.id, p.title.as_deref(), p.body_md.as_deref());
        Ok(Json(RowsChangedResult {
            rows_changed: rows as u64,
        }))
    }

    #[tool(description = "Delete a note by id.")]
    async fn delete_note(
        &self,
        Parameters(p): Parameters<NoteIdParams>,
    ) -> Result<Json<RowsChangedResult>, ErrorData> {
        let rows = self.engine().delete_note(p.id);
        Ok(Json(RowsChangedResult {
            rows_changed: rows as u64,
        }))
    }

    // --- identities ---
    //
    // Named session jars a replay can be sent as. Values never leave this
    // crate's core: reads report cookie names, scopes and lengths, so a
    // transcript stays free of live credentials by construction.

    #[tool(
        description = "List session identities — named cookie jars a replay can be sent as \
                       (as_identity on resend_flow / send_request). Cookie values are never \
                       returned, only names, domains and lengths."
    )]
    async fn list_identities(&self) -> Result<Json<ListIdentitiesResult>, ErrorData> {
        let identities = self
            .engine()
            .identities()
            .into_iter()
            .map(IdentityDto::from)
            .collect();
        Ok(Json(ListIdentitiesResult { identities }))
    }

    #[tool(
        description = "Create a session identity from a hand-supplied cookie jar. Prefer \
                       adopt_flow_session: log in through the proxy once and adopt a captured \
                       flow — it needs no secret pasted anywhere."
    )]
    async fn create_identity(
        &self,
        Parameters(p): Parameters<CreateIdentityParams>,
    ) -> Result<Json<IdentityIdResult>, ErrorData> {
        let name = p.name.trim().to_string();
        if name.is_empty() {
            return Err(ErrorData::invalid_params("name must not be empty", None));
        }
        let host = p.host.as_deref().map(str::trim).filter(|h| !h.is_empty());
        let mut cookies = Vec::new();
        for c in &p.cookies {
            cookies.push(cookie_input(host, c).map_err(|e| ErrorData::invalid_params(e, None))?);
        }
        let new = NewIdentity {
            name,
            host: host.map(str::to_string),
            totp_secret: p.totp_secret.clone().filter(|s| !s.is_empty()),
            note: p.note.clone().filter(|s| !s.is_empty()),
            cookies,
        };
        let id = self
            .engine()
            .create_identity(&new)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        Ok(Json(IdentityIdResult { identity_id: id }))
    }

    #[tool(
        description = "Edit an identity: rename, rebind its host, set or clear the TOTP \
                       secret, or replace the whole cookie jar. Omitted fields are left \
                       alone; an empty string clears a nullable one. Cookie values are \
                       never returned, so there is nothing to re-read first."
    )]
    async fn update_identity(
        &self,
        Parameters(p): Parameters<UpdateIdentityParams>,
    ) -> Result<Json<RowsChangedResult>, ErrorData> {
        // A jar replacement resolves each cookie's default domain against the
        // identity's host — which is either the one given here or the current
        // binding.
        let mut host = p
            .host
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if host.is_none() {
            host = self.engine().identity(p.identity_id).and_then(|i| i.host);
        }
        let cookies = match &p.cookies {
            None => None,
            Some(list) => {
                let mut out = Vec::new();
                for c in list {
                    let host = host.as_deref();
                    out.push(
                        cookie_input(host, c).map_err(|e| ErrorData::invalid_params(e, None))?,
                    );
                }
                Some(out)
            }
        };
        let edit = lockgate_core::IdentityEdit {
            name: p
                .name
                .clone()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            host: p.host.clone(),
            totp_secret: p.totp_secret.clone(),
            note: p.note.clone(),
            cookies,
        };
        let rows = self
            .engine()
            .update_identity(p.identity_id, &edit)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        if rows == 0 {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no identity #{} — list_identities shows what exists",
                    p.identity_id
                ),
                None,
            ));
        }
        Ok(Json(RowsChangedResult {
            rows_changed: rows as u64,
        }))
    }

    #[tool(description = "Delete an identity and its cookie jar.")]
    async fn delete_identity(
        &self,
        Parameters(p): Parameters<IdentityIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        let rows = self.engine().delete_identity(p.identity_id);
        if rows == 0 {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no identity #{} — list_identities shows what exists",
                    p.identity_id
                ),
                None,
            ));
        }
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Mint an identity from a captured flow's session: the flow's request \
                       Cookie header merged with its response Set-Cookie headers (response \
                       wins). This is how the operator's manual login becomes something the \
                       agent can replay as — pick a flow captured right after login. Refuses \
                       a flow that carries no cookies."
    )]
    async fn adopt_flow_session(
        &self,
        Parameters(p): Parameters<AdoptSessionParams>,
    ) -> Result<Json<AdoptSessionResult>, ErrorData> {
        let name = p.name.trim();
        if name.is_empty() {
            return Err(ErrorData::invalid_params("name must not be empty", None));
        }
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let id = engine.adopt_identity_from_flow(p.flow_id as u64, name);
        match id {
            Ok(id) => {
                let identity = engine.identity(id);
                let (count, host) = match &identity {
                    Some(i) => (i.cookies.len() as i64, i.host.clone()),
                    None => (0, None),
                };
                Ok(Json(AdoptSessionResult {
                    target,
                    identity_id: id,
                    cookie_count: count,
                    host,
                }))
            }
            Err(e) => Err(match e {
                lockgate_core::AdoptError::NotFound(id) => {
                    ErrorData::resource_not_found(format!("no flow #{id}"), None)
                }
                lockgate_core::AdoptError::NoSession => ErrorData::invalid_params(
                    "the flow carries no cookies — capture one from after a login",
                    None,
                ),
                lockgate_core::AdoptError::DuplicateName(name) => ErrorData::invalid_params(
                    format!("an identity named “{name}” already exists — pick another name"),
                    None,
                ),
                lockgate_core::AdoptError::Db(e) => {
                    ErrorData::internal_error(format!("adopt failed: {e}"), None)
                }
            }),
        }
    }

    #[tool(
        description = "Make sure a CDP Chrome with a persistent profile is running, so a \
                       browser client can attach to it (e.g. Playwright MCP with \
                       --cdp-endpoint). Idempotent: returns at once when something already \
                       listens. The profile carries the operator's logged-in sessions, so \
                       pages served to this browser are seen as the operator — treat it as \
                       the identity-bearing browser and drive it gently. Leaves Chrome \
                       running when lockgate exits."
    )]
    async fn browser_ensure(&self) -> Result<Json<BrowserEnsureResult>, ErrorData> {
        let cfg = lockgate_core::browser::CdpConfig::from_env();
        match lockgate_core::browser::ensure(&cfg).await {
            Ok(status) => Ok(Json(BrowserEnsureResult {
                cdp_url: status.cdp_url,
                spawned: !status.already_running,
                profile: status.profile.display().to_string(),
                binary: status.binary.display().to_string(),
                headless: status.headless,
            })),
            Err(e) => Err(ErrorData::internal_error(e.to_string(), None)),
        }
    }

    // --- policy ---
    //
    // The guardrails, as data the engine enforces on every send. Managing them
    // over MCP is deliberate: the agent can *read* the floor it stands on, and
    // the operator can draw it without touching a config file.

    #[tool(
        description = "Get the engagement's guardrails: the per-host send-rate ceiling and \
                       the forbidden-URL rules. Enforced in the engine on every send path — \
                       a refused URL never reaches the wire. Empty policy is permissive; \
                       drawing it is how the operator bounds an agent's free hand."
    )]
    async fn get_policy(&self) -> Result<Json<GetPolicyResult>, ErrorData> {
        let p = self.engine().policy();
        let rules = self
            .engine()
            .policy_rules()
            .into_iter()
            .map(|r| PolicyRuleDto {
                id: r.id,
                kind: r.kind,
                pattern: r.pattern,
                note: r.note,
                enabled: r.enabled,
            })
            .collect();
        Ok(Json(GetPolicyResult {
            rate_per_sec: p.rate_per_sec,
            note: p.note,
            rules,
        }))
    }

    #[tool(description = "Set the per-host send-rate ceiling (sends per second). `0` lifts it.")]
    async fn set_rate_limit(
        &self,
        Parameters(p): Parameters<SetRateLimitParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        if p.per_host_per_sec < 0.0 {
            return Err(ErrorData::invalid_params(
                "rate must be >= 0 (0 lifts the ceiling)",
                None,
            ));
        }
        let rate = if p.per_host_per_sec == 0.0 {
            None
        } else {
            Some(p.per_host_per_sec)
        };
        self.engine().set_rate_limit(rate);
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Add an out-of-bounds rule: URLs matching the pattern are refused on \
                       every send path. Draw the floor BEFORE letting an agent loose — \
                       payment flows, other tenants, anything the program's policy excludes."
    )]
    async fn add_policy_rule(
        &self,
        Parameters(p): Parameters<AddPolicyRuleParams>,
    ) -> Result<Json<PolicyIdResult>, ErrorData> {
        let pattern = p.pattern.trim();
        if pattern.is_empty() {
            return Err(ErrorData::invalid_params("pattern must not be empty", None));
        }
        let kind = p.kind.as_deref().unwrap_or("forbid_url_regex");
        let id = self
            .engine()
            .add_policy_rule(kind, pattern, p.note.as_deref())
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        Ok(Json(PolicyIdResult { rule_id: id }))
    }

    #[tool(description = "Delete an out-of-bounds rule.")]
    async fn delete_policy_rule(
        &self,
        Parameters(p): Parameters<RuleIdParams>,
    ) -> Result<Json<OkResult>, ErrorData> {
        let rows = self.engine().delete_policy_rule(p.rule_id);
        if rows == 0 {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no policy rule #{} — get_policy lists what exists",
                    p.rule_id
                ),
                None,
            ));
        }
        Ok(Json(OkResult { ok: true }))
    }

    // --- leads ---

    #[tool(
        description = "Propose a lead: an attack hypothesis worth a verifier's time. One \
                       kind from the vocabulary, one title, and a rationale that states the \
                       mechanism — not 'might be vulnerable'. A verifier (yours or another \
                       agent) settles it with a control via update_lead; an adjudicator \
                       rules on that via adjudicate_lead."
    )]
    async fn create_lead(
        &self,
        Parameters(p): Parameters<CreateLeadParams>,
    ) -> Result<Json<LeadIdResult>, ErrorData> {
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let id = engine
            .create_lead(&lockgate_core::NewLead {
                kind: p.kind,
                title: p.title,
                rationale_md: p.rationale_md,
                endpoint: p.endpoint,
                flow_id: p.flow_id,
            })
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        Ok(Json(LeadIdResult {
            lead_id: id,
            target,
        }))
    }

    #[tool(
        description = "The leads ledger, newest first. This is the coordination artifact \
                       between recon and verification: what was proposed, what settled, what \
                       was ruled inadmissible and why."
    )]
    async fn list_leads(
        &self,
        Parameters(p): Parameters<ListLeadsParams>,
    ) -> Result<Json<ListLeadsResult>, ErrorData> {
        let leads = self
            .engine()
            .leads(p.status.as_deref())
            .into_iter()
            .map(LeadDto::from)
            .collect();
        Ok(Json(ListLeadsResult { leads }))
    }

    #[tool(description = "One lead in full: rationale, verdict, control, ruling.")]
    async fn get_lead(
        &self,
        Parameters(p): Parameters<LeadIdParams>,
    ) -> Result<Json<LeadDto>, ErrorData> {
        self.engine()
            .lead(p.lead_id)
            .map(LeadDto::from)
            .map(Json)
            .ok_or_else(|| {
                ErrorData::resource_not_found(
                    format!("no lead #{} — list_leads shows what exists", p.lead_id),
                    None,
                )
            })
    }

    #[tool(
        description = "Record verification progress on a lead. Settling on verified/refuted \
                       requires verdict AND control — the baseline-vs-exploit check that \
                       discriminates the bug from intended behaviour. Refused in code \
                       otherwise: a conclusion without a control is a guess."
    )]
    async fn update_lead(
        &self,
        Parameters(p): Parameters<UpdateLeadParams>,
    ) -> Result<Json<LeadMutationResult>, ErrorData> {
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let rows = engine
            .record_lead_verdict(
                p.lead_id,
                p.status.as_deref().unwrap_or("verifying"),
                p.verdict.as_deref(),
                p.control.as_deref(),
            )
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        if rows == 0 {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no lead #{} on target “{target}” — list_leads shows what exists",
                    p.lead_id
                ),
                None,
            ));
        }
        let lead = engine.lead(p.lead_id).map(LeadDto::from).ok_or_else(|| {
            ErrorData::internal_error("lead vanished after update".to_string(), None)
        })?;
        Ok(Json(LeadMutationResult { target, lead }))
    }

    #[tool(
        description = "Rule on a verified/refuted lead: admissible or refuted, with a \
                       reason. This is the epistemics pass — read the lead's verdict and \
                       control, judge whether the control actually discriminates, and say \
                       why. Refuses to run before a verdict exists."
    )]
    async fn adjudicate_lead(
        &self,
        Parameters(p): Parameters<AdjudicateLeadParams>,
    ) -> Result<Json<LeadMutationResult>, ErrorData> {
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let rows = engine
            .adjudicate_lead(p.lead_id, &p.ruling, &p.ruling_reason)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        if rows == 0 {
            return Err(ErrorData::resource_not_found(
                format!(
                    "no lead #{} on target “{target}” — list_leads shows what exists",
                    p.lead_id
                ),
                None,
            ));
        }
        let lead = engine.lead(p.lead_id).map(LeadDto::from).ok_or_else(|| {
            ErrorData::internal_error("lead vanished after adjudication".to_string(), None)
        })?;
        Ok(Json(LeadMutationResult { target, lead }))
    }

    // --- materialise / report / scan ---

    #[tool(
        description = "Write the capture's queryable index to a directory: endpoints.jsonl, \
                       write-endpoints.jsonl (the mutating subset), sitemap.jsonl, \
                       findings.jsonl, leads.jsonl, and a README. Deterministic. Full bodies \
                       stay behind the flow:// resources — this is what you grep, not what \
                       you read."
    )]
    async fn materialise(
        &self,
        Parameters(p): Parameters<MaterialiseParams>,
    ) -> Result<Json<MaterialiseResult>, ErrorData> {
        let (_target, engine) = self.resolve(p.target.as_deref())?;
        let dir = std::path::PathBuf::from(p.dir);
        let out = engine
            .materialise(&dir)
            .map_err(|e| ErrorData::internal_error(format!("materialise failed: {e}"), None))?;
        Ok(Json(MaterialiseResult {
            dir: out.dir.display().to_string(),
            files: out
                .files
                .into_iter()
                .map(|f| MaterialisedFileDto {
                    name: f.name,
                    lines: f.lines,
                    bytes: f.bytes,
                })
                .collect(),
        }))
    }

    #[tool(
        description = "Render the whole engagement as one markdown report: findings by \
                       severity with impact/repro/remediation and evidence flow ids, then \
                       the leads ledger with verdicts and rulings. Pure assembly — the \
                       prose is whatever the findings carry."
    )]
    async fn generate_report(&self) -> Result<Json<ReportResult>, ErrorData> {
        let markdown = self.engine().generate_report().ok_or_else(|| {
            ErrorData::internal_error("report generation failed".to_string(), None)
        })?;
        Ok(Json(ReportResult { markdown }))
    }

    #[tool(
        description = "Run the passive scanner over recent flows and file what is new as \
                       draft findings (origin: workflow): CORS wildcard+credentials, cookie \
                       flags, missing HSTS/CSP, version banners. Deduped per rule+host. \
                       These are observations to triage, not verdicts — the scanner never \
                       sleeps, but it also never verifies."
    )]
    async fn scan_flows(
        &self,
        Parameters(p): Parameters<ScanFlowsParams>,
    ) -> Result<Json<ScanResult>, ErrorData> {
        let (target, engine) = self.resolve(p.target.as_deref())?;
        let limit = p.limit.unwrap_or(500).clamp(1, 5000) as usize;
        let out = engine.scan_recent(limit).await;
        Ok(Json(ScanResult {
            target,
            scanned: out.scanned as i64,
            filed: out.filed as i64,
        }))
    }

    /// Read a bounded window of one body and shape it for JSON.
    fn body_preview(
        &self,
        id: i64,
        side: Side,
        offset: i64,
        limit: i64,
        coding: Option<lockgate_core::encoding::Coding>,
    ) -> BodyPreview {
        let side_name = match side {
            Side::Request => "request",
            Side::Response => "response",
        };
        let resource_uri = format!("flow://{id}/{side_name}");

        match self.engine().body_slice(id, side, offset, limit) {
            Some(slice) => {
                let returned = slice.bytes.len() as i64;
                let truncated = offset + returned < slice.total_len;

                // A compressed stream can only be decoded from its start and in
                // full; decoding a window would produce plausible-looking
                // garbage, which is worse than handing back the bytes.
                let whole = offset == 0 && !truncated;
                let raw = hudsucker::hyper::body::Bytes::copy_from_slice(&slice.bytes);
                let decoded_bytes = match (whole, coding) {
                    (true, Some(coding)) => lockgate_core::encoding::decode_body(coding, &raw),
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
            .engine()
            .body_slice(id, side, 0, MAX_RESOURCE_BYTES)
            .ok_or_else(|| ErrorData::resource_not_found(format!("no flow #{id}"), None))?;

        // Response mime comes from the stored row; requests carry none.
        let mime = match side {
            Side::Response => self.engine().flow_detail(id).and_then(|d| d.row.mime),
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
        info.server_info.name = "lockgate-mcp".to_string();
        info.server_info.title = Some("Lockgate — captured traffic".to_string());
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
             create_finding; list_findings shows them all, and update_finding revises one as you \
             confirm it — file it early at low confidence and triage it up rather than sitting on \
             it. Working notes that are not yet a finding belong in create_note / update_note, \
             which the operator reads in the TUI."
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
fn coding_of_pairs(headers: &[(String, String)]) -> Option<lockgate_core::encoding::Coding> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .and_then(|(_, value)| lockgate_core::encoding::Coding::from_header_value(value))
}

// --- scope helpers ---

fn scope_error(e: lockgate_core::scope::ScopeError) -> ErrorData {
    ErrorData::invalid_params(format!("{e:?}"), None)
}

fn rule_dto(rule: &lockgate_core::scope::ScopeRule) -> ScopeRuleDto {
    let (host_kind, host_pattern) = match &rule.spec.host {
        Some((kind, pattern)) => (
            match kind {
                lockgate_core::scope::HostKind::Glob => "glob",
                lockgate_core::scope::HostKind::Regex => "regex",
                lockgate_core::scope::HostKind::Cidr => "cidr",
            },
            Some(pattern.clone()),
        ),
        None => ("any", None),
    };
    ScopeRuleDto {
        id: rule.id,
        action: match rule.action {
            lockgate_core::scope::Action::Include => "include".into(),
            lockgate_core::scope::Action::Exclude => "exclude".into(),
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

fn placeholder_request() -> lockgate_core::CapturedRequest {
    lockgate_core::CapturedRequest {
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
        ResendError::Forbidden {
            rule_id,
            pattern,
            url,
        } => ErrorData::invalid_request(
            format!(
                "policy forbids {url} — it matches out-of-bounds rule #{rule_id} ({pattern}). \
                 The floor is drawn in the engine; ask the operator before touching this."
            ),
            None,
        ),
        ResendError::RateLimited {
            host,
            retry_after_ms,
        } => ErrorData::invalid_request(
            format!(
                "rate limit: {host} is paced — retry in {retry_after_ms}ms rather than \
                 hammering; the ceiling is the program's, not a bug"
            ),
            None,
        ),
        ResendError::IdentityNotFound(id) => ErrorData::resource_not_found(
            format!("no identity #{id} — list_identities shows what exists"),
            None,
        ),
        ResendError::Http(e) => ErrorData::internal_error(format!("resend failed: {e}"), None),
    }
}

/// Turn a wire cookie into a core one, defaulting its domain to the identity's
/// host and its path to `/` — the two attributes a caller usually means.
fn cookie_input(host: Option<&str>, c: &CookieInput) -> Result<lockgate_core::Cookie, String> {
    let name = c.name.trim();
    if name.is_empty() {
        return Err("cookie name must not be empty".to_string());
    }
    Ok(lockgate_core::Cookie {
        name: name.to_string(),
        value: c.value.clone(),
        domain: c
            .domain
            .clone()
            .or_else(|| host.map(str::to_string))
            .unwrap_or_default(),
        path: c.path.clone().unwrap_or_else(|| "/".to_string()),
    })
}

fn write_error(e: lockgate_core::engine::WriteError) -> ErrorData {
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
    use lockgate_core::{CapturedRequest, CapturedResponse, Engine};
    use rmcp::model::ResourceContents;
    use std::sync::Arc;

    fn setup() -> (Arc<Engine>, ProxyServer) {
        let engine = Engine::new();
        let server = ProxyServer::new(crate::Targets::single("test", engine.clone()));
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
                target: None,
                text: "GET /nowhere HTTP/1.1\n\n".into(),
                base_flow_id: None,
                as_identity: None,
                tag: None,
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
                target: None,
                text: "GET / HTTP/1.1\nnot-a-header\n\n".into(),
                base_flow_id: None,
                as_identity: None,
                tag: None,
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
                target: None,
                text: "GET /a HTTP/1.1\n\n".into(),
                base_flow_id: Some(999),
                as_identity: None,
                tag: None,
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
            tag: None,
            include_automate: None,
            offset: None,
            limit: None,
            in_scope: None,
        }
    }

    fn finding_params() -> CreateFindingParams {
        CreateFindingParams {
            target: None,
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
    async fn notes_round_trip_and_edit_one_field_at_a_time() {
        let (_engine, server) = setup();

        let id = server
            .create_note(Parameters(CreateNoteParams {
                title: "auth teardown".into(),
                body_md: Some("refresh token is bound to nothing".into()),
            }))
            .await
            .unwrap()
            .0
            .id;

        // A body edit must not disturb the title, which is what makes
        // update_note safe to call from an agent that only has new prose.
        let res = server
            .update_note(Parameters(UpdateNoteParams {
                id,
                title: None,
                body_md: Some("bound to nothing, see flow #412".into()),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(res.rows_changed, 1);

        let note = server
            .get_note(Parameters(NoteIdParams { id }))
            .await
            .unwrap()
            .0;
        assert_eq!(note.title, "auth teardown");
        assert_eq!(note.body_md, "bound to nothing, see flow #412");
        assert_eq!(server.list_notes().await.unwrap().0.notes.len(), 1);

        // An empty edit is a caller error, not a silent no-op.
        let err = server
            .update_note(Parameters(UpdateNoteParams {
                id,
                title: None,
                body_md: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("title or body_md"), "{}", err.message);

        assert_eq!(
            server
                .delete_note(Parameters(NoteIdParams { id }))
                .await
                .unwrap()
                .0
                .rows_changed,
            1
        );
        assert!(server.list_notes().await.unwrap().0.notes.is_empty());
        // A gone note reads as not-found rather than as an empty one.
        let err = server
            .get_note(Parameters(NoteIdParams { id }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.message.contains(&format!("no note #{id}")),
            "{}",
            err.message
        );
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

    fn update_params(id: i64) -> UpdateFindingParams {
        UpdateFindingParams {
            id,
            title: None,
            severity: None,
            status: None,
            description_md: None,
            repro_md: None,
            impact_md: None,
            remediation_md: None,
            cvss_vector: None,
            cvss_score: None,
            cvss_version: None,
            cwe: None,
        }
    }

    /// The point of the tool: an agent files early and revises as it confirms.
    /// What it does not mention has to survive untouched.
    #[tokio::test]
    async fn update_finding_revises_only_what_it_is_given() {
        let (engine, server) = setup();
        let flow = record(&engine, "http://example.com/vuln", "boom");

        let mut p = finding_params();
        p.description_md = "maybe reflected".into();
        p.evidence = Some(vec![EvidenceInput {
            flow_id: flow,
            label: Some("poc".into()),
        }]);
        let id = server.create_finding(Parameters(p)).await.unwrap().0.id;

        let mut u = update_params(id);
        u.severity = Some("high".into());
        u.status = Some("confirmed".into());
        u.impact_md = Some("session theft".into());
        let rows = server.update_finding(Parameters(u)).await.unwrap().0;
        assert_eq!(rows.rows_changed, 1);

        let g = server
            .get_finding(Parameters(GetFindingParams { id }))
            .await
            .unwrap()
            .0;
        assert_eq!(g.severity, "high");
        assert_eq!(g.status, "confirmed");
        assert_eq!(g.impact_md.as_deref(), Some("session theft"));
        assert_eq!(
            g.description_md, "maybe reflected",
            "an untouched field is untouched"
        );
        assert_eq!(g.title, "t");
        assert_eq!(
            g.evidence.len(),
            1,
            "an edit must not drop the evidence it was filed with"
        );
    }

    /// Clearing has to be possible, and has to be deliberate: `""` clears, and
    /// dropping the CVSS vector takes its score and version with it.
    #[tokio::test]
    async fn update_finding_clears_on_an_empty_string() {
        let (engine, server) = setup();
        record(&engine, "http://example.com/a", "A");

        let mut p = finding_params();
        p.impact_md = Some("guessed".into());
        p.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into());
        p.cvss_score = Some(9.8);
        p.cvss_version = Some("3.1".into());
        let id = server.create_finding(Parameters(p)).await.unwrap().0.id;

        let mut u = update_params(id);
        u.impact_md = Some(String::new());
        u.cvss_vector = Some(String::new());
        server.update_finding(Parameters(u)).await.unwrap();

        let g = server
            .get_finding(Parameters(GetFindingParams { id }))
            .await
            .unwrap()
            .0;
        assert_eq!(g.impact_md, None);
        assert_eq!(g.cvss_vector, None);
        assert_eq!(
            g.cvss_score, None,
            "a score without its vector is not a rating"
        );
        assert_eq!(g.cvss_version, None);
    }

    #[tokio::test]
    async fn update_finding_validates_inputs() {
        let (engine, server) = setup();
        record(&engine, "http://example.com/a", "A");
        let id = server
            .create_finding(Parameters(finding_params()))
            .await
            .unwrap()
            .0
            .id;

        let mut bad_sev = update_params(id);
        bad_sev.severity = Some("catastrophic".into());
        assert!(
            server
                .update_finding(Parameters(bad_sev))
                .await
                .is_err_and(|e| e.message.contains("severity"))
        );

        let mut blank = update_params(id);
        blank.title = Some("   ".into());
        assert!(server.update_finding(Parameters(blank)).await.is_err());

        // An edit that says nothing is a mistake, not a no-op to swallow.
        assert!(
            server
                .update_finding(Parameters(update_params(id)))
                .await
                .is_err_and(|e| e.message.contains("at least one"))
        );

        // Nothing above should have landed.
        let g = server
            .get_finding(Parameters(GetFindingParams { id }))
            .await
            .unwrap()
            .0;
        assert_eq!(g.severity, "low");
        assert_eq!(g.title, "t");

        // An unknown id is 0 rows, not an error — same as update_note.
        let rows = server
            .update_finding(Parameters(UpdateFindingParams {
                title: Some("ghost".into()),
                ..update_params(9999)
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(rows.rows_changed, 0);
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
    async fn identities_round_trip_and_never_leak_a_cookie_value() {
        let (_engine, server) = setup();

        let id = server
            .create_identity(Parameters(CreateIdentityParams {
                name: "admin".into(),
                host: Some("example.com".into()),
                cookies: vec![CookieInput {
                    name: "sid".into(),
                    value: "SECRET-VALUE".into(),
                    domain: None,
                    path: None,
                }],
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                note: Some("the operator's login".into()),
            }))
            .await
            .unwrap()
            .0
            .identity_id;

        let listed = &server.list_identities().await.unwrap().0.identities[0];
        assert_eq!(listed.name, "admin");
        assert_eq!(listed.host.as_deref(), Some("example.com"));
        assert!(listed.has_totp);
        let cookie = &listed.cookies[0];
        assert_eq!(cookie.name, "sid");
        // Domain defaulted to the identity's host, path to /.
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert_eq!(cookie.value_len, 12, "the length, never the value");
        let rendered = serde_json::to_string(&server.list_identities().await.unwrap().0).unwrap();
        assert!(
            !rendered.contains("SECRET-VALUE"),
            "a live session must never reach a transcript: {rendered}"
        );

        // A partial edit leaves the jar alone; a jar replacement is wholesale.
        let rows = server
            .update_identity(Parameters(UpdateIdentityParams {
                identity_id: id,
                name: None,
                host: None,
                totp_secret: None,
                note: Some("now noted".into()),
                cookies: None,
            }))
            .await
            .unwrap()
            .0
            .rows_changed;
        assert_eq!(rows, 1);
        let listed = &server.list_identities().await.unwrap().0.identities[0];
        assert_eq!(listed.cookies.len(), 1, "no cookies given, jar untouched");
        assert_eq!(listed.note.as_deref(), Some("now noted"));

        let rows = server
            .update_identity(Parameters(UpdateIdentityParams {
                identity_id: id,
                name: None,
                host: None,
                totp_secret: None,
                note: None,
                cookies: Some(vec![CookieInput {
                    name: "other".into(),
                    value: "v2".into(),
                    domain: None,
                    path: None,
                }]),
            }))
            .await
            .unwrap()
            .0
            .rows_changed;
        assert_eq!(rows, 1);
        let listed = &server.list_identities().await.unwrap().0.identities[0];
        assert_eq!(listed.cookies.len(), 1);
        assert_eq!(listed.cookies[0].name, "other", "the jar was replaced");

        // Names are unique, and the error says so rather than suffixing.
        let err = server
            .create_identity(Parameters(CreateIdentityParams {
                name: "admin".into(),
                host: None,
                cookies: vec![],
                totp_secret: None,
                note: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("already exists"), "{}", err.message);

        let ok = server
            .delete_identity(Parameters(IdentityIdParams { identity_id: id }))
            .await
            .unwrap()
            .0;
        assert!(ok.ok);
        assert!(
            server
                .list_identities()
                .await
                .unwrap()
                .0
                .identities
                .is_empty()
        );
    }

    #[tokio::test]
    async fn adopting_a_flow_mints_an_identity_from_its_session() {
        let (engine, server) = setup();

        // A post-login flow: request cookie plus two Set-Cookie responses.
        let mut req_headers = HeaderMap::new();
        req_headers.insert("cookie", "sid=abc123".parse().unwrap());
        let flow_id = engine.record_request(CapturedRequest {
            method: Method::GET,
            uri: "https://example.com/app".parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers: req_headers,
            body: Bytes::new(),
        });
        let mut resp_headers = HeaderMap::new();
        resp_headers.append("set-cookie", "role=admin".parse().unwrap());
        engine.record_response(
            flow_id,
            CapturedResponse {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: resp_headers,
                body: Bytes::new(),
            },
        );

        let res = server
            .adopt_flow_session(Parameters(AdoptSessionParams {
                target: None,
                flow_id: flow_id as i64,
                name: "me".into(),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(res.cookie_count, 2, "request cookie merged with Set-Cookie");
        assert_eq!(res.host.as_deref(), Some("example.com"));

        let listed = &server.list_identities().await.unwrap().0.identities[0];
        assert_eq!(listed.name, "me");
        let names: Vec<_> = listed.cookies.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["role", "sid"]);
        assert!(
            !serde_json::to_string(&listed).unwrap().contains("abc123"),
            "adopted values stay in the core"
        );

        // A flow with no session cannot mint one.
        let plain = record(&engine, "http://example.com/x", "x");
        let err = server
            .adopt_flow_session(Parameters(AdoptSessionParams {
                target: None,
                flow_id: plain,
                name: "empty".into(),
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("no cookies"), "{}", err.message);
    }

    #[tokio::test]
    async fn the_leads_ledger_enforces_its_epistemics() {
        let (_engine, server) = setup();

        let id = server
            .create_lead(Parameters(CreateLeadParams {
                target: None,
                kind: "idor".into(),
                title: "Booking ids are sequential".into(),
                rationale_md: "GET /bookings/4711 returned another tenant's booking.".into(),
                endpoint: Some("https://target.com/bookings/{id}".into()),
                flow_id: None,
            }))
            .await
            .unwrap()
            .0
            .lead_id;

        // Proposed, with nothing settled.
        let lead = server
            .get_lead(Parameters(LeadIdParams { lead_id: id }))
            .await
            .unwrap()
            .0;
        assert_eq!(lead.status, "proposed");
        assert_eq!(lead.ruling, None);
        assert_eq!(
            server
                .list_leads(Parameters(ListLeadsParams {
                    status: Some("proposed".into())
                }))
                .await
                .unwrap()
                .0
                .leads
                .len(),
            1
        );
        assert!(
            server
                .list_leads(Parameters(ListLeadsParams {
                    status: Some("verified".into())
                }))
                .await
                .unwrap()
                .0
                .leads
                .is_empty()
        );

        // A conclusion without a control is refused — in code, not in a prompt.
        let err = server
            .update_lead(Parameters(UpdateLeadParams {
                target: None,
                lead_id: id,
                status: Some("verified".into()),
                verdict: Some("it worked".into()),
                control: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("control"), "{}", err.message);

        // The control makes the verdict land.
        server
            .update_lead(Parameters(UpdateLeadParams {
                target: None,
                lead_id: id,
                status: Some("verified".into()),
                verdict: Some("200 with tenant B's id; 403 as tenant A".into()),
                control: Some("same request, swapped tenant id: 200 vs 403".into()),
            }))
            .await
            .unwrap();
        let lead = server
            .get_lead(Parameters(LeadIdParams { lead_id: id }))
            .await
            .unwrap()
            .0;
        assert_eq!(lead.status, "verified");
        assert!(lead.control.is_some());

        // Adjudication refuses to run before a verdict exists...
        let other = server
            .create_lead(Parameters(CreateLeadParams {
                target: None,
                kind: "config".into(),
                title: "Unprobed guess".into(),
                rationale_md: "vibes".into(),
                endpoint: None,
                flow_id: None,
            }))
            .await
            .unwrap()
            .0
            .lead_id;
        let err = server
            .adjudicate_lead(Parameters(AdjudicateLeadParams {
                target: None,
                lead_id: other,
                ruling: "admissible".into(),
                ruling_reason: "looks fine".into(),
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("verdict"), "{}", err.message);

        // ...and on a real verdict, the ruling lands.
        server
            .adjudicate_lead(Parameters(AdjudicateLeadParams {
                target: None,
                lead_id: id,
                ruling: "admissible".into(),
                ruling_reason: "the control discriminates: same request, different tenant".into(),
            }))
            .await
            .unwrap();
        let lead = server
            .get_lead(Parameters(LeadIdParams { lead_id: id }))
            .await
            .unwrap()
            .0;
        assert_eq!(lead.ruling.as_deref(), Some("admissible"));

        // The report carries the verdict and the ruling.
        let report = server.generate_report().await.unwrap().0.markdown;
        assert!(report.contains("## Leads"), "{report}");
        assert!(report.contains("admissible"), "{report}");
    }

    #[tokio::test]
    async fn materialise_and_scan_round_trip() {
        let (engine, server) = setup();

        // A response with every scanner rule firing.
        let mut req_headers = HeaderMap::new();
        req_headers.insert("host", "example.com".parse().unwrap());
        let id = engine.record_request(CapturedRequest {
            method: Method::GET,
            uri: "https://example.com/app".parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers: req_headers,
            body: Bytes::new(),
        });
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("access-control-allow-origin", "*".parse().unwrap());
        resp_headers.insert("access-control-allow-credentials", "true".parse().unwrap());
        resp_headers.insert("server", "nginx/1.24.0".parse().unwrap());
        resp_headers.append("set-cookie", "sid=abc; Path=/".parse().unwrap());
        engine.record_response(
            id,
            CapturedResponse {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: resp_headers,
                body: Bytes::new(),
            },
        );

        // The scanner files draft findings with origin=workflow, deduped.
        let out = server
            .scan_flows(Parameters(ScanFlowsParams {
                target: None,
                limit: Some(100),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(out.scanned, 1);
        assert!(
            out.filed >= 4,
            "CORS + cookies + HSTS + banner: {}",
            out.filed
        );

        // Second run files nothing new — per rule+host dedup.
        let again = server
            .scan_flows(Parameters(ScanFlowsParams {
                target: None,
                limit: Some(100),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(again.filed, 0, "dedup must hold across runs");

        let findings = server.list_findings().await.unwrap().0.findings;
        assert!(
            findings.iter().all(|f| f.origin == "workflow"),
            "the scanner speaks as the tool, not as verified work"
        );
        assert!(findings.iter().all(|f| f.status == "draft"));

        // Materialise writes an index the report agrees with.
        let dir = std::env::temp_dir().join(format!("lockgate-mcp-mat-{}", std::process::id()));
        let out = server
            .materialise(Parameters(MaterialiseParams {
                target: None,
                dir: dir.display().to_string(),
            }))
            .await
            .unwrap()
            .0;
        let names: Vec<_> = out.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"endpoints.jsonl"), "{names:?}");
        let endpoints = std::fs::read_to_string(dir.join("endpoints.jsonl")).unwrap();
        assert!(endpoints.contains("example.com"), "{endpoints}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_call_lands_on_the_target_it_names_not_the_session_default() {
        let engine_a = Engine::new();
        let engine_b = Engine::new();
        let server = ProxyServer::new(Arc::new(crate::Targets {
            engines: vec![
                ("a".into(), engine_a.clone()),
                ("b".into(), engine_b.clone()),
            ],
        }));

        // Explicit target wins over the session default (which is "a").
        let res = server
            .create_lead(Parameters(CreateLeadParams {
                target: Some("b".into()),
                kind: "config".into(),
                title: "explicit".into(),
                rationale_md: "r".into(),
                endpoint: None,
                flow_id: None,
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(res.target, "b");
        assert_eq!(engine_b.leads(None).len(), 1, "landed in b");
        assert_eq!(engine_a.leads(None).len(), 0, "and only in b");

        // Session selection: set_target("a"), then an un-named call hits a.
        server
            .set_target(Parameters(TargetNameParams { name: "a".into() }))
            .await
            .unwrap();
        let res = server
            .create_lead(Parameters(CreateLeadParams {
                target: None,
                kind: "config".into(),
                title: "session default".into(),
                rationale_md: "r".into(),
                endpoint: None,
                flow_id: None,
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(res.target, "a");
        assert_eq!(engine_a.leads(None).len(), 1);
        assert_eq!(engine_b.leads(None).len(), 1, "b untouched");

        // list_targets marks a active for THIS session.
        let listed = server.list_targets().await.unwrap().0;
        let a = listed.targets.iter().find(|t| t.name == "a").unwrap();
        let b = listed.targets.iter().find(|t| t.name == "b").unwrap();
        assert!(a.active && !b.active);

        // An unknown target is a named error, in both the explicit and the
        // switch path — the agent always learns before anything happens.
        let err = server
            .create_lead(Parameters(CreateLeadParams {
                target: Some("nope".into()),
                kind: "config".into(),
                title: "x".into(),
                rationale_md: "x".into(),
                endpoint: None,
                flow_id: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("no target"), "{}", err.message);
        let err = server
            .set_target(Parameters(TargetNameParams {
                name: "nope".into(),
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(err.message.contains("no target"), "{}", err.message);
        // And the failed switch left the session where it was.
        let listed = server.list_targets().await.unwrap().0;
        assert!(
            listed
                .targets
                .iter()
                .find(|t| t.name == "a")
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn policy_round_trips_and_validates_its_rules() {
        let (_engine, server) = setup();

        // Default: permissive. Nothing an existing session does changes.
        let p = server.get_policy().await.unwrap().0;
        assert_eq!(p.rate_per_sec, None);
        assert!(p.rules.is_empty());

        server
            .set_rate_limit(Parameters(SetRateLimitParams {
                per_host_per_sec: 2.5,
            }))
            .await
            .unwrap();
        let p = server.get_policy().await.unwrap().0;
        assert_eq!(p.rate_per_sec, Some(2.5));

        // 0 lifts the ceiling rather than wedging the project at zero.
        server
            .set_rate_limit(Parameters(SetRateLimitParams {
                per_host_per_sec: 0.0,
            }))
            .await
            .unwrap();
        assert_eq!(server.get_policy().await.unwrap().0.rate_per_sec, None);

        let rule_id = server
            .add_policy_rule(Parameters(AddPolicyRuleParams {
                kind: None,
                pattern: r"^https://target\\.com/pay".into(),
                note: Some("money flows are out of bounds".into()),
            }))
            .await
            .unwrap()
            .0
            .rule_id;
        let p = server.get_policy().await.unwrap().0;
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].kind, "forbid_url_regex");
        assert!(p.rules[0].enabled);

        // A rule that cannot compile — or matches everything — is refused at
        // write time. A guardrail that silently never matches is worse than
        // none.
        for bad in ["(unclosed", ""] {
            let err = server
                .add_policy_rule(Parameters(AddPolicyRuleParams {
                    kind: None,
                    pattern: bad.into(),
                    note: None,
                }))
                .await
                .map(|_| ())
                .unwrap_err();
            assert!(!err.message.is_empty());
        }
        assert_eq!(server.get_policy().await.unwrap().0.rules.len(), 1);

        let ok = server
            .delete_policy_rule(Parameters(RuleIdParams { rule_id }))
            .await
            .unwrap()
            .0;
        assert!(ok.ok);
        assert!(server.get_policy().await.unwrap().0.rules.is_empty());

        let err = server
            .delete_policy_rule(Parameters(RuleIdParams { rule_id: 999 }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.message.contains("no policy rule #999"),
            "{}",
            err.message
        );
    }

    #[tokio::test]
    async fn resend_with_an_unknown_identity_names_the_problem() {
        let (engine, server) = setup();
        let id = record(&engine, "http://example.com/x", "x");

        let err = server
            .resend_flow(Parameters(ResendFlowParams {
                target: None,
                id,
                as_identity: Some(7),
                tag: None,
            }))
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            err.message.contains("no identity #7"),
            "message was: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn resend_refuses_out_of_scope() {
        use lockgate_core::scope::{self, Action, HostKind, RuleSpec};

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
            .resend_flow(Parameters(ResendFlowParams {
                target: None,
                id,
                as_identity: None,
                tag: None,
            }))
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
        assert_eq!(info.server_info.name, "lockgate-mcp");
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
