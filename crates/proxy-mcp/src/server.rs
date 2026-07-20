//! The MCP server: seven tools for recon over captured traffic, plus the
//! `flow://` resources that carry full request/response bodies on demand.
//!
//! Every tool is a thin shell over an `Engine` verb. Reads go straight to the
//! engine's database-backed queries; the two writes (annotate, create finding)
//! go through the engine too, which funnels them to the single writer task —
//! this server never opens a database of its own.

use std::sync::Arc;

use proxy_core::{Engine, FlowQuery, NewFinding, ResendError, Side};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::handler::server::router::tool::ToolRouter;
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
                       with offset/limit. Use get_flow for headers and body previews."
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
        let rows = self.engine.query_flows(&query, offset, limit);
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

        let request_body = self.body_preview(p.id, Side::Request, offset, limit);
        let response_body = self.body_preview(p.id, Side::Response, offset, limit);

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
        let resent = self.engine.resend(p.id as u64).await.map_err(resend_error)?;
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
        let id = self.engine.create_finding(finding).await.map_err(write_error)?;
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
    fn body_preview(&self, id: i64, side: Side, offset: i64, limit: i64) -> BodyPreview {
        let side_name = match side {
            Side::Request => "request",
            Side::Response => "response",
        };
        let resource_uri = format!("flow://{id}/{side_name}");

        match self.engine.body_slice(id, side, offset, limit) {
            Some(slice) => {
                let returned = slice.bytes.len() as i64;
                let (text, base64) = encode_bytes(&slice.bytes);
                BodyPreview {
                    truncated: offset + returned < slice.total_len,
                    total_len: slice.total_len,
                    storage: slice.storage,
                    offset,
                    text,
                    base64,
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
            format!("invalid {field} {value:?}; expected one of {}", allowed.join(", ")),
            None,
        ))
    }
}

fn resend_error(e: ResendError) -> ErrorData {
    match e {
        ResendError::NotFound(id) => {
            ErrorData::resource_not_found(format!("no flow #{id}"), None)
        }
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
        let r = server.list_flows(Parameters(list_params())).await.unwrap().0;
        assert_eq!(r.returned, 1);
        assert_eq!(r.flows[0].id, a);

        // Opt in: both show.
        let mut p = list_params();
        p.include_automate = Some(true);
        assert_eq!(server.list_flows(Parameters(p)).await.unwrap().0.returned, 2);

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
        assert_eq!(server.list_flows(Parameters(p)).await.unwrap().0.limit, MAX_LIMIT);
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
            .map(|_| ()).unwrap_err();
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

        let r = server.list_flows(Parameters(list_params())).await.unwrap().0;
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
            .map(|_| ()).unwrap_err();
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
        let err = server.create_finding(Parameters(bad_sev)).await.map(|_| ()).unwrap_err();
        assert!(err.message.contains("invalid severity"));

        let mut bad_status = finding_params();
        bad_status.status = Some("vibing".into());
        let err = server
            .create_finding(Parameters(bad_status))
            .await
            .map(|_| ()).unwrap_err();
        assert!(err.message.contains("invalid status"));

        // A dangling evidence id is caught up front, not as an opaque write error.
        let mut bad_ev = finding_params();
        bad_ev.evidence = Some(vec![EvidenceInput {
            flow_id: id + 999,
            label: None,
        }]);
        let err = server.create_finding(Parameters(bad_ev)).await.map(|_| ()).unwrap_err();
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
            .map(|_| ()).unwrap_err();
        assert!(err.message.contains("scope"), "message was: {}", err.message);
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
