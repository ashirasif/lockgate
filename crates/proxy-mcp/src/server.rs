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
        let response = self.engine.resend(p.id as u64).await.map_err(resend_error)?;
        // "text/html; charset=utf-8" -> "text/html", matching how capture stores mime.
        let mime = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());
        Ok(Json(ResendFlowResult {
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
        let finding = NewFinding {
            title: p.title,
            severity: p.severity,
            status: p.status.unwrap_or_else(|| "draft".to_string()),
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
            evidence: p
                .evidence
                .unwrap_or_default()
                .into_iter()
                .map(|e| (e.flow_id, e.label))
                .collect(),
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
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("flow://{id}/request", "flow-request-body")
                .with_description("The full request body of flow {id}."),
            ResourceTemplate::new("flow://{id}/response", "flow-response-body")
                .with_description("The full response body of flow {id}."),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let (id, side) = parse_flow_uri(&request.uri).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("unrecognised resource uri: {}", request.uri),
                None,
            )
        })?;

        let slice = self
            .engine
            .body_slice(id, side, 0, MAX_RESOURCE_BYTES)
            .ok_or_else(|| {
                ErrorData::resource_not_found(format!("no flow #{id}"), None)
            })?;

        // Response mime comes from the stored row; requests carry none.
        let mime = match side {
            Side::Response => self.engine.flow_detail(id).and_then(|d| d.row.mime),
            Side::Request => None,
        };

        let contents = match std::str::from_utf8(&slice.bytes) {
            Ok(text) => {
                let c = ResourceContents::text(text, request.uri);
                match mime {
                    Some(m) => c.with_mime_type(m),
                    None => c,
                }
            }
            Err(_) => {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&slice.bytes);
                let c = ResourceContents::blob(encoded, request.uri);
                match mime {
                    Some(m) => c.with_mime_type(m),
                    None => c,
                }
            }
        };
        Ok(ReadResourceResult::new(vec![contents]))
    }
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
