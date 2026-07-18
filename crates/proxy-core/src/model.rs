use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version, body::Bytes};

/// Stable identifier so the Repeater, TUI, and MCP can all refer to "flow #7".
pub type FlowId = u64;

/// A request as we captured it off the wire. Owns its body so it can be replayed later.
#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// The response that came back for a captured request.
#[derive(Clone, Debug)]
pub struct CapturedResponse {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A history entry: a request paired with its response (once it arrives).
/// `response` is `None` between the request going out and the response coming back
/// (or forever, if the connection drops).
#[derive(Clone, Debug)]
pub struct Flow {
    pub id: FlowId,
    pub request: CapturedRequest,
    pub response: Option<CapturedResponse>,
}

/// A cheap row for list views (TUI/MCP) that don't need full bodies.
#[derive(Clone, Debug)]
pub struct FlowSummary {
    pub id: FlowId,
    pub method: Method,
    pub uri: Uri,
    pub status: Option<StatusCode>,
}
