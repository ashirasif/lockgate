use std::sync::Arc;

use hudsucker::hyper::header::HOST;

use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
use crate::store::FlowStore;

/// The seam. Owns all proxy state and defines every verb the frontends
/// (proxy handlers, TUI, MCP) are allowed to perform. Frontends hold an
/// `Arc<Engine>` and call these methods — they never touch the store directly.
pub struct Engine {
    store: FlowStore,
    /// One reused client (and its connection pool) for all Repeater resends.
    http: reqwest::Client,
}

#[derive(Debug)]
pub enum ResendError {
    NotFound(FlowId),
    /// The stored request had no usable absolute URL to send to.
    NoTarget,
    Http(reqwest::Error),
}

impl From<reqwest::Error> for ResendError {
    fn from(e: reqwest::Error) -> Self {
        ResendError::Http(e)
    }
}

impl Engine {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            store: FlowStore::new(),
            http: reqwest::Client::new(),
        })
    }

    // --- capture verbs (called by the proxy handlers) ---

    pub fn record_request(&self, request: CapturedRequest) -> FlowId {
        self.store.add_request(request)
    }

    pub fn record_response(&self, id: FlowId, response: CapturedResponse) {
        self.store.attach_response(id, response);
    }

    // --- control verbs (called by TUI / MCP) ---

    pub fn list_flows(&self) -> Vec<FlowSummary> {
        self.store.list()
    }

    pub fn get_flow(&self, id: FlowId) -> Option<Flow> {
        self.store.get(id)
    }

    /// Replay a captured request straight at the target (not back through us),
    /// Burp-Repeater style, and return the fresh response.
    pub async fn resend(&self, id: FlowId) -> Result<CapturedResponse, ResendError> {
        let flow = self.store.get(id).ok_or(ResendError::NotFound(id))?;
        let req = flow.request;
        let url = target_url(&req).ok_or(ResendError::NoTarget)?;

        let resp = self
            .http
            .request(req.method, url)
            .headers(req.headers)
            .body(req.body)
            .send()
            .await?;

        let status = resp.status();
        let version = resp.version();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?;

        Ok(CapturedResponse {
            status,
            version,
            headers,
            body,
        })
    }
}

/// Reqwest needs an absolute URL. Plain-HTTP proxied requests already carry one
/// in absolute-form (`http://host/path`). MITM'd HTTPS requests arrive in
/// origin-form (`/path`) with the host only in the `Host` header, so rebuild it
/// and assume `https` (we only see decrypted traffic on the TLS path).
fn target_url(req: &CapturedRequest) -> Option<String> {
    if req.uri.host().is_some() {
        return Some(req.uri.to_string());
    }
    let host = req.headers.get(HOST)?.to_str().ok()?;
    let path = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    Some(format!("https://{host}{path}"))
}
