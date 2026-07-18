use std::path::Path;
use std::sync::Arc;

use hudsucker::hyper::header::HOST;

use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary, now_micros};
use crate::store::FlowStore;
use crate::db::ProjectPaths;
use crate::writer::{Source, WriteEvent, WriteHandle};

/// The seam. Owns all proxy state and defines every verb the frontends
/// (proxy handlers, TUI, MCP) are allowed to perform. Frontends hold an
/// `Arc<Engine>` and call these methods — they never touch the store directly.
pub struct Engine {
    store: FlowStore,
    /// One reused client (and its connection pool) for all Repeater resends.
    http: reqwest::Client,
    /// `None` when running purely in memory (tests, `Engine::new`).
    writer: Option<WriteHandle>,
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
    /// In-memory only: nothing survives the process.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            store: FlowStore::new(),
            http: reqwest::Client::new(),
            writer: None,
        })
    }

    /// Back this engine with a project on disk, creating and migrating it as
    /// needed. Flows still land in memory first; the database is written behind
    /// a channel so capture never waits on the disk.
    ///
    /// Opening a project starts a new `capture_run` within it; history from
    /// previous runs stays and flow ids continue past it.
    pub fn open_project(root: &Path) -> rusqlite::Result<Arc<Self>> {
        let paths = ProjectPaths::new(root);
        let (writer, next_id) = crate::writer::spawn(&paths, now_micros())?;
        Ok(Arc::new(Self {
            store: FlowStore::with_next_id(next_id),
            http: reqwest::Client::new(),
            writer: Some(writer),
        }))
    }

    // --- capture verbs (called by the proxy handlers) ---

    pub fn record_request(&self, request: CapturedRequest) -> FlowId {
        self.record_request_from(request, Source::Proxy, None)
    }

    fn record_request_from(
        &self,
        request: CapturedRequest,
        source: Source,
        parent_id: Option<FlowId>,
    ) -> FlowId {
        let started_at = now_micros();
        // The id is allocated in memory because `handle_request` needs it
        // synchronously, long before the writer task reaches the disk.
        let id = self.store.add_request(request.clone(), started_at);

        if let Some(writer) = &self.writer {
            writer.send(WriteEvent::Request {
                id,
                source,
                parent_id,
                started_at,
                request,
            });
        }
        id
    }

    pub fn record_response(&self, id: FlowId, response: CapturedResponse) {
        let ended_at = now_micros();
        self.store.attach_response(id, response.clone(), ended_at);

        if let Some(writer) = &self.writer {
            writer.send(WriteEvent::Response {
                id,
                ended_at,
                response,
            });
        }
    }

    /// Flush pending history to disk and stop the writer.
    ///
    /// Must be called before the process exits: the writer runs on a blocking
    /// task, so anything still queued dies with the process otherwise. A no-op
    /// for in-memory engines, and safe to call more than once.
    pub async fn shutdown(&self) {
        if let Some(writer) = &self.writer {
            writer.shutdown().await;
        }
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
    ///
    /// The replay is itself recorded as a new flow carrying `parent_id = id`,
    /// so a send and its origin stay linked instead of the result vanishing.
    pub async fn resend(&self, id: FlowId) -> Result<CapturedResponse, ResendError> {
        let flow = self.store.get(id).ok_or(ResendError::NotFound(id))?;
        let req = flow.request;
        let url = target_url(&req).ok_or(ResendError::NoTarget)?;

        let replay_id = self.record_request_from(req.clone(), Source::Repeater, Some(id));

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

        let response = CapturedResponse {
            status,
            version,
            headers,
            body,
        };
        self.record_response(replay_id, response.clone());

        Ok(response)
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
