use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use hudsucker::hyper::header::HOST;

use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary, now_micros};
use crate::store::FlowStore;
use tokio::sync::oneshot;
use tracing::error;
use crate::db::ProjectPaths;
use crate::finding::{Finding, NewFinding};
use crate::read::{self, BodySlice, FlowDetail, FlowQuery, FlowRow, Side, SitemapNode};
use crate::scope::{Matcher, Target};
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
    /// A second connection for reads. The writer owns its own on a blocking
    /// thread, and WAL mode lets readers run concurrently with it. `Connection`
    /// is `Send` but not `Sync`, hence the mutex; every read locks briefly and
    /// never holds the guard across an await.
    read: Option<Mutex<Connection>>,
    /// Where the project's files live. Held so body reads can locate spilled
    /// blobs (`blobs/`); `None` for in-memory engines.
    paths: Option<ProjectPaths>,
}

/// A write that goes through the single writer task failed to land.
#[derive(Debug)]
pub enum WriteError {
    /// The engine is in-memory (tests, `Engine::new`): there is no project to
    /// write to.
    NoProject,
    /// The writer rejected or dropped the event before it committed — the write
    /// did not happen.
    Dropped,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::NoProject => write!(f, "no project database is open"),
            WriteError::Dropped => write!(f, "the write did not commit"),
        }
    }
}

impl std::error::Error for WriteError {}

#[derive(Debug)]
pub enum ResendError {
    NotFound(FlowId),
    /// The stored request had no usable absolute URL to send to.
    NoTarget,
    /// The target falls outside the active scope. Replaying is an *action* — it
    /// puts fresh traffic on the wire — so it is gated on scope even though
    /// merely viewing the flow is not.
    OutOfScope,
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
            read: None,
            paths: None,
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
        // Opened after the writer, so the schema is already migrated.
        let read = crate::db::open(&paths.db())?;
        Ok(Arc::new(Self {
            store: FlowStore::with_next_id(next_id),
            http: reqwest::Client::new(),
            writer: Some(writer),
            read: Some(Mutex::new(read)),
            paths: Some(paths),
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

    /// Run `f` against the project database. `None` for in-memory engines.
    ///
    /// The closure form keeps the guard from escaping, so a caller cannot hold
    /// the connection lock across an await by accident.
    pub fn with_db<T>(&self, f: impl FnOnce(&Connection) -> T) -> Option<T> {
        let conn = self.read.as_ref()?.lock().unwrap();
        Some(f(&conn))
    }

    /// The compiled matcher for the active scope, or unrestricted if no scope is
    /// active or the engine has no database.
    pub fn scope_matcher(&self) -> Matcher {
        self.with_db(crate::scope::active_matcher)
            .transpose()
            .unwrap_or_else(|e| {
                // A scope that will not compile must not silently widen the
                // view, but it also must not take the UI down: report it and
                // fall back to showing everything, which is at least visible.
                error!(error = %e, "active scope failed to compile");
                None
            })
            .unwrap_or_default()
    }

    /// History filtered to the active scope.
    ///
    /// Scope is applied here rather than stored on each flow: it is mutable, so
    /// a column would mean rewriting every row whenever a rule changes.
    pub fn list_flows_in_scope(&self) -> Vec<FlowSummary> {
        let matcher = self.scope_matcher();
        let flows = self.store.list();
        if matcher.is_unrestricted() {
            return flows;
        }
        flows
            .into_iter()
            .filter(|flow| {
                let (host, port, path) = summary_target(flow);
                matcher.matches(&Target {
                    host: &host,
                    port,
                    path: &path,
                })
            })
            .collect()
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

        // Replaying puts traffic on the wire, so it must respect the active
        // scope even though viewing the flow does not. An unrestricted scope
        // (the default) lets everything through.
        let matcher = self.scope_matcher();
        if !matcher.is_unrestricted() {
            let (host, port, path) = request_target(&req);
            if !matcher.matches(&Target {
                host: &host,
                port,
                path: &path,
            }) {
                return Err(ResendError::OutOfScope);
            }
        }

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

    // --- read verbs backed by the project database (used by the MCP) ---
    //
    // These read history from SQLite rather than the in-memory store, so they
    // span every capture run in the project, not just the current one. All
    // return `None`/empty for an in-memory engine, which has no database.

    /// A page of flow rows (no bodies), newest first, matching `query`.
    pub fn query_flows(&self, query: &FlowQuery, offset: i64, limit: i64) -> Vec<FlowRow> {
        self.with_db(|conn| read::flows(conn, query, offset, limit))
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "query_flows failed");
                None
            })
            .unwrap_or_default()
    }

    /// Full metadata for one flow (headers, body lengths), or `None` if there is
    /// no such flow. Bodies are fetched separately via [`Engine::body_slice`].
    pub fn flow_detail(&self, id: i64) -> Option<FlowDetail> {
        self.with_db(|conn| read::flow_detail(conn, id))
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "flow_detail failed");
                None
            })
            .flatten()
    }

    /// A window into a flow's request or response body. `None` if the flow does
    /// not exist; a `BodySlice` with `storage == "none"` if it exists but has no
    /// body on that side.
    pub fn body_slice(&self, id: i64, side: Side, offset: i64, limit: i64) -> Option<BodySlice> {
        let blobs = self.paths.as_ref()?.blobs();
        self.with_db(|conn| read::body_slice(conn, &blobs, id, side, offset, limit))
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "body_slice failed");
                None
            })
            .flatten()
    }

    /// Sitemap nodes, optionally scoped to one host, ordered parent-before-child.
    pub fn sitemap(&self, host: Option<&str>, offset: i64, limit: i64) -> Vec<SitemapNode> {
        self.with_db(|conn| read::sitemap(conn, host, offset, limit))
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "sitemap failed");
                None
            })
            .unwrap_or_default()
    }

    /// Every finding in the project, newest first.
    pub fn list_findings(&self) -> Vec<Finding> {
        self.with_db(crate::finding::list)
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "list_findings failed");
                None
            })
            .unwrap_or_default()
    }

    /// One finding by id, or `None` if absent.
    pub fn get_finding(&self, id: i64) -> Option<Finding> {
        self.with_db(|conn| crate::finding::get(conn, id))
            .transpose()
            .unwrap_or_else(|e| {
                error!(error = %e, "get_finding failed");
                None
            })
            .flatten()
    }

    // --- write verbs routed through the single writer task (used by the MCP) ---
    //
    // Every database write in the process goes through the writer, so these hand
    // the work off on the channel and await a reply that is released only once
    // the batch commits. A closed reply channel means the write did not land.

    /// Set a flow's triage comment and/or highlight. `None` leaves that field
    /// unchanged. Returns the number of rows changed — 0 for an unknown id.
    pub async fn annotate_flow(
        &self,
        id: FlowId,
        comment: Option<String>,
        highlight: Option<String>,
    ) -> Result<u64, WriteError> {
        let writer = self.writer.as_ref().ok_or(WriteError::NoProject)?;
        let (reply, rx) = oneshot::channel();
        writer.send(WriteEvent::Annotate {
            id,
            comment,
            highlight,
            reply,
        });
        rx.await.map_err(|_| WriteError::Dropped)
    }

    /// Author a finding, returning its new id once the row is durably committed.
    pub async fn create_finding(&self, finding: NewFinding) -> Result<i64, WriteError> {
        let writer = self.writer.as_ref().ok_or(WriteError::NoProject)?;
        let (reply, rx) = oneshot::channel();
        writer.send(WriteEvent::CreateFinding {
            finding: Box::new(finding),
            reply,
        });
        rx.await.map_err(|_| WriteError::Dropped)
    }
}

/// The scope-relevant parts of a captured request: host (from the URI or the
/// `Host` header), the port resolved from the scheme when absent, and the path.
/// Mirrors what the writer stores, so a scope decision here matches the columns.
fn request_target(req: &CapturedRequest) -> (String, u16, String) {
    let path = req
        .uri
        .path_and_query()
        .map(|pq| pq.path().to_string())
        .unwrap_or_else(|| "/".to_string());

    if let Some(host) = req.uri.host() {
        let https = req.uri.scheme_str() != Some("http");
        let port = req.uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        return (host.to_string(), port, path);
    }

    // Origin-form: host lives only in the `Host` header, and we assume https
    // (plain-HTTP requests arrive in absolute-form and take the branch above).
    let raw = req
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (raw.to_string(), 443),
        },
        None => (raw.to_string(), 443),
    };
    (host, port, path)
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

/// Pull the scope-relevant parts out of a summary row.
///
/// The port is resolved from the scheme when the URI omits it, matching what the
/// writer stores, so a port rule means the same thing either way.
fn summary_target(flow: &FlowSummary) -> (String, u16, String) {
    let host = flow.uri.host().unwrap_or_default().to_string();
    let https = flow.uri.scheme_str() != Some("http");
    let port = flow.uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = flow.uri.path().to_string();
    (host, port, path)
}
