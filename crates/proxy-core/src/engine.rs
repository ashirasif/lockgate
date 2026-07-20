use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use hudsucker::hyper::header::HOST;

use crate::db::ProjectPaths;
use crate::finding::{Finding, NewFinding};
use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary, now_micros};
use crate::read::{self, BodySlice, FlowDetail, FlowQuery, FlowRow, Side, SitemapNode};
use crate::scope::{Matcher, Target};
use crate::writer::{Source, WriteEvent, WriteHandle, write_batch};
use tokio::sync::oneshot;
use tracing::error;

/// The seam. Owns all proxy state and defines every verb the frontends
/// (proxy handlers, TUI, MCP) are allowed to perform. Frontends hold an
/// `Arc<Engine>` and call these methods — they never touch persistence directly.
///
/// History lives in the project database, not in memory: the engine keeps no
/// captured bodies resident, so a long session's memory is bounded by the id
/// counter, not by how much traffic flowed. Reads reconstruct flows from SQLite
/// (see `read.rs`); every write goes through `Persist`.
pub struct Engine {
    /// Flow ids are handed out here, synchronously — the proxy handler needs an
    /// id the instant a request arrives, long before it reaches the disk.
    next_id: AtomicU64,
    /// One reused client (and its connection pool) for all Repeater resends.
    http: reqwest::Client,
    persist: Persist,
}

/// How captured traffic is stored, and where reads come from.
enum Persist {
    /// Production. Writes go to the background writer (capture never waits on the
    /// disk); reads use a second WAL connection that runs concurrently with it.
    /// `Connection` is `Send` but not `Sync`, hence the mutex — every read locks
    /// briefly and never holds the guard across an await.
    Async {
        writer: WriteHandle,
        read: Mutex<Connection>,
        paths: ProjectPaths,
    },
    /// In-memory, for `Engine::new` and tests. A single connection written
    /// *synchronously*, so a recorded flow is visible to the very next read with
    /// no runtime or background writer in play — which is the contract the
    /// synchronous `record → read → assert` tests depend on.
    Memory {
        conn: Mutex<Connection>,
        run_id: i64,
        paths: ProjectPaths,
    },
}

/// A write routed through persistence did not commit. Every write goes through
/// the one writer, so the only failure a caller sees is the reply channel
/// closing before the batch committed.
#[derive(Debug)]
pub enum WriteError {
    Dropped,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

/// A successful resend: the fresh response, plus the id of the new flow the
/// replay was recorded as (parented to the original). Callers want the id so
/// they can point at the replay in history, not just see its response.
#[derive(Debug)]
pub struct Resent {
    pub replay_id: FlowId,
    pub response: CapturedResponse,
}

impl Engine {
    /// In-memory only: nothing survives the process. Backed by an in-memory
    /// database written synchronously, so reads see writes immediately.
    pub fn new() -> Arc<Self> {
        let conn = crate::db::open_memory().expect("open in-memory project database");
        let run_id = crate::db::begin_run(&conn, now_micros()).expect("begin capture run");
        Arc::new(Self {
            next_id: AtomicU64::new(0),
            http: reqwest::Client::new(),
            persist: Persist::Memory {
                conn: Mutex::new(conn),
                run_id,
                // A body large enough to spill (>5MB) would land here; tests
                // never produce one, so this directory is never created.
                paths: ProjectPaths::new(std::env::temp_dir()),
            },
        })
    }

    /// Back this engine with a project on disk, creating and migrating it as
    /// needed. The database is written behind a channel so capture never waits
    /// on the disk, and read concurrently through a second WAL connection.
    ///
    /// Opening a project starts a new `capture_run` within it; history from
    /// previous runs stays and flow ids continue past it.
    pub fn open_project(root: &Path) -> rusqlite::Result<Arc<Self>> {
        let paths = ProjectPaths::new(root);
        let (writer, next_id) = crate::writer::spawn(&paths, now_micros())?;
        // Opened after the writer, so the schema is already migrated.
        let read = crate::db::open(&paths.db())?;
        Ok(Arc::new(Self {
            next_id: AtomicU64::new(next_id),
            http: reqwest::Client::new(),
            persist: Persist::Async {
                writer,
                read: Mutex::new(read),
                paths,
            },
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
        // Allocated before the row exists on disk: `handle_request` needs the id
        // synchronously to correlate the response that follows.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let started_at = now_micros();
        self.write(WriteEvent::Request {
            id,
            source,
            parent_id,
            started_at,
            request,
        });
        id
    }

    pub fn record_response(&self, id: FlowId, response: CapturedResponse) {
        let ended_at = now_micros();
        self.write(WriteEvent::Response {
            id,
            ended_at,
            response,
        });
    }

    /// Persist one event: enqueued for the background writer in production, or
    /// applied synchronously to the in-memory database in tests.
    fn write(&self, event: WriteEvent) {
        match &self.persist {
            Persist::Async { writer, .. } => writer.send(event),
            Persist::Memory {
                conn, run_id, paths, ..
            } => {
                let mut conn = conn.lock().unwrap();
                if let Err(e) = write_batch(&mut conn, paths, *run_id, vec![event]) {
                    // Matches the async writer's stance: a lost event beats a
                    // panic on the capture path.
                    error!(error = %e, "failed to persist event");
                }
            }
        }
    }

    /// Flush pending history to disk and stop the writer.
    ///
    /// Must be called before the process exits: the writer runs on a blocking
    /// task, so anything still queued dies with the process otherwise. A no-op
    /// for in-memory engines, and safe to call more than once.
    pub async fn shutdown(&self) {
        if let Persist::Async { writer, .. } = &self.persist {
            writer.shutdown().await;
        }
    }

    // --- control verbs (called by TUI / MCP) ---

    pub fn list_flows(&self) -> Vec<FlowSummary> {
        self.read(read::list_flows)
    }

    /// The connection reads go through: the dedicated WAL reader in production,
    /// or the single in-memory connection in tests.
    fn read_conn(&self) -> &Mutex<Connection> {
        match &self.persist {
            Persist::Async { read, .. } => read,
            Persist::Memory { conn, .. } => conn,
        }
    }

    fn paths(&self) -> &ProjectPaths {
        match &self.persist {
            Persist::Async { paths, .. } | Persist::Memory { paths, .. } => paths,
        }
    }

    /// Run a read against the database, logging and returning the default on
    /// error — a failed history query must not take a frontend down.
    fn read<T: Default>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> T {
        let conn = self.read_conn().lock().unwrap();
        f(&conn).unwrap_or_else(|e| {
            error!(error = %e, "database read failed");
            T::default()
        })
    }

    /// Run `f` against the project database.
    ///
    /// The closure form keeps the guard from escaping, so a caller cannot hold
    /// the connection lock across an await by accident. Always `Some` now that
    /// even the in-memory engine is database-backed; the `Option` stays so
    /// callers built around a possibly-absent database keep compiling.
    pub fn with_db<T>(&self, f: impl FnOnce(&Connection) -> T) -> Option<T> {
        let conn = self.read_conn().lock().unwrap();
        Some(f(&conn))
    }

    /// The compiled matcher for the active scope, or unrestricted if no scope is
    /// active.
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
    /// Scope is applied at read time rather than stored on each flow: it is
    /// mutable, so a column would mean rewriting every row whenever a rule
    /// changes.
    pub fn list_flows_in_scope(&self) -> Vec<FlowSummary> {
        let matcher = self.scope_matcher();
        self.read(|conn| read::list_flows_in_scope(conn, &matcher))
    }

    pub fn get_flow(&self, id: FlowId) -> Option<Flow> {
        let paths = self.paths().clone();
        self.read(|conn| read::get_flow(conn, &paths, id))
    }

    /// Replay a captured request straight at the target (not back through us),
    /// Burp-Repeater style, and return the fresh response.
    ///
    /// The replay is itself recorded as a new flow carrying `parent_id = id`,
    /// so a send and its origin stay linked instead of the result vanishing.
    pub async fn resend(&self, id: FlowId) -> Result<Resent, ResendError> {
        let flow = self.get_flow(id).ok_or(ResendError::NotFound(id))?;
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

        Ok(Resent {
            replay_id,
            response,
        })
    }

    // --- read verbs backed by the project database (used by the MCP) ---
    //
    // These read the same history the TUI verbs do, spanning every capture run
    // in the project. They return plain owned data shaped for JSON.

    /// A page of flow rows (no bodies), newest first, matching `query`.
    pub fn query_flows(&self, query: &FlowQuery, offset: i64, limit: i64) -> Vec<FlowRow> {
        self.read(|conn| read::flows(conn, query, offset, limit))
    }

    /// Full metadata for one flow (headers, body lengths), or `None` if there is
    /// no such flow. Bodies are fetched separately via [`Engine::body_slice`].
    pub fn flow_detail(&self, id: i64) -> Option<FlowDetail> {
        self.read(|conn| read::flow_detail(conn, id))
    }

    /// A window into a flow's request or response body. `None` if the flow does
    /// not exist; a `BodySlice` with `storage == "none"` if it exists but has no
    /// body on that side.
    pub fn body_slice(&self, id: i64, side: Side, offset: i64, limit: i64) -> Option<BodySlice> {
        let blobs = self.paths().blobs();
        self.read(|conn| read::body_slice(conn, &blobs, id, side, offset, limit))
    }

    /// Sitemap nodes, optionally scoped to one host, ordered parent-before-child.
    pub fn sitemap(&self, host: Option<&str>, offset: i64, limit: i64) -> Vec<SitemapNode> {
        self.read(|conn| read::sitemap(conn, host, offset, limit))
    }

    /// Every finding in the project, newest first.
    pub fn list_findings(&self) -> Vec<Finding> {
        self.read(crate::finding::list)
    }

    /// One finding by id, or `None` if absent.
    pub fn get_finding(&self, id: i64) -> Option<Finding> {
        self.read(|conn| crate::finding::get(conn, id))
    }

    // --- write verbs routed through persistence (used by the MCP) ---
    //
    // Every database write in the process goes through `write`, so these hand the
    // work off and await a reply released only once the batch commits. A closed
    // reply channel means the write did not land.

    /// Set a flow's triage comment and/or highlight. `None` leaves that field
    /// unchanged. Returns the number of rows changed — 0 for an unknown id.
    pub async fn annotate_flow(
        &self,
        id: FlowId,
        comment: Option<String>,
        highlight: Option<String>,
    ) -> Result<u64, WriteError> {
        let (reply, rx) = oneshot::channel();
        self.write(WriteEvent::Annotate {
            id,
            comment,
            highlight,
            reply,
        });
        rx.await.map_err(|_| WriteError::Dropped)
    }

    /// Author a finding, returning its new id once the row is durably committed.
    pub async fn create_finding(&self, finding: NewFinding) -> Result<i64, WriteError> {
        let (reply, rx) = oneshot::channel();
        self.write(WriteEvent::CreateFinding {
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
