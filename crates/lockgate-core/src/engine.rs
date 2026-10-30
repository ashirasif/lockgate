use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension};

use hudsucker::hyper::header::HOST;

use crate::db::ProjectPaths;
use crate::finding::{Finding, FindingEdit, NewFinding, WriteUp};
use crate::identity::{self, Identity, IdentityEdit, NewIdentity};
use crate::intercept::Intercept;
use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary, now_micros};
use crate::note::{NewNote, Note};
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
    /// Traffic held in flight awaiting an operator verdict. Off by default, so
    /// an engine nobody is watching never holds anything.
    intercept: Intercept,
    /// Open WebSocket upgrades, keyed by the only thing a frame carries: the
    /// client address and the server URI. The value is the flow the upgrade
    /// came from, plus a per-socket frame counter.
    sockets: Mutex<HashMap<SocketKey, OpenSocket>>,
    /// When each host last accepted a send — the state behind the policy
    /// rate ceiling. In-memory on purpose: a restart forgetting a throttle is
    /// a shrug, not a correctness problem, and it must never touch the disk.
    send_lasts: Mutex<HashMap<String, std::time::Instant>>,
    /// (rule, host) pairs the passive scanner has already filed this run —
    /// the first line of scanner dedup, so a hundred responses of the same
    /// host cost one finding even before the database check runs.
    scanned: Mutex<HashSet<(String, String)>>,
    /// Where headline events go (phone push), when the operator asked for it.
    /// `disabled()` by default so no caller ever branches on configuration.
    /// A mutex because the engine lives in an `Arc` and notifications are
    /// configured once, after construction, by whoever built it.
    notifier: std::sync::Mutex<crate::notify::Notifier>,
}

/// Everything observable about engine state, collapsed to a value that can be
/// compared against a previous one. Opaque by design: only equality means
/// anything, and an unequal pair says only "something changed", never what.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Revision {
    data_version: i64,
    total_changes: u64,
    intercept: crate::intercept::InterceptRevision,
}

/// What a WebSocket frame can identify itself by: nothing more than where it
/// came from and where it is going.
type SocketKey = (std::net::SocketAddr, String);

/// The flow whose upgrade opened a socket, and its running frame counter.
type OpenSocket = (FlowId, Arc<AtomicI64>);

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
    /// The URL hits an out-of-bounds policy rule. Distinct from scope: scope
    /// is what the operator is *testing*, policy is what they ruled off-limits
    /// even in-scope.
    Forbidden {
        rule_id: i64,
        pattern: String,
        url: String,
    },
    /// The policy's per-host send ceiling is engaged. `retry_after_ms` is when
    /// the next send to this host may go.
    RateLimited {
        host: String,
        retry_after_ms: u64,
    },
    /// The replay asked to be sent as an identity that does not exist.
    IdentityNotFound(i64),
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
            intercept: Intercept::default(),
            sockets: Mutex::new(HashMap::new()),
            send_lasts: Mutex::new(HashMap::new()),
            scanned: Mutex::new(HashSet::new()),
            notifier: std::sync::Mutex::new(crate::notify::Notifier::disabled()),
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
            intercept: Intercept::default(),
            sockets: Mutex::new(HashMap::new()),
            send_lasts: Mutex::new(HashMap::new()),
            scanned: Mutex::new(HashSet::new()),
            notifier: std::sync::Mutex::new(crate::notify::Notifier::disabled()),
        }))
    }

    /// The intercept queue. Frontends toggle it and answer held items through
    /// this; the proxy handlers hold traffic on it.
    pub fn intercept(&self) -> &Intercept {
        &self.intercept
    }

    /// Turn on phone push (see `notify::Notifier`). Called once at startup
    /// when `--ntfy` is set; off by default.
    pub fn set_notifier(&self, notifier: crate::notify::Notifier) {
        *self.notifier.lock().unwrap() = notifier;
    }

    // --- capture verbs (called by the proxy handlers) ---

    pub fn record_request(&self, request: CapturedRequest) -> FlowId {
        self.record_request_from(request, Source::Proxy, None)
    }

    /// Reserve a flow id without recording anything yet.
    ///
    /// The proxy handler needs an id up front to correlate the response that
    /// follows, but when interception is on it does not yet know what the
    /// request will *be* — the operator may still edit it. So it reserves here,
    /// holds, then calls [`Engine::record_request_as`] with whatever actually
    /// went on the wire, keeping history honest about it.
    pub fn reserve_flow_id(&self) -> FlowId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Record a proxied request under an id already handed out by
    /// [`Engine::reserve_flow_id`].
    pub fn record_request_as(&self, id: FlowId, request: CapturedRequest) {
        self.write(WriteEvent::Request {
            id,
            source: Source::Proxy,
            parent_id: None,
            started_at: now_micros(),
            request,
            tag: None,
        });
    }

    fn record_request_from(
        &self,
        request: CapturedRequest,
        source: Source,
        parent_id: Option<FlowId>,
    ) -> FlowId {
        self.record_tagged(request, source, parent_id, None)
    }

    /// [`record_request_from`], with the send's purpose attached. The tag is
    /// part of the same write as the row itself — a replay's label can never
    /// lag its traffic.
    fn record_tagged(
        &self,
        request: CapturedRequest,
        source: Source,
        parent_id: Option<FlowId>,
        tag: Option<String>,
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
            tag,
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
                conn,
                run_id,
                paths,
                ..
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
        // Anything still held would otherwise die with the process, leaving the
        // client's socket hanging until it times out. Release it first.
        self.intercept.forward_all();
        if let Persist::Async { writer, .. } = &self.persist {
            writer.shutdown().await;
        }
    }

    // --- control verbs (called by TUI / MCP) ---

    /// The proxy history: HTTP exchanges only. WebSocket connections have their
    /// own listing so the two histories stay separate.
    pub fn list_flows(&self) -> Vec<FlowSummary> {
        self.read(|conn| read::list_flows(conn, crate::read::FlowKind::Http))
    }

    /// The WebSocket history: connections only, each a `101` upgrade whose
    /// frames hang off it via [`Engine::ws_messages`].
    pub fn list_ws_flows(&self) -> Vec<FlowSummary> {
        self.read(|conn| read::list_flows(conn, crate::read::FlowKind::WebSocket))
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
    /// A cheap token that changes whenever anything a frontend displays has
    /// changed — captured traffic, findings, notes, scopes, or the intercept
    /// queue. Costs a mutex, a pragma read and two atomic loads, with no I/O and
    /// no table access, so a UI can poll it far more often than it could afford
    /// to reload.
    ///
    /// Both database halves are needed because writes arrive on two different
    /// connections. `data_version` is SQLite's own cache-invalidation counter:
    /// it moves when *another* connection commits, which covers everything the
    /// background writer records (flows, WebSocket frames, findings and notes
    /// created through it) but deliberately ignores this connection's own
    /// writes. `total_changes` covers exactly that remainder — the scope and
    /// triage edits that `with_db` / `with_scope` apply directly to the read
    /// connection. Neither is something a future write path has to remember to
    /// update, which is the point: a missed bump here would show a stale UI.
    pub fn revision(&self) -> Revision {
        let conn = self.read_conn().lock().unwrap();
        Revision {
            data_version: conn
                .pragma_query_value(None, "data_version", |r| r.get(0))
                .unwrap_or(0),
            total_changes: conn.total_changes(),
            intercept: self.intercept.revision(),
        }
    }

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

    /// Move a finding through triage. Returns rows changed, so an unknown id is
    /// distinguishable from a no-op.
    pub fn set_finding_triage(
        &self,
        id: i64,
        severity: Option<&str>,
        status: Option<&str>,
    ) -> usize {
        self.with_db(|conn| crate::finding::set_triage(conn, id, severity, status, now_micros()))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// Replace a finding's whole write-up — all four prose columns at once,
    /// since they are edited as one document (see `finding::WriteUp`).
    ///
    /// Synchronous like the triage edits: the write-up is saved from a
    /// keystroke, and the editor pane needs to know it landed before it clears
    /// its dirty flag.
    pub fn set_finding_write_up(&self, id: i64, write_up: &WriteUp) -> usize {
        self.with_db(|conn| crate::finding::set_write_up(conn, id, write_up, now_micros()))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// Apply a partial edit to a finding — the MCP's `update_finding`. Returns
    /// rows changed, so an unknown id is distinguishable from a no-op.
    pub fn update_finding(&self, id: i64, edit: &FindingEdit) -> usize {
        self.with_db(|conn| crate::finding::update(conn, id, edit, now_micros()))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// Retitle a finding. Returns rows changed.
    pub fn set_finding_title(&self, id: i64, title: &str) -> usize {
        self.with_db(|conn| crate::finding::set_title(conn, id, title, now_micros()))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    pub fn delete_finding(&self, id: i64) -> usize {
        self.with_db(|conn| crate::finding::delete(conn, id))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// Edit a note's title and/or body. `None` leaves that field alone. Returns
    /// rows changed, so an unknown id is distinguishable from a no-op.
    ///
    /// Synchronous like the finding edits above: a note is saved from a
    /// keystroke, and the editor pane needs to know it landed before it clears
    /// its dirty flag.
    pub fn update_note(&self, id: i64, title: Option<&str>, body_md: Option<&str>) -> usize {
        self.with_db(|conn| crate::note::update(conn, id, title, body_md, now_micros()))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    pub fn delete_note(&self, id: i64) -> usize {
        self.with_db(|conn| crate::note::delete(conn, id))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    // --- websockets ---
    //
    // Frames arrive with no reference to the exchange that opened the socket —
    // hudsucker gives a client address and a server URI and nothing else. So an
    // upgrade registers itself here, and frames look themselves up by the same
    // pair. Rapid reconnects to the same endpoint are ambiguous under that key,
    // which is why the newest upgrade wins.

    /// Remember that this flow's response was a 101, so its frames can find it.
    pub fn note_upgrade(&self, client: std::net::SocketAddr, server: &str, flow: FlowId) {
        let mut sockets = self.sockets.lock().unwrap();
        // Bounded: a long session opens and closes many sockets, and this map
        // would otherwise grow for the life of the process.
        if sockets.len() > 512 {
            sockets.clear();
        }
        sockets.insert(
            (client, server.to_string()),
            (flow, Arc::new(AtomicI64::new(0))),
        );
    }

    /// The flow a frame belongs to, and the next sequence number on it.
    pub fn ws_frame_slot(
        &self,
        client: std::net::SocketAddr,
        server: &str,
    ) -> Option<(FlowId, i64)> {
        let sockets = self.sockets.lock().unwrap();
        let (flow, seq) = sockets.get(&(client, server.to_string()))?;
        Some((*flow, seq.fetch_add(1, Ordering::Relaxed)))
    }

    /// Record one frame.
    pub fn record_ws_message(
        &self,
        flow_id: FlowId,
        seq: i64,
        direction: &'static str,
        opcode: &'static str,
        payload: hudsucker::hyper::body::Bytes,
    ) {
        self.write(WriteEvent::WsMessage {
            flow_id,
            seq,
            direction,
            opcode,
            sent_at: now_micros(),
            payload,
        });
    }

    /// Every frame on a flow, in order.
    pub fn ws_messages(&self, flow_id: FlowId) -> Vec<crate::read::WsMessage> {
        let paths = self.paths().clone();
        self.read(|conn| crate::read::ws_messages(conn, &paths, flow_id as i64))
    }

    // --- scope ---
    //
    // These write through the read connection rather than the writer task. That
    // is deliberate: the writer exists to batch a firehose of captured traffic,
    // and scope edits are a handful of user-initiated statements. Routing them
    // through the queue would mean a rule edit did not take effect until the
    // next flush, which is exactly when someone is watching for it to.

    /// Scope work against the project database.
    ///
    /// `with_db` hands back an `Option` that is always `Some`; going straight
    /// to the connection keeps these signatures about scope errors rather than
    /// about a state that cannot occur.
    fn with_scope<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, crate::scope::ScopeError>,
    ) -> Result<T, crate::scope::ScopeError> {
        let conn = self.read_conn().lock().unwrap();
        f(&conn)
    }

    pub fn scopes(&self) -> Vec<crate::scope::Scope> {
        self.with_scope(crate::scope::list_scopes)
            .unwrap_or_default()
    }

    pub fn active_scope(&self) -> Option<crate::scope::Scope> {
        self.with_scope(crate::scope::active_scope).ok().flatten()
    }

    pub fn create_scope(&self, name: &str) -> Result<i64, crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::create_scope(conn, name))
    }

    pub fn delete_scope(&self, id: i64) -> Result<(), crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::delete_scope(conn, id))
    }

    pub fn set_active_scope(&self, id: i64) -> Result<(), crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::set_active(conn, id))
    }

    pub fn scope_rules(&self, scope_id: i64) -> Vec<crate::scope::ScopeRule> {
        self.with_scope(|conn| crate::scope::list_rules(conn, scope_id))
            .unwrap_or_default()
    }

    pub fn add_scope_rule(
        &self,
        scope_id: i64,
        action: crate::scope::Action,
        spec: &crate::scope::RuleSpec,
    ) -> Result<i64, crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::add_rule(conn, scope_id, action, spec, None))
    }

    pub fn delete_scope_rule(&self, id: i64) -> Result<(), crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::delete_rule(conn, id))
    }

    pub fn set_scope_rule_enabled(
        &self,
        id: i64,
        enabled: bool,
    ) -> Result<(), crate::scope::ScopeError> {
        self.with_scope(|conn| crate::scope::set_rule_enabled(conn, id, enabled))
    }

    /// History filtered to the active scope.
    ///
    /// Scope is applied at read time rather than stored on each flow: it is
    /// mutable, so a column would mean rewriting every row whenever a rule
    /// changes.
    pub fn list_flows_in_scope(&self) -> Vec<FlowSummary> {
        let matcher = self.scope_matcher();
        self.read(|conn| read::list_flows_in_scope(conn, &matcher, crate::read::FlowKind::Http))
    }

    /// WebSocket connections, narrowed to the active scope.
    pub fn list_ws_flows_in_scope(&self) -> Vec<FlowSummary> {
        let matcher = self.scope_matcher();
        self.read(|conn| {
            read::list_flows_in_scope(conn, &matcher, crate::read::FlowKind::WebSocket)
        })
    }

    pub fn get_flow(&self, id: FlowId) -> Option<Flow> {
        let paths = self.paths().clone();
        self.read(|conn| read::get_flow(conn, &paths, id))
    }

    // --- identities ---
    //
    // Same shape as the scope edits: user-initiated writes of a handful of rows
    // that must be visible the moment the call returns, so they run against the
    // read connection rather than the capture writer.

    pub fn identities(&self) -> Vec<Identity> {
        self.read(identity::list)
    }

    pub fn identity(&self, id: i64) -> Option<Identity> {
        self.read(|conn| identity::get(conn, id))
    }

    /// Mint an identity. The name is unique — a duplicate is a caller error,
    /// reported as such rather than silently suffixing. Synchronous: the caller
    /// needs to know it landed (and its id) before carrying on.
    pub fn create_identity(&self, new: &NewIdentity) -> Result<i64, identity::IdentityError> {
        let conn = self.read_conn().lock().unwrap();
        identity::insert(&conn, new, now_micros())
    }

    pub fn update_identity(
        &self,
        id: i64,
        edit: &IdentityEdit,
    ) -> Result<usize, identity::IdentityError> {
        let conn = self.read_conn().lock().unwrap();
        identity::update(&conn, id, edit, now_micros())
    }

    pub fn delete_identity(&self, id: i64) -> usize {
        self.with_db(|conn| identity::delete(conn, id))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// Mint an identity from a captured flow's session (see
    /// `identity::adopt`) — the "log in once by hand, then adopt" path.
    pub fn adopt_identity_from_flow(
        &self,
        flow_id: FlowId,
        name: &str,
    ) -> Result<i64, identity::AdoptError> {
        let conn = self.read_conn().lock().unwrap();
        identity::adopt(&conn, flow_id, name, now_micros())
    }

    // --- policy ---
    //
    // The engagement's guardrails. Reads happen per send inside `send_request`;
    // these verbs are the operator's (and the MCP's) way of drawing them.
    // Writes are synchronous like scope: the next send must see them.

    pub fn policy(&self) -> crate::policy::Policy {
        self.with_db(crate::policy::get)
            .and_then(|p| p.ok())
            .unwrap_or(crate::policy::Policy {
                rate_per_sec: None,
                note: None,
            })
    }

    /// Set the per-host send ceiling. `None` lifts it. Returns rows changed.
    pub fn set_rate_limit(&self, rate_per_sec: Option<f64>) -> usize {
        self.with_db(|conn| crate::policy::set_rate(conn, rate_per_sec))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    pub fn set_policy_note(&self, note: Option<&str>) -> usize {
        self.with_db(|conn| crate::policy::set_note(conn, note))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    pub fn policy_rules(&self) -> Vec<crate::policy::PolicyRule> {
        self.with_db(crate::policy::rules)
            .and_then(|r| r.ok())
            .unwrap_or_default()
    }

    pub fn add_policy_rule(
        &self,
        kind: &str,
        pattern: &str,
        note: Option<&str>,
    ) -> Result<i64, crate::policy::PolicyError> {
        let conn = self.read_conn().lock().unwrap();
        crate::policy::add_rule(&conn, kind, pattern, note)
    }

    pub fn delete_policy_rule(&self, id: i64) -> usize {
        self.with_db(|conn| crate::policy::delete_rule(conn, id))
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    /// The rate half of policy, held in `send_lasts`: one reserved slot per
    /// host, min-interval `1/rate`. Errors with `retry_after_ms` rather than
    /// sleeping — a send that must block the TUI or an MCP call for seconds is
    /// a hang wearing a costume; the caller paces itself instead. Reserving
    /// happens only after scope and the forbidden list have passed, so a
    /// refusal never consumes budget.
    fn enforce_rate_limit(
        &self,
        policy: Option<&crate::policy::Policy>,
        req: &CapturedRequest,
    ) -> Result<(), ResendError> {
        let Some(rate) = policy.and_then(|p| p.rate_per_sec).filter(|r| *r > 0.0) else {
            return Ok(());
        };
        let (host, _, _) = request_target(req);
        let min_interval = std::time::Duration::from_secs_f64(1.0 / rate);

        let mut lasts = self.send_lasts.lock().unwrap();
        let now = std::time::Instant::now();
        if let Some(last) = lasts.get(&host) {
            let elapsed = now.duration_since(*last);
            if let Some(wait) = min_interval.checked_sub(elapsed) {
                return Err(ResendError::RateLimited {
                    host,
                    retry_after_ms: wait.as_millis() as u64,
                });
            }
        }
        // The slot is reserved even if the HTTP round trip later fails: the
        // wire was touched, and pacing exists to pace the wire.
        lasts.insert(host, now);
        Ok(())
    }

    // --- leads: the ledger between the thinking agents and the probing ones ---

    /// Recon proposes. Returns the new lead id.
    ///
    /// A lead that lands on a primitive the chain playbook knows also runs the
    /// chain pass (see [`crate::chain`]) — silently, and never recursively: a
    /// `chain` lead classifies as nothing.
    pub fn create_lead(&self, lead: &crate::lead::NewLead) -> Result<i64, crate::lead::LeadError> {
        let id = {
            let conn = self.read_conn().lock().unwrap();
            crate::lead::propose(&conn, lead, now_micros())?
        };
        if let Some(stored) = self.lead(id) {
            let _ =
                self.with_db(|conn| crate::chain::propose_for_lead(conn, &stored, now_micros()));
        }
        Ok(id)
    }

    /// The ledger, newest first, optionally narrowed to one status.
    pub fn leads(&self, status: Option<&str>) -> Vec<crate::lead::Lead> {
        self.read(|conn| crate::lead::list(conn, status))
    }

    pub fn lead(&self, id: i64) -> Option<crate::lead::Lead> {
        self.read(|conn| crate::lead::get(conn, id))
    }

    /// The verifier's word (see `lead::record_verdict`).
    pub fn record_lead_verdict(
        &self,
        id: i64,
        status: &str,
        verdict: Option<&str>,
        control: Option<&str>,
    ) -> Result<usize, crate::lead::LeadError> {
        let rows = {
            let conn = self.read_conn().lock().unwrap();
            crate::lead::record_verdict(&conn, id, status, verdict, control, now_micros())?
        };
        if rows > 0
            && let Some(lead) = self.lead(id)
        {
            // Only the settlements buzz: proposed→verifying is process, not news.
            if matches!(status, "verified" | "refuted" | "reported") {
                self.notifier
                    .lock()
                    .unwrap()
                    .notify(crate::notify::Event::LeadSettled {
                        lead_id: id,
                        title: lead.title.clone(),
                        status: status.to_string(),
                    });
            }
            // A primitive that just settled as verified is load-bearing: run
            // the chain pass so compositions with it get their question filed.
            // No-op for kinds the playbook does not speak, chains included.
            if status == "verified" {
                let _ =
                    self.with_db(|conn| crate::chain::propose_for_lead(conn, &lead, now_micros()));
            }
        }
        Ok(rows)
    }

    /// The adjudicator's word — the only path that writes a ruling (see
    /// `lead::adjudicate`).
    pub fn adjudicate_lead(
        &self,
        id: i64,
        ruling: &str,
        reason: &str,
    ) -> Result<usize, crate::lead::LeadError> {
        let conn = self.read_conn().lock().unwrap();
        crate::lead::adjudicate(&conn, id, ruling, reason, now_micros())
    }

    // --- chains: the model pass's read and write ---

    /// The model pass's write path: a chain the playbook cannot see, with its
    /// members and the questions to dispatch (see [`crate::chain::file_chain`]).
    /// Idempotent on title — running the pass twice files nothing twice.
    pub fn file_chain(
        &self,
        new: crate::chain::NewChain,
    ) -> Result<crate::chain::FiledChain, crate::chain::ChainError> {
        let conn = self.read_conn().lock().unwrap();
        crate::chain::file_chain(&conn, &new, now_micros())
    }

    /// One chain reassembled: its members and its questions.
    pub fn chain(&self, id: i64) -> Option<crate::chain::ReviewChain> {
        self.with_db(|conn| crate::chain::chain(conn, id)).flatten()
    }

    /// The model pass's read: everything held, compacted for reasoning about
    /// compositions (see [`crate::chain::review`]). Deterministic — the
    /// reasoning is the caller's; this is the brief it reasons over.
    pub fn chain_review(&self) -> Option<crate::chain::Review> {
        self.with_db(crate::chain::review)
    }

    // --- materialise: the capture as a greppable directory ---

    /// Write the engagement index to `dir` (see `materialise`).
    pub fn materialise(
        &self,
        dir: &Path,
    ) -> Result<crate::materialise::Materialised, crate::materialise::MaterialiseError> {
        let conn = self.read_conn().lock().unwrap();
        let paths = self.paths().clone();
        crate::materialise::materialise(&conn, &paths, dir)
    }

    // --- report: findings and leads, assembled ---

    /// The whole engagement as one markdown document.
    pub fn generate_report(&self) -> Option<String> {
        self.with_db(|conn| crate::report::generate(conn).ok())
            .flatten()
    }

    // --- passive scanner ---

    /// Scan one exchange and file what the rules find, deduped per (rule,
    /// host). Called from the proxy handler with the bytes already in hand —
    /// never a re-read, which would race the background writer.
    ///
    /// Fails into silence, like every capture-path extra: a scanner problem
    /// must never cost a captured byte, and a duplicate finding is a triage
    /// annoyance rather than a correctness break.
    pub async fn scan_and_file(
        &self,
        flow_id: FlowId,
        scheme: &str,
        host: &str,
        res: &CapturedResponse,
    ) {
        let mime: Option<String> = res
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());
        for hit in crate::scanner::scan(scheme, &mime, &res.headers) {
            self.file_scan_hit(flow_id, hit, host).await;
        }
    }

    /// One rule hit, through the dedup gates: this run's in-memory set first,
    /// then the database (so a restart does not re-file old news), then the
    /// write. Marked seen either way once attempted — a refused write must
    /// not become a retry storm on the capture path.
    async fn file_scan_hit(&self, flow_id: FlowId, hit: crate::scanner::ScanHit, host: &str) {
        if !self
            .scanned
            .lock()
            .unwrap()
            .insert((hit.rule.to_string(), host.to_string()))
        {
            return;
        }
        let known = self.with_db(|conn| {
            conn.query_row(
                "SELECT 1 FROM finding WHERE title = ?1 AND host IS ?2",
                rusqlite::params![hit.title, host],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .unwrap_or(true)
        });
        let known = known.unwrap_or(true);
        if known {
            return;
        }
        let finding = crate::finding::NewFinding {
            title: hit.title.clone(),
            severity: hit.severity.to_string(),
            status: "draft".to_string(),
            cvss_vector: None,
            cvss_score: None,
            cvss_version: None,
            cwe: hit.cwe.map(str::to_string),
            description_md: hit.description_md.clone(),
            repro_md: Some(format!(
                "Observed on flow #{flow_id}. The full exchange is in the history; \
                 the header line is the evidence."
            )),
            impact_md: None,
            remediation_md: None,
            host: Some(host.to_string()),
            path: None,
            evidence: vec![(flow_id as i64, Some("trigger".into()))],
            origin: "workflow".to_string(),
        };
        // Through the one writer; a dropped reply is a lost draft finding,
        // which is the correct way for this to fail.
        let _ = self.create_finding(finding).await;
    }

    /// Scan the most recent `limit` flows on demand and file what is new.
    pub async fn scan_recent(&self, limit: usize) -> crate::scanner::ScanOutcome {
        let summaries = self.list_flows();
        let ids: Vec<FlowId> = summaries.iter().take(limit).map(|s| s.id).collect();
        let before = self.list_findings().len();
        let mut scanned = 0usize;
        for id in ids {
            let Some(flow) = self.get_flow(id) else {
                continue;
            };
            let Some(res) = flow.response else {
                continue;
            };
            let host = flow
                .request
                .uri
                .host()
                .map(str::to_string)
                .or_else(|| {
                    flow.request
                        .headers
                        .get(HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let scheme = flow.request.uri.scheme_str().unwrap_or("https").to_string();
            let mime: Option<String> = res
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());
            scanned += 1;
            for hit in crate::scanner::scan(&scheme, &mime, &res.headers) {
                self.file_scan_hit(id, hit, &host).await;
            }
        }
        crate::scanner::ScanOutcome {
            scanned,
            filed: self.list_findings().len() - before,
        }
    }

    /// Replay a captured request straight at the target (not back through us),
    /// Burp-Repeater style, and return the fresh response.
    ///
    /// The replay is itself recorded as a new flow carrying `parent_id = id`,
    /// so a send and its origin stay linked instead of the result vanishing.
    pub async fn resend(&self, id: FlowId) -> Result<Resent, ResendError> {
        self.resend_as(id, None, None).await
    }

    /// [`Engine::resend`], optionally sent *as* an identity: the identity's
    /// cookie jar replaces the request's, so the replay is what that session
    /// would have sent. This is the access-control primitive — replay the same
    /// request under two identities and diff what answers.
    ///
    /// `tag` labels the replay with what it was *for* (`lead:idor-3`), so
    /// evidence can be filtered by the question that produced it.
    pub async fn resend_as(
        &self,
        id: FlowId,
        as_identity: Option<i64>,
        tag: Option<String>,
    ) -> Result<Resent, ResendError> {
        let flow = self.get_flow(id).ok_or(ResendError::NotFound(id))?;
        self.send_request(flow.request, Some(id), as_identity, tag)
            .await
    }

    /// Send an arbitrary request — typically one the operator edited in the
    /// Repeater — and record it as a new flow.
    ///
    /// `origin` links the send back to the flow it was derived from, so an
    /// edited replay still shows its lineage. `None` for a request composed from
    /// scratch. `as_identity` sends with that identity's cookie jar replacing
    /// the request's (see [`Engine::resend_as`]); `tag` labels the flow with
    /// its purpose.
    ///
    /// Every send passes the same gates, in order: scope, policy (forbidden
    /// URLs then the rate ceiling), identity. A refusal happens before anything
    /// is recorded — history only ever shows traffic that actually left.
    pub async fn send_request(
        &self,
        mut req: CapturedRequest,
        origin: Option<FlowId>,
        as_identity: Option<i64>,
        tag: Option<String>,
    ) -> Result<Resent, ResendError> {
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

        // Policy is the floor under every caller: TUI, MCP, agent verifier
        // alike. Checked before identity, so a forbidden URL never spends a
        // rate slot. Rules and ceiling are a handful of rows — cheap against
        // the cost of the send itself. A read failure degrades to permissive,
        // matching how every other engine read degrades: the engine still
        // works, it just does not throttle.
        let policy = self.with_db(|conn| crate::policy::get(conn).ok()).flatten();
        let rules = self
            .with_db(|conn| crate::policy::rules(conn).ok())
            .flatten();
        if let Some(rule) = rules
            .as_deref()
            .and_then(|r| crate::policy::violation(r, &url))
        {
            return Err(ResendError::Forbidden {
                rule_id: rule.id,
                pattern: rule.pattern,
                url,
            });
        }
        self.enforce_rate_limit(policy.as_ref(), &req)?;

        // Applied before the replay is recorded, so history shows the request
        // exactly as it went on the wire — the evidence must carry the identity.
        if let Some(identity_id) = as_identity {
            let identity = self
                .identity(identity_id)
                .ok_or(ResendError::IdentityNotFound(identity_id))?;
            let path = req
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let host = match req.uri.host() {
                Some(h) => h.to_string(),
                None => req
                    .headers
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string(),
            };
            identity::apply(&mut req.headers, &identity.cookies, &host, &path);
        }

        let replay_id = self.record_tagged(req.clone(), Source::Repeater, origin, tag);

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

    /// The same listing, narrowed to the active scope.
    pub fn query_flows_in_scope(&self, query: &FlowQuery, offset: i64, limit: i64) -> Vec<FlowRow> {
        let matcher = self.scope_matcher();
        self.read(|conn| read::flows_in_scope(conn, query, &matcher, offset, limit))
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

    /// Every note in the project, newest first.
    pub fn list_notes(&self) -> Vec<Note> {
        self.read(crate::note::list)
    }

    /// One note by id, or `None` if absent.
    pub fn get_note(&self, id: i64) -> Option<Note> {
        self.read(|conn| crate::note::get(conn, id))
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
    ///
    /// A finding that lands on a primitive the chain playbook knows also runs
    /// the chain pass (see [`crate::chain`]) after the write commits: severity
    /// lives in compositions, and the moment a new leg arrives next to the old
    /// ones is when the composition becomes visible. Scanner drafts go through
    /// here too, so capture-time findings chain as well.
    pub async fn create_finding(&self, finding: NewFinding) -> Result<i64, WriteError> {
        let (reply, rx) = oneshot::channel();
        self.write(WriteEvent::CreateFinding {
            finding: Box::new(finding.clone()),
            reply,
        });
        let id = rx.await.map_err(|_| WriteError::Dropped)?;
        if finding.status != "false_positive" {
            self.notifier
                .lock()
                .unwrap()
                .notify(crate::notify::Event::Finding {
                    severity: finding.severity.clone(),
                    title: finding.title.clone(),
                    host: finding.host.clone(),
                });
            let _ = self.with_db(|conn| {
                crate::chain::propose_for_finding(conn, id, &finding, now_micros())
            });
        }
        Ok(id)
    }

    /// Start a note, returning its new id once the row is durably committed.
    pub async fn create_note(&self, note: NewNote) -> Result<i64, WriteError> {
        let (reply, rx) = oneshot::channel();
        self.write(WriteEvent::CreateNote {
            note: Box::new(note),
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
