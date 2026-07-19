//! The persistence write path.
//!
//! Capture must never block on the disk, so `Engine` only pushes events onto an
//! unbounded channel; a single background task drains it and writes. That task
//! is the only writer in the process, which is what lets WAL mode do its job.

use std::sync::Mutex;

use hudsucker::hyper::header::{CONTENT_TYPE, HOST};
use hudsucker::hyper::{HeaderMap, Uri};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::db::{INLINE_BODY_LIMIT, ProjectPaths};
use crate::finding::NewFinding;
use crate::model::{CapturedRequest, CapturedResponse, FlowId, now_micros};

/// How many events to fold into a single transaction. Purely a bound on how
/// much work one failed batch can lose.
const MAX_BATCH: usize = 256;

/// A batch can fail on either the database or the blob spill, and the two are
/// worth telling apart in the log — a full disk reads very differently from a
/// constraint violation.
#[derive(Debug)]
pub enum WriteError {
    Db(rusqlite::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Db(e) => write!(f, "database: {e}"),
            WriteError::Io(e) => write!(f, "blob storage: {e}"),
        }
    }
}

impl From<rusqlite::Error> for WriteError {
    fn from(e: rusqlite::Error) -> Self {
        WriteError::Db(e)
    }
}

impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        WriteError::Io(e)
    }
}

/// Where a flow came from. Stored as text so the values stay readable in
/// `sqlite3` and adding a variant needs no migration.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    Proxy,
    Repeater,
    /// Automate/Intruder results share `flow` with everything else and are kept
    /// out of the default history view by this column, rather than by living in
    /// a separate table.
    Automate,
    Import,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Proxy => "proxy",
            Source::Repeater => "repeater",
            Source::Automate => "automate",
            Source::Import => "import",
        }
    }
}

pub enum WriteEvent {
    Request {
        id: FlowId,
        source: Source,
        /// Set for Repeater resends: the flow this one was replayed from.
        parent_id: Option<FlowId>,
        started_at: i64,
        request: CapturedRequest,
    },
    Response {
        id: FlowId,
        ended_at: i64,
        response: CapturedResponse,
    },
    /// Set a flow's triage comment and/or highlight. `None` leaves that column
    /// unchanged; `Some` sets it (an empty string clears it to the empty string).
    ///
    /// The reply carries the number of rows changed, so the caller can tell an
    /// applied annotation from an unknown flow id. If the batch fails to commit
    /// the sender is dropped, which the caller observes as a closed channel.
    Annotate {
        id: FlowId,
        comment: Option<String>,
        highlight: Option<String>,
        reply: oneshot::Sender<u64>,
    },
    /// Author a finding. The reply carries the new finding's id, released only
    /// once the row is durably committed.
    CreateFinding {
        finding: Box<NewFinding>,
        reply: oneshot::Sender<i64>,
    },
    /// Commit whatever is already queued, then stop. Sent by `shutdown`.
    Stop,
}

/// A reply that must not be answered until the batch that produced it commits:
/// handing back a finding id (or an annotation ack) before the write is durable
/// would let a reader chase a row that a rollback then erased.
enum Pending {
    Annotate(oneshot::Sender<u64>, u64),
    Finding(oneshot::Sender<i64>, i64),
}

impl Pending {
    fn fulfil(self) {
        // A gone receiver just means the caller stopped waiting; nothing to do.
        match self {
            Pending::Annotate(tx, rows) => {
                let _ = tx.send(rows);
            }
            Pending::Finding(tx, id) => {
                let _ = tx.send(id);
            }
        }
    }
}

/// Handle held by `Engine`.
pub struct WriteHandle {
    tx: UnboundedSender<WriteEvent>,
    /// Taken by `shutdown` so the writer can be joined exactly once.
    join: Mutex<Option<JoinHandle<()>>>,
}

impl WriteHandle {
    /// Never blocks and never fails loudly: losing history is not worth
    /// stalling or killing a proxied connection over.
    pub fn send(&self, event: WriteEvent) {
        if self.tx.send(event).is_err() {
            warn!("history writer is gone; dropping event");
        }
    }

    /// Flush every queued event and wait for the writer to finish.
    ///
    /// Uses an explicit `Stop` event rather than dropping the sender: `Engine`
    /// lives behind an `Arc`, so taking the sender back out would mean putting
    /// a lock on the capture path to serve a once-per-process operation.
    ///
    /// Idempotent — a second call finds the join handle already taken.
    pub async fn shutdown(&self) {
        let handle = self.join.lock().unwrap().take();
        let Some(handle) = handle else { return };

        // If the writer already died the send fails, but the join still
        // reports how, so there is nothing to bail out for here.
        let _ = self.tx.send(WriteEvent::Stop);

        if let Err(e) = handle.await {
            error!(error = %e, "history writer did not shut down cleanly");
        }
    }
}

/// Open the database, start a session, and spawn the writer.
///
/// Returns the handle plus the id the in-memory allocator should resume from,
/// so reopening an existing file continues past the stored flows.
pub fn spawn(paths: &ProjectPaths, started_at: i64) -> rusqlite::Result<(WriteHandle, FlowId)> {
    let conn = crate::db::open_project(paths)?;
    let run_id = crate::db::begin_run(&conn, started_at)?;
    let next_id = crate::db::next_flow_id(&conn)?;

    let (tx, rx) = unbounded_channel();

    let paths = paths.clone();
    // rusqlite is synchronous, so the writer lives on a blocking thread rather
    // than occupying a runtime worker for the duration of every fsync.
    let join = tokio::task::spawn_blocking(move || run(conn, paths, run_id, rx));

    Ok((
        WriteHandle {
            tx,
            join: Mutex::new(Some(join)),
        },
        next_id,
    ))
}

fn run(
    mut conn: Connection,
    paths: ProjectPaths,
    run_id: i64,
    mut rx: UnboundedReceiver<WriteEvent>,
) {
    // Block for the first event, then sweep up everything that queued while the
    // previous transaction was committing. Under load this coalesces naturally;
    // when idle it commits immediately instead of waiting out a timer.
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }

        // `Stop` is only ever the last thing sent, so anything ahead of it in
        // this batch still gets committed before we go.
        let stopping = batch
            .iter()
            .any(|event| matches!(event, WriteEvent::Stop));

        let count = batch.len();
        if let Err(e) = write_batch(&mut conn, &paths, run_id, batch) {
            // Keep serving: a lost batch of history beats a dead writer that
            // silently drops everything from here on.
            error!(error = %e, count, "failed to persist batch");
        }

        if stopping {
            break;
        }
    }
}

fn write_batch(
    conn: &mut Connection,
    paths: &ProjectPaths,
    run_id: i64,
    batch: Vec<WriteEvent>,
) -> Result<(), WriteError> {
    let tx = conn.transaction()?;

    // Replies held back until the commit below succeeds. If any `?` below fires,
    // or the commit fails, this vec drops with its senders unanswered, and every
    // waiting caller sees a closed channel — the correct signal that its write
    // did not land.
    let mut pending: Vec<Pending> = Vec::new();

    for event in batch {
        match event {
            WriteEvent::Request {
                id,
                source,
                parent_id,
                started_at,
                request,
            } => {
                let body_id = intern_body(&tx, paths, &request.body)?;
                let (scheme, host, port, path) = target_parts(&request);

                tx.execute(
                    "INSERT INTO flow (
                        id, run_id, source, parent_id, started_at,
                        method, uri, http_version, req_headers, req_body_id,
                        host, scheme, path, port
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                    params![
                        id as i64,
                        run_id,
                        source.as_str(),
                        parent_id.map(|p| p as i64),
                        started_at,
                        request.method.as_str(),
                        request.uri.to_string(),
                        format!("{:?}", request.version),
                        encode_headers(&request.headers),
                        body_id,
                        &host,
                        scheme,
                        &path,
                        port,
                    ],
                )?;

                // Same transaction as the flow insert, so the tree can never
                // disagree with the traffic it was built from.
                touch_sitemap(&tx, &host, &path, started_at)?;
            }

            WriteEvent::Response {
                id,
                ended_at,
                response,
            } => {
                let body_id = intern_body(&tx, paths, &response.body)?;
                let mime = response
                    .headers
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    // "text/html; charset=utf-8" -> "text/html"
                    .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());

                tx.execute(
                    "UPDATE flow
                        SET ended_at = ?1, status = ?2, resp_headers = ?3,
                            resp_body_id = ?4, mime = ?5, resp_len = ?6
                      WHERE id = ?7",
                    params![
                        ended_at,
                        response.status.as_u16(),
                        encode_headers(&response.headers),
                        body_id,
                        mime,
                        response.body.len() as i64,
                        id as i64,
                    ],
                )?;
            }

            WriteEvent::Annotate {
                id,
                comment,
                highlight,
                reply,
            } => {
                let rows = annotate(&tx, id, comment.as_deref(), highlight.as_deref())?;
                pending.push(Pending::Annotate(reply, rows as u64));
            }

            WriteEvent::CreateFinding { finding, reply } => {
                let finding_id = crate::finding::insert(&tx, &finding, now_micros())?;
                pending.push(Pending::Finding(reply, finding_id));
            }

            // Nothing to write; it only exists to break the drain loop.
            WriteEvent::Stop => {}
        }
    }

    tx.commit()?;

    // Durable now: release every held-back reply.
    for reply in pending {
        reply.fulfil();
    }
    Ok(())
}

/// Update a flow's triage columns in place, touching only the ones provided.
/// Returns the number of rows changed (0 for an unknown id).
fn annotate(
    conn: &Connection,
    id: FlowId,
    comment: Option<&str>,
    highlight: Option<&str>,
) -> rusqlite::Result<usize> {
    // Build the SET list from whichever columns were supplied, so passing only a
    // comment does not blank an existing highlight.
    let mut sets: Vec<&str> = Vec::new();
    let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::new();
    if let Some(comment) = &comment {
        sets.push("comment = ?");
        binds.push(comment);
    }
    if let Some(highlight) = &highlight {
        sets.push("highlight = ?");
        binds.push(highlight);
    }
    if sets.is_empty() {
        return Ok(0);
    }

    let id = id as i64;
    binds.push(&id);
    let sql = format!("UPDATE flow SET {} WHERE id = ?", sets.join(", "));
    conn.execute(&sql, rusqlite::params_from_iter(binds))
}

/// Insert a body if we have not seen these exact bytes before, returning its id.
/// Empty bodies get no row at all — `NULL` says "nothing" more cheaply.
///
/// Bodies over `INLINE_BODY_LIMIT` are written to `blobs/` and the row keeps
/// only the digest and length, so a large download never lands in a SQLite row.
fn intern_body(
    conn: &Connection,
    paths: &ProjectPaths,
    body: &[u8],
) -> Result<Option<i64>, WriteError> {
    if body.is_empty() {
        return Ok(None);
    }

    let digest = Sha256::digest(body);
    let digest = digest.as_slice();

    // The common case for a crawl is a hit: same asset fetched over and over.
    if let Some(id) = conn
        .query_row("SELECT id FROM body WHERE sha256 = ?1", [digest], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?
    {
        return Ok(Some(id));
    }

    if body.len() > INLINE_BODY_LIMIT {
        spill_to_disk(paths, digest, body)?;
        conn.execute(
            "INSERT INTO body (sha256, len, storage, data) VALUES (?1, ?2, 'file', NULL)",
            params![digest, body.len() as i64],
        )?;
    } else {
        conn.execute(
            "INSERT INTO body (sha256, len, storage, data) VALUES (?1, ?2, 'inline', ?3)",
            params![digest, body.len() as i64, body],
        )?;
    }

    Ok(Some(conn.last_insert_rowid()))
}

/// Write a blob content-addressed. Via a temp file and rename so a crash cannot
/// leave a half-written body that its digest claims is complete.
fn spill_to_disk(paths: &ProjectPaths, digest: &[u8], body: &[u8]) -> std::io::Result<()> {
    let final_path = paths.blob(digest);
    if final_path.exists() {
        // Content-addressed: same digest means same bytes, nothing to do.
        return Ok(());
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = final_path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &final_path)
}

/// Upsert the host → directory → leaf chain for a request, bumping counts.
///
/// Every ancestor is counted, so a host node's `flow_count` is the total for
/// that host and the UI needs no recursive aggregate to render the tree.
fn touch_sitemap(conn: &Connection, host: &str, path: &str, now: i64) -> rusqlite::Result<()> {
    if host.is_empty() {
        return Ok(());
    }

    let mut parent = upsert_node(conn, None, "host", host, "", host, now)?;

    // "/a/b/c" -> ["a", "b", "c"]; the last segment is the leaf, the rest dirs.
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut full = String::new();

    for (i, segment) in segments.iter().enumerate() {
        full.push('/');
        full.push_str(segment);
        let kind = if i == segments.len() - 1 {
            "leaf"
        } else {
            "dir"
        };
        parent = upsert_node(conn, Some(parent), kind, host, &full, segment, now)?;
    }

    Ok(())
}

fn upsert_node(
    conn: &Connection,
    parent_id: Option<i64>,
    kind: &str,
    host: &str,
    path: &str,
    name: &str,
    now: i64,
) -> rusqlite::Result<i64> {
    conn.query_row(
        "INSERT INTO sitemap_node
            (parent_id, kind, host, path, name, first_seen, last_seen, flow_count, origin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1, 'observed')
         ON CONFLICT(host, path) DO UPDATE SET
            last_seen  = excluded.last_seen,
            flow_count = flow_count + 1,
            -- A node guessed as a directory that later gets requested directly
            -- is really a leaf; promote it rather than leaving the tree lying.
            kind       = CASE WHEN excluded.kind = 'leaf' THEN 'leaf' ELSE kind END
         RETURNING id",
        params![parent_id, kind, host, path, name, now],
        |r| r.get(0),
    )
}

/// Serialise a header block back to its wire form, preserving order and
/// duplicates. Original casing is *not* preserved: `HeaderMap` lowercases names
/// on parse, so it is already gone before we see it.
fn encode_headers(headers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Split the request target into the columns list views filter on.
///
/// Derived once, here, rather than recomputed at read time: if the fallback
/// guesses wrong the wrong value is at least visible in the data instead of
/// hidden inside a function.
///
/// The port is always resolved, falling back to the scheme default, so a scope
/// rule constraining a port means the same thing whether or not the client
/// wrote `:443` out.
fn target_parts(req: &CapturedRequest) -> (String, String, u16, String) {
    let uri: &Uri = &req.uri;
    let path = uri
        .path_and_query()
        .map(|pq| pq.path().to_string())
        .unwrap_or_else(|| "/".to_string());

    if let Some(host) = uri.host() {
        let scheme = uri.scheme_str().unwrap_or("http").to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        return (scheme, host.to_string(), port, path);
    }

    // Origin-form target: the host only exists in the `Host` header. We assume
    // https because plain-HTTP requests reach us in absolute-form and would
    // have taken the branch above.
    let raw = req.headers.get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    // A Host header may carry a port ("example.com:8443"); split it back out so
    // it lands in `port` rather than corrupting `host`.
    let (host, port) = match raw.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            // Not a port — most likely a bare IPv6 literal.
            Err(_) => (raw.to_string(), 443),
        },
        None => (raw.to_string(), 443),
    };
    ("https".to_string(), host, port, path)
}
