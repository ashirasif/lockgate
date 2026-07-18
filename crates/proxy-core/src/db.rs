//! Project database: schema, migrations, and on-disk layout.
//!
//! A project is a *directory*, not a single file:
//!
//! ```text
//! my-engagement/
//!   project.db        the schema below
//!   blobs/ab/cdef…    bodies too large to keep inline (see INLINE_BODY_LIMIT)
//! ```
//!
//! One database per project, with a separate registry listing them (see
//! `registry.rs`). The traffic tables reach millions of rows while everything
//! else stays in the thousands, so keeping projects in one file would put a
//! `project_id` prefix on the hot indexes forever to organise the small tables.
//! Per-project directories also make export `cp -r` and delete `rm -r`.
//!
//! Fidelity note: header blocks are stored as raw bytes rather than normalised
//! into a `(flow_id, name, value)` table. For a security tool the duplicates and
//! the ordering *are* the signal — that is what request smuggling and header
//! injection look like on the wire — and normalising destroys them. The scalar
//! columns alongside (`host`, `scheme`, `mime`, ...) are derived purely so list
//! views can filter and sort without parsing the blob; the blob is the truth.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// Bodies at or below this stay in the `body` table; larger ones spill to
/// `blobs/`. Keeps a 200MB download from landing in a SQLite row while leaving
/// the overwhelming majority of traffic inline where it is cheapest to read.
pub const INLINE_BODY_LIMIT: usize = 5 * 1024 * 1024;

/// Bumped whenever `MIGRATIONS` grows. Persisted in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 1;

/// Applied in order, starting from whatever `user_version` the file is at.
/// Append only — never edit a statement that has already shipped.
const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    -- One execution of the proxy. Named `capture_run` rather than `session`
    -- because "session" is badly overloaded here: a Replay session (a saved
    -- group of requests) and session handling (auth macros) are both different
    -- things that will want the word later.
    CREATE TABLE capture_run (
      id         INTEGER PRIMARY KEY,
      started_at INTEGER NOT NULL,
      ended_at   INTEGER
    );

    -- Bodies live apart from `flow` so that list queries (id, method, uri,
    -- status) never page in a 10MB response. Content-addressed because a crawl
    -- refetches the same JS bundle hundreds of times.
    CREATE TABLE body (
      id      INTEGER PRIMARY KEY,
      sha256  BLOB NOT NULL UNIQUE,
      len     INTEGER NOT NULL,
      -- inline: bytes are in `data`
      -- file:   bytes are at blobs/<sha256[0..2]>/<sha256>
      -- evicted: deliberately deleted to reclaim space. Distinct from "no body"
      --          on purpose — they read very differently in old history.
      storage TEXT NOT NULL DEFAULT 'inline',
      data    BLOB
    );

    CREATE TABLE flow (
      id           INTEGER PRIMARY KEY,
      run_id       INTEGER NOT NULL REFERENCES capture_run(id),
      -- proxy | repeater | automate | import.
      -- Automate runs put their results here too and are filtered out of the
      -- default history view by this column, rather than living in a side table.
      source       TEXT    NOT NULL,
      parent_id    INTEGER REFERENCES flow(id),
      started_at   INTEGER NOT NULL,
      ended_at     INTEGER,

      method       TEXT    NOT NULL,
      uri          TEXT    NOT NULL,
      http_version TEXT    NOT NULL,
      req_headers  BLOB    NOT NULL,
      req_body_id  INTEGER REFERENCES body(id),

      status       INTEGER,
      resp_headers BLOB,
      resp_body_id INTEGER REFERENCES body(id),

      host         TEXT    NOT NULL,
      scheme       TEXT    NOT NULL,
      path         TEXT    NOT NULL,
      mime         TEXT,
      resp_len     INTEGER,
      -- Not yet populated: the proxy handlers currently ignore `HttpContext`,
      -- which is the only source of the client address.
      client_addr  TEXT,
      error        TEXT,

      -- Triage. A scribble on a row, as distinct from `note` (a document).
      comment      TEXT,
      highlight    TEXT
    );

    -- Deliberately no `in_scope` column. Scope is mutable, so storing it would
    -- mean rewriting millions of rows on every rule edit; it is evaluated at
    -- query time against `host` instead.
    CREATE INDEX flow_run_time ON flow(run_id, started_at);
    CREATE INDEX flow_host     ON flow(host);
    CREATE INDEX flow_parent   ON flow(parent_id);
    CREATE INDEX flow_source   ON flow(source);

    -- Empty until `ProxyHandler::handle_message` records instead of forwarding.
    -- Shipped now so widening capture later needs no second migration.
    --
    -- `flow_id` points at the upgrade GET (the flow that got a 101), which is
    -- the only connection identity available: `WebSocketContext` carries just
    -- (client addr, server uri) and no connection id, so frames are matched to
    -- the most recent open upgrade for that pair. That is ambiguous if a client
    -- reconnects to the same endpoint rapidly.
    CREATE TABLE ws_message (
      id        INTEGER PRIMARY KEY,
      flow_id   INTEGER NOT NULL REFERENCES flow(id),
      seq       INTEGER NOT NULL,
      direction TEXT    NOT NULL,
      opcode    TEXT    NOT NULL,
      sent_at   INTEGER NOT NULL,
      body_id   INTEGER REFERENCES body(id)
    );
    CREATE INDEX ws_flow_seq ON ws_message(flow_id, seq);

    -- Materialised, not derived: a `SELECT DISTINCT host, path` over millions
    -- of flows per render is not viable, and nodes must be able to exist with
    -- no flow behind them (crawled or imported) and to own their own comment
    -- and scope membership. Spans capture runs — this is project knowledge.
    CREATE TABLE sitemap_node (
      id         INTEGER PRIMARY KEY,
      parent_id  INTEGER REFERENCES sitemap_node(id) ON DELETE CASCADE,
      kind       TEXT NOT NULL,   -- host | dir | leaf
      host       TEXT NOT NULL,
      path       TEXT NOT NULL,   -- full path from root; '' on host nodes
      name       TEXT NOT NULL,   -- this segment only, for display
      first_seen INTEGER NOT NULL,
      last_seen  INTEGER NOT NULL,
      flow_count INTEGER NOT NULL DEFAULT 0,
      origin     TEXT NOT NULL,   -- observed | manual | imported
      comment    TEXT,
      highlight  TEXT,
      UNIQUE (host, path)
    );
    CREATE INDEX sitemap_parent ON sitemap_node(parent_id);

    -- Named sets rather than one global list: you routinely want "all client
    -- assets" and "just the app I am testing now" and to switch between them.
    CREATE TABLE scope (
      id        INTEGER PRIMARY KEY,
      name      TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 0
    );

    -- Inclusion is the lever: no include rules means everything is in scope,
    -- and adding one narrows the view to matching assets. Excludes carve holes
    -- and always win over includes, so the result never depends on row order.
    CREATE TABLE scope_rule (
      id           INTEGER PRIMARY KEY,
      scope_id     INTEGER NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
      kind         TEXT NOT NULL,  -- host_glob | host_regex | cidr | path_prefix | port
      pattern      TEXT NOT NULL,
      action       TEXT NOT NULL,  -- include | exclude
      enabled      INTEGER NOT NULL DEFAULT 1,
      sort_order   INTEGER NOT NULL DEFAULT 0,
      -- Set when the rule was created by ticking a sitemap node, so the UI can
      -- show that checkbox state honestly and untick can remove the rule.
      from_node_id INTEGER REFERENCES sitemap_node(id) ON DELETE SET NULL
    );
    CREATE INDEX scope_rule_scope ON scope_rule(scope_id);

    -- Project-level markdown documents. Scribbles on individual rows go in the
    -- `comment` columns on `flow` / `sitemap_node` instead: a note is a
    -- document, a comment is an annotation, and conflating them would need a
    -- polymorphic link table SQLite cannot enforce.
    CREATE TABLE note (
      id         INTEGER PRIMARY KEY,
      title      TEXT NOT NULL,
      body_md    TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE finding (
      id             INTEGER PRIMARY KEY,
      title          TEXT NOT NULL,
      -- Independent of cvss_score on purpose: judgement overrides the vector,
      -- and plenty of findings never get a vector at all.
      severity       TEXT NOT NULL,   -- info|low|medium|high|critical
      status         TEXT NOT NULL,   -- draft|confirmed|false_positive|reported|fixed|wont_fix
      cvss_vector    TEXT,
      -- Pure function of the vector, but stored: it is sorted and filtered on
      -- constantly and SQLite cannot compute it.
      cvss_score     REAL,
      cvss_version   TEXT,
      cwe            TEXT,
      description_md TEXT NOT NULL,
      repro_md       TEXT,
      impact_md      TEXT,
      remediation_md TEXT,
      host           TEXT,
      path           TEXT,
      created_at     INTEGER NOT NULL,
      updated_at     INTEGER NOT NULL,
      -- manual | workflow. Distinguishes "the tool thinks" from "I verified"
      -- once passive rules can raise findings.
      origin         TEXT NOT NULL DEFAULT 'manual'
    );
    CREATE INDEX finding_severity ON finding(severity);
    CREATE INDEX finding_status   ON finding(status);

    -- Many-to-many: a good finding usually needs a baseline flow and an
    -- exploited flow to demonstrate the difference.
    CREATE TABLE finding_evidence (
      finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
      flow_id    INTEGER NOT NULL REFERENCES flow(id),
      label      TEXT,
      PRIMARY KEY (finding_id, flow_id)
    );

    CREATE TABLE saved_filter (
      id         INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      query      TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0
    );
    "#,
];

/// Where a project's files live.
#[derive(Clone, Debug)]
pub struct ProjectPaths {
    pub root: PathBuf,
}

impl ProjectPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn db(&self) -> PathBuf {
        self.root.join("project.db")
    }

    pub fn blobs(&self) -> PathBuf {
        self.root.join("blobs")
    }

    /// Sharded by the first byte of the digest: a flat directory of hundreds of
    /// thousands of blobs is slow to list and unpleasant on some filesystems.
    pub fn blob(&self, sha256: &[u8]) -> PathBuf {
        let hex = hex(sha256);
        self.blobs().join(&hex[0..2]).join(&hex)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Open (creating if needed) a project, bringing its schema up to date.
pub fn open_project(paths: &ProjectPaths) -> rusqlite::Result<Connection> {
    std::fs::create_dir_all(paths.blobs()).map_err(io_err)?;
    let conn = open(&paths.db())?;
    Ok(conn)
}

/// Open a database file and migrate it. Used for projects and the registry.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;

    // WAL gives us one writer concurrent with many readers, which is exactly
    // the shape here: a single writer task, with the TUI reading freely.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // NORMAL rather than FULL: on a crash we may lose the last transaction of
    // captured traffic, which is a fair trade for not fsyncing every batch.
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    migrate(&conn, MIGRATIONS, SCHEMA_VERSION)?;
    Ok(conn)
}

pub(crate) fn migrate(
    conn: &Connection,
    migrations: &[&str],
    latest: i64,
) -> rusqlite::Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

    if current > latest {
        // Older binary, newer file. Refusing beats silently misreading it.
        return Err(rusqlite::Error::InvalidPath(
            format!("database schema v{current} is newer than supported v{latest}").into(),
        ));
    }

    for (i, migration) in migrations.iter().enumerate().skip(current as usize) {
        conn.execute_batch(migration)?;
        conn.pragma_update(None, "user_version", (i + 1) as i64)?;
    }

    Ok(())
}

pub(crate) fn io_err(e: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::InvalidPath(e.to_string().into())
}

/// Start a capture run for this proxy execution and return its id.
pub fn begin_run(conn: &Connection, started_at: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO capture_run (started_at) VALUES (?1)",
        [started_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Flow ids are handed out in memory (the proxy handler needs one synchronously,
/// before the writer task has touched the disk), so on reopen we must continue
/// past whatever is already stored rather than colliding with it.
pub fn next_flow_id(conn: &Connection) -> rusqlite::Result<u64> {
    conn.query_row("SELECT COALESCE(MAX(id), -1) + 1 FROM flow", [], |r| {
        r.get::<_, i64>(0)
    })
    .map(|id| id as u64)
}
