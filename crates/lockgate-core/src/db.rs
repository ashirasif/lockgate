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
const SCHEMA_VERSION: i64 = 3;

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
    // v2 — scope rules become conjunctions.
    //
    // v1 gave each rule a single (kind, pattern), so rules could only ever OR
    // together: "host *.linear.app" and "path /api" meant linear.app *or*
    // anything under /api anywhere, when what scoping a sitemap directory needs
    // is the intersection. A rule is now a set of optional constraints that must
    // all hold, which is also how Burp models scope (protocol/host/port/file).
    //
    // Dropping rather than migrating rows: nothing ever wrote to the v1 table.
    r#"
    DROP TABLE scope_rule;

    CREATE TABLE scope_rule (
      id           INTEGER PRIMARY KEY,
      scope_id     INTEGER NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
      action       TEXT NOT NULL,   -- include | exclude

      -- Each constraint is optional; NULL means "any". A rule matches a request
      -- only when every non-NULL constraint matches it.
      host_kind    TEXT,            -- glob | regex | cidr
      host_pattern TEXT,
      port         INTEGER,
      path_prefix  TEXT,

      enabled      INTEGER NOT NULL DEFAULT 1,
      sort_order   INTEGER NOT NULL DEFAULT 0,
      -- Set when the rule came from ticking a sitemap node, so the UI can show
      -- that checkbox state honestly and unticking can remove the rule.
      from_node_id INTEGER REFERENCES sitemap_node(id) ON DELETE SET NULL,

      -- host_kind and host_pattern are meaningful only together.
      CHECK ((host_kind IS NULL) = (host_pattern IS NULL))
    );
    CREATE INDEX scope_rule_scope ON scope_rule(scope_id);
    CREATE INDEX scope_rule_node  ON scope_rule(from_node_id);

    -- Needed for port constraints to be evaluable at all. Backfilled from the
    -- scheme default, which is what the old rows would have used implicitly.
    ALTER TABLE flow ADD COLUMN port INTEGER;
    UPDATE flow SET port = CASE scheme WHEN 'https' THEN 443 ELSE 80 END;
    "#,
    // v3
    //
    // Covering indexes for the history lists, which the TUI re-runs on every
    // 50ms tick. Without them both queries fall back to a table scan, and `flow`
    // stores `req_headers` / `resp_headers` as inline BLOBs — so listing 19k
    // flows dragged a 255MB table through the page cache 20 times a second, for
    // five small columns. The cost grew with the capture until it dominated a
    // whole core.
    //
    // Both indexes carry exactly the `list_flows` projection and lead with
    // `id DESC`, so each query is answered by an ordered scan of the index alone
    // — no table rows, and no sort for the ORDER BY.
    r#"
    -- Carries the scope columns as well, so the scope-filtered variant of the
    -- list (which additionally selects host/port/path) is covered by the same
    -- index rather than dropping back to a table scan.
    CREATE INDEX flow_list ON flow(id DESC, status, method, uri, started_at, host, port, path);

    -- WebSockets are a fraction of a percent of traffic, so the partial index
    -- is tiny and the `status = 101` list becomes near-free. The HTTP side
    -- can't have the mirror of this: `status IS NULL OR status != 101` is a
    -- negation SQLite won't turn into a seek, which is why `flow_list` above
    -- is built to be scanned rather than searched.
    CREATE INDEX flow_ws ON flow(id DESC, method, uri, started_at) WHERE status = 101;
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
        Self::blob_in(&self.blobs(), sha256)
    }

    /// The blob path under an explicit `blobs/` root. Same sharding as `blob`,
    /// for callers (reads) that hold the root directly rather than a `ProjectPaths`.
    pub fn blob_in(blobs_root: &Path, sha256: &[u8]) -> PathBuf {
        let hex = hex(sha256);
        blobs_root.join(&hex[0..2]).join(&hex)
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
    // WAL allows one writer at a time. Capture batches are short, but a scope
    // edit arriving mid-batch would otherwise fail outright rather than wait a
    // few milliseconds for it.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;

    migrate(&conn, MIGRATIONS, SCHEMA_VERSION)?;
    Ok(conn)
}

/// A migrated in-memory database, backing `Engine::new`. Nothing survives the
/// process, and there is no WAL (it is meaningless for `:memory:`): the engine
/// writes to it synchronously on one connection, so the record→read contract the
/// tests rely on holds without a background writer.
pub fn open_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn, MIGRATIONS, SCHEMA_VERSION)?;
    Ok(conn)
}

pub(crate) fn migrate(conn: &Connection, migrations: &[&str], latest: i64) -> rusqlite::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Projects created before the conjunction rewrite must upgrade in place,
    /// not just work when created fresh. Applies v1 alone, then migrates.
    #[test]
    fn upgrades_a_v1_project_to_latest() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();

        // A v1 flow, written the way the old code did: no port column existed.
        conn.execute("INSERT INTO capture_run (id, started_at) VALUES (1, 0)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO flow (id, run_id, source, started_at, method, uri,
                               http_version, req_headers, host, scheme, path)
             VALUES (1, 1, 'proxy', 0, 'GET', 'https://x.com/a', 'HTTP/1.1',
                     X'', 'x.com', 'https', '/a'),
                    (2, 1, 'proxy', 0, 'GET', 'http://y.com/b', 'HTTP/1.1',
                     X'', 'y.com', 'http', '/b')",
            [],
        )
        .unwrap();

        migrate(&conn, MIGRATIONS, SCHEMA_VERSION).unwrap();

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Existing rows keep their data and get a port backfilled from scheme.
        let ports: Vec<i64> = conn
            .prepare("SELECT port FROM flow ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(ports, vec![443, 80], "port must be backfilled per scheme");

        // scope_rule is the new conjunction shape.
        conn.execute("INSERT INTO scope (id, name) VALUES (1, 's')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO scope_rule (scope_id, action, host_kind, host_pattern, path_prefix)
             VALUES (1, 'include', 'glob', '*.x.com', '/api')",
            [],
        )
        .unwrap();

        // The CHECK must reject a half-specified host constraint.
        assert!(
            conn.execute(
                "INSERT INTO scope_rule (scope_id, action, host_kind) VALUES (1, 'include', 'glob')",
                [],
            )
            .is_err(),
            "host_kind without host_pattern should violate the CHECK"
        );
    }

    /// Migrating twice must be a no-op, not a re-application.
    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn, MIGRATIONS, SCHEMA_VERSION).unwrap();
        migrate(&conn, MIGRATIONS, SCHEMA_VERSION).unwrap();

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// A file written by a newer binary must be refused, not misread.
    #[test]
    fn refuses_a_future_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99i64).unwrap();
        assert!(migrate(&conn, MIGRATIONS, SCHEMA_VERSION).is_err());
    }
}
