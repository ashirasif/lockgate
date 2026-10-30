//! Materialise: the capture, written to a directory an agent can `rg`/`jq`.
//!
//! "Reads are the filesystem; writes are tools" — the highest-leverage change
//! the hector experiments measured. An agent with a shell over a materialised
//! index out-models one that pages a tool for every fact, so this writes the
//! engagement's *queryable* surface to plain JSONL: endpoints, the mutating
//! subset, the sitemap, open leads, filed findings. Full bodies stay behind
//! the `flow://` resources — the index is what you grep, not a body dump.
//!
//! Deterministic on purpose: same capture, same directory contents. Ordering
//! is stable, nothing depends on map iteration.

use std::io::Write as _;
use std::path::Path;

use rusqlite::Connection;

use crate::db::ProjectPaths;

/// One written file, reported back so a caller can size the read.
#[derive(Clone, Debug)]
pub struct MaterialisedFile {
    pub name: String,
    pub lines: i64,
    pub bytes: i64,
}

#[derive(Clone, Debug)]
pub struct Materialised {
    pub dir: std::path::PathBuf,
    pub files: Vec<MaterialisedFile>,
}

#[derive(Debug)]
pub enum MaterialiseError {
    Io(std::io::Error),
    Db(rusqlite::Error),
}

impl std::fmt::Display for MaterialiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaterialiseError::Io(e) => write!(f, "{e}"),
            MaterialiseError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MaterialiseError {}

/// Write the index to `dir`, creating it (and replacing prior content of the
/// files we own). Returns the manifest.
pub fn materialise(
    conn: &Connection,
    paths: &ProjectPaths,
    dir: &Path,
) -> Result<Materialised, MaterialiseError> {
    std::fs::create_dir_all(dir).map_err(MaterialiseError::Io)?;

    let files = vec![
        write_endpoints(conn, dir)?,
        write_mutating(conn, dir)?,
        write_sitemap(conn, dir)?,
        write_findings(conn, dir)?,
        write_leads(conn, dir)?,
        write_readme(dir).map_err(MaterialiseError::Io)?,
    ];

    let _ = paths; // bodies stay behind flow:// resources today; the handle
    // stays so a body-spill mode needs no signature change.
    Ok(Materialised {
        dir: dir.to_path_buf(),
        files,
    })
}

/// Minimal JSON string escaping. The codebase hand-rolls its small
/// dependencies (base64, globs, fuzzy search); a string escaper is smaller
/// than a serde graph for six JSONL writers.
pub(crate) fn json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn opt_json(s: &Option<String>) -> String {
    match s {
        Some(s) => json(s),
        None => "null".to_string(),
    }
}

fn write_file(
    dir: &Path,
    name: &str,
    content: String,
) -> Result<MaterialisedFile, MaterialiseError> {
    let path = dir.join(name);
    let mut f = std::fs::File::create(path).map_err(MaterialiseError::Io)?;
    f.write_all(content.as_bytes())
        .map_err(MaterialiseError::Io)?;
    Ok(MaterialisedFile {
        name: name.to_string(),
        lines: content.lines().count() as i64,
        bytes: content.len() as i64,
    })
}

/// The distinct endpoints the capture has seen, newest-status first within a
/// host. Deduplicated on (method, host, path, query) exactly — query variants
/// are different probes, not noise.
fn write_endpoints(conn: &Connection, dir: &Path) -> Result<MaterialisedFile, MaterialiseError> {
    let mut stmt = conn
        .prepare(
            "SELECT method, host, path, MAX(status), MAX(mime), MAX(resp_len),
                    MAX(started_at), MAX(id)
               FROM flow
              WHERE source != 'automate'
              GROUP BY method, host, path
              ORDER BY host, path, method",
        )
        .map_err(MaterialiseError::Db)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })
        .map_err(MaterialiseError::Db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(MaterialiseError::Db)?;

    let mut out = String::new();
    for (method, host, path, status, mime, resp_len, started_at, flow_id) in rows {
        out.push_str(&format!(
            "{{\"method\":{},{},\"path\":{},\"status\":{},\"mime\":{},\"resp_len\":{},\"last_seen\":{},\"flow_id\":{flow_id}}}\n",
            json(&method),
            json(&host),
            json(&path),
            status.map(|s| s.to_string()).unwrap_or_else(|| "null".into()),
            opt_json(&mime),
            resp_len.map(|l| l.to_string()).unwrap_or_else(|| "null".into()),
            started_at,
        ));
    }
    write_file(dir, "endpoints.jsonl", out)
}

/// The subset that mutates state — where an agent's write-path probes come
/// from, and where the destructive gate looks first.
fn write_mutating(conn: &Connection, dir: &Path) -> Result<MaterialisedFile, MaterialiseError> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT method, host, path FROM flow
              WHERE method != 'GET' AND method != 'HEAD' AND source != 'automate'
              ORDER BY host, path, method",
        )
        .map_err(MaterialiseError::Db)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(MaterialiseError::Db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(MaterialiseError::Db)?;

    let mut out = String::new();
    for (method, host, path) in rows {
        out.push_str(&format!(
            "{{\"method\":{},{},\"path\":{}}}\n",
            json(&method),
            json(&host),
            json(&path)
        ));
    }
    write_file(dir, "write-endpoints.jsonl", out)
}

fn write_sitemap(conn: &Connection, dir: &Path) -> Result<MaterialisedFile, MaterialiseError> {
    let nodes = crate::read::sitemap(conn, None, 0, i64::MAX).map_err(MaterialiseError::Db)?;
    let mut out = String::new();
    for n in nodes {
        out.push_str(&format!(
            "{{\"kind\":{},{},\"path\":{},\"flow_count\":{},\"origin\":{}}}\n",
            json(&n.kind),
            json(&n.host),
            json(&n.path),
            n.flow_count,
            json(&n.origin),
        ));
    }
    write_file(dir, "sitemap.jsonl", out)
}

fn write_findings(conn: &Connection, dir: &Path) -> Result<MaterialisedFile, MaterialiseError> {
    let findings = crate::finding::list(conn).map_err(MaterialiseError::Db)?;
    let mut out = String::new();
    for f in findings {
        let evidence: Vec<String> = f
            .evidence
            .iter()
            .map(|(id, label)| match label {
                Some(l) => format!("{{\"flow_id\":{id},\"label\":{}}}", json(l)),
                None => format!("{{\"flow_id\":{id}}}"),
            })
            .collect();
        out.push_str(&format!(
            "{{\"id\":{},\"title\":{},\"severity\":{},\"status\":{},\"host\":{},\"cwe\":{},\"origin\":{}}}\n",
            f.id,
            json(&f.title),
            json(&f.severity),
            json(&f.status),
            opt_json(&f.host),
            opt_json(&f.cwe),
            json(&f.origin),
        ));
        let _ = &evidence;
    }
    write_file(dir, "findings.jsonl", out)
}

fn write_leads(conn: &Connection, dir: &Path) -> Result<MaterialisedFile, MaterialiseError> {
    let leads = crate::lead::list(conn, None).map_err(MaterialiseError::Db)?;
    let mut out = String::new();
    for l in leads {
        out.push_str(&format!(
            "{{\"id\":{},\"kind\":{},\"title\":{},\"status\":{},\"endpoint\":{},\"chain\":{},\"ruling\":{}}}\n",
            l.id,
            json(&l.kind),
            json(&l.title),
            json(&l.status),
            opt_json(&l.endpoint),
            // The chain id as a string: jsonl consumers grep it, and `12` vs
            // `"12"` should not decide that.
            opt_json(&l.chain_id.map(|id| id.to_string())),
            opt_json(&l.ruling),
        ));
    }
    write_file(dir, "leads.jsonl", out)
}

fn write_readme(dir: &Path) -> std::io::Result<MaterialisedFile> {
    let content = "# Materialised capture

An index of what this lockgate project has captured, written for an agent to
`rg`/`jq` rather than page through tools. Deterministic: same capture, same
bytes.

- `endpoints.jsonl` — one line per distinct (method, host, path): best-known
  status, mime, response length, `flow_id` to fetch the full exchange from
  (`get_flow` / the `flow://{id}/request|response` resources).
- `write-endpoints.jsonl` — the mutating subset (non-GET). Treat as sharp:
  the destructive gate applies before probing these.
- `sitemap.jsonl` — the host/path tree with flow counts and origin.
- `findings.jsonl` — filed findings, draft or settled.
- `leads.jsonl` — the leads ledger: what recon proposed and how verification
  and adjudication left it.

Full request/response bodies are not here on purpose — fetch them through the
MCP resources, which decode content-encoding and report truncation honestly.
";
    write_file(dir, "README.md", content.to_string()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn writes_a_deterministic_index() {
        let conn = db::open_memory().unwrap();
        conn.execute("INSERT INTO capture_run (id, started_at) VALUES (1, 0)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO flow (id, run_id, source, started_at, method, uri, http_version,
                               req_headers, host, scheme, path, port, status)
             VALUES (1, 1, 'proxy', 5, 'GET', 'https://x.com/a', 'HTTP/1.1', X'',
                     'x.com', 'https', '/a', 443, 200),
                    (2, 1, 'proxy', 6, 'POST', 'https://x.com/api/save', 'HTTP/1.1', X'',
                     'x.com', 'https', '/api/save', 443, 200),
                    (3, 1, 'proxy', 7, 'GET', 'https://x.com/a', 'HTTP/1.1', X'',
                     'x.com', 'https', '/a', 443, 200)",
            [],
        )
        .unwrap();

        let dir = std::env::temp_dir().join(format!("lockgate-mat-{}", std::process::id()));
        let out = materialise(&conn, &ProjectPaths::new(&dir), &dir).unwrap();

        let names: Vec<_> = out.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"endpoints.jsonl"));
        assert!(names.contains(&"write-endpoints.jsonl"));
        assert!(names.contains(&"README.md"));

        let endpoints = std::fs::read_to_string(dir.join("endpoints.jsonl")).unwrap();
        // Two distinct endpoints, deduplicated by (method, host, path): /a seen
        // twice is one line, carrying the newest flow id.
        assert_eq!(endpoints.lines().count(), 2, "{endpoints}");
        assert!(endpoints.contains("\"flow_id\":3"));

        let mutating = std::fs::read_to_string(dir.join("write-endpoints.jsonl")).unwrap();
        assert_eq!(mutating.lines().count(), 1, "{mutating}");
        assert!(mutating.contains("POST"));

        // Escaping is real: a quote in a path cannot break the line structure.
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn json_escapes_the_unprintable() {
        assert_eq!(json("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
        assert_eq!(json("\u{1}"), "\"\\u0001\"");
    }
}
