//! DB-backed reads for frontends (TUI, MCP).
//!
//! Capture writes go through the writer task; these are the other direction —
//! the queries a frontend runs against history. They read from the project
//! database (not the in-memory store) so they see every capture run, not just
//! the current one, which is what an agent doing recon on a project expects.
//!
//! Everything here returns plain owned data (strings, ints, bytes) rather than
//! `http` types, so the shapes serialise straight to JSON without a frontend
//! having to know about `Uri`/`HeaderMap`.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, ToSql, params_from_iter};

use crate::db::ProjectPaths;

/// Which half of a flow a body request refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Request,
    Response,
}

/// A row for list views: everything but the bodies.
#[derive(Clone, Debug)]
pub struct FlowRow {
    pub id: i64,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub resp_len: Option<i64>,
    pub source: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub comment: Option<String>,
    pub highlight: Option<String>,
    pub error: Option<String>,
}

/// A single flow in full, minus the body bytes (fetched separately as a resource
/// so a 10MB response never rides inline on a metadata read).
#[derive(Clone, Debug)]
pub struct FlowDetail {
    pub row: FlowRow,
    pub http_version: String,
    pub parent_id: Option<i64>,
    pub req_headers: Vec<(String, String)>,
    pub req_body_len: i64,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body_len: i64,
}

/// A window into a body. `total_len` is the full size so a caller can page
/// through with `offset`/`limit` without guessing when it has reached the end.
#[derive(Clone, Debug)]
pub struct BodySlice {
    pub total_len: i64,
    /// inline | file | evicted | none. `none` distinguishes an empty/absent body
    /// from one deliberately reclaimed (`evicted`); `bytes` is empty for both.
    pub storage: String,
    pub bytes: Vec<u8>,
}

/// A sitemap node, flat. The tree is reconstructed from `parent_id` by whoever
/// renders it.
#[derive(Clone, Debug)]
pub struct SitemapNode {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub kind: String,
    pub host: String,
    pub path: String,
    pub name: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub flow_count: i64,
    pub origin: String,
    pub comment: Option<String>,
    pub highlight: Option<String>,
}

/// Filters for a flow listing. Every field is optional; `None` means "no
/// constraint". Absent filters are cheaper than a match-all pattern.
#[derive(Clone, Debug, Default)]
pub struct FlowQuery {
    /// Substring match on host (case-insensitive via SQLite's default `LIKE`).
    pub host: Option<String>,
    /// Exact method, matched uppercased.
    pub method: Option<String>,
    /// Exact source: proxy | repeater | automate | import.
    pub source: Option<String>,
    /// Substring match on the request URI.
    pub uri_contains: Option<String>,
    /// Only responses with this exact status.
    pub status: Option<u16>,
}

const FLOW_COLUMNS: &str = "id, method, uri, host, path, status, mime, resp_len,
    source, started_at, ended_at, comment, highlight, error";

fn row_to_flow(r: &rusqlite::Row) -> rusqlite::Result<FlowRow> {
    Ok(FlowRow {
        id: r.get(0)?,
        method: r.get(1)?,
        uri: r.get(2)?,
        host: r.get(3)?,
        path: r.get(4)?,
        status: r.get::<_, Option<i64>>(5)?.map(|s| s as u16),
        mime: r.get(6)?,
        resp_len: r.get(7)?,
        source: r.get(8)?,
        started_at: r.get(9)?,
        ended_at: r.get(10)?,
        comment: r.get(11)?,
        highlight: r.get(12)?,
        error: r.get(13)?,
    })
}

/// A page of flows, newest first.
///
/// `limit` is clamped by the caller; here we just apply it. Newest-first because
/// "what just happened" is the common recon question, and offset paging over a
/// descending id is stable as long as new rows only ever append.
pub fn flows(
    conn: &Connection,
    q: &FlowQuery,
    offset: i64,
    limit: i64,
) -> rusqlite::Result<Vec<FlowRow>> {
    let mut sql = format!("SELECT {FLOW_COLUMNS} FROM flow");
    let mut where_clauses: Vec<String> = Vec::new();
    let mut binds: Vec<Box<dyn ToSql>> = Vec::new();

    if let Some(host) = &q.host {
        where_clauses.push(format!("host LIKE ?{}", binds.len() + 1));
        binds.push(Box::new(format!("%{host}%")));
    }
    if let Some(method) = &q.method {
        where_clauses.push(format!("method = ?{}", binds.len() + 1));
        binds.push(Box::new(method.to_ascii_uppercase()));
    }
    if let Some(source) = &q.source {
        where_clauses.push(format!("source = ?{}", binds.len() + 1));
        binds.push(Box::new(source.clone()));
    }
    if let Some(uri) = &q.uri_contains {
        where_clauses.push(format!("uri LIKE ?{}", binds.len() + 1));
        binds.push(Box::new(format!("%{uri}%")));
    }
    if let Some(status) = q.status {
        where_clauses.push(format!("status = ?{}", binds.len() + 1));
        binds.push(Box::new(status as i64));
    }

    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    sql.push_str(&format!(
        " ORDER BY id DESC LIMIT ?{} OFFSET ?{}",
        binds.len() + 1,
        binds.len() + 2
    ));
    binds.push(Box::new(limit));
    binds.push(Box::new(offset));

    let mut stmt = conn.prepare(&sql)?;
    stmt.query_map(params_from_iter(binds.iter().map(|b| b.as_ref())), row_to_flow)?
        .collect()
}

pub fn flow_detail(conn: &Connection, id: i64) -> rusqlite::Result<Option<FlowDetail>> {
    let detail = conn
        .query_row(
            &format!(
                "SELECT {FLOW_COLUMNS}, http_version, parent_id, req_headers, resp_headers,
                        (SELECT len FROM body WHERE id = flow.req_body_id),
                        (SELECT len FROM body WHERE id = flow.resp_body_id)
                   FROM flow WHERE id = ?1"
            ),
            [id],
            |r| {
                let row = row_to_flow(r)?;
                let http_version: String = r.get(14)?;
                let parent_id: Option<i64> = r.get(15)?;
                let req_headers: Vec<u8> = r.get(16)?;
                let resp_headers: Option<Vec<u8>> = r.get(17)?;
                let req_body_len: Option<i64> = r.get(18)?;
                let resp_body_len: Option<i64> = r.get(19)?;
                Ok(FlowDetail {
                    row,
                    http_version,
                    parent_id,
                    req_headers: decode_headers(&req_headers),
                    req_body_len: req_body_len.unwrap_or(0),
                    resp_headers: resp_headers
                        .as_deref()
                        .map(decode_headers)
                        .unwrap_or_default(),
                    resp_body_len: resp_body_len.unwrap_or(0),
                })
            },
        )
        .optional()?;
    Ok(detail)
}

/// Read a window of a flow's request or response body.
///
/// Bodies live in the `body` table (inline) or in `blobs/` (spilled), keyed by
/// digest; this resolves whichever and returns the requested slice. `blobs_root`
/// is the project's `blobs/` directory, needed only for the spilled case.
pub fn body_slice(
    conn: &Connection,
    blobs_root: &Path,
    id: i64,
    side: Side,
    offset: i64,
    limit: i64,
) -> rusqlite::Result<Option<BodySlice>> {
    let body_col = match side {
        Side::Request => "req_body_id",
        Side::Response => "resp_body_id",
    };

    // A flow that exists but has no body of this side yields `Some` row with a
    // NULL body id — reported as an empty `none` slice, distinct from a missing
    // flow (`None`).
    let row = conn
        .query_row(
            &format!(
                "SELECT b.len, b.storage, b.sha256, b.data
                   FROM flow f LEFT JOIN body b ON b.id = f.{body_col}
                  WHERE f.id = ?1"
            ),
            [id],
            |r| {
                let len: Option<i64> = r.get(0)?;
                let storage: Option<String> = r.get(1)?;
                let sha256: Option<Vec<u8>> = r.get(2)?;
                let data: Option<Vec<u8>> = r.get(3)?;
                Ok((len, storage, sha256, data))
            },
        )
        .optional()?;

    let Some((len, storage, sha256, data)) = row else {
        return Ok(None); // no such flow
    };

    let Some(total_len) = len else {
        // Flow exists, but this side has no body.
        return Ok(Some(BodySlice {
            total_len: 0,
            storage: "none".to_string(),
            bytes: Vec::new(),
        }));
    };

    let storage = storage.unwrap_or_default();
    let bytes = match storage.as_str() {
        "inline" => data.unwrap_or_default(),
        "file" => {
            let Some(digest) = sha256 else {
                return Ok(Some(evicted(total_len)));
            };
            let path = ProjectPaths::blob_in(blobs_root, &digest);
            match std::fs::read(&path) {
                Ok(bytes) => bytes,
                // Row says `file` but the blob is gone: treat as evicted rather
                // than failing the whole read.
                Err(_) => return Ok(Some(evicted(total_len))),
            }
        }
        // "evicted" or anything unexpected: the metadata survives, the bytes do not.
        _ => return Ok(Some(evicted(total_len))),
    };

    Ok(Some(slice(total_len, &storage, &bytes, offset, limit)))
}

fn evicted(total_len: i64) -> BodySlice {
    BodySlice {
        total_len,
        storage: "evicted".to_string(),
        bytes: Vec::new(),
    }
}

fn slice(total_len: i64, storage: &str, bytes: &[u8], offset: i64, limit: i64) -> BodySlice {
    let start = (offset.max(0) as usize).min(bytes.len());
    let end = start.saturating_add(limit.max(0) as usize).min(bytes.len());
    BodySlice {
        total_len,
        storage: storage.to_string(),
        bytes: bytes[start..end].to_vec(),
    }
}

/// The sitemap, optionally scoped to one host, ordered so a caller reading top
/// to bottom always sees a parent before its children.
pub fn sitemap(
    conn: &Connection,
    host: Option<&str>,
    offset: i64,
    limit: i64,
) -> rusqlite::Result<Vec<SitemapNode>> {
    let mut sql = String::from(
        "SELECT id, parent_id, kind, host, path, name, first_seen, last_seen,
                flow_count, origin, comment, highlight
           FROM sitemap_node",
    );
    let mut binds: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(host) = host {
        sql.push_str(" WHERE host = ?1");
        binds.push(Box::new(host.to_string()));
    }
    sql.push_str(&format!(
        " ORDER BY host, path LIMIT ?{} OFFSET ?{}",
        binds.len() + 1,
        binds.len() + 2
    ));
    binds.push(Box::new(limit));
    binds.push(Box::new(offset));

    let mut stmt = conn.prepare(&sql)?;
    stmt.query_map(params_from_iter(binds.iter().map(|b| b.as_ref())), |r| {
        Ok(SitemapNode {
            id: r.get(0)?,
            parent_id: r.get(1)?,
            kind: r.get(2)?,
            host: r.get(3)?,
            path: r.get(4)?,
            name: r.get(5)?,
            first_seen: r.get(6)?,
            last_seen: r.get(7)?,
            flow_count: r.get(8)?,
            origin: r.get(9)?,
            comment: r.get(10)?,
            highlight: r.get(11)?,
        })
    })?
    .collect()
}

/// Decode a stored header block (`name: value\r\n` repeated) back into pairs.
///
/// Names are already lowercased and original casing is gone (see `writer.rs`).
/// Values that were not valid UTF-8 come back lossily rather than dropping the
/// header, so a malformed value stays visible instead of vanishing.
fn decode_headers(blob: &[u8]) -> Vec<(String, String)> {
    blob.split(|&b| b == b'\n')
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                return None;
            }
            let pos = line.iter().position(|&b| b == b':')?;
            let name = String::from_utf8_lossy(&line[..pos]).trim().to_string();
            // Skip the ": " separator; tolerate a bare ":" with no space.
            let value_start = if line.get(pos + 1) == Some(&b' ') {
                pos + 2
            } else {
                pos + 1
            };
            let value = String::from_utf8_lossy(&line[value_start..]).to_string();
            Some((name, value))
        })
        .collect()
}
