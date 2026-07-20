//! The database-backed read path for every frontend.
//!
//! History lives in the project database, never in memory, so both frontends
//! reconstruct what they need from SQLite here. Two audiences share this module:
//!
//! - the **TUI**, which wants `model` types (`FlowSummary`, `Flow` with real
//!   `http` headers and body bytes) — the inverse of `writer.rs`, where
//!   `decode_header_map` undoes `encode_headers` and `load_body` undoes
//!   `intern_body`;
//! - the **MCP**, which wants plain owned data (strings, ints, byte windows)
//!   that serialises straight to JSON, with bodies fetched as bounded slices so
//!   a metadata read never drags a 10MB body inline.
//!
//! Parsing is deliberately total — a stored method, URI, or version that no
//! longer round-trips falls back to a sane default rather than failing the whole
//! read. The bytes were written from valid values, so this is a guard, not a
//! path we expect to take.

use std::path::Path;

use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::header::{HeaderName, HeaderValue};
use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version};
use rusqlite::{Connection, OptionalExtension, ToSql, params_from_iter};
use tracing::warn;

use crate::db::ProjectPaths;
use crate::model::{CapturedRequest, CapturedResponse, Flow, FlowId, FlowSummary};
use crate::scope::{Matcher, Target};

// ===================================================================
// TUI reads: reconstruct `model` types from the database.
// ===================================================================

/// Lightweight history rows in id order, which is also capture order.
pub fn list_flows(conn: &Connection) -> rusqlite::Result<Vec<FlowSummary>> {
    conn.prepare("SELECT id, method, uri, status FROM flow ORDER BY id")?
        .query_map([], |r| {
            Ok(summary(
                r.get(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?
        .collect()
}

/// The same rows, filtered to the active scope.
///
/// Scope is matched against the derived `host` / `port` / `path` columns rather
/// than the raw `uri`, because a MITM'd HTTPS request stores its target in
/// origin-form (`/path`) with the host only in a header — the columns already
/// resolved that at write time.
pub fn list_flows_in_scope(
    conn: &Connection,
    matcher: &Matcher,
) -> rusqlite::Result<Vec<FlowSummary>> {
    if matcher.is_unrestricted() {
        return list_flows(conn);
    }

    let mut stmt =
        conn.prepare("SELECT id, method, uri, status, host, port, path FROM flow ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            summary(
                r.get(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ),
            r.get::<_, String>(4)?,
            r.get::<_, Option<i64>>(5)?.unwrap_or(0) as u16,
            r.get::<_, String>(6)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (summary, host, port, path) = row?;
        if matcher.matches(&Target {
            host: &host,
            port,
            path: &path,
        }) {
            out.push(summary);
        }
    }
    Ok(out)
}

/// A full flow, bodies included — for the detail pane and for Repeater resends,
/// which need the original request to replay it.
pub fn get_flow(
    conn: &Connection,
    paths: &ProjectPaths,
    id: FlowId,
) -> rusqlite::Result<Option<Flow>> {
    let row = conn
        .query_row(
            "SELECT method, uri, http_version, req_headers, req_body_id,
                    status, resp_headers, resp_body_id, started_at, ended_at
               FROM flow WHERE id = ?1",
            [id as i64],
            |r| {
                Ok(ReconRow {
                    method: r.get(0)?,
                    uri: r.get(1)?,
                    version: r.get(2)?,
                    req_headers: r.get(3)?,
                    req_body_id: r.get(4)?,
                    status: r.get(5)?,
                    resp_headers: r.get(6)?,
                    resp_body_id: r.get(7)?,
                    started_at: r.get(8)?,
                    ended_at: r.get(9)?,
                })
            },
        )
        .optional()?;

    let Some(row) = row else { return Ok(None) };

    let request = CapturedRequest {
        method: parse_method(&row.method),
        uri: parse_uri(&row.uri),
        version: parse_version(&row.version),
        headers: decode_header_map(&row.req_headers),
        body: load_body(conn, paths, row.req_body_id)?,
    };

    let response = match parse_status(row.status) {
        Some(status) => Some(CapturedResponse {
            status,
            // The response's HTTP version is not stored separately; reuse the
            // request's, which it matches in practice. Nothing displays it, so a
            // column for it would be pure schema churn.
            version: parse_version(&row.version),
            headers: decode_header_map(row.resp_headers.as_deref().unwrap_or_default()),
            body: load_body(conn, paths, row.resp_body_id)?,
        }),
        None => None,
    };

    Ok(Some(Flow {
        id,
        request,
        response,
        started_at: row.started_at,
        ended_at: row.ended_at,
    }))
}

struct ReconRow {
    method: String,
    uri: String,
    version: String,
    req_headers: Vec<u8>,
    req_body_id: Option<i64>,
    status: Option<i64>,
    resp_headers: Option<Vec<u8>>,
    resp_body_id: Option<i64>,
    started_at: i64,
    ended_at: Option<i64>,
}

fn summary(id: i64, method: String, uri: String, status: Option<i64>) -> FlowSummary {
    FlowSummary {
        id: id as FlowId,
        method: parse_method(&method),
        uri: parse_uri(&uri),
        status: parse_status(status),
    }
}

/// Load body bytes for a `body` row id. `None` (no body) and a missing spilled
/// blob both read as empty — the alternative, failing the flow read outright,
/// helps no one looking at old history.
fn load_body(
    conn: &Connection,
    paths: &ProjectPaths,
    body_id: Option<i64>,
) -> rusqlite::Result<Bytes> {
    let Some(body_id) = body_id else {
        return Ok(Bytes::new());
    };

    let row = conn
        .query_row(
            "SELECT storage, sha256, data FROM body WHERE id = ?1",
            [body_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()?;

    let Some((storage, sha256, data)) = row else {
        return Ok(Bytes::new());
    };

    match storage.as_str() {
        "inline" => Ok(Bytes::from(data.unwrap_or_default())),
        "file" => match std::fs::read(paths.blob(&sha256)) {
            Ok(bytes) => Ok(Bytes::from(bytes)),
            Err(e) => {
                warn!(error = %e, "spilled body blob is unreadable; showing empty");
                Ok(Bytes::new())
            }
        },
        // "evicted", or anything a newer writer introduces: nothing to return.
        _ => Ok(Bytes::new()),
    }
}

fn parse_method(s: &str) -> Method {
    Method::from_bytes(s.as_bytes()).unwrap_or(Method::GET)
}

fn parse_uri(s: &str) -> Uri {
    s.parse().unwrap_or_default()
}

fn parse_status(status: Option<i64>) -> Option<StatusCode> {
    status.and_then(|n| StatusCode::from_u16(n as u16).ok())
}

fn parse_version(s: &str) -> Version {
    match s {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        // Includes "HTTP/1.1" and anything unrecognised.
        _ => Version::HTTP_11,
    }
}

/// Rebuild a `HeaderMap` from the `name: value\r\n` block `encode_headers`
/// wrote, preserving order and duplicates. Lines that no longer parse are
/// skipped rather than fatal.
fn decode_header_map(blob: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in blob.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        // `encode_headers` writes exactly one space after the colon.
        let value = value.strip_prefix(b" ").unwrap_or(value);
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }
    headers
}

// ===================================================================
// MCP reads: plain owned data, JSON-shaped, bodies as bounded slices.
// ===================================================================

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
    /// The requested window `[offset, offset+limit)`.
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
    /// Include `automate`-source flows (Intruder/Automate output). When false
    /// they are excluded — unless `source` is set, which selects explicitly and
    /// overrides this. Default (via `Default`) is false: exclude them.
    pub include_automate: bool,
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
/// Newest-first because "what just happened" is the common recon question, and
/// offset paging over a descending id is stable as long as new rows only ever
/// append.
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
    // Automate output shares the flow table; keep it out of a default survey
    // unless asked for, or unless a specific source was named (which wins).
    if !q.include_automate && q.source.is_none() {
        where_clauses.push("source != 'automate'".to_string());
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
    stmt.query_map(
        params_from_iter(binds.iter().map(|b| b.as_ref())),
        row_to_flow,
    )?
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
                    req_headers: header_pairs(&req_headers),
                    req_body_len: req_body_len.unwrap_or(0),
                    resp_headers: resp_headers
                        .as_deref()
                        .map(header_pairs)
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

/// Decode a stored header block into `(name, value)` pairs for JSON.
///
/// Built on `decode_header_map` so the two decoders cannot drift; the map form
/// already preserves order and duplicates, which `iter` then walks in order.
fn header_pairs(blob: &[u8]) -> Vec<(String, String)> {
    decode_header_map(blob)
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_round_trip_through_encode_decode() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.append("set-cookie", "a=1".parse().unwrap());
        headers.append("set-cookie", "b=2".parse().unwrap());

        let encoded = crate::writer::encode_headers(&headers);
        let decoded = decode_header_map(&encoded);

        assert_eq!(decoded.get("content-type").unwrap(), "application/json");
        let cookies: Vec<_> = decoded.get_all("set-cookie").iter().collect();
        assert_eq!(
            cookies,
            vec!["a=1", "b=2"],
            "order and duplicates preserved"
        );
    }

    #[test]
    fn header_pairs_preserve_order_and_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", "a=1".parse().unwrap());
        headers.append("set-cookie", "b=2".parse().unwrap());
        let encoded = crate::writer::encode_headers(&headers);

        let pairs = header_pairs(&encoded);
        assert_eq!(
            pairs,
            vec![
                ("set-cookie".to_string(), "a=1".to_string()),
                ("set-cookie".to_string(), "b=2".to_string()),
            ]
        );
    }

    #[test]
    fn versions_round_trip() {
        for v in [
            Version::HTTP_09,
            Version::HTTP_10,
            Version::HTTP_11,
            Version::HTTP_2,
            Version::HTTP_3,
        ] {
            assert_eq!(parse_version(&format!("{v:?}")), v);
        }
    }
}
