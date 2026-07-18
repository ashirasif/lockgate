//! End-to-end checks on the write path: record through `Engine`, then read the
//! rows back out of SQLite with a fresh connection.

use std::path::{Path, PathBuf};

use hudsucker::hyper::{HeaderMap, Method, StatusCode, Uri, Version, body::Bytes};
use proxy_core::{CapturedRequest, CapturedResponse, Engine};

/// A project is a directory (`project.db` + `blobs/`), so tests get one each.
fn temp_project(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("proxy-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn db_of(root: &Path) -> PathBuf {
    root.join("project.db")
}

fn request(uri: &str, body: &str) -> CapturedRequest {
    let mut headers = HeaderMap::new();
    headers.insert("host", "example.com".parse().unwrap());
    // Two values under one name: the row must round-trip both.
    headers.append("x-dup", "one".parse().unwrap());
    headers.append("x-dup", "two".parse().unwrap());

    CapturedRequest {
        method: Method::POST,
        uri: uri.parse::<Uri>().unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::from(body.to_string()),
    }
}

fn response(body: &str) -> CapturedResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
    CapturedResponse {
        status: StatusCode::OK,
        version: Version::HTTP_11,
        headers,
        body: Bytes::from(body.to_string()),
    }
}

/// The writer batches on a background thread, so poll until the row lands.
fn await_rows(path: &Path, sql: &str, expected: i64) -> bool {
    for _ in 0..100 {
        let conn = rusqlite::Connection::open(db_of(path)).unwrap();
        let n: i64 = conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1);
        if n == expected {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[tokio::test]
async fn persists_request_and_response() {
    let path = temp_project("basic");
    let engine = Engine::open_project(&path).unwrap();

    let id = engine.record_request(request("http://example.com/a?q=1", "hello"));
    engine.record_response(id, response("<html/>"));

    assert!(
        await_rows(&path, "SELECT COUNT(*) FROM flow WHERE ended_at IS NOT NULL", 1),
        "flow never reached the database"
    );

    let conn = rusqlite::Connection::open(db_of(&path)).unwrap();
    let (method, host, scheme, dbpath, status, mime, len): (
        String, String, String, String, i64, String, i64,
    ) = conn
        .query_row(
            "SELECT method, host, scheme, path, status, mime, resp_len FROM flow WHERE id = ?1",
            [id as i64],
            |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(method, "POST");
    assert_eq!(host, "example.com");
    assert_eq!(scheme, "http");
    assert_eq!(dbpath, "/a");
    assert_eq!(status, 200);
    assert_eq!(mime, "text/html", "charset should be stripped");
    assert_eq!(len, 7);

    // Duplicate headers survive as separate lines, in order.
    let headers: Vec<u8> = conn
        .query_row("SELECT req_headers FROM flow WHERE id = ?1", [id as i64], |r| r.get(0))
        .unwrap();
    let headers = String::from_utf8(headers).unwrap();
    assert!(headers.contains("x-dup: one\r\n"), "got: {headers:?}");
    assert!(headers.contains("x-dup: two\r\n"), "got: {headers:?}");

    let body: Vec<u8> = conn
        .query_row(
            "SELECT b.data FROM flow f JOIN body b ON b.id = f.req_body_id WHERE f.id = ?1",
            [id as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(body, b"hello");
}

#[tokio::test]
async fn identical_bodies_are_stored_once() {
    let path = temp_project("dedupe");
    let engine = Engine::open_project(&path).unwrap();

    for _ in 0..5 {
        let id = engine.record_request(request("http://example.com/asset.js", "same-bytes"));
        engine.record_response(id, response("identical-response"));
    }

    assert!(await_rows(&path, "SELECT COUNT(*) FROM flow", 5));
    assert!(
        await_rows(&path, "SELECT COUNT(*) FROM body", 2),
        "5 identical request/response pairs should intern to 2 body rows"
    );
}

/// The point of `shutdown`: after it returns, everything is on disk. Note the
/// deliberate absence of `await_rows` here — polling would hide a broken flush.
#[tokio::test]
async fn shutdown_flushes_pending_writes() {
    let path = temp_project("flush");
    let engine = Engine::open_project(&path).unwrap();

    // Enough to span several batches, queued with no pause for the writer.
    for i in 0..500 {
        let id = engine.record_request(request(&format!("http://example.com/{i}"), "req"));
        engine.record_response(id, response(&format!("resp-{i}")));
    }

    engine.shutdown().await;

    let conn = rusqlite::Connection::open(db_of(&path)).unwrap();
    let flows: i64 = conn
        .query_row("SELECT COUNT(*) FROM flow", [], |r| r.get(0))
        .unwrap();
    let completed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM flow WHERE ended_at IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();

    assert_eq!(flows, 500, "requests were dropped on shutdown");
    assert_eq!(completed, 500, "responses were dropped on shutdown");

    // Idempotent: the join handle is already taken, so this must not hang or panic.
    engine.shutdown().await;
}

#[tokio::test]
async fn reopening_resumes_flow_ids() {
    let path = temp_project("resume");

    let first = {
        let engine = Engine::open_project(&path).unwrap();
        let id = engine.record_request(request("http://example.com/x", "a"));
        engine.record_response(id, response("b"));
        assert!(await_rows(&path, "SELECT COUNT(*) FROM flow", 1));
        id
    };

    // Fresh engine over the same file: ids must continue, not collide.
    let engine = Engine::open_project(&path).unwrap();
    let second = engine.record_request(request("http://example.com/y", "c"));
    assert_eq!(second, first + 1);

    assert!(await_rows(&path, "SELECT COUNT(*) FROM flow", 2));
    assert!(
        await_rows(&path, "SELECT COUNT(DISTINCT id) FROM capture_run", 2),
        "each run should open its own capture_run"
    );
}

/// Bodies over the 5MB cap go to `blobs/`, not into a SQLite row.
#[tokio::test]
async fn large_bodies_spill_to_disk() {
    let path = temp_project("spill");
    let engine = Engine::open_project(&path).unwrap();

    let big = "x".repeat(6 * 1024 * 1024);
    let small = "y".repeat(1024);

    let id = engine.record_request(request("http://example.com/upload", &small));
    engine.record_response(id, response(&big));
    engine.shutdown().await;

    let conn = rusqlite::Connection::open(db_of(&path)).unwrap();
    let (storage, len, data): (String, i64, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT b.storage, b.len, b.data FROM flow f
               JOIN body b ON b.id = f.resp_body_id WHERE f.id = ?1",
            [id as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();

    assert_eq!(storage, "file");
    assert_eq!(len, 6 * 1024 * 1024, "length is recorded even when spilled");
    assert!(data.is_none(), "spilled body must not also sit inline");

    // The small request body is under the cap and stays inline.
    let req_storage: String = conn
        .query_row(
            "SELECT b.storage FROM flow f JOIN body b ON b.id = f.req_body_id WHERE f.id = ?1",
            [id as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(req_storage, "inline");

    // Exactly one blob on disk, and its contents round-trip.
    let mut blobs = Vec::new();
    for shard in std::fs::read_dir(path.join("blobs")).unwrap() {
        for entry in std::fs::read_dir(shard.unwrap().path()).unwrap() {
            blobs.push(entry.unwrap().path());
        }
    }
    assert_eq!(blobs.len(), 1, "expected one spilled blob, got {blobs:?}");
    assert_eq!(std::fs::read(&blobs[0]).unwrap().len(), big.len());
    assert!(
        blobs[0].extension().is_none_or(|e| e != "tmp"),
        "temp file was left behind: {blobs:?}"
    );
}

/// The sitemap is materialised as a host -> dir -> leaf tree by the writer,
/// accumulates across capture runs, and counts every ancestor.
#[tokio::test]
async fn sitemap_builds_a_tree() {
    let path = temp_project("sitemap");

    {
        let engine = Engine::open_project(&path).unwrap();
        for _ in 0..3 {
            let id = engine.record_request(request("http://example.com/api/v1/users", "a"));
            engine.record_response(id, response("b"));
        }
        let id = engine.record_request(request("http://example.com/api/v1/orders", "a"));
        engine.record_response(id, response("b"));
        engine.shutdown().await;
    }

    let conn = rusqlite::Connection::open(db_of(&path)).unwrap();

    let node = |p: &str| -> (String, String, i64) {
        conn.query_row(
            "SELECT kind, name, flow_count FROM sitemap_node WHERE host = 'example.com' AND path = ?1",
            [p],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|e| panic!("no node for {p:?}: {e}"))
    };

    assert_eq!(node(""), ("host".into(), "example.com".into(), 4));
    assert_eq!(node("/api"), ("dir".into(), "api".into(), 4));
    assert_eq!(node("/api/v1"), ("dir".into(), "v1".into(), 4));
    assert_eq!(node("/api/v1/users"), ("leaf".into(), "users".into(), 3));
    assert_eq!(node("/api/v1/orders"), ("leaf".into(), "orders".into(), 1));

    // Tree structure: the leaf's parent chain must reach the host node.
    let parent_path: String = conn
        .query_row(
            "SELECT p.path FROM sitemap_node c JOIN sitemap_node p ON p.id = c.parent_id
              WHERE c.host = 'example.com' AND c.path = '/api/v1/users'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(parent_path, "/api/v1");

    // A second capture run accumulates into the same tree rather than resetting.
    let engine = Engine::open_project(&path).unwrap();
    let id = engine.record_request(request("http://example.com/api/v1/users", "a"));
    engine.record_response(id, response("b"));
    engine.shutdown().await;

    let conn = rusqlite::Connection::open(db_of(&path)).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT flow_count FROM sitemap_node WHERE host='example.com' AND path='/api/v1/users'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 4, "sitemap should span capture runs");
}
