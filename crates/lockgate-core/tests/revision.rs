//! `Engine::revision` is what the TUI uses to decide it can skip reloading, so
//! the property that matters is one-directional: a revision that fails to move
//! after a write shows the operator stale traffic, and captured traffic they
//! cannot see is the one thing this tool must never do.
//!
//! Writes reach the database on two different connections — the background
//! writer for captured traffic, the read connection for scope and triage edits
//! — and the intercept queue never touches SQLite at all. Each of those three
//! paths is covered here, because each is caught by a different half of the
//! token.

use std::path::PathBuf;
use std::time::Duration;

use hudsucker::hyper::{HeaderMap, Method, Uri, Version, body::Bytes};
use lockgate_core::{CapturedRequest, Engine, NewFinding};

fn temp_project(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("lockgate-rev-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn request(uri: &str) -> CapturedRequest {
    let mut headers = HeaderMap::new();
    headers.insert("host", "example.com".parse().unwrap());
    CapturedRequest {
        method: Method::GET,
        uri: uri.parse::<Uri>().unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::new(),
    }
}

/// Poll for the writer's commit rather than sleeping a fixed span: the point is
/// that the revision *does* move, and a flaky sleep would turn a real failure
/// into an intermittent one.
async fn wait_for_change(engine: &Engine, before: lockgate_core::Revision) -> bool {
    for _ in 0..200 {
        if engine.revision() != before {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Captured traffic commits on the background writer — a different connection
/// from the one reads use, which is exactly the case `data_version` exists to
/// catch and the case a naive same-connection check would miss.
#[tokio::test]
async fn traffic_recorded_by_the_writer_moves_the_revision() {
    let path = temp_project("traffic");
    let engine = Engine::open_project(&path).unwrap();

    let before = engine.revision();
    engine.record_request(request("http://example.com/a"));

    assert!(
        wait_for_change(&engine, before).await,
        "a captured request must move the revision, or the history stops updating"
    );

    engine.shutdown().await;
    let _ = std::fs::remove_dir_all(&path);
}

/// Findings and scopes are written straight to the read connection, where
/// `data_version` deliberately stays put. `total_changes` is what covers them.
#[tokio::test]
async fn edits_on_the_read_connection_move_the_revision() {
    let path = temp_project("edits");
    let engine = Engine::open_project(&path).unwrap();

    let id = engine
        .create_finding(NewFinding {
            title: "test".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    // Settle the write that created it, so what the next assert observes is the
    // triage edit alone and not the tail of this one.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let before = engine.revision();
    engine.set_finding_triage(id, Some("high"), None);
    assert_ne!(
        engine.revision(),
        before,
        "a triage edit is invisible to data_version, so total_changes must catch it"
    );

    let before = engine.revision();
    engine.create_scope("scope").unwrap();
    assert_ne!(
        engine.revision(),
        before,
        "scope edits take the same read-connection path"
    );

    engine.shutdown().await;
    let _ = std::fs::remove_dir_all(&path);
}

/// The queue is in memory and never reaches SQLite, so neither database half
/// sees it.
#[tokio::test]
async fn the_intercept_queue_moves_the_revision() {
    let engine = Engine::new();
    engine.intercept().set_enabled(true);

    let before = engine.revision();

    // `hold_request` parks until answered, so it has to run alongside us.
    let held = {
        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .intercept()
                .hold_request(1, request("http://example.com/held"))
                .await
        })
    };
    assert!(
        wait_for_change(&engine, before).await,
        "a held request must move the revision, or it never appears in the queue"
    );

    // Answering it moves the token again: the length falls back to zero, and
    // the operator's view has to follow.
    let queued = engine.revision();
    let ticket = engine.intercept().queue()[0].ticket;
    engine.intercept().forward(ticket, None);
    assert_ne!(
        engine.revision(),
        queued,
        "answering an item must move the revision, or it lingers on screen"
    );

    held.await.unwrap();
}

/// The other direction, and the reason any of this is worth doing: an idle
/// engine must hold the token still, or every tick reloads and nothing is saved.
#[tokio::test]
async fn an_idle_engine_holds_the_revision_still() {
    let path = temp_project("idle");
    let engine = Engine::open_project(&path).unwrap();

    engine.record_request(request("http://example.com/a"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let settled = engine.revision();
    for _ in 0..20 {
        assert_eq!(
            engine.revision(),
            settled,
            "an idle engine must report an unchanged revision"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    engine.shutdown().await;
    let _ = std::fs::remove_dir_all(&path);
}
