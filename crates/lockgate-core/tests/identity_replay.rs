//! Identities end to end: adopt a captured session, replay as it, and see the
//! identity's cookies leave on the wire — while the captured jar stays intact.

use std::net::SocketAddr;
use std::sync::Arc;

use hudsucker::hyper::{
    HeaderMap, Method, StatusCode, Uri, Version, body::Bytes, header::HeaderValue,
};
use lockgate_core::{CapturedRequest, CapturedResponse, Engine};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// An origin that answers every request the same and records what it received,
/// so the test can assert on the request bytes lockgate actually sent.
async fn spawn_echo_origin() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let shared = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let received = shared.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                received
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());

                let body = "ok";
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    (addr, received)
}

/// A captured "post-login" flow: the browser's `Cookie` header plus the
/// `Set-Cookie` the login response just set — exactly what adoption merges.
fn record_login_flow(engine: &Engine, host: &str, port: u16) -> u64 {
    let mut req_headers = HeaderMap::new();
    req_headers.insert("host", format!("{host}:{port}").parse().unwrap());
    req_headers.insert("cookie", "sid=old-session".parse().unwrap());

    let id = engine.record_request(CapturedRequest {
        method: Method::GET,
        uri: format!("http://{host}:{port}/dashboard")
            .parse::<Uri>()
            .unwrap(),
        version: Version::HTTP_11,
        headers: req_headers,
        body: Bytes::new(),
    });

    let mut resp_headers = HeaderMap::new();
    resp_headers.append(
        "set-cookie",
        HeaderValue::from_str(&format!("sid=fresh-session; Domain={host}; Path=/")).unwrap(),
    );
    resp_headers.append("set-cookie", "role=admin; Path=/".parse().unwrap());
    engine.record_response(
        id,
        CapturedResponse {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: resp_headers,
            body: Bytes::new(),
        },
    );
    id
}

#[tokio::test]
async fn a_replay_as_identity_carries_its_jar_not_the_flows() {
    let (addr, received) = spawn_echo_origin().await;
    let engine = Engine::new();

    let flow = record_login_flow(&engine, "127.0.0.1", addr.port());
    let identity_id = engine
        .adopt_identity_from_flow(flow, "admin")
        .expect("the flow carries a session");

    // The replay targets the same host:port, so scope (inactive) never refuses.
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        format!("127.0.0.1:{}", addr.port()).parse().unwrap(),
    );
    headers.insert("cookie", "sid=stale-cookie".parse().unwrap());
    let request = CapturedRequest {
        method: Method::GET,
        uri: format!("http://127.0.0.1:{}/dashboard", addr.port())
            .parse::<Uri>()
            .unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::new(),
    };

    let sent = engine
        .send_request(request, Some(flow), Some(identity_id), None)
        .await
        .expect("the send lands");
    assert_eq!(sent.response.status, StatusCode::OK);

    let wire = received
        .lock()
        .unwrap()
        .last()
        .expect("the origin saw one request")
        .clone();
    assert!(
        wire.contains("sid=fresh-session") && wire.contains("role=admin"),
        "the identity's jar (response Set-Cookie winning over the request's) is what went out:\n{wire}"
    );
    assert!(
        !wire.contains("stale-cookie"),
        "the original request's cookies are replaced, not merged:\n{wire}"
    );

    // The recorded replay shows what actually left — the evidence is the wire.
    let replay = engine.get_flow(sent.replay_id).expect("replay recorded");
    let cookie = replay
        .request
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cookie.contains("sid=fresh-session") && cookie.contains("role=admin"),
        "the stored replay carries the identity's jar: {cookie}"
    );
}

#[tokio::test]
async fn an_unknown_identity_is_refused_before_anything_leaves() {
    let (addr, received) = spawn_echo_origin().await;
    let engine = Engine::new();
    let flow = record_login_flow(&engine, "127.0.0.1", addr.port());

    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        format!("127.0.0.1:{}", addr.port()).parse().unwrap(),
    );
    let request = CapturedRequest {
        method: Method::GET,
        uri: format!("http://127.0.0.1:{}/dashboard", addr.port())
            .parse::<Uri>()
            .unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::new(),
    };

    let err = engine
        .send_request(request, Some(flow), Some(4242), None)
        .await
        .expect_err("no identity 4242 exists");
    assert!(
        matches!(err, lockgate_core::ResendError::IdentityNotFound(4242)),
        "got: {err:?}"
    );
    assert!(
        received.lock().unwrap().is_empty(),
        "nothing may reach the wire for an identity that does not exist"
    );
}

#[tokio::test]
async fn an_identity_without_matching_cookies_sends_no_cookie_header() {
    let (addr, received) = spawn_echo_origin().await;
    let engine = Engine::new();
    let flow = record_login_flow(&engine, "127.0.0.1", addr.port());
    let identity_id = engine.adopt_identity_from_flow(flow, "admin").unwrap();

    // A different host: the identity's jar is bound elsewhere, so the replay
    // goes out with no Cookie header at all — never with the wrong session.
    // `localhost` resolves to the same origin but is a different host string.
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        format!("127.0.0.1:{}", addr.port()).parse().unwrap(),
    );
    headers.insert("cookie", "sid=wrong-host".parse().unwrap());
    let request = CapturedRequest {
        method: Method::GET,
        uri: format!("http://localhost:{}/", addr.port())
            .parse::<Uri>()
            .unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::new(),
    };

    engine
        .send_request(request, None, Some(identity_id), None)
        .await
        .expect("the send lands (no scope active)");

    let wire = received
        .lock()
        .unwrap()
        .last()
        .expect("one request")
        .clone();
    assert!(
        !wire.contains("cookie:"),
        "a jar bound to another host must not leak its session:\n{wire}"
    );
}

fn request_to(addr: SocketAddr, host: &str, path: &str) -> CapturedRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        format!("127.0.0.1:{}", addr.port()).parse().unwrap(),
    );
    CapturedRequest {
        method: Method::GET,
        uri: format!("http://{host}:{port}{path}", port = addr.port())
            .parse::<Uri>()
            .unwrap(),
        version: Version::HTTP_11,
        headers,
        body: Bytes::new(),
    }
}

#[tokio::test]
async fn a_forbidden_url_is_refused_before_anything_leaves() {
    let (addr, received) = spawn_echo_origin().await;
    let engine = Engine::new();
    let rule_id = engine
        .add_policy_rule("forbid_url_regex", r"/pay", Some("never touch money flows"))
        .unwrap();

    let err = engine
        .send_request(
            request_to(addr, "127.0.0.1", "/pay?amount=all"),
            None,
            None,
            None,
        )
        .await
        .expect_err("policy must refuse the payment flow");
    match err {
        lockgate_core::ResendError::Forbidden {
            rule_id: id,
            pattern,
            url,
        } => {
            assert_eq!(id, rule_id);
            assert_eq!(pattern, r"/pay");
            assert!(url.contains("/pay"));
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
    assert!(
        received.lock().unwrap().is_empty(),
        "a forbidden URL never reaches the wire"
    );

    // The in-bounds sibling still passes: policy is a floor, not a wall.
    engine
        .send_request(request_to(addr, "127.0.0.1", "/api"), None, None, None)
        .await
        .expect("non-forbidden path is unaffected");
}

#[tokio::test]
async fn the_rate_ceiling_paces_sends_per_host() {
    let (addr, _received) = spawn_echo_origin().await;
    let engine = Engine::new();
    engine.set_rate_limit(Some(2.0)); // 500ms between sends to a host

    engine
        .send_request(request_to(addr, "127.0.0.1", "/a"), None, None, None)
        .await
        .expect("the first send goes");

    // Too soon: refused with a retry hint, before recording anything.
    let err = engine
        .send_request(request_to(addr, "127.0.0.1", "/b"), None, None, None)
        .await
        .expect_err("the ceiling must bite");
    match err {
        lockgate_core::ResendError::RateLimited {
            host,
            retry_after_ms,
        } => {
            assert_eq!(host, "127.0.0.1");
            assert!(
                retry_after_ms > 0 && retry_after_ms <= 500,
                "{retry_after_ms}"
            );
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }

    // A different host is paced independently: ceilings are per host.
    let (other_addr, _r2) = spawn_echo_origin().await;
    engine
        .send_request(request_to(other_addr, "localhost", "/c"), None, None, None)
        .await
        .expect("another host is not throttled by this one");

    // Lifting the ceiling lifts it immediately.
    engine.set_rate_limit(None);
    engine
        .send_request(request_to(addr, "127.0.0.1", "/d"), None, None, None)
        .await
        .expect("no ceiling, no wait");
}

#[tokio::test]
async fn a_tagged_send_is_findable_by_its_tag() {
    let (addr, _received) = spawn_echo_origin().await;
    let engine = Engine::new();

    let sent = engine
        .send_request(
            request_to(addr, "127.0.0.1", "/dashboard"),
            None,
            None,
            Some("lead:idor-3".to_string()),
        )
        .await
        .expect("the send lands");

    // The detail path carries the tag — this is what the TUI and get_flow show.
    let detail = engine.flow_detail(sent.replay_id as i64).unwrap();
    assert_eq!(detail.row.tag.as_deref(), Some("lead:idor-3"));

    // ...and the listing filters on it exactly: the attribution loop.
    let query = lockgate_core::FlowQuery {
        tag: Some("lead:idor-3".into()),
        ..Default::default()
    };
    let hits = engine.query_flows(&query, 0, 100);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, detail.row.id);

    let empty = engine.query_flows(
        &lockgate_core::FlowQuery {
            tag: Some("lead:other".into()),
            ..Default::default()
        },
        0,
        100,
    );
    assert!(empty.is_empty(), "an unrelated tag matches nothing");
}

#[tokio::test]
async fn identity_bearing_traffic_never_rides_a_non_trusted_exit() {
    let (addr, _received) = spawn_echo_origin().await;
    let engine = Engine::new();

    let flow = record_login_flow(&engine, "127.0.0.1", addr.port());
    let identity_id = engine
        .adopt_identity_from_flow(flow, "t1")
        .expect("the flow carries a session");

    // A harvested proxy: hostile by class, present in the plane.
    let hostile = engine
        .add_egress_exit(&lockgate_core::NewEgressExit {
            name: "free-proxy-1".into(),
            kind: "hostile".into(),
            proxy_url: Some("socks5://127.0.0.1:9".into()), // nothing listens
            note: None,
        })
        .unwrap();

    // Pin the identity to it: the pin records intent, it does not grant
    // permission.
    engine
        .update_identity(
            identity_id,
            &lockgate_core::IdentityEdit {
                egress_exit_id: Some(hostile),
                ..Default::default()
            },
        )
        .unwrap();

    let err = engine
        .send_request(
            request_to(addr, "127.0.0.1", "/dashboard"),
            None,
            Some(identity_id),
            None,
        )
        .await
        .unwrap_err();
    match &err {
        lockgate_core::ResendError::EgressRefused {
            identity,
            exit,
            kind,
        } => {
            assert_eq!(identity, "t1");
            assert_eq!(exit, "free-proxy-1");
            assert_eq!(kind, "hostile");
        }
        other => panic!("expected the egress refusal, got {other:?}"),
    }

    // An explicit via_exit cannot route around the rule either.
    let err = engine
        .send_request_via(
            request_to(addr, "127.0.0.1", "/x"),
            None,
            Some(identity_id),
            None,
            Some("free-proxy-1"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        lockgate_core::ResendError::EgressRefused { .. }
    ));

    // And a refusal leaves no trace in history: nothing left, nothing recorded.
    let before = engine
        .query_flows(&lockgate_core::FlowQuery::default(), 0, 100)
        .len();
    let _ = engine
        .send_request(
            request_to(addr, "127.0.0.1", "/dashboard"),
            None,
            Some(identity_id),
            None,
        )
        .await
        .unwrap_err();
    let _ = engine
        .send_request_via(
            request_to(addr, "127.0.0.1", "/x"),
            None,
            Some(identity_id),
            None,
            Some("free-proxy-1"),
        )
        .await
        .unwrap_err();
    let after = engine
        .query_flows(&lockgate_core::FlowQuery::default(), 0, 100)
        .len();
    assert_eq!(before, after, "refused sends must not be recorded");

    // Anonymous traffic through the pooled/hostile exit is none of the rule's
    // business — the send leaves (or fails on the dead proxy), but it is not
    // refused here. The dead proxy proves the client was actually built.
    let err = engine
        .send_request_via(
            request_to(addr, "127.0.0.1", "/anon"),
            None,
            None,
            None,
            Some("free-proxy-1"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, lockgate_core::ResendError::Http(_)),
        "unreachable proxy, not a policy refusal: {err:?}"
    );
}
