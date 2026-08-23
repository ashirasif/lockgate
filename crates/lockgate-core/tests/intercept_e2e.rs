//! Intercept through the real proxy.
//!
//! `tests/intercept.rs` covers the queue in isolation. This drives actual HTTP
//! through `lockgate_core::serve` to prove the handler wiring: that a held request
//! really does stall the client, that forwarding releases it, that an edit
//! reaches the target, and that a drop answers the client instead of hanging it.
//!
//! Plain HTTP only — HTTPS would drag in the CA and certificate trust, and the
//! hold points are the same code either way.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lockgate_core::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A target that reports the request line and any body it received, so a test
/// can tell whether an edit actually reached the far side.
async fn spawn_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let received = String::from_utf8_lossy(&buf[..n]).to_string();
                // Echo what we saw, so assertions can inspect it.
                let body = format!("SAW:{received}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

/// Start the proxy on an ephemeral port and return the engine behind it.
async fn spawn_proxy() -> (Arc<Engine>, SocketAddr) {
    // Bind first to claim a free port, then drop it so the proxy can take it.
    // A race is possible in principle; in practice the window is negligible and
    // the alternative is threading a listener through `serve`.
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let engine = Engine::new();
    let serving = engine.clone();
    tokio::spawn(async move {
        let _ = lockgate_core::serve(serving, addr).await;
    });

    // Wait for it to accept connections.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (engine, addr)
}

fn client(proxy: SocketAddr) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// Wait for the next hold and forward it unmodified.
///
/// With both legs intercepted, every exchange holds twice — once on the way out
/// and once on the way back — so a test that only answers the request would
/// stall on the response it forgot about.
async fn forward_next(engine: &Engine) {
    wait_for_queue(engine, 1).await;
    let ticket = engine.intercept().queue()[0].ticket;
    engine.intercept().forward(ticket, None);
}

async fn wait_for_queue(engine: &Engine, n: usize) {
    for _ in 0..400 {
        if engine.intercept().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "queue never reached {n} (stuck at {})",
        engine.intercept().len()
    );
}

#[tokio::test]
async fn traffic_flows_normally_when_intercept_is_off() {
    let target = spawn_target().await;
    let (_engine, proxy) = spawn_proxy().await;

    let res = client(proxy)
        .get(format!("http://{target}/plain"))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    assert!(res.text().await.unwrap().contains("GET /plain"));
}

/// The core promise: a held request does not reach the target until forwarded.
#[tokio::test]
async fn a_held_request_stalls_until_forwarded() {
    let target = spawn_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);

    let url = format!("http://{target}/held");
    let request = tokio::spawn(async move { client(proxy).get(url).send().await });

    wait_for_queue(&engine, 1).await;
    // Still held: the client must not have a response yet.
    assert!(
        !request.is_finished(),
        "the request should still be stalled"
    );

    let ticket = engine.intercept().queue()[0].ticket;
    assert!(engine.intercept().forward(ticket, None));
    // The response holds on its own ticket; release it too.
    forward_next(&engine).await;

    let res = request.await.unwrap().unwrap();
    assert!(res.status().is_success());
    assert!(res.text().await.unwrap().contains("GET /held"));
}

/// An edit made while held must be what the target actually receives.
#[tokio::test]
async fn an_edited_request_reaches_the_target_edited() {
    let target = spawn_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);

    let url = format!("http://{target}/original");
    let request = tokio::spawn(async move { client(proxy).get(url).send().await });

    wait_for_queue(&engine, 1).await;
    let held = engine.intercept().queue().remove(0);
    let lockgate_core::Pending::Request(mut req) = held.pending.clone() else {
        panic!("expected a held request");
    };

    // Rewrite the path, then forward the edited version.
    let authority = req.uri.authority().unwrap().clone();
    req.uri = hudsucker::hyper::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query("/edited")
        .build()
        .unwrap();
    assert!(
        engine
            .intercept()
            .forward(held.ticket, Some(lockgate_core::Pending::Request(req)))
    );
    forward_next(&engine).await;

    let body = request.await.unwrap().unwrap().text().await.unwrap();
    assert!(
        body.contains("GET /edited"),
        "the target should have seen the edit, saw: {body}"
    );
    assert!(!body.contains("/original"), "the edit did not take: {body}");
}

/// Dropping must answer the client. A dropped request that simply never
/// returned would hang the browser, which is the failure this design exists to
/// avoid.
#[tokio::test]
async fn a_dropped_request_answers_the_client() {
    let target = spawn_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);

    let url = format!("http://{target}/doomed");
    let request = tokio::spawn(async move { client(proxy).get(url).send().await });

    wait_for_queue(&engine, 1).await;
    let ticket = engine.intercept().queue()[0].ticket;
    assert!(engine.intercept().discard(ticket));

    let res = request.await.unwrap().unwrap();
    assert_eq!(
        res.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "a drop should surface as a gateway error, not a hang"
    );
}

/// Responses hold on their own ticket, after the request has already gone out.
#[tokio::test]
async fn a_response_can_be_held_and_edited() {
    let target = spawn_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);

    let url = format!("http://{target}/resp");
    let request = tokio::spawn(async move { client(proxy).get(url).send().await });

    // First ticket is the request; forward it so the exchange reaches the target.
    wait_for_queue(&engine, 1).await;
    let req_ticket = engine.intercept().queue()[0].ticket;
    assert!(engine.intercept().queue()[0].pending.is_request());
    engine.intercept().forward(req_ticket, None);

    // Now the response comes back and holds on a ticket of its own.
    wait_for_queue(&engine, 1).await;
    let held = engine.intercept().queue().remove(0);
    assert!(!held.pending.is_request(), "expected a held response");
    let lockgate_core::Pending::Response(mut res) = held.pending.clone() else {
        unreachable!();
    };

    res.status = hudsucker::hyper::StatusCode::IM_A_TEAPOT;
    engine
        .intercept()
        .forward(held.ticket, Some(lockgate_core::Pending::Response(res)));

    let got = request.await.unwrap().unwrap();
    assert_eq!(
        got.status(),
        reqwest::StatusCode::IM_A_TEAPOT,
        "the edited status should reach the client"
    );
}

/// Turning interception off mid-hold must release what is already queued rather
/// than stranding it.
#[tokio::test]
async fn disabling_releases_stalled_traffic() {
    let target = spawn_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);

    let url = format!("http://{target}/stalled");
    let request = tokio::spawn(async move { client(proxy).get(url).send().await });

    wait_for_queue(&engine, 1).await;
    engine.intercept().set_enabled(false);

    let res = request.await.unwrap().unwrap();
    assert!(
        res.status().is_success(),
        "the request should have been released"
    );
}
