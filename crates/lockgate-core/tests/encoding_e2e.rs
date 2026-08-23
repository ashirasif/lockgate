//! Compressed traffic through the real proxy, from capture to display to edit.
//!
//! `encoding.rs` tests the codecs in isolation. This proves the pairing that
//! actually matters: a gzipped response is stored as it arrived, shown decoded,
//! and — once edited — goes back out re-compressed so the client can read it.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lockgate_core::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Large and repetitive, so gzip actually encodes it rather than emitting a
/// literal block that would read as plaintext and fake a pass.
fn payload() -> String {
    let mut s = String::from("{\"items\":[");
    for i in 0..200 {
        s.push_str(&format!("{{\"id\":{i},\"token\":\"needle\"}},"));
    }
    s.push_str("null]}");
    s
}

fn gzip(text: &str) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(text.as_bytes()).unwrap();
    e.finish().unwrap()
}

async fn spawn_gzip_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let body = gzip(&payload());
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

async fn spawn_proxy() -> (Arc<Engine>, SocketAddr) {
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let engine = Engine::new();
    let serving = engine.clone();
    tokio::spawn(async move {
        let _ = lockgate_core::serve(serving, addr).await;
    });
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

async fn wait_for_flow(engine: &Engine) -> u64 {
    for _ in 0..400 {
        if let Some(flow) = engine.list_flows().first() {
            return flow.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no flow was recorded");
}

/// The bytes on the wire are the evidence; storing something else would be a
/// lie about what happened.
#[tokio::test]
async fn a_compressed_body_is_stored_exactly_as_it_arrived() {
    let target = spawn_gzip_target().await;
    let (engine, proxy) = spawn_proxy().await;
    let _ = client(proxy)
        .get(format!("http://{target}/gz"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await;

    let id = wait_for_flow(&engine).await;
    let flow = engine.get_flow(id).unwrap();
    let stored = &flow.response.as_ref().unwrap().body;

    assert!(
        stored.starts_with(&[0x1f, 0x8b]),
        "stored body should still be gzip-framed"
    );
    assert!(
        stored.len() < payload().len() / 2,
        "stored {} bytes for a {} byte payload",
        stored.len(),
        payload().len()
    );
}

/// The whole point: what an operator reads is the body, not the compression.
#[tokio::test]
async fn a_compressed_body_renders_decoded() {
    let target = spawn_gzip_target().await;
    let (engine, proxy) = spawn_proxy().await;
    let _ = client(proxy)
        .get(format!("http://{target}/gz"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await;

    let id = wait_for_flow(&engine).await;
    let flow = engine.get_flow(id).unwrap();
    let response = flow.response.as_ref().unwrap();

    let raw = lockgate_core::http_text::render_response(response);
    assert!(
        !raw.contains("needle"),
        "the raw rendering is the wire bytes"
    );

    let shown = lockgate_core::http_text::render_response_decoded(response);
    assert!(
        shown.contains("needle"),
        "the decoded rendering is readable"
    );
    assert!(
        shown.contains("content-encoding: gzip"),
        "headers are untouched"
    );
}

/// An edit made against the decoded view has to reach the client, which means
/// going back out compressed — plaintext under a gzip header is rejected.
#[tokio::test]
async fn an_edited_response_is_re_compressed_before_it_is_sent() {
    let target = spawn_gzip_target().await;
    let (engine, proxy) = spawn_proxy().await;
    engine.intercept().set_enabled(true);
    engine.intercept().set_hold_requests(false);

    let call = tokio::spawn({
        let url = format!("http://{target}/gz");
        let c = client(proxy);
        async move { c.get(url).send().await.unwrap().bytes().await.unwrap() }
    });

    // Wait for the response leg to be held, then edit it as a human would.
    let held = loop {
        if let Some(held) = engine.intercept().queue_of(false).first().cloned() {
            break held;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let lockgate_core::Pending::Response(original) = &held.pending else {
        panic!("expected a response");
    };

    let shown = lockgate_core::http_text::render_response_decoded(original);
    assert!(shown.contains("needle"), "the operator sees plaintext");
    let edited_text = shown.replace("needle", "haystack");
    let edited = lockgate_core::http_text::parse_response(&edited_text, original).unwrap();

    assert!(
        edited.body.starts_with(&[0x1f, 0x8b]),
        "the edit must be re-compressed on the way out"
    );
    engine
        .intercept()
        .forward(held.ticket, Some(lockgate_core::Pending::Response(edited)));

    // The client gunzips it, so it only sees the edit if the framing survived.
    let received = call.await.unwrap();
    let mut text = String::new();
    flate2::read::GzDecoder::new(&received[..])
        .read_to_string(&mut text)
        .expect("client should receive a valid gzip stream");
    assert!(
        text.contains("haystack"),
        "the edit should reach the client"
    );
    assert!(!text.contains("needle"));
}
