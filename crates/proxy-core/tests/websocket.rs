//! WebSocket frames through the real proxy.
//!
//! The upgrade is an ordinary HTTP exchange and is captured as a flow; the
//! frames that follow carry no reference to it, so this proves the correlation
//! actually holds end to end.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use proxy_core::Engine;
use tokio::net::{TcpListener, TcpStream};

/// An echo server that upgrades and mirrors whatever it is sent.
async fn spawn_ws_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        let _ = ws.send(msg).await;
                    }
                }
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
        let _ = proxy_core::serve(serving, addr).await;
    });
    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (engine, addr)
}

/// Open a WebSocket *through* the proxy.
///
/// The handshake is written by hand because a normal client writes an
/// origin-form request (`GET /socket`), which a proxy has no way to route. A
/// browser going to `ws://` sends absolute-form, so that is what this sends —
/// otherwise the proxy answers 400 and nothing is exercised.
async fn connect_through(
    proxy: SocketAddr,
    target: SocketAddr,
) -> tokio_tungstenite::WebSocketStream<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    // The key from RFC 6455's own example; the server's accept value is not
    // checked here, since the point is what the proxy does in between.
    let handshake = format!(
        "GET http://{target}/socket HTTP/1.1\r\n\
         Host: {target}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(handshake.as_bytes()).await.unwrap();

    // Read exactly the response head, leaving any frame bytes in the socket.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(n > 0, "proxy closed during the handshake");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected an upgrade, got: {head}"
    );

    tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await
}

#[tokio::test]
async fn frames_are_recorded_against_the_flow_that_upgraded() {
    use tokio_tungstenite::tungstenite::Message;

    let target = spawn_ws_target().await;
    let (engine, proxy) = spawn_proxy().await;

    let mut ws = connect_through(proxy, target).await;
    ws.send(Message::Text("hello from the client".into()))
        .await
        .unwrap();
    // Wait for the echo, so both directions have been through the proxy.
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed.to_text().unwrap(), "hello from the client");
    ws.close(None).await.ok();

    // The upgrade itself is a flow.
    let flow_id = {
        let mut found = None;
        for _ in 0..400 {
            if let Some(flow) = engine.list_ws_flows().first() {
                found = Some(flow.id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        found.expect("the upgrade should be captured as a flow")
    };

    // And the frames hang off it.
    let mut messages = Vec::new();
    for _ in 0..400 {
        messages = engine.ws_messages(flow_id);
        if messages.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        messages.len() >= 2,
        "expected both directions, got {}",
        messages.len()
    );
    let text: Vec<String> = messages
        .iter()
        .map(|m| String::from_utf8_lossy(&m.payload).to_string())
        .collect();
    assert!(
        text.iter().any(|t| t.contains("hello from the client")),
        "{text:?}"
    );

    let directions: Vec<&str> = messages.iter().map(|m| m.direction.as_str()).collect();
    assert!(directions.contains(&"c2s"), "{directions:?}");
    assert!(directions.contains(&"s2c"), "{directions:?}");

    // Sequence numbers order the conversation.
    let seqs: Vec<i64> = messages.iter().map(|m| m.seq).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "frames should come back in order");
}

/// Frames must pass through unchanged — recording is observation, not
/// interference.
#[tokio::test]
async fn recording_does_not_alter_the_conversation() {
    use tokio_tungstenite::tungstenite::Message;

    let target = spawn_ws_target().await;
    let (_engine, proxy) = spawn_proxy().await;

    let mut ws = connect_through(proxy, target).await;
    for i in 0..5 {
        let sent = format!("message {i}");
        ws.send(Message::Text(sent.clone())).await.unwrap();
        let back = ws.next().await.unwrap().unwrap();
        assert_eq!(
            back.to_text().unwrap(),
            sent,
            "echo should be byte-identical"
        );
    }
    ws.close(None).await.ok();
}
