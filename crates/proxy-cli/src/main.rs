mod tui;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proxy_core::Engine;
use tracing::error;

const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

/// The TUI owns the terminal, so logs must go to a file — printing to stdout
/// would scribble over the interface.
fn init_logging() {
    let file = std::fs::File::create("proxy.log").expect("failed to create proxy.log");
    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .init();
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_logging();

    let engine = Engine::new();

    // Proxy runs in the background; the TUI runs on the main task.
    let proxy_engine = engine.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy_core::serve(proxy_engine, LISTEN_ADDR).await {
            error!(error = %e, "proxy stopped");
        }
    });

    tui::run(engine).await
}
