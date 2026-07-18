mod tui;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use proxy_core::model::now_micros;
use proxy_core::{Engine, Registry};
use tracing::error;

const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

/// Everything lives under `~/.proxy` (or the working directory if `HOME` is
/// unset): the registry listing projects, and the project directories
/// themselves. Until there is a project picker, we open a single default one.
fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".proxy"))
        .unwrap_or_else(|| PathBuf::from(".proxy"))
}

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

    let data_dir = data_dir();
    let registry =
        Registry::open(&data_dir.join("registry.db")).expect("failed to open project registry");
    let project = registry
        .create("default", &data_dir.join("projects/default"), now_micros())
        .expect("failed to create default project");
    registry
        .touch(project.id, now_micros())
        .expect("failed to update project");

    let engine = Engine::open_project(&project.path).expect("failed to open project");

    // Proxy runs in the background; the TUI runs on the main task.
    let proxy_engine = engine.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy_core::serve(proxy_engine, LISTEN_ADDR).await {
            error!(error = %e, "proxy stopped");
        }
    });

    // Flush before returning, whether the TUI exited cleanly or errored —
    // otherwise the last batch of captured traffic dies with the process.
    let result = tui::run(engine.clone()).await;
    engine.shutdown().await;
    result
}
