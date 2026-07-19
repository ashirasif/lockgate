mod command;
mod input;
mod tui;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use proxy_core::model::now_micros;
use proxy_core::{Engine, Registry};
use tracing::{error, info, warn};

const LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);

/// How long to wait for the writer to drain before giving up on it.
///
/// A stuck writer must not make the process unkillable: ignoring a `kill` sends
/// the user reaching for `-9`, which loses the batch anyway and with no warning.
///
/// Generous on purpose. This is a backstop for a *wedged* writer, not a latency
/// budget: draining a heavy session is legitimately slow (a 400-request burst of
/// 2 MB bodies measured 31s), and cutting that short would turn a working flush
/// into silent data loss.
const FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Resolves when the process is asked to terminate.
///
/// Note this is not the path Ctrl-C takes: the TUI puts the terminal in raw
/// mode, which disables signal generation, so Ctrl-C arrives as an ordinary key
/// event. This covers `kill`, and shells or supervisors that signal the process
/// directly on shutdown.
#[cfg(unix)]
async fn terminate_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    // Failing to register a handler is a process-level problem, not something
    // to paper over: without it we would silently never flush.
    let mut term = signal(SignalKind::terminate()).expect("failed to listen for SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("failed to listen for SIGINT");

    tokio::select! {
        _ = term.recv() => info!("received SIGTERM"),
        _ = int.recv() => info!("received SIGINT"),
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received ctrl-c");
}

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

    // Whichever way we leave — clean quit, TUI error, or a signal — the writer
    // has to drain first, or the last batch of captured traffic dies with the
    // process.
    let result = tokio::select! {
        result = tui::run(engine.clone()) => result,
        _ = terminate_signal() => {
            // The TUI future is dropped here, part-way through its loop, so the
            // `ratatui::restore()` at the end of `tui::run` never runs. Undo the
            // raw mode and alternate screen ourselves; skipping this leaves the
            // user staring at an unusable terminal.
            ratatui::restore();
            Ok(())
        }
    };

    if tokio::time::timeout(FLUSH_TIMEOUT, engine.shutdown())
        .await
        .is_err()
    {
        // Returning here would not actually get us out: dropping the runtime
        // joins blocking tasks, so a wedged writer would hang the process just
        // past the timeout that was supposed to prevent exactly that. Leaving by
        // the only door that skips the join. An interrupted transaction is safe —
        // SQLite commits atomically, so the batch is lost, never half-applied.
        warn!("writer did not drain within {FLUSH_TIMEOUT:?}; exiting without it");
        std::process::exit(1);
    }
    result
}
