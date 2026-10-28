mod args;
mod clipboard;
mod command;
mod editor;
mod highlighter;
mod input;
mod startup;
mod syntax;
mod tui;
mod vim;

use std::path::PathBuf;

use lockgate_core::model::now_micros;
use lockgate_core::{Engine, Registry};
use tracing::{error, info, warn};

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

/// Everything lives under `~/.lockgate` (or the working directory if `HOME` is
/// unset): the registry listing projects, and the project directories
/// themselves. Until there is a project picker, we open a single default one.
fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".lockgate"))
        .unwrap_or_else(|| PathBuf::from(".lockgate"))
}

/// The TUI owns the terminal, so logs must go to a file — printing to stdout
/// would scribble over the interface.
fn init_logging() {
    let file = std::fs::File::create("lockgate.log").expect("failed to create lockgate.log");
    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .init();
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = match args::parse(std::env::args().skip(1)) {
        args::Parsed::Run(args) => *args,
        args::Parsed::Print(text) => {
            print!("{text}");
            return Ok(());
        }
        args::Parsed::Error(e) => {
            eprintln!("lockgate: {e}");
            std::process::exit(2);
        }
    };

    // Before logging or any of the setup: this writes a file and leaves, and
    // has no business opening a database or claiming a port to do it.
    if let Some(path) = &args.export_ca {
        std::fs::write(path, lockgate_core::ca::certificate_pem())?;
        println!("wrote the CA certificate to {}", path.display());
        return Ok(());
    }

    init_logging();

    let data_dir = args.data_dir.clone().unwrap_or_else(data_dir);
    let registry =
        Registry::open(&data_dir.join("registry.db")).expect("failed to open project registry");
    let projects_dir = startup::projects_dir(&data_dir);

    // Which project? `--project` names one directly (the scriptable path);
    // otherwise the startup picker opens, and a project only exists once the user
    // has chosen or created one. `create` is idempotent on the path, so naming a
    // project both makes a new one and reopens an existing one.
    let project = match &args.project {
        Some(name) => registry
            .create(name, &projects_dir.join(name), now_micros())
            .expect("failed to open project"),
        None => match startup::pick(&registry, &projects_dir)? {
            Some(project) => project,
            // The user left the picker without opening anything. Nothing has
            // been spawned yet, so this is a clean exit.
            None => return Ok(()),
        },
    };
    registry
        .touch(project.id, now_micros())
        .expect("failed to update project");

    let engine = Engine::open_project(&project.path).expect("failed to open project");
    info!(
        project = %project.name,
        proxy = %args.proxy_addr(),
        "started"
    );

    // Proxy runs in the background; the TUI runs on the main task.
    let proxy_engine = engine.clone();
    let proxy_addr = args.proxy_addr();
    tokio::spawn(async move {
        if let Err(e) = lockgate_core::serve(proxy_engine, proxy_addr).await {
            error!(error = %e, "proxy stopped");
        }
    });

    // MCP server shares the same engine, in-process, so there is one SQLite
    // writer. A failure here (e.g. the port is taken) must not take the proxy or
    // TUI down: log it and carry on without the MCP.
    //
    // Port 0 or `--no-mcp` means the operator turned it off — running a second
    // instance otherwise logs a bind failure that looks like a bug.
    if args.mcp_port != 0 && !args.no_mcp {
        let mcp_engine = engine.clone();
        let mcp_addr = args.mcp_addr();
        tokio::spawn(async move {
            if let Err(e) = lockgate_mcp::serve(mcp_engine, mcp_addr).await {
                error!(error = %e, "MCP server stopped");
            }
        });
    }

    // Whichever way we leave — clean quit, TUI error, or a signal — the writer
    // has to drain first, or the last batch of captured traffic dies with the
    // process.
    let result = if args.no_tui {
        // Headless: nobody owns the terminal, so say where to point things and
        // sit on the signal. There is no TUI future to race, and `ratatui`
        // never ran, so there is nothing to restore either.
        let mcp = if args.mcp_port != 0 && !args.no_mcp {
            format!(", MCP http://{}/mcp", args.mcp_addr())
        } else {
            String::new()
        };
        println!(
            "lockgate — proxy http://{}{mcp} — Ctrl-C to stop",
            args.proxy_addr()
        );
        terminate_signal().await;
        Ok(())
    } else {
        tokio::select! {
            result = tui::run(engine.clone()) => result,
            _ = terminate_signal() => {
                // The TUI future is dropped here, part-way through its loop, so the
                // `ratatui::restore()` at the end of `tui::run` never runs. Undo the
                // raw mode and alternate screen ourselves; skipping this leaves the
                // user staring at an unusable terminal.
                ratatui::restore();
                Ok(())
            }
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
