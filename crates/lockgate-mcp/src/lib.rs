//! MCP frontend for the proxy.
//!
//! A Model Context Protocol server that lets an agent do recon over the proxy's
//! captured traffic: list and inspect flows, walk the sitemap, replay requests,
//! annotate, and record findings.
//!
//! It runs **in-process** as a third holder of the shared `Arc<Engine>`, beside
//! the proxy handler and the TUI, so there is one engine and one SQLite writer.
//! Because the TUI owns this process's stdin/stdout, the transport is
//! **streamable HTTP on a localhost port**, not stdio — the client is configured
//! with a URL. See [`serve`].

mod dto;
mod server;
mod status;

pub use server::{ProxyServer, Targets};

use std::net::SocketAddr;
use std::sync::Arc;

use rmcp::transport::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use tracing::info;

/// The path the streamable-HTTP endpoint is mounted at. The client URL is
/// `http://<addr>/mcp`.
pub const MCP_PATH: &str = "/mcp";

/// Serve the MCP over streamable HTTP on `addr`, sharing `targets` with the
/// rest of the process. Runs until the listener errors or the task is dropped.
///
/// A fresh [`ProxyServer`] is built per session by the transport's factory;
/// each only clones the `Arc<Targets>` and keeps its own selected target, so
/// all sessions read and write the same projects while two agents can work
/// two targets at once.
///
/// `/status` rides the same listener — every target at a glance from a phone,
/// sidebar layout. Loopback-bound by default; when the listener is exposed,
/// set `status_token` and the page answers only with `?token=<it>` (or the
/// `X-Status-Token` header, for app proxies that inject headers).
pub async fn serve(
    targets: Arc<Targets>,
    addr: SocketAddr,
    status_token: Option<String>,
) -> std::io::Result<()> {
    let service = StreamableHttpService::new(
        {
            let targets = targets.clone();
            move || Ok(ProxyServer::new(targets.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    let app = axum::Router::new()
        .nest_service(MCP_PATH, service)
        .merge(status::router(targets, status_token));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, path = MCP_PATH, "MCP server listening");
    axum::serve(listener, app).await
}
