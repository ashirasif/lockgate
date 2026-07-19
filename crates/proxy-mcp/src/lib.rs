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

pub use server::ProxyServer;

use std::net::SocketAddr;
use std::sync::Arc;

use proxy_core::Engine;
use rmcp::transport::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use tracing::info;

/// The path the streamable-HTTP endpoint is mounted at. The client URL is
/// `http://<addr>/mcp`.
pub const MCP_PATH: &str = "/mcp";

/// Serve the MCP over streamable HTTP on `addr`, sharing `engine` with the rest
/// of the process. Runs until the listener errors or the task is dropped.
///
/// A fresh [`ProxyServer`] is built per session by the transport's factory;
/// each only clones the `Arc<Engine>`, so all sessions read and write the one
/// project.
pub async fn serve(engine: Arc<Engine>, addr: SocketAddr) -> std::io::Result<()> {
    let service = StreamableHttpService::new(
        move || Ok(ProxyServer::new(engine.clone())),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    let app = axum::Router::new().nest_service(MCP_PATH, service);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, path = MCP_PATH, "MCP server listening");
    axum::serve(listener, app).await
}
