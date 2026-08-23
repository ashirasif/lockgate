use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};

use crate::engine::Engine;
use crate::proxy::ProxyHandler;

/// Run the MITM proxy until it stops. Everything it captures lands in `engine`.
pub async fn serve(
    engine: Arc<Engine>,
    addr: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(crate::ca::authority())
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(ProxyHandler::new(engine.clone()))
        .with_websocket_handler(ProxyHandler::new(engine))
        .build()?;

    proxy.start().await?;
    Ok(())
}
