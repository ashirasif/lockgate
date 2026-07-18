mod engine;
mod model;
mod proxy;
mod store;

use std::{error::Error as StdError, net::SocketAddr};

use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::error;

use crate::engine::Engine;
use crate::proxy::ProxyHandler;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

/// Temporary manual Repeater until the TUI exists: type a flow id on stdin and
/// it gets resent, printing the fresh response status.
fn spawn_repeater(engine: std::sync::Arc<Engine>) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<u64>() {
                Ok(id) => match engine.resend(id).await {
                    Ok(resp) => {
                        println!("resend #{id} -> {} ({} bytes)", resp.status, resp.body.len())
                    }
                    Err(e) => println!("resend #{id} failed: {e:?}"),
                },
                Err(_) => println!("type a flow id (number), got: {line:?}"),
            }
        }
    });
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key_pair = include_str!("ca/ca.key");
    let ca_cert = include_str!("ca/ca.cer");
    let key_pair = KeyPair::from_pem(key_pair).expect("Failed to parse private key");
    let issuer =
        Issuer::from_ca_cert_pem(ca_cert, key_pair).expect("Failed to parse CA certificate");
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    let engine = Engine::new();
    spawn_repeater(engine.clone());

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(ProxyHandler::new(engine.clone()))
        .with_websocket_handler(ProxyHandler::new(engine.clone()))
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    if let Err(e) = proxy.start().await {
        error!(error = &e as &dyn StdError, "Failed to start proxy");
    }
}
