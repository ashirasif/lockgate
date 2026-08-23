//! The CA is reachable through the proxy, so a phone can install it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lockgate_core::Engine;
use tokio::net::TcpListener;

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

#[tokio::test]
async fn the_ca_certificate_is_downloadable_through_the_proxy() {
    let (_engine, proxy) = spawn_proxy().await;

    let res = client(proxy)
        .get("http://proxy/ca.cer")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/x-x509-ca-cert",
        "the mime type is what makes a phone offer to install it"
    );

    let body = res.text().await.unwrap();
    assert!(body.starts_with("-----BEGIN CERTIFICATE-----"), "{body}");
    assert_eq!(
        body,
        lockgate_core::ca::certificate_pem(),
        "must serve the same cert the proxy actually signs with"
    );
}

#[tokio::test]
async fn the_landing_page_explains_how_to_install_it() {
    let (_engine, proxy) = spawn_proxy().await;
    let body = client(proxy)
        .get("http://proxy/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("/ca.cer"), "should link to the certificate");
    assert!(
        body.to_lowercase().contains("trust"),
        "should say how to trust it"
    );
}

#[tokio::test]
async fn every_self_host_answers() {
    let (_engine, proxy) = spawn_proxy().await;
    for host in [
        "lockgate",
        "lockgate.local",
        "lockgate.ca",
        "proxy",
        "proxy.local",
        "proxy.ca",
    ] {
        let res = client(proxy)
            .get(format!("http://{host}/ca.cer"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{host} should answer");
    }
}

/// The console is not traffic. Recording it would put noise in the one view you
/// want clean.
#[tokio::test]
async fn serving_the_ca_is_not_recorded_as_a_flow() {
    let (engine, proxy) = spawn_proxy().await;
    let _ = client(proxy)
        .get("http://proxy/ca.cer")
        .send()
        .await
        .unwrap();
    let _ = client(proxy).get("http://proxy/").send().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        engine.list_flows().is_empty(),
        "the proxy's own console should not appear in history"
    );
}
