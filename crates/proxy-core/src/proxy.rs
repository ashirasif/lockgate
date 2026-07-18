use std::collections::VecDeque;
use std::sync::Arc;

use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    hyper::{Method, Request, Response},
    tokio_tungstenite::tungstenite::Message,
};

use crate::engine::Engine;
use crate::model::{CapturedRequest, CapturedResponse, FlowId};

/// One of these is cloned per connection by hudsucker. `pending` is therefore a
/// per-connection FIFO: for HTTP/1.1 requests and responses are strictly ordered,
/// so pushing the id in `handle_request` and popping it in `handle_response`
/// correlates the two. (This assumption breaks under HTTP/2 multiplexing.)
#[derive(Clone)]
pub struct ProxyHandler {
    engine: Arc<Engine>,
    pending: VecDeque<FlowId>,
}

impl ProxyHandler {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            pending: VecDeque::new(),
        }
    }
}

impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        // CONNECT sets up the TLS tunnel; it isn't a resendable HTTP request and
        // gets no paired response through `handle_response`. Recording it would
        // desync the pending-id FIFO, so pass it through untouched.
        if parts.method == Method::CONNECT {
            let req = Request::from_parts(parts, Body::from(bytes));
            return RequestOrResponse::Request(req);
        }

        let id = self.engine.record_request(CapturedRequest {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: bytes.clone(),
        });
        self.pending.push_back(id);

        let req = Request::from_parts(parts, Body::from(bytes));
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        if let Some(id) = self.pending.pop_front() {
            self.engine.record_response(
                id,
                CapturedResponse {
                    status: parts.status,
                    version: parts.version,
                    headers: parts.headers.clone(),
                    body: bytes.clone(),
                },
            );
        }

        Response::from_parts(parts, Body::from(bytes))
    }
}

impl WebSocketHandler for ProxyHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        Some(msg)
    }
}
