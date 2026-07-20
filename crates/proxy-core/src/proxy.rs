use std::collections::VecDeque;
use std::sync::Arc;

use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    hyper::{Method, Request, Response},
    tokio_tungstenite::tungstenite::Message,
};

use crate::engine::Engine;
use crate::intercept::{Pending, Verdict};
use crate::model::{CapturedRequest, CapturedResponse, FlowId};

/// What the client gets in place of traffic the operator dropped. A definite
/// gateway error beats a hung socket, and 502 is the honest description: we are
/// the gateway, and we declined to complete the exchange.
fn dropped_response() -> Response<Body> {
    Response::builder()
        .status(hudsucker::hyper::StatusCode::BAD_GATEWAY)
        .body(Body::from("dropped by intercept"))
        .expect("a status and a fixed body always assemble")
}

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

        // Reserve the id before holding: the operator may edit the request, and
        // history should record what actually went on the wire, not what arrived.
        let id = self.engine.reserve_flow_id();
        let captured = CapturedRequest {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: bytes.clone(),
        };

        // Passes straight through when interception is off.
        let verdict = self
            .engine
            .intercept()
            .hold_request(id, captured.clone())
            .await;
        let req = match verdict {
            // The queue is typed by the hold that created the entry, so a
            // response here would mean the frontend answered the wrong ticket.
            // Fail open with what we captured rather than guessing.
            Verdict::Forward(pending) => match *pending {
                Pending::Request(req) => req,
                Pending::Response(_) => captured,
            },
            Verdict::Drop => {
                // Short-circuiting means hudsucker never calls `handle_response`
                // for this exchange, so the id must NOT go on the pending FIFO —
                // otherwise every later response on this connection correlates
                // to the wrong request.
                self.engine.record_request_as(id, captured);
                return RequestOrResponse::Response(dropped_response());
            }
        };

        self.engine.record_request_as(id, req.clone());
        self.pending.push_back(id);

        // Rebuild from the (possibly edited) request so edits reach the target.
        let mut out = Request::builder()
            .method(req.method.clone())
            .uri(req.uri.clone())
            .version(req.version);
        if let Some(headers) = out.headers_mut() {
            *headers = req.headers.clone();
        }
        match out.body(Body::from(req.body.clone())) {
            Ok(req) => RequestOrResponse::Request(req),
            // An edit produced something that will not assemble into a request
            // (an unparseable URI, say). Answering the client beats panicking on
            // the capture path.
            Err(_) => RequestOrResponse::Response(dropped_response()),
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        let captured = CapturedResponse {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body: bytes.clone(),
        };

        // No pending id means we never recorded the request (a CONNECT, or a
        // desync). Nothing to correlate to, so don't hold it either — an
        // operator answering a ticket with no flow behind it has nothing to see.
        let Some(id) = self.pending.pop_front() else {
            return Response::from_parts(parts, Body::from(bytes));
        };

        let verdict = self
            .engine
            .intercept()
            .hold_response(id, captured.clone())
            .await;
        let res = match verdict {
            Verdict::Forward(pending) => match *pending {
                Pending::Response(res) => res,
                Pending::Request(_) => captured,
            },
            Verdict::Drop => {
                self.engine.record_response(id, captured);
                return dropped_response();
            }
        };

        self.engine.record_response(id, res.clone());

        let mut out = Response::builder().status(res.status).version(res.version);
        if let Some(headers) = out.headers_mut() {
            *headers = res.headers.clone();
        }
        out.body(Body::from(res.body.clone()))
            .unwrap_or_else(|_| dropped_response())
    }
}

impl WebSocketHandler for ProxyHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        Some(msg)
    }
}
