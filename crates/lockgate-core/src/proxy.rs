use std::collections::VecDeque;
use std::sync::Arc;

use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    hyper::{Method, Request, Response, body::Bytes},
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

/// Hosts that mean "the proxy itself" rather than somewhere to forward to.
///
/// Burp answers on `burp`, mitmproxy on `mitm.it`; the idea is the same and it
/// is the only practical way to get a CA onto a phone, where you cannot copy a
/// file off the laptop. Anything already configured to use this proxy can just
/// browse here.
///
/// The generic `proxy*` names stay alongside the product ones: they cost
/// nothing, and they are what fingers reach for.
const SELF_HOSTS: &[&str] = &[
    "lockgate",
    "lockgate.local",
    "lockgate.ca",
    "proxy",
    "proxy.local",
    "proxy.ca",
];

/// Serve the CA certificate, or a page pointing at it.
///
/// Deliberately HTTP-only and only reachable *through* the proxy: it is not
/// bound to a port anyone else can reach, and a client that is not already
/// using this proxy cannot get here at all.
fn self_service(path: &str) -> Response<Body> {
    // `application/x-x509-ca-cert` is what makes iOS and Android offer to
    // install it rather than download it as a file.
    if path.starts_with("/ca.cer") || path.starts_with("/ca.crt") {
        return Response::builder()
            .status(hudsucker::hyper::StatusCode::OK)
            .header("content-type", "application/x-x509-ca-cert")
            .header(
                "content-disposition",
                "attachment; filename=\"lockgate-ca.cer\"",
            )
            .body(Body::from(crate::ca::certificate_pem()))
            .expect("a fixed body always assembles");
    }

    let page = concat!(
        "<!doctype html><html><head><title>lockgate</title>",
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">",
        "<style>body{font:16px/1.5 system-ui;margin:3rem auto;max-width:34rem;padding:0 1rem}",
        "a{display:inline-block;padding:.6rem 1rem;border:1px solid;border-radius:.4rem;",
        "text-decoration:none}code{background:#8881;padding:.1rem .3rem}</style></head><body>",
        "<h1>lockgate</h1><p>You are going through this proxy. Install its CA to intercept HTTPS.</p>",
        "<p><a href=\"/ca.cer\">Download CA certificate</a></p>",
        "<p><small>macOS: open it, then trust it in Keychain Access. ",
        "iOS: install the profile, then enable it under General &rarr; About &rarr; ",
        "Certificate Trust Settings. Android: Settings &rarr; Security &rarr; ",
        "Install from storage. Firefox has its own store &mdash; import it in Settings.</small></p>",
        "<p><small>Anything trusting this CA can have its traffic read by whoever holds ",
        "the key. Remove it when you are done.</small></p>",
        "</body></html>"
    );
    Response::builder()
        .status(hudsucker::hyper::StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(page))
        .expect("a fixed body always assembles")
}

fn is_websocket_upgrade(headers: &hudsucker::hyper::HeaderMap) -> bool {
    headers
        .get(hudsucker::hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// The `ws://`/`wss://` form of an upgrade target, matching how hudsucker
/// rewrites the URI before handing frames to the handler.
fn websocket_uri(uri: &hudsucker::hyper::Uri) -> String {
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(
        match parts.scheme.as_ref().map(|s| s.as_str()) {
            Some("https") => "wss",
            _ => "ws",
        }
        .try_into()
        .expect("ws and wss are valid schemes"),
    );
    hudsucker::hyper::Uri::from_parts(parts)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| uri.to_string())
}

/// Stands in for the 101 hudsucker sends on our behalf, so an upgraded flow
/// reads as completed rather than as a request still in flight.
fn switching_protocols() -> CapturedResponse {
    CapturedResponse {
        status: hudsucker::hyper::StatusCode::SWITCHING_PROTOCOLS,
        version: hudsucker::hyper::Version::HTTP_11,
        headers: hudsucker::hyper::HeaderMap::new(),
        body: Bytes::new(),
    }
}

/// One of these is cloned per connection by hudsucker. `pending` is therefore a
/// per-connection FIFO: for HTTP/1.1 requests and responses are strictly ordered,
/// so pushing the id in `handle_request` and popping it in `handle_response`
/// correlates the two. (This assumption breaks under HTTP/2 multiplexing.)
#[derive(Clone)]
pub struct ProxyHandler {
    engine: Arc<Engine>,
    pending: VecDeque<FlowId>,
    /// Per-connection FIFO, paired with `pending`: the host and scheme the
    /// response's request went to, remembered here because the passive
    /// scanner needs them and `handle_response` sees only the response.
    pending_meta: VecDeque<(String, String)>,
}

/// The host and scheme a request is headed for, from the (possibly edited)
/// request the proxy actually forwarded.
fn meta_of(req: &CapturedRequest) -> (String, String) {
    let host = req
        .uri
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers
                .get(hudsucker::hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let scheme = req.uri.scheme_str().unwrap_or("https").to_string();
    (host, scheme)
}

impl ProxyHandler {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            engine,
            pending: VecDeque::new(),
            pending_meta: VecDeque::new(),
        }
    }
}

impl HttpHandler for ProxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        // CONNECT sets up the TLS tunnel; it isn't a resendable HTTP request and
        // gets no paired response through `handle_response`. Recording it would
        // desync the pending-id FIFO, so pass it through untouched.
        if parts.method == Method::CONNECT {
            let req = Request::from_parts(parts, Body::from(bytes));
            return RequestOrResponse::Request(req);
        }

        // Answered by us rather than forwarded, and not recorded: this is the
        // proxy's own console, not captured traffic, and putting it in history
        // would be noise in the one view you want clean.
        if parts
            .uri
            .host()
            .is_some_and(|host| SELF_HOSTS.contains(&host.to_ascii_lowercase().as_str()))
        {
            return RequestOrResponse::Response(self_service(parts.uri.path()));
        }

        // A WebSocket upgrade never reaches `handle_response`: hudsucker answers
        // the 101 itself via hyper_tungstenite and then pumps frames, so this
        // exchange has no response leg to pair with. It therefore must not join
        // the pending FIFO — an id pushed here and never popped would pair the
        // *next* response on this connection with the wrong request.
        if is_websocket_upgrade(&parts.headers) {
            let id = self.engine.reserve_flow_id();
            let captured = CapturedRequest {
                method: parts.method.clone(),
                uri: parts.uri.clone(),
                version: parts.version,
                headers: parts.headers.clone(),
                body: bytes.clone(),
            };
            self.engine.record_request_as(id, captured);
            // Synthesized, because the real 101 is hudsucker's and we never see
            // it. Without this the flow sits pending forever, which reads as a
            // request that never completed rather than a socket that opened.
            self.engine.record_response(id, switching_protocols());

            // Frames name the endpoint with a ws/wss scheme — hudsucker rewrites
            // it before upgrading — so register under that form or the lookup
            // will never match.
            self.engine
                .note_upgrade(ctx.client_addr, &websocket_uri(&parts.uri), id);

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
        let meta = meta_of(&req);
        self.pending.push_back(id);
        self.pending_meta.push_back(meta);

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
                self.pending_meta.pop_front();
                return dropped_response();
            }
        };

        self.engine.record_response(id, res.clone());

        // The scanner runs against bytes already in hand and files through
        // the writer; awaited here so clones of this handler never share a
        // half-updated dedup set. Header checks only — nothing that could
        // measure in the response's latency budget.
        if let Some((host, scheme)) = self.pending_meta.pop_front() {
            self.engine.scan_and_file(id, &scheme, &host, &res).await;
        }

        let mut out = Response::builder().status(res.status).version(res.version);
        if let Some(headers) = out.headers_mut() {
            *headers = res.headers.clone();
        }
        out.body(Body::from(res.body.clone()))
            .unwrap_or_else(|_| dropped_response())
    }
}

impl WebSocketHandler for ProxyHandler {
    /// Record the frame and pass it through untouched.
    ///
    /// Observation only, deliberately: intercepting a frame means holding one
    /// side of a live full-duplex conversation, which reorders it relative to
    /// the other side. Recording is the useful half and cannot break anything.
    async fn handle_message(&mut self, ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        let (client, server, direction) = match ctx {
            WebSocketContext::ClientToServer { src, dst, .. } => (*src, dst.to_string(), "c2s"),
            WebSocketContext::ServerToClient { src, dst, .. } => (*dst, src.to_string(), "s2c"),
        };

        // No slot means the upgrade was not recorded — a socket opened before
        // this handler existed, or a reconnect that lost the race on the key.
        // Nothing to attach the frame to, so let it through unrecorded rather
        // than inventing a flow for it.
        if let Some((flow, seq)) = self.engine.ws_frame_slot(client, &server) {
            let (opcode, payload) = match &msg {
                Message::Text(text) => ("text", Bytes::copy_from_slice(text.as_bytes())),
                Message::Binary(bytes) => ("binary", Bytes::copy_from_slice(bytes)),
                Message::Ping(bytes) => ("ping", Bytes::copy_from_slice(bytes)),
                Message::Pong(bytes) => ("pong", Bytes::copy_from_slice(bytes)),
                Message::Close(_) => ("close", Bytes::new()),
                Message::Frame(_) => ("binary", Bytes::new()),
            };
            self.engine
                .record_ws_message(flow, seq, direction, opcode, payload);
        }
        Some(msg)
    }
}
