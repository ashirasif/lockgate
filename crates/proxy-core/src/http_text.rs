//! Raw HTTP messages as editable text, and back again.
//!
//! The Repeater and the Intercept queue both let an operator change a message
//! before it goes out. Rather than build a structured editor per field, both
//! present the message the way it looks on the wire and reparse what comes back
//! — the same bargain Burp's Repeater makes. One text buffer covers the request
//! line, every header, and the body, including malformed input that a structured
//! editor would refuse to represent.
//!
//! Round-tripping an unedited message must be lossless in the ways that matter
//! (method, target, header order and duplicates, body bytes). It is *not* byte
//! exact: header casing is normalised by `HeaderMap`, and line endings become
//! CRLF on the way out.

use crate::{CapturedRequest, CapturedResponse};
use hudsucker::hyper::{
    HeaderMap, Method, StatusCode, Uri, Version,
    body::Bytes,
    header::{HeaderName, HeaderValue},
};

/// What language a message body is written in.
///
/// Public and shared with [`crate::pretty`] on purpose: the highlighter and the
/// formatter must never disagree about what a body is, or `gq` would reformat
/// something as JSON that the pane is colouring as HTML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Json,
    Html,
    Form,
    Plain,
}

/// Pick a body language.
///
/// `Content-Type` is consulted first, but a body that *looks* like JSON is
/// treated as JSON regardless of what the header claims. Mislabelled bodies are
/// routine in this line of work — `text/plain` wrapping JSON is common enough
/// that trusting the header would make the feature useless exactly when someone
/// is looking hardest.
pub fn detect_body(headers: &[String], body: &[String]) -> Language {
    let content_type = headers
        .iter()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_ascii_lowercase())
        })
        .unwrap_or_default();

    if content_type.contains("json") {
        return Language::Json;
    }
    if content_type.contains("x-www-form-urlencoded") {
        return Language::Form;
    }
    if content_type.contains("html") || content_type.contains("xml") {
        return Language::Html;
    }
    match body
        .iter()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| l.trim_start().chars().next())
    {
        Some('{' | '[') => Language::Json,
        Some('<') => Language::Html,
        _ => Language::Plain,
    }
}

/// Why an edited message could not be turned back into something sendable.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    /// The first line was not `METHOD TARGET [VERSION]` / `VERSION STATUS ...`.
    BadStartLine(String),
    BadMethod(String),
    BadUri(String),
    BadStatus(String),
    /// A header line had no `:`, or a name/value the HTTP grammar rejects.
    BadHeader(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "the message is empty"),
            ParseError::BadStartLine(l) => write!(f, "bad start line: {l}"),
            ParseError::BadMethod(m) => write!(f, "bad method: {m}"),
            ParseError::BadUri(u) => write!(f, "bad target: {u}"),
            ParseError::BadStatus(s) => write!(f, "bad status: {s}"),
            ParseError::BadHeader(h) => write!(f, "bad header: {h}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Render a request as editable wire text.
pub fn render_request(req: &CapturedRequest) -> String {
    let target = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri.to_string());
    let mut out = format!("{} {} {}\n", req.method, target, version_str(req.version));
    write_headers(&mut out, &req.headers);
    out.push('\n');
    out.push_str(&lossy(&req.body));
    out
}

/// Render a response as editable wire text.
pub fn render_response(res: &CapturedResponse) -> String {
    let reason = res.status.canonical_reason().unwrap_or("");
    let mut out = format!(
        "{} {} {}\n",
        version_str(res.version),
        res.status.as_u16(),
        reason
    );
    write_headers(&mut out, &res.headers);
    out.push('\n');
    out.push_str(&lossy(&res.body));
    out
}

/// Parse edited text back into a request.
///
/// `original` supplies what the text cannot: the absolute URI. Edited text
/// carries an origin-form target (`/path`), matching how a proxied HTTPS request
/// looks on the wire, so scheme and authority are recovered from the message
/// being edited — or from an edited `Host` header, which is the point of letting
/// someone edit it.
pub fn parse_request(
    text: &str,
    original: &CapturedRequest,
) -> Result<CapturedRequest, ParseError> {
    let (start, headers, body) = split_message(text)?;

    let mut parts = start.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ParseError::BadStartLine(start.into()))?;
    let target = parts
        .next()
        .ok_or_else(|| ParseError::BadStartLine(start.into()))?;
    let version = parts.next().map(parse_version).unwrap_or(original.version);

    let method =
        Method::from_bytes(method.as_bytes()).map_err(|_| ParseError::BadMethod(method.into()))?;
    let headers = parse_headers(&headers)?;

    // An absolute target speaks for itself. Otherwise rebuild the authority from
    // the edited Host header (falling back to the original URI's), so changing
    // Host actually redirects the request rather than being silently ignored.
    let uri = if target.contains("://") {
        target
            .parse::<Uri>()
            .map_err(|_| ParseError::BadUri(target.into()))?
    } else {
        let host = headers
            .get(hudsucker::hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| original.uri.host().map(|h| h.to_string()));
        match host {
            Some(host) => {
                let scheme = original.uri.scheme_str().unwrap_or("https");
                format!("{scheme}://{host}{target}")
                    .parse::<Uri>()
                    .map_err(|_| ParseError::BadUri(target.into()))?
            }
            // Nothing to build an authority from; keep it origin-form and let
            // the send path resolve it the way it resolves any captured request.
            None => target
                .parse::<Uri>()
                .map_err(|_| ParseError::BadUri(target.into()))?,
        }
    };

    Ok(CapturedRequest {
        method,
        uri,
        version,
        headers,
        body: Bytes::from(body.into_bytes()),
    })
}

/// Parse edited text back into a response.
pub fn parse_response(
    text: &str,
    original: &CapturedResponse,
) -> Result<CapturedResponse, ParseError> {
    let (start, headers, body) = split_message(text)?;

    let mut parts = start.split_whitespace();
    let version = parts.next().map(parse_version).unwrap_or(original.version);
    let code = parts
        .next()
        .ok_or_else(|| ParseError::BadStartLine(start.into()))?;
    let status = code
        .parse::<u16>()
        .ok()
        .and_then(|c| StatusCode::from_u16(c).ok())
        .ok_or_else(|| ParseError::BadStatus(code.into()))?;

    Ok(CapturedResponse {
        status,
        version,
        headers: parse_headers(&headers)?,
        body: Bytes::from(body.into_bytes()),
    })
}

/// Split wire text into its start line, header lines, and body.
///
/// The first blank line ends the headers; everything after it is body, verbatim.
/// A message with no blank line at all is all headers and no body, which is what
/// someone who deleted the trailing newlines meant.
fn split_message(text: &str) -> Result<(&str, Vec<&str>, String), ParseError> {
    // Tolerate CRLF on the way in even though we only emit LF: text pasted from
    // elsewhere, or edited on Windows, should not be a parse error.
    let text = text.trim_start_matches(['\r', '\n']);
    if text.trim().is_empty() {
        return Err(ParseError::Empty);
    }

    let mut lines = text.split('\n');
    let start = lines.next().unwrap_or("").trim_end_matches('\r');

    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            body.push('\n');
            body.push_str(line);
            continue;
        }
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            in_body = true;
            continue;
        }
        headers.push(trimmed);
    }
    // The loop prefixes every body line with '\n', including the first, which
    // belongs to the blank separator rather than the body.
    if body.starts_with('\n') {
        body.remove(0);
    }

    Ok((start, headers, body))
}

fn parse_headers(lines: &[&str]) -> Result<HeaderMap, ParseError> {
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ParseError::BadHeader((*line).into()))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| ParseError::BadHeader((*line).into()))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| ParseError::BadHeader((*line).into()))?;
        // `append`, not `insert`: duplicates are meaningful (Set-Cookie), and an
        // operator who typed the same header twice meant to send it twice.
        headers.append(name, value);
    }
    Ok(headers)
}

fn write_headers(out: &mut String, headers: &HeaderMap) {
    for (name, value) in headers {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(&String::from_utf8_lossy(value.as_bytes()));
        out.push('\n');
    }
}

/// Bodies are shown as text so they can be edited. Binary bodies survive viewing
/// but not editing — the replacement chars go back out as themselves — which is
/// the accepted cost of a text editor over a hex one.
fn lossy(body: &Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

fn parse_version(s: &str) -> Version {
    match s.trim() {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2" | "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3" | "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> CapturedRequest {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.append("x-dup", "one".parse().unwrap());
        headers.append("x-dup", "two".parse().unwrap());
        CapturedRequest {
            method: Method::POST,
            uri: "https://example.com/a/b?q=1".parse().unwrap(),
            version: Version::HTTP_11,
            headers,
            body: Bytes::from_static(b"hello=world"),
        }
    }

    #[test]
    fn request_renders_as_wire_text() {
        let text = render_request(&req());
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("POST /a/b?q=1 HTTP/1.1"));
        assert!(text.contains("host: example.com"));
        assert!(text.ends_with("\nhello=world"));
    }

    #[test]
    fn unedited_request_round_trips() {
        let original = req();
        let parsed = parse_request(&render_request(&original), &original).unwrap();
        assert_eq!(parsed.method, original.method);
        assert_eq!(parsed.uri, original.uri);
        assert_eq!(parsed.body, original.body);
        assert_eq!(parsed.headers.len(), original.headers.len());
    }

    /// Duplicate headers are meaningful, so both values must survive the trip.
    #[test]
    fn duplicate_headers_survive() {
        let original = req();
        let parsed = parse_request(&render_request(&original), &original).unwrap();
        let dups: Vec<_> = parsed.headers.get_all("x-dup").iter().collect();
        assert_eq!(dups.len(), 2);
    }

    #[test]
    fn editing_the_method_and_body_takes_effect() {
        let original = req();
        let text = "GET /changed HTTP/1.1\nhost: example.com\n\nnew body";
        let parsed = parse_request(text, &original).unwrap();
        assert_eq!(parsed.method, Method::GET);
        assert_eq!(parsed.uri.path(), "/changed");
        assert_eq!(parsed.body, Bytes::from_static(b"new body"));
    }

    /// Editing Host must actually redirect the request — otherwise the edit is
    /// theatre, and the operator can't tell.
    #[test]
    fn editing_host_redirects_the_request() {
        let original = req();
        let text = "GET /a HTTP/1.1\nhost: other.test\n\n";
        let parsed = parse_request(text, &original).unwrap();
        assert_eq!(parsed.uri.host(), Some("other.test"));
        assert_eq!(
            parsed.uri.scheme_str(),
            Some("https"),
            "scheme should carry over from the original"
        );
    }

    #[test]
    fn a_body_containing_blank_lines_stays_intact() {
        let original = req();
        let text = "POST / HTTP/1.1\nhost: a.test\n\nline one\n\nline three";
        let parsed = parse_request(text, &original).unwrap();
        assert_eq!(parsed.body, Bytes::from_static(b"line one\n\nline three"));
    }

    #[test]
    fn a_message_with_no_body_parses() {
        let original = req();
        let parsed = parse_request("GET / HTTP/1.1\nhost: a.test", &original).unwrap();
        assert!(parsed.body.is_empty());
        assert_eq!(parsed.headers.len(), 1);
    }

    #[test]
    fn crlf_input_is_tolerated() {
        let original = req();
        let parsed =
            parse_request("GET /x HTTP/1.1\r\nhost: a.test\r\n\r\nbody", &original).unwrap();
        assert_eq!(parsed.uri.path(), "/x");
        assert_eq!(parsed.body, Bytes::from_static(b"body"));
        assert_eq!(
            parsed.headers.get("host").unwrap(),
            "a.test",
            "the CR must not end up inside the header value"
        );
    }

    #[test]
    fn malformed_input_is_reported_not_panicked() {
        let original = req();
        assert!(matches!(
            parse_request("", &original),
            Err(ParseError::Empty)
        ));
        assert!(matches!(
            parse_request("GET /x HTTP/1.1\nnot-a-header\n\n", &original),
            Err(ParseError::BadHeader(_))
        ));
        assert!(matches!(
            parse_request("ONLYONE\n\n", &original),
            Err(ParseError::BadStartLine(_))
        ));
    }

    #[test]
    fn response_round_trips_and_edits() {
        let original = CapturedResponse {
            status: StatusCode::NOT_FOUND,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"nope"),
        };
        let text = render_response(&original);
        assert!(text.starts_with("HTTP/1.1 404 Not Found"));

        let parsed = parse_response(&text, &original).unwrap();
        assert_eq!(parsed.status, StatusCode::NOT_FOUND);
        assert_eq!(parsed.body, original.body);

        let edited = parse_response("HTTP/1.1 200 OK\n\nyes", &original).unwrap();
        assert_eq!(edited.status, StatusCode::OK);
        assert_eq!(edited.body, Bytes::from_static(b"yes"));
    }
}
