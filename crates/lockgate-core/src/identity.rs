//! Identities: named session credentials a replay can be sent *as*.
//!
//! An identity is a cookie jar captured once — normally by the operator logging
//! in through the proxy by hand and then adopting a flow ([`adopt`]) — plus an
//! optional TOTP secret and note. Replays opt into one with `as_identity`, and
//! the identity's jar replaces the request's `Cookie` header wholesale: what
//! goes on the wire is what the identity would have sent, which is the point
//! when the evidence has to show "this request ran as `admin`".
//!
//! Credential *values* live here and nowhere else. Every read path that leaves
//! the engine (TUI, MCP) reports names and lengths, never values — a transcript
//! or a report must not carry a live session.

use std::collections::HashMap;

use hudsucker::hyper::HeaderMap;
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::FlowId;

/// One cookie in an identity's jar. `domain`/`path` carry the scoping the
/// `Set-Cookie` that produced them stated (defaulted to the capture's host and
/// `/` where absent) — they decide what a later replay may carry them to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
}

/// Where an identity's account came from. The report's black-box claim hangs
/// off this: findings demonstrated by `SelfRegistered` identities needed no
/// operator credentials; `Operator` ones did, and say so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Provenance {
    /// Logged in / adopted / pasted by the operator.
    #[default]
    Operator,
    /// Registered by the agent during a run, with credentials the engine
    /// generated and held.
    SelfRegistered,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Operator => "operator",
            Provenance::SelfRegistered => "self_registered",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "operator" => Some(Provenance::Operator),
            "self_registered" => Some(Provenance::SelfRegistered),
            _ => None,
        }
    }
}

/// What a caller supplies to mint an identity. `id` and timestamps are stamped
/// on insert.
#[derive(Clone, Debug, Default)]
pub struct NewIdentity {
    pub name: String,
    /// The host the session belongs to, when it belongs to one. `None` means
    /// the jar is offered to every replay (its own per-cookie domains still
    /// scope the individual cookies).
    pub host: Option<String>,
    pub totp_secret: Option<String>,
    pub note: Option<String>,
    pub cookies: Vec<Cookie>,
    /// The password the account was registered with, when the agent created
    /// the account itself. Stored under engine custody; never in `Identity`,
    /// so no read path can carry it. `identity::password` is the only way out,
    /// for the browser re-login flow.
    pub password: Option<String>,
    /// Where this account came from. Defaults to `Operator` — the adopt and
    /// hand-built paths — because a missing value must not quietly claim the
    /// agent earned it.
    pub provenance: Provenance,
    /// The mailbox address that seeded it (`probe+t1@gmail.com`): the cleanup
    /// registry for accounts a run created.
    pub seed_account: Option<String>,
}

/// A stored identity, read back with its jar. Deliberately no `password`:
/// the read type cannot leak a credential it does not hold; the browser
/// re-login flow fetches it with [`password`]. `password_stored` is the flag
/// reads carry instead of the value.
#[derive(Clone, Debug)]
pub struct Identity {
    pub id: i64,
    pub name: String,
    pub host: Option<String>,
    pub totp_secret: Option<String>,
    pub note: Option<String>,
    pub provenance: Provenance,
    pub seed_account: Option<String>,
    pub password_stored: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub cookies: Vec<Cookie>,
}

/// A partial edit. `None` leaves the column alone; `Some("")` clears it.
/// `cookies` replaces the whole jar when given.
#[derive(Clone, Debug, Default)]
pub struct IdentityEdit {
    pub name: Option<String>,
    pub host: Option<String>,
    pub totp_secret: Option<String>,
    pub note: Option<String>,
    pub cookies: Option<Vec<Cookie>>,
    /// Sets the custody password. Not clearable to `None` by edit once set —
    /// an account either has this password or the edit is a mistake; empty
    /// string is ignored rather than interpreted as "clear".
    pub password: Option<String>,
    pub provenance: Option<Provenance>,
    pub seed_account: Option<String>,
}

/// Why minting or editing an identity can fail, beyond a lost database.
#[derive(Debug)]
pub enum IdentityError {
    /// The name is taken. Names are what `as_identity` carries, so they are
    /// unique the way a role name is.
    DuplicateName(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::DuplicateName(name) => {
                write!(f, "an identity named “{name}” already exists")
            }
            IdentityError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn duplicate(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT 1 FROM identity WHERE name = ?1", [name], |_| Ok(()))
        .optional()
        .map(|o| o.is_some())
}

/// Insert an identity with its jar, returning the new id.
///
/// Synchronous against the caller's connection, like `note` and `scope`: these
/// are user-initiated writes of a handful of rows that must be visible the
/// instant the call returns, not captured traffic for the writer to batch.
pub fn insert(conn: &Connection, n: &NewIdentity, now: i64) -> Result<i64, IdentityError> {
    if duplicate(conn, &n.name).map_err(IdentityError::Db)? {
        return Err(IdentityError::DuplicateName(n.name.clone()));
    }
    conn.execute(
        "INSERT INTO identity
           (name, host, totp_secret, note, password, provenance, seed_account,
            created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            n.name,
            n.host,
            n.totp_secret,
            n.note,
            n.password,
            n.provenance.as_str(),
            n.seed_account,
            now
        ],
    )
    .map_err(IdentityError::Db)?;
    let id = conn.last_insert_rowid();
    replace_cookies(conn, id, &n.cookies).map_err(IdentityError::Db)?;
    Ok(id)
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Identity>> {
    let ids: Vec<i64> = conn
        .prepare("SELECT id FROM identity ORDER BY id")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ids.into_iter()
        .map(|id| get(conn, id).map(Option::unwrap))
        .collect()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Identity>> {
    let Some(mut identity) = conn
        .query_row(
            "SELECT id, name, host, totp_secret, note, provenance, seed_account,
                    password IS NOT NULL, created_at, updated_at
               FROM identity WHERE id = ?1",
            [id],
            |r| {
                Ok(Identity {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    host: r.get(2)?,
                    totp_secret: r.get(3)?,
                    note: r.get(4)?,
                    provenance: Provenance::parse(&r.get::<_, String>(5)?)
                        .unwrap_or(Provenance::Operator),
                    seed_account: r.get(6)?,
                    password_stored: r.get(7)?,
                    created_at: r.get(8)?,
                    updated_at: r.get(9)?,
                    cookies: Vec::new(),
                })
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    let mut stmt = conn.prepare(
        "SELECT name, value, domain, path FROM identity_cookie
          WHERE identity_id = ?1 ORDER BY domain, name, path",
    )?;
    identity.cookies = stmt
        .query_map([id], |r| {
            Ok(Cookie {
                name: r.get(0)?,
                value: r.get(1)?,
                domain: r.get(2)?,
                path: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Some(identity))
}

/// Apply a partial edit. Returns rows changed — 0 for an unknown id. A given
/// field replaces that column outright (an empty string clears a nullable one,
/// matching how `update_finding` behaves); `cookies` replaces the whole jar
/// when given.
pub fn update(
    conn: &Connection,
    id: i64,
    edit: &IdentityEdit,
    now: i64,
) -> Result<usize, IdentityError> {
    let Some(current) = get(conn, id).map_err(IdentityError::Db)? else {
        return Ok(0);
    };
    if let Some(name) = &edit.name
        && *name != current.name
        && duplicate(conn, name).map_err(IdentityError::Db)?
    {
        return Err(IdentityError::DuplicateName(name.clone()));
    }
    let host = edit.host.clone().or(current.host);
    let totp_secret = edit.totp_secret.clone().or(current.totp_secret);
    let note = edit.note.clone().or(current.note);
    let seed_account = edit.seed_account.clone().or(current.seed_account);
    let changed = conn
        .execute(
            "UPDATE identity
                SET name = ?2, host = ?3, totp_secret = ?4, note = ?5,
                    password = COALESCE(?6, password),
                    provenance = ?7, seed_account = ?8,
                    updated_at = ?9
              WHERE id = ?1",
            params![
                id,
                edit.name.clone().unwrap_or(current.name),
                host,
                totp_secret,
                note,
                // Empty is "nothing to say", not "clear": a password once set
                // cannot be silently dropped.
                edit.password.clone().filter(|p| !p.is_empty()),
                edit.provenance.unwrap_or(current.provenance).as_str(),
                seed_account,
                now
            ],
        )
        .map_err(IdentityError::Db)?;
    if let Some(cookies) = &edit.cookies {
        replace_cookies(conn, id, cookies).map_err(IdentityError::Db)?;
    }
    Ok(changed)
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM identity WHERE id = ?1", [id])
}

/// The custody password for an identity, when one is stored. The only read
/// path for it — `Identity` does not carry it, so list/get cannot leak it, and
/// the browser re-login flow (which must type it into a real form) is the only
/// caller that has a reason to.
pub fn password(conn: &Connection, id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT password FROM identity WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .optional()
}

fn replace_cookies(conn: &Connection, id: i64, cookies: &[Cookie]) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM identity_cookie WHERE identity_id = ?1", [id])?;
    for c in cookies {
        conn.execute(
            "INSERT OR REPLACE INTO identity_cookie (identity_id, name, value, domain, path)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, c.name, c.value, c.domain, c.path],
        )?;
    }
    Ok(())
}

/// Why adopting a flow as an identity can fail.
#[derive(Debug)]
pub enum AdoptError {
    NotFound(FlowId),
    /// The flow carries neither a `Cookie` request header nor `Set-Cookie`
    /// responses — there is no session in it to adopt.
    NoSession,
    DuplicateName(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for AdoptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptError::NotFound(id) => write!(f, "no flow #{id}"),
            AdoptError::NoSession => {
                write!(f, "the flow carries no cookies to adopt")
            }
            AdoptError::DuplicateName(name) => {
                write!(f, "an identity named “{name}” already exists")
            }
            AdoptError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AdoptError {}

/// Mint an identity from a captured flow: its request `Cookie` header merged
/// with every `Set-Cookie` its response set, response winning. Returns the new
/// identity id.
///
/// This is the "log in once by hand" path: browse through the proxy, pick the
/// post-login flow, adopt it, and the session is a name from then on.
pub fn adopt(conn: &Connection, flow_id: FlowId, name: &str, now: i64) -> Result<i64, AdoptError> {
    let (req_headers, resp_headers, host): (Vec<u8>, Option<Vec<u8>>, String) = conn
        .query_row(
            "SELECT req_headers, resp_headers, host FROM flow WHERE id = ?1",
            [flow_id as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(AdoptError::Db)?
        .ok_or(AdoptError::NotFound(flow_id))?;

    let request = decode_headers(&req_headers);
    let response = resp_headers.as_deref().map(decode_headers);

    let cookies = session_cookies(&request, response.as_ref(), &host);
    if cookies.is_empty() {
        return Err(AdoptError::NoSession);
    }

    insert(
        conn,
        &NewIdentity {
            name: name.to_string(),
            host: Some(host),
            cookies,
            ..NewIdentity::default()
        },
        now,
    )
    .map_err(|e| match e {
        IdentityError::DuplicateName(name) => AdoptError::DuplicateName(name),
        IdentityError::Db(e) => AdoptError::Db(e),
    })
}

/// The jar a flow carries: request `Cookie` pairs keyed to the flow's host,
/// overlaid with each response `Set-Cookie` (which may state its own Domain
/// and Path). Response wins on collision — it is the newer word on the value.
pub fn session_cookies(
    request: &HeaderMap,
    response: Option<&HeaderMap>,
    host: &str,
) -> Vec<Cookie> {
    let mut jar: HashMap<(String, String, String), Cookie> = HashMap::new();

    for value in request.get_all("cookie") {
        for pair in value.to_str().unwrap_or("").split(';') {
            let pair = pair.trim();
            let Some((name, val)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let cookie = Cookie {
                name: name.to_string(),
                value: val.trim().to_string(),
                domain: host.to_string(),
                path: "/".to_string(),
            };
            jar.insert(key(&cookie), cookie);
        }
    }

    if let Some(response) = response {
        for value in response.get_all("set-cookie") {
            if let Some(cookie) = parse_set_cookie(value.to_str().unwrap_or(""), host) {
                jar.insert(key(&cookie), cookie);
            }
        }
    }

    let mut cookies: Vec<Cookie> = jar.into_values().collect();
    cookies.sort_by(|a, b| (&a.domain, &a.name, &a.path).cmp(&(&b.domain, &b.name, &b.path)));
    cookies
}

fn key(c: &Cookie) -> (String, String, String) {
    (c.name.clone(), c.domain.clone(), c.path.clone())
}

/// Parse one `Set-Cookie` value: `name=value` first, then attributes. Only
/// Domain and Path matter to us — a jar is scoped by where it may be replayed,
/// not by expiry (a pentest outlives a cookie's Max-Age all the time).
fn parse_set_cookie(value: &str, default_host: &str) -> Option<Cookie> {
    let mut parts = value.split(';');
    let (name, val) = parts.next()?.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = Cookie {
        name: name.to_string(),
        value: val.trim().to_string(),
        domain: default_host.to_string(),
        path: "/".to_string(),
    };
    for attr in parts {
        let (k, v) = match attr.trim().split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => continue, // Secure, HttpOnly, Partitioned: no value
        };
        match k.as_str() {
            "domain" => {
                // RFC 6265: a leading dot is meaningless; the domain matches
                // the host and any subdomain of it.
                cookie.domain = v.trim_start_matches('.').to_ascii_lowercase();
            }
            "path" => cookie.path = v,
            _ => {}
        }
    }
    Some(cookie)
}

/// Replace the request's `Cookie` header with the identity jar's cookies that
/// match `host`/`path`, and drop the header when none do.
///
/// Matching is RFC 6265 domain-match (equal, or the host is a subdomain of the
/// cookie's domain) and prefix path-match. Deliberately a *replacement*, not a
/// merge: replaying as an identity means the identity's session, and carrying
/// the original request's cookies alongside would forge a franken-session no
/// real user could present — evidence must show what the identity sends.
pub fn apply(headers: &mut HeaderMap, cookies: &[Cookie], host: &str, path: &str) {
    let host = host.to_ascii_lowercase();
    let matching: Vec<&Cookie> = cookies
        .iter()
        .filter(|c| {
            let domain_ok = host == c.domain || host.ends_with(&format!(".{}", c.domain));
            domain_ok && path_matches(path, &c.path)
        })
        .collect();

    headers.remove("cookie");
    if matching.is_empty() {
        return;
    }
    let header = matching
        .iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(value) = header.parse() {
        headers.insert("cookie", value);
    }
}

/// Decode a stored header blob. Same wire format `writer::encode_headers`
/// produces (`name: value\r\n` repeats); kept here rather than widening
/// `read.rs`'s private copy because adoption reads stored blobs directly.
fn decode_headers(blob: &[u8]) -> HeaderMap {
    use hudsucker::hyper::header::{HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    for line in blob.split(|&b| b == b'\n') {
        let line = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name),
            HeaderValue::from_bytes(value.strip_prefix(b" ").unwrap_or(value)),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

/// RFC 6265 §5.1.4 path-match: identical, or the cookie path is a prefix of
/// the request path that either ends on a `/` itself or cuts the request path
/// on one. A cookie-path of `/` matches everything.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    fn cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
        }
    }

    #[test]
    fn round_trips_a_jar() {
        let c = conn();
        let id = insert(
            &c,
            &NewIdentity {
                name: "admin".into(),
                host: Some("example.com".into()),
                cookies: vec![cookie("session", "abc"), cookie("csrf", "42")],
                ..NewIdentity::default()
            },
            1,
        )
        .unwrap();

        let got = get(&c, id).unwrap().unwrap();
        assert_eq!(got.name, "admin");
        assert_eq!(got.host.as_deref(), Some("example.com"));
        assert_eq!(got.cookies.len(), 2);
        let session = got.cookies.iter().find(|c| c.name == "session").unwrap();
        assert_eq!(session.value, "abc");
        assert!(list(&c).unwrap().len() == 1);
    }

    #[test]
    fn names_are_unique() {
        let c = conn();
        insert(
            &c,
            &NewIdentity {
                name: "a".into(),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        assert!(
            matches!(
                insert(
                    &c,
                    &NewIdentity {
                        name: "a".into(),
                        ..Default::default()
                    },
                    2
                ),
                Err(IdentityError::DuplicateName(_))
            ),
            "a second identity with the same name must be refused"
        );
    }

    #[test]
    fn update_replaces_the_whole_jar_or_leaves_it() {
        let c = conn();
        let id = insert(
            &c,
            &NewIdentity {
                name: "u".into(),
                cookies: vec![cookie("a", "1")],
                ..Default::default()
            },
            1,
        )
        .unwrap();

        update(
            &c,
            id,
            &IdentityEdit {
                note: Some("mine".into()),
                ..Default::default()
            },
            2,
        )
        .unwrap();
        assert_eq!(
            get(&c, id).unwrap().unwrap().cookies.len(),
            1,
            "no cookies given, jar untouched"
        );

        update(
            &c,
            id,
            &IdentityEdit {
                cookies: Some(vec![cookie("b", "2")]),
                ..Default::default()
            },
            3,
        )
        .unwrap();
        let got = get(&c, id).unwrap().unwrap();
        assert_eq!(
            got.cookies,
            vec![cookie("b", "2")],
            "given cookies replace the jar"
        );
        assert_eq!(got.note.as_deref(), Some("mine"));
    }

    #[test]
    fn set_cookie_domain_and_path_are_honoured() {
        let mut request = HeaderMap::new();
        request.insert("cookie", "a=1; b=2".parse().unwrap());
        let mut response = HeaderMap::new();
        response.append(
            "set-cookie",
            "a=9; Domain=.example.com; Path=/app; Secure; HttpOnly"
                .parse()
                .unwrap(),
        );
        response.append("set-cookie", "c=3".parse().unwrap());

        let cookies = session_cookies(&request, Some(&response), "example.com");
        // Different Path means two distinct cookies sharing a name — both kept.
        let app = cookies
            .iter()
            .find(|c| c.name == "a" && c.path == "/app")
            .unwrap();
        assert_eq!(app.value, "9", "the response's newer value");
        assert_eq!(app.domain, "example.com", "leading dot stripped");
        assert!(
            cookies
                .iter()
                .any(|c| c.name == "a" && c.path == "/" && c.value == "1"),
            "the request's own path-/ cookie is distinct, not overwritten"
        );
        let b = cookies.iter().find(|c| c.name == "b").unwrap();
        assert_eq!(b.value, "2", "request-only cookie kept");
        assert_eq!(
            b.domain, "example.com",
            "request cookies default to the flow host"
        );
        assert!(cookies.iter().any(|c| c.name == "c" && c.path == "/"));
    }

    #[test]
    fn a_response_cookie_wins_on_a_true_collision() {
        let mut request = HeaderMap::new();
        request.insert("cookie", "a=old".parse().unwrap());
        let mut response = HeaderMap::new();
        response.append("set-cookie", "a=new".parse().unwrap());
        let cookies = session_cookies(&request, Some(&response), "example.com");
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].value, "new",
            "response is the newer word on the value"
        );
    }

    #[test]
    fn apply_matches_domain_and_path() {
        let jar = vec![
            cookie("site", "1"),
            Cookie {
                name: "app".into(),
                value: "2".into(),
                domain: "example.com".into(),
                path: "/app".into(),
            },
            Cookie {
                name: "sub".into(),
                value: "3".into(),
                domain: "api.example.com".into(),
                path: "/".into(),
            },
        ];

        let mut headers = HeaderMap::new();
        headers.insert("cookie", "stale=yes".parse().unwrap());
        apply(&mut headers, &jar, "example.com", "/app/settings");

        let sent = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(sent.contains("site=1"), "domain match carries: {sent}");
        assert!(sent.contains("app=2"), "path prefix carries: {sent}");
        assert!(
            !sent.contains("sub=3"),
            "another host's cookie must not carry: {sent}"
        );
        assert!(
            !sent.contains("stale"),
            "the original header is replaced, not merged"
        );
    }

    #[test]
    fn apply_drops_the_header_when_nothing_matches() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "stale=yes".parse().unwrap());
        apply(&mut headers, &jar_of("example.com"), "other.com", "/");
        assert!(
            headers.get("cookie").is_none(),
            "replaying as an identity on a host it has no cookies for sends none"
        );
    }

    fn jar_of(domain: &str) -> Vec<Cookie> {
        vec![Cookie {
            name: "s".into(),
            value: "1".into(),
            domain: domain.into(),
            path: "/".into(),
        }]
    }

    /// Adoption reads the flow's stored header blobs, so it goes through a real
    /// recorded flow rather than hand-fed maps.
    #[test]
    fn adopt_pulls_the_session_out_of_a_flow() {
        use crate::engine::Engine;
        use crate::model::{CapturedRequest, CapturedResponse};
        use hudsucker::hyper::{Method, StatusCode, Uri, Version};

        let engine = Engine::new();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "sid=abc123".parse().unwrap());
        let mut resp_headers = HeaderMap::new();
        resp_headers.append(
            "set-cookie",
            "role=admin; Domain=example.com".parse().unwrap(),
        );

        let id = engine.record_request(CapturedRequest {
            method: Method::GET,
            uri: "https://example.com/login".parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers,
            body: Default::default(),
        });
        engine.record_response(
            id,
            CapturedResponse {
                status: StatusCode::OK,
                version: Version::HTTP_11,
                headers: resp_headers,
                body: Default::default(),
            },
        );

        let c = conn();
        // Same bytes the writer would have stored, so the decode path is real.
        c.execute("INSERT INTO capture_run (id, started_at) VALUES (1, 0)", [])
            .unwrap();
        c.execute(
            "INSERT INTO flow (id, run_id, source, started_at, method, uri, http_version,
                               req_headers, resp_headers, host, scheme, path)
             VALUES (?1, 1, 'proxy', 0, 'GET', 'https://example.com/login', 'HTTP/1.1',
                     ?2, ?3, 'example.com', 'https', '/login')",
            params![
                id as i64,
                crate::writer::encode_headers(&{
                    let mut h = HeaderMap::new();
                    h.insert("cookie", "sid=abc123".parse().unwrap());
                    h
                }),
                crate::writer::encode_headers(&{
                    let mut h = HeaderMap::new();
                    h.append(
                        "set-cookie",
                        "role=admin; Domain=example.com".parse().unwrap(),
                    );
                    h
                }),
            ],
        )
        .unwrap();

        let identity_id = adopt(&c, id, "me", 0).unwrap();
        let identity = get(&c, identity_id).unwrap().unwrap();
        assert_eq!(identity.name, "me");
        assert_eq!(identity.host.as_deref(), Some("example.com"));
        assert!(
            identity
                .cookies
                .iter()
                .any(|c| c.name == "sid" && c.value == "abc123"),
            "request cookie adopted"
        );
        assert!(
            identity
                .cookies
                .iter()
                .any(|c| c.name == "role" && c.value == "admin"),
            "set-cookie adopted"
        );
    }

    #[test]
    fn adopt_refuses_a_flow_without_cookies() {
        let c = conn();
        c.execute("INSERT INTO capture_run (id, started_at) VALUES (1, 0)", [])
            .unwrap();
        c.execute(
            "INSERT INTO flow (id, run_id, source, started_at, method, uri, http_version,
                               req_headers, host, scheme, path)
             VALUES (7, 1, 'proxy', 0, 'GET', 'https://x.com/', 'HTTP/1.1', X'', 'x.com', 'https', '/')",
            [],
        )
        .unwrap();
        assert!(matches!(adopt(&c, 7, "me", 0), Err(AdoptError::NoSession)));
        assert!(matches!(
            adopt(&c, 99, "me", 0),
            Err(AdoptError::NotFound(99))
        ));
    }
}
