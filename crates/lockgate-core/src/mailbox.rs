//! Mailboxes: where the engine reads verification mail from.
//!
//! Self-registration (phase 6) is a loop the agent runs alone: fill the form,
//! wait for the verification mail, follow the link or paste the code. The
//! mailbox abstraction is the middle step, and its contract is deliberately
//! narrow — *await a mail for address X, return the link and the code* —
//! because that is all registration ever needs from a mailbox. Gmail-over-IMAP
//! with an app password is the first backend; the IMAP endpoint is a column,
//! not a constant, so a different provider is an argument, not a fork.
//!
//! Custody rule, same as identity cookies and TOTP secrets: the app password
//! is stored here and nowhere else. `MailboxAccount` — the type every read
//! path returns — does not have a field for it, so a list cannot leak it; the
//! dedicated [`app_password`] call exists for [`fetch_verification`], which
//! holds it only for the lifetime of one IMAP session.

use std::collections::HashSet;
use std::net::TcpStream;
use std::sync::{Arc, LazyLock};

use rusqlite::{Connection, OptionalExtension, params};

/// A stored mailbox, read back without its credential — by construction: the
/// type has no password field.
#[derive(Clone, Debug)]
pub struct MailboxAccount {
    pub id: i64,
    pub address: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_username: String,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// What a caller supplies to register a mailbox with the engine. The
/// `imap_*` fields default in `MailboxDefaults` when the caller only knows
/// "it's a Gmail account".
#[derive(Clone, Debug)]
pub struct NewMailboxAccount {
    pub address: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_username: String,
    /// App password (Gmail) or equivalent. Write-only from every read path.
    pub app_password: String,
    pub note: Option<String>,
}

/// The IMAP defaults for Gmail, so registering one is an address and an app
/// password rather than a form about ports.
pub const GMAIL_IMAP_HOST: &str = "imap.gmail.com";
pub const GMAIL_IMAP_PORT: u16 = 993;

/// Why a mailbox operation can fail.
#[derive(Debug)]
pub enum MailboxError {
    /// The address is already registered — it names the account the way an
    /// identity name names a jar.
    DuplicateAddress(String),
    Db(rusqlite::Error),
    /// Talking to the IMAP server failed: connect, TLS, login, or protocol.
    /// The string is the cause; it never contains the app password.
    Imap(String),
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailboxError::DuplicateAddress(a) => {
                write!(f, "a mailbox for “{a}” is already registered")
            }
            MailboxError::Db(e) => write!(f, "{e}"),
            MailboxError::Imap(e) => write!(f, "imap: {e}"),
        }
    }
}

impl std::error::Error for MailboxError {}

/// One verification mail, already reduced to what registration needs: who
/// sent it, what it was about, and the link and/or code to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationMail {
    pub from: String,
    pub subject: String,
    pub link: Option<String>,
    pub code: Option<String>,
}

fn duplicate(conn: &Connection, address: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM mailbox_account WHERE address = ?1",
        [address],
        |_| Ok(()),
    )
    .optional()
    .map(|o| o.is_some())
}

/// Register a mailbox. Synchronous like the identity writes: a handful of
/// rows the caller must see landed before continuing.
pub fn insert(conn: &Connection, n: &NewMailboxAccount, now: i64) -> Result<i64, MailboxError> {
    if duplicate(conn, &n.address).map_err(MailboxError::Db)? {
        return Err(MailboxError::DuplicateAddress(n.address.clone()));
    }
    conn.execute(
        "INSERT INTO mailbox_account
           (address, imap_host, imap_port, imap_username, app_password, note,
            created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            n.address,
            n.imap_host,
            n.imap_port,
            n.imap_username,
            n.app_password,
            n.note,
            now
        ],
    )
    .map_err(MailboxError::Db)?;
    Ok(conn.last_insert_rowid())
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<MailboxAccount>> {
    let mut stmt = conn.prepare(
        "SELECT id, address, imap_host, imap_port, imap_username, note,
                created_at, updated_at
           FROM mailbox_account ORDER BY id",
    )?;
    stmt.query_map([], |r| {
        Ok(MailboxAccount {
            id: r.get(0)?,
            address: r.get(1)?,
            imap_host: r.get(2)?,
            imap_port: r.get::<_, i64>(3)? as u16,
            imap_username: r.get(4)?,
            note: r.get(5)?,
            created_at: r.get(6)?,
            updated_at: r.get(7)?,
        })
    })?
    .collect()
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM mailbox_account WHERE id = ?1", [id])
}

/// The endpoint half of an account, for [`fetch_verification`]. Split from
/// the password so callers snapshot both under a lock and then let go of it
/// before any network runs.
#[derive(Clone, Debug)]
pub struct ImapEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Look up an account's endpoint and app password. The only read path for the
/// credential; `fetch_verification_by_id` is its only consumer.
pub fn endpoint_and_password(
    conn: &Connection,
    id: i64,
) -> rusqlite::Result<Option<(ImapEndpoint, String)>> {
    conn.query_row(
        "SELECT imap_host, imap_port, imap_username, app_password
           FROM mailbox_account WHERE id = ?1",
        [id],
        |r| {
            Ok((
                ImapEndpoint {
                    host: r.get(0)?,
                    port: r.get::<_, i64>(1)? as u16,
                    username: r.get(2)?,
                },
                r.get(3)?,
            ))
        },
    )
    .optional()
}

/// The first HTTP(S) URL in the text. Registration mails put the confirm link
/// first, and `http://` inside prose ("click http://... to...") is rarer than
/// the button URL — first match is the right guess.
pub fn extract_link(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| {
                !c.is_ascii_alphanumeric()
                    && c != '/'
                    && c != ':'
                    && c != '.'
                    && c != '?'
                    && c != '='
                    && c != '&'
                    && c != '-'
                    && c != '#'
                    && c != '%'
            })
        })
        .find(|w| w.starts_with("https://") || w.starts_with("http://"))
        .map(str::to_string)
}

/// A standalone 4–8 digit code: `\b` on both sides, so a run of any other
/// length (an order number, a year inside a longer number) is not a match —
/// `\b\d{4,8}\b` cannot match *inside* a longer digit run because there is
/// no word boundary there. Four floors out years and most prices in prose;
/// eight ceilings out "your order 123456789 has shipped".
pub fn extract_code(text: &str) -> Option<String> {
    static CODE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\b\d{4,8}\b").unwrap());
    CODE.find(text).map(|m| m.as_str().to_string())
}

/// The read-only half of an IMAP fetch: everything except the network call.
/// Public so the tests can exercise matching and extraction against raw
/// RFC822 bytes without a server.
pub fn mail_from_rfc822(raw: &[u8], sender_contains: Option<&str>) -> Option<VerificationMail> {
    use mailparse::MailHeaderMap;
    let parsed = match mailparse::parse_mail(raw) {
        Ok(p) => p,
        Err(_) => return None,
    };
    let from = parsed.headers.get_first_value("From").unwrap_or_default();
    if let Some(needle) = sender_contains
        && !from
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    {
        return None;
    }
    let subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_default();
    let text = body_text(&parsed);
    Some(VerificationMail {
        from,
        subject,
        link: extract_link(&text),
        code: extract_code(&text),
    })
}

/// Prefer `text/plain`; fall back to a `text/html` part with tags stripped.
/// Verification mails ship both, and the plain half needs no tag-stripping
/// heuristics to find a URL in.
fn body_text(part: &mailparse::ParsedMail<'_>) -> String {
    let mut plain: Option<String> = None;
    let mut html: Option<String> = None;
    collect_bodies(part, &mut plain, &mut html);
    plain.or(html).unwrap_or_default()
}

fn collect_bodies(
    part: &mailparse::ParsedMail<'_>,
    plain: &mut Option<String>,
    html: &mut Option<String>,
) {
    if part.subparts.is_empty() {
        let mimetype = part.ctype.mimetype.as_str();
        let body = part.get_body().unwrap_or_default();
        if mimetype == "text/plain" {
            if plain.is_none() {
                *plain = Some(body);
            }
        } else if mimetype == "text/html" && html.is_none() {
            *html = Some(strip_tags(&body));
        }
        return;
    }
    for sub in &part.subparts {
        collect_bodies(sub, plain, html);
    }
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// One IMAP pass: connect, log in, and return the newest unseen mail for
/// `to_address` (optionally filtered by sender), marking it seen. `None`
/// means nothing matched yet — the caller's poll loop decides what that
/// means.
///
/// Blocking, on purpose: it is called from the engine's synchronous surface
/// (`fetch_verification_by_id`) which the MCP layer parks on a blocking
/// thread. Holding a tokio worker for one IMAP round-trip would be worse
/// plumbing for the same wait.
pub fn fetch_verification(
    endpoint: &ImapEndpoint,
    app_password: &str,
    to_address: &str,
    sender_contains: Option<&str>,
) -> Result<Option<VerificationMail>, MailboxError> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .map_err(|e| MailboxError::Imap(format!("connect: {e}")))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| MailboxError::Imap(format!("read timeout: {e}")))?;
    let mut client = imap::Client::new(tls_stream(&endpoint.host, tcp)?);
    client
        .read_greeting()
        .map_err(|e| MailboxError::Imap(format!("greeting: {e}")))?;
    let imap_err = |e: imap::Error| MailboxError::Imap(e.to_string());
    let mut session = client
        .login(&endpoint.username, app_password)
        .map_err(|(e, _)| MailboxError::Imap(format!("login: {e}")))?;
    let result = (|| {
        session.select("INBOX").map_err(imap_err)?;
        let uids: HashSet<u32> = session
            .uid_search(format!("UNSEEN TO \"{to_address}\""))
            .map_err(imap_err)?;
        // Newest first: when a signup form sent two mails, the second is the
        // one whose link is still valid.
        let mut ordered: Vec<u32> = uids.into_iter().collect();
        ordered.sort_unstable_by(|a, b| b.cmp(a));
        for uid in ordered {
            let fetches = session
                .uid_fetch(uid.to_string(), "(UID RFC822)")
                .map_err(imap_err)?;
            for fetch in fetches.iter() {
                let Some(raw) = fetch.body() else { continue };
                if let Some(mail) = mail_from_rfc822(raw, sender_contains) {
                    let _ = session.uid_store(uid.to_string(), "+FLAGS (\\Seen)");
                    return Ok(Some(mail));
                }
            }
        }
        Ok(None)
    })();
    let _ = session.logout();
    result
}

fn tls_stream(
    domain: &str,
    stream: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, MailboxError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| MailboxError::Imap(format!("tls name: {e}")))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| MailboxError::Imap(format!("tls: {e}")))?;
    Ok(rustls::StreamOwned::new(conn, stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    fn new_mailbox(address: &str) -> NewMailboxAccount {
        NewMailboxAccount {
            address: address.to_string(),
            imap_host: GMAIL_IMAP_HOST.to_string(),
            imap_port: GMAIL_IMAP_PORT,
            imap_username: address.to_string(),
            app_password: "apppassword".to_string(),
            note: None,
        }
    }

    #[test]
    fn a_registered_mailbox_reads_back_without_its_credential() {
        let conn = conn();
        let id = insert(&conn, &new_mailbox("probe@gmail.com"), 1).unwrap();
        let accounts = list(&conn).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, id);
        assert_eq!(accounts[0].imap_host, GMAIL_IMAP_HOST);
        // The credential is reachable only through the dedicated call.
        let (_, password) = endpoint_and_password(&conn, id).unwrap().unwrap();
        assert_eq!(password, "apppassword");
    }

    #[test]
    fn addresses_are_unique() {
        let conn = conn();
        insert(&conn, &new_mailbox("probe@gmail.com"), 1).unwrap();
        assert!(matches!(
            insert(&conn, &new_mailbox("probe@gmail.com"), 2),
            Err(MailboxError::DuplicateAddress(_))
        ));
    }

    #[test]
    fn the_link_is_the_first_url_and_the_code_is_standalone_digits() {
        let text = "Hi! Confirm your account.\n\nhttps://app.example.com/verify?token=abc123&x=1\n\nOr use code 448193. It expires in 10 minutes.";
        assert_eq!(
            extract_link(text).as_deref(),
            Some("https://app.example.com/verify?token=abc123&x=1")
        );
        assert_eq!(extract_code(text).as_deref(), Some("448193"));
        // Numbers glued to more digits or words are not codes.
        assert_eq!(extract_code("order 1234567890 shipped"), None);
        assert_eq!(extract_code("no digits at all"), None);
        assert_eq!(extract_link("no url here"), None);
    }

    #[test]
    fn a_multipart_mail_yields_its_plain_half_and_passes_the_sender_filter() {
        let raw = concat!(
            "From: noreply@example-app.com\r\n",
            "To: probe+t1@gmail.com\r\n",
            "Subject: Confirm your signup\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=BOUND\r\n",
            "\r\n",
            "--BOUND\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Confirm: https://example-app.com/confirm?t=xyz\r\n",
            "--BOUND\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<a href=\"https://bad.example/never\">click</a>\r\n",
            "--BOUND--\r\n",
        );
        let mail = mail_from_rfc822(raw.as_bytes(), Some("example-app.com")).unwrap();
        assert_eq!(mail.subject, "Confirm your signup");
        // The plain part's link wins over the HTML's.
        assert_eq!(
            mail.link.as_deref(),
            Some("https://example-app.com/confirm?t=xyz")
        );
        // Sender filter is substring, case-insensitive; a miss returns None.
        assert!(mail_from_rfc822(raw.as_bytes(), Some("someone-else")).is_none());
    }

    #[test]
    fn an_html_only_mail_still_yields_link_and_code() {
        let raw = concat!(
            "From: security@corp.test\r\n",
            "Subject: Your code\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>Your code is <b>771204</b></p>",
        );
        let mail = mail_from_rfc822(raw.as_bytes(), None).unwrap();
        assert_eq!(mail.code.as_deref(), Some("771204"));
    }
}
