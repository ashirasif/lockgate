//! The egress plane: which network exit a send leaves through, and which
//! exits identity-bearing traffic may never touch (phase 9).
//!
//! Free proxies harvested from the open web are MITMs you did not build. The
//! rule that keeps them useful without making them dangerous is a trust
//! class, and it is enforced in the engine's send path — not in prompts
//! (hector, lesson D):
//!
//! - `trusted` — the engine's own direct egress, or an exit the operator
//!   vouches for (their VPS, their residential exit). Only trusted exits may
//!   carry a send replayed `as_identity`.
//! - `pooled` — a commercial pool the operator pays for. Anonymous traffic
//!   only.
//! - `hostile` — harvested free proxies. Anonymous traffic only, and expect
//!   to be MITM'd: never anything a cookie or token rides on.
//!
//! Identities pin to an exit (`identity.egress_exit_id`); `NULL` is the
//! engine's own egress. A pinned non-trusted exit does not weaken the rule —
//! the send is refused, because a pin is where a session *should* leave
//! from, not permission to leak it.

use rusqlite::{Connection, OptionalExtension, params};

pub const EGRESS_KINDS: &[&str] = &["trusted", "pooled", "hostile"];

#[derive(Clone, Debug)]
pub struct NewEgressExit {
    pub name: String,
    pub kind: String,
    /// `http://`, `https://` or `socks5://` proxy URL. `None` means direct
    /// egress — allowed for `trusted` only, and only once.
    pub proxy_url: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EgressExit {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub proxy_url: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug)]
pub enum EgressError {
    DuplicateName(String),
    /// A non-trusted exit without a proxy URL — there is nothing to route
    /// through.
    NeedsProxy(String),
    /// A second direct exit. There is exactly one "the engine's own egress".
    SecondDirect,
    UnknownKind(String),
    /// The exit is in use as an identity's pin; delete fails until the pin
    /// is moved. Refusing here beats a dangling reference.
    InUse(i64),
    Db(rusqlite::Error),
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressError::DuplicateName(n) => write!(f, "an egress exit named “{n}” already exists"),
            EgressError::NeedsProxy(k) => {
                write!(
                    f,
                    "a “{k}” exit needs a proxy URL — that is the whole point of it"
                )
            }
            EgressError::SecondDirect => write!(
                f,
                "the direct exit already exists — there is exactly one “the engine's own egress”"
            ),
            EgressError::UnknownKind(k) => {
                write!(f, "kind must be one of {EGRESS_KINDS:?}, not {k:?}")
            }
            EgressError::InUse(id) => write!(
                f,
                "exit #{id} is pinned to an identity — move or clear the pin first"
            ),
            EgressError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EgressError {}

fn duplicate(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT 1 FROM egress_exit WHERE name = ?1", [name], |_| {
        Ok(())
    })
    .optional()
    .map(|o| o.is_some())
}

pub fn insert(conn: &Connection, n: &NewEgressExit, now: i64) -> Result<i64, EgressError> {
    if !EGRESS_KINDS.contains(&n.kind.as_str()) {
        return Err(EgressError::UnknownKind(n.kind.clone()));
    }
    if duplicate(conn, &n.name).map_err(EgressError::Db)? {
        return Err(EgressError::DuplicateName(n.name.clone()));
    }
    let proxy = n
        .proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    if proxy.is_none() && n.kind != "trusted" {
        return Err(EgressError::NeedsProxy(n.kind.clone()));
    }
    if proxy.is_none()
        && conn
            .query_row(
                "SELECT 1 FROM egress_exit WHERE kind = 'trusted' AND proxy_url IS NULL",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(EgressError::Db)?
            .is_some()
    {
        return Err(EgressError::SecondDirect);
    }
    conn.execute(
        "INSERT INTO egress_exit (name, kind, proxy_url, note, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![n.name, n.kind, proxy, n.note, now],
    )
    .map_err(EgressError::Db)?;
    Ok(conn.last_insert_rowid())
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<EgressExit>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, kind, proxy_url, note, created_at, updated_at
           FROM egress_exit ORDER BY id",
    )?;
    stmt.query_map([], row)?.collect()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<EgressExit>> {
    conn.query_row(
        "SELECT id, name, kind, proxy_url, note, created_at, updated_at
           FROM egress_exit WHERE id = ?1",
        [id],
        row,
    )
    .optional()
}

pub fn delete(conn: &Connection, id: i64) -> Result<usize, EgressError> {
    let pinned: Option<i64> = conn
        .query_row(
            "SELECT id FROM identity WHERE egress_exit_id = ?1 LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(EgressError::Db)?;
    if pinned.is_some() {
        return Err(EgressError::InUse(id));
    }
    conn.execute("DELETE FROM egress_exit WHERE id = ?1", [id])
        .map_err(EgressError::Db)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EgressExit> {
    Ok(EgressExit {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        proxy_url: r.get(3)?,
        note: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    #[test]
    fn the_rules_of_the_plane() {
        let conn = conn();
        // Direct egress exists once, and is trusted by definition.
        insert(
            &conn,
            &NewEgressExit {
                name: "direct".into(),
                kind: "trusted".into(),
                proxy_url: None,
                note: None,
            },
            1,
        )
        .unwrap();
        assert!(matches!(
            insert(
                &conn,
                &NewEgressExit {
                    name: "direct-2".into(),
                    kind: "trusted".into(),
                    proxy_url: None,
                    note: None,
                },
                2
            ),
            Err(EgressError::SecondDirect)
        ));
        // A pool without a URL is a label, not an exit.
        assert!(matches!(
            insert(
                &conn,
                &NewEgressExit {
                    name: "residential".into(),
                    kind: "pooled".into(),
                    proxy_url: None,
                    note: None,
                },
                3
            ),
            Err(EgressError::NeedsProxy(_))
        ));
        // Operator's residential exit is trusted *with* a URL.
        insert(
            &conn,
            &NewEgressExit {
                name: "residential".into(),
                kind: "trusted".into(),
                proxy_url: Some("http://10.0.0.2:3128".into()),
                note: Some("the operator's exit".to_string()),
            },
            4,
        )
        .unwrap();
        // Harvested proxies are hostile by default.
        let hostile = insert(
            &conn,
            &NewEgressExit {
                name: "free-proxy-1".into(),
                kind: "hostile".into(),
                proxy_url: Some("socks5://1.2.3.4:1080".into()),
                note: None,
            },
            5,
        )
        .unwrap();
        // A pinned identity keeps the exit alive.
        conn.execute(
            "INSERT INTO identity (name, egress_exit_id, created_at, updated_at)
             VALUES ('x', ?1, 1, 1)",
            [hostile],
        )
        .unwrap();
        assert!(matches!(delete(&conn, hostile), Err(EgressError::InUse(_))));
    }
}
