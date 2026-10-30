//! The run's long-term memory: the attack-tree frontier and the milestone
//! trail (phase 8).
//!
//! Context windows die every few hours; the run survives only if its state
//! lives in the project database and a fresh context can be handed a digest
//! of it. The frontier is that state: every ladder the run intends to climb,
//! which one is active, which reached a milestone, and — the part a
//! relaunched context must consult before it retries anything — which are
//! dead ends and why.
//!
//! Statuses are a closed vocabulary because the strategy scheduler and the
//! watchdog read them: `active` is the current expansion, `dead_end` is
//! buried (with the reason in `note_md`), `exhausted` is spent without a
//! verdict either way (budget ran out mid-ladder), `milestone_reached` marks
//! graded progress — "have session", "SSRF confirmed" — which is how a stall
//! is distinguished from slow-but-moving.

use rusqlite::{Connection, OptionalExtension, params};

/// The ladder vocabulary: the seeded RCE paths a goal run expands. `other`
/// plus a good title covers anything not named here.
pub const LADDERS: &[&str] = &[
    "auth_bypass",
    "upload_traversal",
    "deserialization",
    "ssti",
    "cmd_injection",
    "ssrf_internal",
    "known_cve",
    "tenant_admin",
    "signup_mass_assignment",
    "config_exposure",
    "other",
];

pub const FRONTIER_STATUSES: &[&str] = &[
    "proposed",
    "active",
    "milestone_reached",
    "dead_end",
    "exhausted",
];

#[derive(Clone, Debug)]
pub struct NewFrontierItem {
    pub goal_id: i64,
    pub title: String,
    pub ladder: String,
    pub priority: i64,
    pub note_md: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FrontierItem {
    pub id: i64,
    pub goal_id: i64,
    pub title: String,
    pub ladder: String,
    pub status: String,
    pub priority: i64,
    pub note_md: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct Milestone {
    pub id: i64,
    pub goal_id: i64,
    pub title: String,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug)]
pub enum FrontierError {
    UnknownVocabulary(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for FrontierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrontierError::UnknownVocabulary(s) => {
                write!(f, "not a known ladder or status: {s:?}")
            }
            FrontierError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FrontierError {}

/// Propose a frontier item. Ladder is validated against the vocabulary so
/// materialise and prompts share one list.
pub fn propose(conn: &Connection, n: &NewFrontierItem, now: i64) -> Result<i64, FrontierError> {
    if !LADDERS.contains(&n.ladder.as_str()) {
        return Err(FrontierError::UnknownVocabulary(n.ladder.clone()));
    }
    conn.execute(
        "INSERT INTO frontier_item (goal_id, title, ladder, priority, note_md,
                                    created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![n.goal_id, n.title, n.ladder, n.priority, n.note_md, now],
    )
    .map_err(FrontierError::Db)?;
    Ok(conn.last_insert_rowid())
}

/// Move an item to a status, with a note that must say why when the status
/// buries it (`dead_end`, `exhausted`). The note is what a relaunched
/// context reads instead of repeating the attempt.
pub fn set_status(
    conn: &Connection,
    id: i64,
    status: &str,
    note: Option<&str>,
    now: i64,
) -> Result<usize, FrontierError> {
    if !FRONTIER_STATUSES.contains(&status) {
        return Err(FrontierError::UnknownVocabulary(status.to_string()));
    }
    if matches!(status, "dead_end" | "exhausted") && note.map(str::trim).unwrap_or("").is_empty() {
        return Err(FrontierError::UnknownVocabulary(
            "burying an item requires a note saying why".into(),
        ));
    }
    let changed = conn
        .execute(
            "UPDATE frontier_item
                SET status = ?2,
                    note_md = CASE WHEN ?3 IS NULL OR ?3 = '' THEN note_md ELSE ?3 END,
                    updated_at = ?4
              WHERE id = ?1",
            params![id, status, note.filter(|n| !n.trim().is_empty()), now],
        )
        .map_err(FrontierError::Db)?;
    Ok(changed)
}

/// Re-prioritise without touching status — the strategy scheduler's lever.
pub fn set_priority(
    conn: &Connection,
    id: i64,
    priority: i64,
    now: i64,
) -> Result<usize, FrontierError> {
    conn.execute(
        "UPDATE frontier_item SET priority = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, priority, now],
    )
    .map_err(FrontierError::Db)
}

pub fn list(
    conn: &Connection,
    goal_id: i64,
    status: Option<&str>,
) -> rusqlite::Result<Vec<FrontierItem>> {
    let sql = match status {
        Some(_) => {
            "SELECT id, goal_id, title, ladder, status, priority, note_md, created_at, updated_at
               FROM frontier_item WHERE goal_id = ?1 AND status = ?2
               ORDER BY priority DESC, id"
        }
        None => {
            "SELECT id, goal_id, title, ladder, status, priority, note_md, created_at, updated_at
               FROM frontier_item WHERE goal_id = ?1
               ORDER BY priority DESC, id"
        }
    };
    let mut stmt = conn.prepare(sql)?;
    let map = |r: &rusqlite::Row<'_>| {
        Ok(FrontierItem {
            id: r.get(0)?,
            goal_id: r.get(1)?,
            title: r.get(2)?,
            ladder: r.get(3)?,
            status: r.get(4)?,
            priority: r.get(5)?,
            note_md: r.get(6)?,
            created_at: r.get(7)?,
            updated_at: r.get(8)?,
        })
    };
    match status {
        Some(s) => stmt.query_map(params![goal_id, s], map)?.collect(),
        None => stmt.query_map([goal_id], map)?.collect(),
    }
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<FrontierItem>> {
    conn.query_row(
        "SELECT id, goal_id, title, ladder, status, priority, note_md, created_at, updated_at
           FROM frontier_item WHERE id = ?1",
        [id],
        |r| {
            Ok(FrontierItem {
                id: r.get(0)?,
                goal_id: r.get(1)?,
                title: r.get(2)?,
                ladder: r.get(3)?,
                status: r.get(4)?,
                priority: r.get(5)?,
                note_md: r.get(6)?,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
            })
        },
    )
    .optional()
}

/// Record a milestone — graded progress on the path to the goal. The trail
/// is what a watchdog reads: no milestone in N turns is a stall, however
/// busy the transcript looks.
pub fn milestone(
    conn: &Connection,
    goal_id: i64,
    title: &str,
    note: Option<&str>,
    now: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO milestone (goal_id, title, note, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![goal_id, title, note, now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn milestones(conn: &Connection, goal_id: i64, limit: i64) -> rusqlite::Result<Vec<Milestone>> {
    let mut stmt = conn.prepare(
        "SELECT id, goal_id, title, note, created_at
           FROM milestone WHERE goal_id = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    stmt.query_map(params![goal_id, limit], |r| {
        Ok(Milestone {
            id: r.get(0)?,
            goal_id: r.get(1)?,
            title: r.get(2)?,
            note: r.get(3)?,
            created_at: r.get(4)?,
        })
    })?
    .collect()
}

/// The state digest: everything a relaunched context needs to resume the run
/// — goal and its budget, the active frontier, recent milestones, the
/// dead-ends it must not retry, and the canary oracle's standing. Rendered
/// as markdown because it is injected into a prompt, not parsed by a program.
pub fn state_digest(conn: &Connection) -> rusqlite::Result<String> {
    use std::fmt::Write;
    let mut out = String::from("# Run state digest\n\n");
    let Some(goal) = crate::goal::running(conn)? else {
        let _ = writeln!(
            out,
            "No goal running. The last settled goal's ledger is in the goal table."
        );
        return Ok(out);
    };
    let _ = writeln!(
        out,
        "## Goal #{} — {} (running, budget {}ms)\n\nPredicate: {}\n",
        goal.id, goal.text, goal.budget_ms, goal.success_predicate_md
    );

    let active = list(conn, goal.id, Some("active"))?;
    let _ = writeln!(out, "## Active frontier");
    if active.is_empty() {
        let _ = writeln!(out, "- (nothing active — pick from proposed)");
    }
    for item in &active {
        let _ = writeln!(
            out,
            "- [#{}] {} ({}): {}",
            item.id,
            item.title,
            item.ladder,
            item.note_md.as_deref().unwrap_or("—")
        );
    }

    let proposed = list(conn, goal.id, Some("proposed"))?;
    let _ = writeln!(out, "\n## Proposed (highest priority first)");
    for item in proposed.iter().take(10) {
        let _ = writeln!(
            out,
            "- [#{}] {} ({}, priority {})",
            item.id, item.title, item.ladder, item.priority
        );
    }

    let _ = writeln!(out, "\n## Dead ends — do not retry without new information");
    for item in list(conn, goal.id, Some("dead_end"))? {
        let _ = writeln!(
            out,
            "- [#{}] {}: {}",
            item.id,
            item.title,
            item.note_md.as_deref().unwrap_or("no note")
        );
    }

    let _ = writeln!(out, "\n## Milestones (newest first)");
    for m in milestones(conn, goal.id, 10)? {
        let _ = writeln!(
            out,
            "- {}{}",
            m.title,
            m.note
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default()
        );
    }

    let hits = conn.query_row(
        "SELECT COUNT(*) FROM canary_nonce WHERE goal_id = ?1 AND hit_at IS NOT NULL",
        [goal.id],
        |r| r.get::<_, i64>(0),
    )?;
    let minted = conn.query_row(
        "SELECT COUNT(*) FROM canary_nonce WHERE goal_id = ?1",
        [goal.id],
        |r| r.get::<_, i64>(0),
    )?;
    let _ = writeln!(
        out,
        "\n## Canary oracle\n\n{hits} hit(s) of {minted} minted nonce(s). `achieved` settles only with a hit."
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::goal::{NewGoal, open as open_goal};

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    fn goal(conn: &Connection) -> i64 {
        open_goal(
            conn,
            &NewGoal {
                text: "RCE".into(),
                success_predicate_md: "canary fires".into(),
                canary_domain: Some("canary.example.net".into()),
                budget_ms: 0,
            },
            1,
        )
        .unwrap()
    }

    #[test]
    fn burying_an_item_requires_the_reason() {
        let conn = conn();
        let g = goal(&conn);
        let id = propose(
            &conn,
            &NewFrontierItem {
                goal_id: g,
                title: "SSRF to metadata service".into(),
                ladder: "ssrf_internal".into(),
                priority: 5,
                note_md: None,
            },
            2,
        )
        .unwrap();
        // A dead end without a note is how a relaunched context repeats a
        // buried attempt.
        assert!(set_status(&conn, id, "dead_end", Some(" "), 3).is_err());
        set_status(
            &conn,
            id,
            "dead_end",
            Some("169.254.169.254 not routed from the app"),
            3,
        )
        .unwrap();
        let items = list(&conn, g, Some("dead_end")).unwrap();
        assert_eq!(
            items[0].note_md.as_deref(),
            Some("169.254.169.254 not routed from the app")
        );

        // Unknown ladders never enter the ledger.
        assert!(
            propose(
                &conn,
                &NewFrontierItem {
                    goal_id: g,
                    title: "x".into(),
                    ladder: "magic".into(),
                    priority: 0,
                    note_md: None,
                },
                4
            )
            .is_err()
        );
    }

    #[test]
    fn the_digest_names_the_goal_the_frontier_and_the_dead_ends() {
        let conn = conn();
        let g = goal(&conn);
        propose(
            &conn,
            &NewFrontierItem {
                goal_id: g,
                title: "Upload + path traversal".into(),
                ladder: "upload_traversal".into(),
                priority: 9,
                note_md: None,
            },
            2,
        )
        .unwrap();
        milestone(
            &conn,
            g,
            "anonymous crawl complete",
            Some("sitemap materialised"),
            3,
        )
        .unwrap();
        let digest = state_digest(&conn).unwrap();
        assert!(digest.contains("Upload + path traversal"));
        assert!(digest.contains("anonymous crawl complete"));
        assert!(digest.contains("Dead ends"));
        assert!(digest.contains("0 hit(s) of 0 minted"));
    }
}
