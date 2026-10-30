//! The goal plane: what a run is after, and the only four ways it may stop.
//!
//! "The agent can't stop until it has achieved its goal" is not implementable
//! as written — an agent that literally cannot stop is a runaway. The
//! implementable invariant, and the one this module enforces in code rather
//! than in prompts (hector, lesson D), is:
//!
//! 1. A run has exactly one `running` goal. A new goal is refused while one
//!    runs — abandoning a goal silently is not a verb.
//! 2. The run may settle only into one of four states: `achieved`,
//!    `budget_exhausted`, `frontier_empty`, `operator_killed`.
//! 3. Every settle demands a written justification (`stop_reason_md`); the
//!    ledger refuses a silent stop.
//! 4. `achieved` additionally demands the oracle: at least one canary nonce
//!    minted for the goal has a recorded hit. The LLM believing it succeeded
//!    is not evidence; a nonce that fired is.
//!
//! `done()` therefore belongs to the harness — an LLM may *ask* to settle, but
//! the refusal it gets when the oracle has not fired is structural.

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

/// The four legal stop states. Everything else — including "I think I'm
/// done" — is refused, because those are the only exits that leave an
/// auditable story behind.
pub const GOAL_STATUSES: &[&str] = &[
    "achieved",
    "budget_exhausted",
    "frontier_empty",
    "operator_killed",
];

/// Why a goal operation can fail.
#[derive(Debug)]
pub enum GoalError {
    /// Another goal is still running; settle it (or kill it) first.
    AlreadyRunning(i64),
    /// The goal exists but is not running — it was already settled.
    NotRunning(i64),
    UnknownGoal(i64),
    /// An illegal settle state. The message names the legal set.
    IllegalState(String),
    /// A settle without a justification. The ledger refuses silent stops.
    JustificationRequired,
    /// An `achieved` settle with no canary hit recorded for the goal — the
    /// oracle has not fired, so the claim is belief, not evidence.
    OracleNotSatisfied,
    Db(rusqlite::Error),
}

impl std::fmt::Display for GoalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoalError::AlreadyRunning(id) => {
                write!(f, "goal #{id} is still running — settle or kill it first")
            }
            GoalError::NotRunning(id) => write!(f, "goal #{id} is not running"),
            GoalError::UnknownGoal(id) => write!(f, "no goal #{id}"),
            GoalError::IllegalState(s) => write!(
                f,
                "“{s}” is not a legal stop state — one of {GOAL_STATUSES:?}, with a justification"
            ),
            GoalError::JustificationRequired => {
                write!(f, "settling a goal requires a written stop reason")
            }
            GoalError::OracleNotSatisfied => write!(
                f,
                "cannot settle “achieved”: no canary nonce for this goal has a recorded hit \
                 — mint one per attempt, record the hit, then settle"
            ),
            GoalError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GoalError {}

/// What a run is after, as supplied by the operator or harness.
#[derive(Clone, Debug)]
pub struct NewGoal {
    pub text: String,
    /// The predicate the oracle implements, in auditable prose ("command
    /// output observable via a canary callback carrying our nonce").
    pub success_predicate_md: String,
    /// The operator's canary listener domain; minted nonces render as
    /// `<nonce>.<domain>` for DNS-style payloads or `?c=<nonce>` for URLs.
    pub canary_domain: Option<String>,
    /// Wall-clock budget. Zero means unbounded — the watchdog still reads it.
    pub budget_ms: i64,
}

#[derive(Clone, Debug)]
pub struct Goal {
    pub id: i64,
    pub text: String,
    pub success_predicate_md: String,
    pub canary_domain: Option<String>,
    pub budget_ms: i64,
    pub status: String,
    pub stop_reason_md: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub settled_at: Option<i64>,
}

/// The running goal, if any. The run's records (frontier, milestones,
/// nonces) hang off it; a run without one is just browsing.
pub fn running(conn: &Connection) -> rusqlite::Result<Option<Goal>> {
    conn.query_row(
        "SELECT id, text, success_predicate_md, canary_domain, budget_ms, status,
                stop_reason_md, created_at, updated_at, settled_at
           FROM goal WHERE status = 'running' ORDER BY id DESC LIMIT 1",
        [],
        row,
    )
    .optional()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Goal>> {
    conn.query_row(
        "SELECT id, text, success_predicate_md, canary_domain, budget_ms, status,
                stop_reason_md, created_at, updated_at, settled_at
           FROM goal WHERE id = ?1",
        [id],
        row,
    )
    .optional()
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Goal> {
    Ok(Goal {
        id: r.get(0)?,
        text: r.get(1)?,
        success_predicate_md: r.get(2)?,
        canary_domain: r.get(3)?,
        budget_ms: r.get(4)?,
        status: r.get(5)?,
        stop_reason_md: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
        settled_at: r.get(9)?,
    })
}

/// Open a goal. Refused while another runs: a goal is a commitment with a
/// ledger behind it, not a note that can be quietly replaced.
pub fn open(conn: &Connection, n: &NewGoal, now: i64) -> Result<i64, GoalError> {
    if let Some(g) = running(conn).map_err(GoalError::Db)? {
        return Err(GoalError::AlreadyRunning(g.id));
    }
    conn.execute(
        "INSERT INTO goal (text, success_predicate_md, canary_domain, budget_ms,
                           created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            n.text,
            n.success_predicate_md,
            n.canary_domain,
            n.budget_ms,
            now
        ],
    )
    .map_err(GoalError::Db)?;
    Ok(conn.last_insert_rowid())
}

/// Settle the running goal into one of the four stop states.
///
/// The two guards are the point of the module: a justification is required
/// for every state, and `achieved` is refused unless a canary nonce minted
/// for this goal has a recorded hit. An agent that believes it succeeded but
/// cannot show a nonce that fired gets `OracleNotSatisfied` — structurally,
/// not rhetorically.
pub fn settle(
    conn: &Connection,
    goal_id: i64,
    state: &str,
    reason_md: &str,
    now: i64,
) -> Result<usize, GoalError> {
    if !GOAL_STATUSES.contains(&state) {
        return Err(GoalError::IllegalState(state.to_string()));
    }
    if reason_md.trim().is_empty() {
        return Err(GoalError::JustificationRequired);
    }
    let goal = get(conn, goal_id)
        .map_err(GoalError::Db)?
        .ok_or(GoalError::UnknownGoal(goal_id))?;
    if goal.status != "running" {
        return Err(GoalError::NotRunning(goal_id));
    }
    if state == "achieved" && !nonce_hit_for_goal(conn, goal_id).map_err(GoalError::Db)? {
        return Err(GoalError::OracleNotSatisfied);
    }
    conn.execute(
        "UPDATE goal
            SET status = ?2, stop_reason_md = ?3, settled_at = ?4, updated_at = ?4
          WHERE id = ?1 AND status = 'running'",
        params![goal_id, state, reason_md.trim(), now],
    )
    .map_err(GoalError::Db)
}

/// Whether any nonce minted for this goal has fired. The `achieved` gate.
pub fn nonce_hit_for_goal(conn: &Connection, goal_id: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM canary_nonce WHERE goal_id = ?1 AND hit_at IS NOT NULL LIMIT 1",
        [goal_id],
        |_| Ok(()),
    )
    .optional()
    .map(|o| o.is_some())
}

// --- canary nonces ---

/// One canary: a unique nonce per attempt, so a hit names the exact payload
/// that fired — attribution a bare "it worked" can never carry.
#[derive(Clone, Debug)]
pub struct CanaryNonce {
    pub id: i64,
    pub goal_id: i64,
    pub nonce: String,
    pub label: Option<String>,
    /// The flow whose payload carried the nonce, recorded with the hit.
    pub hit_flow_id: Option<i64>,
    pub hit_at: Option<i64>,
    pub minted_at: i64,
}

/// Mint a nonce for the running goal. Uniqueness is the property that
/// matters — the nonce names *this* attempt — so it is a digest of the
/// clock, the label and a fresh row id: collisions are impossible in
/// practice, and there is no secret to guess, because the target is meant to
/// echo it back.
pub fn mint_nonce(
    conn: &Connection,
    goal_id: i64,
    label: Option<&str>,
    now: i64,
) -> Result<CanaryNonce, GoalError> {
    let goal = get(conn, goal_id)
        .map_err(GoalError::Db)?
        .ok_or(GoalError::UnknownGoal(goal_id))?;
    if goal.status != "running" {
        return Err(GoalError::NotRunning(goal_id));
    }
    conn.execute(
        "INSERT INTO canary_nonce (goal_id, nonce, label, minted_at) VALUES (?1, ?2, ?3, ?4)",
        params![goal_id, "", label, now],
    )
    .map_err(GoalError::Db)?;
    let id = conn.last_insert_rowid();
    let mut hasher = Sha256::new();
    hasher.update(id.to_le_bytes());
    hasher.update(now.to_le_bytes());
    hasher.update(label.unwrap_or("").as_bytes());
    let nonce = crate::db::hex(&hasher.finalize())[..16].to_string();
    conn.execute(
        "UPDATE canary_nonce SET nonce = ?2 WHERE id = ?1",
        params![id, nonce],
    )
    .map_err(GoalError::Db)?;
    Ok(CanaryNonce {
        id,
        goal_id,
        nonce,
        label: label.map(str::to_string),
        hit_flow_id: None,
        hit_at: None,
        minted_at: now,
    })
}

/// Record that a nonce fired — called when the canary listener (operator
/// infrastructure, phase 0) reports the callback. `flow_id` links the hit to
/// the send whose payload carried the nonce: the evidence chain from
/// "it fired" to "this request did it".
pub fn record_hit(
    conn: &Connection,
    nonce: &str,
    flow_id: Option<i64>,
    now: i64,
) -> Result<Option<CanaryNonce>, GoalError> {
    let updated = conn
        .execute(
            "UPDATE canary_nonce
                SET hit_at = ?3, hit_flow_id = COALESCE(?2, hit_flow_id)
              WHERE nonce = ?1 AND hit_at IS NULL",
            params![nonce, flow_id, now],
        )
        .map_err(GoalError::Db)?;
    if updated == 0 {
        return Ok(None);
    }
    conn.query_row(
        "SELECT id, goal_id, nonce, label, hit_flow_id, hit_at, minted_at
           FROM canary_nonce WHERE nonce = ?1",
        [nonce],
        |r| {
            Ok(CanaryNonce {
                id: r.get(0)?,
                goal_id: r.get(1)?,
                nonce: r.get(2)?,
                label: r.get(3)?,
                hit_flow_id: r.get(4)?,
                hit_at: r.get(5)?,
                minted_at: r.get(6)?,
            })
        },
    )
    .optional()
    .map_err(GoalError::Db)
}

pub fn nonces(conn: &Connection, goal_id: i64) -> rusqlite::Result<Vec<CanaryNonce>> {
    let mut stmt = conn.prepare(
        "SELECT id, goal_id, nonce, label, hit_flow_id, hit_at, minted_at
           FROM canary_nonce WHERE goal_id = ?1 ORDER BY id",
    )?;
    stmt.query_map([goal_id], |r| {
        Ok(CanaryNonce {
            id: r.get(0)?,
            goal_id: r.get(1)?,
            nonce: r.get(2)?,
            label: r.get(3)?,
            hit_flow_id: r.get(4)?,
            hit_at: r.get(5)?,
            minted_at: r.get(6)?,
        })
    })?
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    #[test]
    fn a_run_holds_exactly_one_goal() {
        let conn = conn();
        let a = open(
            &conn,
            &NewGoal {
                text: "Achieve RCE on app.example.com".into(),
                success_predicate_md: "canary callback with our nonce".into(),
                canary_domain: Some("canary.example.net".into()),
                budget_ms: 4 * 60 * 60 * 1000,
            },
            1,
        )
        .unwrap();
        assert!(matches!(
            open(&conn, &NewGoal {
                text: "another".into(),
                success_predicate_md: "x".into(),
                canary_domain: None,
                budget_ms: 0,
            }, 2),
            Err(GoalError::AlreadyRunning(id)) if id == a
        ));
    }

    #[test]
    fn achieved_is_refused_until_the_oracle_fires() {
        let conn = conn();
        let id = open(
            &conn,
            &NewGoal {
                text: "RCE".into(),
                success_predicate_md: "canary fires".into(),
                canary_domain: Some("canary.example.net".into()),
                budget_ms: 1000,
            },
            1,
        )
        .unwrap();
        let nonce = mint_nonce(&conn, id, Some("upload-then-traverse"), 2).unwrap();
        // No hit yet: belief is not evidence.
        assert!(matches!(
            settle(&conn, id, "achieved", "I am fairly sure", 3),
            Err(GoalError::OracleNotSatisfied)
        ));
        // The listener reports the callback. (Unlinked here — the FK to flow
        // demands a real flow row, which the integration tests have.)
        record_hit(&conn, &nonce.nonce, None, 4).unwrap();
        settle(&conn, id, "achieved", "nonce fired; flow 42 carried it", 5).unwrap();
        // Settled twice is refused — the story ends once.
        assert!(matches!(
            settle(&conn, id, "operator_killed", "changed my mind", 6),
            Err(GoalError::NotRunning(_))
        ));
        assert_eq!(get(&conn, id).unwrap().unwrap().status, "achieved");
    }

    #[test]
    fn every_stop_needs_a_reason_and_a_legal_state() {
        let conn = conn();
        let id = open(
            &conn,
            &NewGoal {
                text: "RCE".into(),
                success_predicate_md: "canary fires".into(),
                canary_domain: None,
                budget_ms: 0,
            },
            1,
        )
        .unwrap();
        assert!(matches!(
            settle(&conn, id, "budget_exhausted", "  ", 2),
            Err(GoalError::JustificationRequired)
        ));
        assert!(matches!(
            settle(&conn, id, "done", "because", 2),
            Err(GoalError::IllegalState(_))
        ));
        settle(
            &conn,
            id,
            "frontier_empty",
            "every ladder refuted, ledger in notes",
            2,
        )
        .unwrap();
    }

    #[test]
    fn nonces_are_unique_per_mint() {
        let conn = conn();
        let id = open(
            &conn,
            &NewGoal {
                text: "RCE".into(),
                success_predicate_md: "canary fires".into(),
                canary_domain: None,
                budget_ms: 0,
            },
            1,
        )
        .unwrap();
        let a = mint_nonce(&conn, id, Some("a"), 2).unwrap();
        let b = mint_nonce(&conn, id, Some("a"), 2).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(nonces(&conn, id).unwrap().len(), 2);
        // Recording a hit twice does not duplicate the evidence.
        record_hit(&conn, &a.nonce, None, 3).unwrap();
        assert!(record_hit(&conn, &a.nonce, None, 4).unwrap().is_none());
        assert!(nonce_hit_for_goal(&conn, id).unwrap());
    }
}
