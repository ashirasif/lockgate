//! The leads ledger: proposed attack hypotheses and how they were settled.
//!
//! The loop this table serves is hector's, kept honest: recon *proposes* a
//! lead, a verifier *settles* it with a control, an adjudicator *rules* on the
//! verdict. Three actors with three write paths — [`propose`], [`record_verdict`],
//! [`adjudicate`] — so the separation of labour is enforced by which function
//! can touch which columns, not by prompt etiquette. A verifier structurally
//! cannot write a ruling; an adjudicator structurally cannot invent a verdict.
//!
//! `control` is where correctness lives. A verdict that says "confirmed IDOR"
//! without the discriminating check (same request, other tenant's id, 200 vs
//! 403) is a guess that reads like a finding; the ledger refuses it.

use rusqlite::{Connection, OptionalExtension, params};

/// The lead vocabulary. Free to extend — `other` plus a good title covers the
/// rest — but named here so prompts and reports share one list.
pub const LEAD_KINDS: &[&str] = &[
    "idor",
    "authz",
    "ratelimit",
    "injection",
    "logic",
    "config",
    "exposure",
    "other",
];

pub const LEAD_STATUSES: &[&str] = &["proposed", "verifying", "verified", "refuted", "reported"];

/// The adjudicator's vocabulary. Deliberately two words, not a scale.
pub const RULINGS: &[&str] = &["admissible", "refuted"];

/// What recon supplies. `id` and the verdict columns are stamped later, by the
/// actors whose job that is.
#[derive(Clone, Debug)]
pub struct NewLead {
    pub kind: String,
    pub title: String,
    pub rationale_md: String,
    pub endpoint: Option<String>,
    pub flow_id: Option<i64>,
}

/// A stored lead, read back whole.
#[derive(Clone, Debug)]
pub struct Lead {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub rationale_md: String,
    pub endpoint: Option<String>,
    pub flow_id: Option<i64>,
    pub status: String,
    pub verdict: Option<String>,
    pub control: Option<String>,
    pub ruling: Option<String>,
    pub ruling_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug)]
pub enum LeadError {
    /// A kind, status, or ruling outside the vocabularies.
    BadValue(String),
    /// A verdict was recorded without a control.
    NoControl,
    /// Adjudication before a verdict exists — nothing to rule on.
    NoVerdict,
    NotFound(i64),
    Db(rusqlite::Error),
}

impl std::fmt::Display for LeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeadError::BadValue(why) => write!(f, "{why}"),
            LeadError::NoControl => write!(
                f,
                "a verdict needs its control: the baseline-vs-exploit check that \
                 discriminates the bug from intended behaviour"
            ),
            LeadError::NoVerdict => write!(
                f,
                "nothing to adjudicate — record a verdict (with a control) first"
            ),
            LeadError::NotFound(id) => write!(f, "no lead #{id}"),
            LeadError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LeadError {}

fn check_status(status: &str) -> Result<(), LeadError> {
    if LEAD_STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(LeadError::BadValue(format!(
            "unknown status “{status}” — known: {}",
            LEAD_STATUSES.join(", ")
        )))
    }
}

/// Recon files a lead. Refuses unknown kinds — a typo must fail at write time,
/// not quietly never match a filter later.
pub fn propose(conn: &Connection, lead: &NewLead, now: i64) -> Result<i64, LeadError> {
    if !LEAD_KINDS.contains(&lead.kind.as_str()) {
        return Err(LeadError::BadValue(format!(
            "unknown kind “{}” — known: {}",
            lead.kind,
            LEAD_KINDS.join(", ")
        )));
    }
    if lead.title.trim().is_empty() || lead.rationale_md.trim().is_empty() {
        return Err(LeadError::BadValue(
            "title and rationale_md must not be empty".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO lead (kind, title, rationale_md, endpoint, flow_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            lead.kind,
            lead.title.trim(),
            lead.rationale_md,
            lead.endpoint,
            lead.flow_id,
            now
        ],
    )
    .map_err(LeadError::Db)?;
    Ok(conn.last_insert_rowid())
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Lead>> {
    conn.query_row(
        "SELECT id, kind, title, rationale_md, endpoint, flow_id, status,
                verdict, control, ruling, ruling_reason, created_at, updated_at
           FROM lead WHERE id = ?1",
        [id],
        row_to_lead,
    )
    .optional()
}

const LEAD_COLUMNS: &str = "id, kind, title, rationale_md, endpoint, flow_id, status, verdict, control, ruling, \
     ruling_reason, created_at, updated_at";

pub fn list(conn: &Connection, status: Option<&str>) -> rusqlite::Result<Vec<Lead>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {LEAD_COLUMNS} FROM lead
          WHERE status = COALESCE(?1, status)
          ORDER BY id DESC"
    ))?;
    let rows = stmt.query_map([status], row_to_lead)?;
    rows.collect()
}

fn row_to_lead(r: &rusqlite::Row) -> rusqlite::Result<Lead> {
    Ok(Lead {
        id: r.get(0)?,
        kind: r.get(1)?,
        title: r.get(2)?,
        rationale_md: r.get(3)?,
        endpoint: r.get(4)?,
        flow_id: r.get(5)?,
        status: r.get(6)?,
        verdict: r.get(7)?,
        control: r.get(8)?,
        ruling: r.get(9)?,
        ruling_reason: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

/// The verifier's word: what happened when the lead was probed, and the
/// control that discriminates bug from behaviour. Status moves with it.
pub fn record_verdict(
    conn: &Connection,
    id: i64,
    status: &str,
    verdict: Option<&str>,
    control: Option<&str>,
    now: i64,
) -> Result<usize, LeadError> {
    check_status(status)?;
    let Some(current) = get(conn, id).map_err(LeadError::Db)? else {
        return Err(LeadError::NotFound(id));
    };
    let verdict = verdict.map(str::to_string).or(current.verdict);
    let control = control.map(str::to_string).or(current.control);

    // A settled status must carry its evidence. `proposed`/`verifying` may
    // still be wordless; `verified`/`refuted` may not.
    if matches!(status, "verified" | "refuted") && (verdict.is_none() || control.is_none()) {
        return Err(LeadError::NoControl);
    }

    conn.execute(
        "UPDATE lead
            SET status = ?2, verdict = ?3, control = ?4, updated_at = ?5
          WHERE id = ?1",
        params![id, status, verdict, control, now],
    )
    .map_err(LeadError::Db)
}

/// The adjudicator's word, and the only path that can write it. Rules on a
/// verdict that exists — before that there is nothing to judge.
pub fn adjudicate(
    conn: &Connection,
    id: i64,
    ruling: &str,
    reason: &str,
    now: i64,
) -> Result<usize, LeadError> {
    if !RULINGS.contains(&ruling) {
        return Err(LeadError::BadValue(format!(
            "unknown ruling “{ruling}” — known: {}",
            RULINGS.join(", ")
        )));
    }
    if reason.trim().is_empty() {
        return Err(LeadError::BadValue(
            "ruling_reason must not be empty — a ruling without its why is a vote".to_string(),
        ));
    }
    let Some(current) = get(conn, id).map_err(LeadError::Db)? else {
        return Err(LeadError::NotFound(id));
    };
    if current.verdict.is_none() {
        return Err(LeadError::NoVerdict);
    }
    conn.execute(
        "UPDATE lead SET ruling = ?2, ruling_reason = ?3, updated_at = ?4 WHERE id = ?1",
        params![id, ruling, reason.trim(), now],
    )
    .map_err(LeadError::Db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn conn() -> Connection {
        db::open_memory().unwrap()
    }

    fn lead(kind: &str) -> NewLead {
        NewLead {
            kind: kind.into(),
            title: "Booking ids are sequential".into(),
            rationale_md: "GET /bookings/4711 returned another tenant's data".into(),
            endpoint: Some("https://target.com/bookings/{id}".into()),
            flow_id: None,
        }
    }

    #[test]
    fn propose_get_list_round_trip() {
        let c = conn();
        let id = propose(&c, &lead("idor"), 1).unwrap();
        let got = get(&c, id).unwrap().unwrap();
        assert_eq!(got.status, "proposed");
        assert_eq!(got.verdict, None);
        assert_eq!(got.ruling, None);
        assert_eq!(list(&c, None).unwrap().len(), 1);
        assert_eq!(list(&c, Some("proposed")).unwrap().len(), 1);
        assert!(list(&c, Some("verified")).unwrap().is_empty());
    }

    #[test]
    fn unknown_kind_is_refused_at_write_time() {
        let c = conn();
        let err = propose(&c, &lead("why_not"), 1).unwrap_err();
        assert!(matches!(err, LeadError::BadValue(_)), "{err}");
    }

    #[test]
    fn a_verdict_without_a_control_is_refused() {
        let c = conn();
        let id = propose(&c, &lead("idor"), 1).unwrap();
        assert!(matches!(
            record_verdict(&c, id, "verified", Some("it worked"), None, 2),
            Err(LeadError::NoControl)
        ));
        // The control makes it land.
        record_verdict(
            &c,
            id,
            "verified",
            Some("200 with tenant B's id; 403 as tenant A"),
            Some("same request, swapped tenant: 200 vs 403"),
            2,
        )
        .unwrap();
        let got = get(&c, id).unwrap().unwrap();
        assert_eq!(got.status, "verified");
        assert!(got.control.is_some());
    }

    #[test]
    fn adjudication_requires_a_verdict_and_only_speaks_twice() {
        let c = conn();
        let id = propose(&c, &lead("logic"), 1).unwrap();
        assert!(matches!(
            adjudicate(&c, id, "admissible", "control is discriminating", 2),
            Err(LeadError::NoVerdict)
        ));

        record_verdict(
            &c,
            id,
            "refuted",
            Some("endpoint is documented public per program policy"),
            Some("program policy names the endpoint as out of scope for authz"),
            2,
        )
        .unwrap();
        adjudicate(&c, id, "refuted", "policy, not a bug", 3).unwrap();
        let got = get(&c, id).unwrap().unwrap();
        assert_eq!(got.ruling.as_deref(), Some("refuted"));

        assert!(matches!(
            adjudicate(&c, id, "maybe", "no", 4),
            Err(LeadError::BadValue(_))
        ));
        assert!(matches!(
            adjudicate(&c, id, "admissible", "", 4),
            Err(LeadError::BadValue(_))
        ));
    }

    #[test]
    fn unknown_status_is_refused() {
        let c = conn();
        let id = propose(&c, &lead("config"), 1).unwrap();
        assert!(matches!(
            record_verdict(&c, id, "done", None, None, 2),
            Err(LeadError::BadValue(_))
        ));
    }
}
