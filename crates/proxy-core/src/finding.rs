//! Findings: the security issues an engagement produces.
//!
//! A finding is authored, not captured, so unlike traffic it is written on
//! demand rather than off a channel of wire events. The write still goes through
//! the one writer task (see `writer.rs`) so the process keeps a single SQLite
//! writer; this module only supplies the row shape and the SQL, called from
//! inside that task's transaction.

use rusqlite::{Connection, OptionalExtension, params};

/// The fields a caller supplies to raise a finding. Everything the database
/// derives or stamps (`id`, timestamps) is added on insert, so this is only what
/// a human (or a workflow) actually knows.
#[derive(Clone, Debug, Default)]
pub struct NewFinding {
    pub title: String,
    /// info | low | medium | high | critical. Validated by the caller; stored as
    /// text so it stays readable in `sqlite3`.
    pub severity: String,
    /// draft | confirmed | false_positive | reported | fixed | wont_fix.
    pub status: String,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cwe: Option<String>,
    pub description_md: String,
    pub repro_md: Option<String>,
    pub impact_md: Option<String>,
    pub remediation_md: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    /// The captured flows that demonstrate the issue, with an optional label
    /// (e.g. "baseline", "exploited") per flow.
    pub evidence: Vec<(i64, Option<String>)>,
}

/// A stored finding, read back for listing and detail views.
#[derive(Clone, Debug)]
pub struct Finding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cwe: Option<String>,
    pub description_md: String,
    pub repro_md: Option<String>,
    pub impact_md: Option<String>,
    pub remediation_md: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub origin: String,
    /// `(flow_id, label)` rows from `finding_evidence`.
    pub evidence: Vec<(i64, Option<String>)>,
}

/// Insert a finding and its evidence links, returning the new id.
///
/// Runs inside the writer's transaction (`conn` is really a `&Transaction`), so
/// the finding and its evidence commit together or not at all.
pub fn insert(conn: &Connection, f: &NewFinding, now: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO finding (
            title, severity, status, cvss_vector, cvss_score, cvss_version, cwe,
            description_md, repro_md, impact_md, remediation_md, host, path,
            created_at, updated_at, origin
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14,'manual')",
        params![
            f.title,
            f.severity,
            f.status,
            f.cvss_vector,
            f.cvss_score,
            f.cvss_version,
            f.cwe,
            f.description_md,
            f.repro_md,
            f.impact_md,
            f.remediation_md,
            f.host,
            f.path,
            now,
        ],
    )?;
    let id = conn.last_insert_rowid();

    for (flow_id, label) in &f.evidence {
        conn.execute(
            "INSERT INTO finding_evidence (finding_id, flow_id, label) VALUES (?1, ?2, ?3)",
            params![id, flow_id, label],
        )?;
    }

    Ok(id)
}

/// Every finding, newest first. Findings number in the tens, not the millions,
/// so this is unpaginated on purpose.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT id, title, severity, status, cvss_vector, cvss_score, cvss_version, cwe,
                description_md, repro_md, impact_md, remediation_md, host, path,
                created_at, updated_at, origin
           FROM finding ORDER BY id DESC",
    )?;
    let rows = stmt
        .query_map([], row_to_finding)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    // Fill evidence per finding. The count is small, so N+1 is cheaper to read
    // than a join we would have to regroup by hand.
    rows.into_iter()
        .map(|mut f| {
            f.evidence = evidence_for(conn, f.id)?;
            Ok(f)
        })
        .collect()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<Finding>> {
    let mut finding = conn
        .query_row(
            "SELECT id, title, severity, status, cvss_vector, cvss_score, cvss_version, cwe,
                    description_md, repro_md, impact_md, remediation_md, host, path,
                    created_at, updated_at, origin
               FROM finding WHERE id = ?1",
            [id],
            row_to_finding,
        )
        .optional()?;
    if let Some(f) = &mut finding {
        f.evidence = evidence_for(conn, id)?;
    }
    Ok(finding)
}

fn evidence_for(
    conn: &Connection,
    finding_id: i64,
) -> rusqlite::Result<Vec<(i64, Option<String>)>> {
    let mut stmt = conn.prepare(
        "SELECT flow_id, label FROM finding_evidence WHERE finding_id = ?1 ORDER BY flow_id",
    )?;
    stmt.query_map([finding_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect()
}

fn row_to_finding(r: &rusqlite::Row) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: r.get(0)?,
        title: r.get(1)?,
        severity: r.get(2)?,
        status: r.get(3)?,
        cvss_vector: r.get(4)?,
        cvss_score: r.get(5)?,
        cvss_version: r.get(6)?,
        cwe: r.get(7)?,
        description_md: r.get(8)?,
        repro_md: r.get(9)?,
        impact_md: r.get(10)?,
        remediation_md: r.get(11)?,
        host: r.get(12)?,
        path: r.get(13)?,
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
        origin: r.get(16)?,
        evidence: Vec::new(),
    })
}
