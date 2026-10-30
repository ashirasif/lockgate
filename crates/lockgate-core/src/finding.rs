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
    /// manual | workflow — "I verified" vs "the tool thinks". The passive
    /// scanner files `workflow`; everything a human or agent files is `manual`.
    pub origin: String,
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

/// The four prose columns as one markdown document.
///
/// A finding's write-up is stored in four columns because a report generator
/// wants them apart, but it is *written* as one document — nobody drafts an
/// impact statement in isolation from the reproduction above it. So the columns
/// render to a single markdown page with `## ` section headings and parse back
/// out of one, which is what lets the TUI hand the whole write-up to a buffer
/// or to `$EDITOR` in one piece.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteUp {
    /// Everything above the first recognised heading. Untitled on purpose: the
    /// description is what a finding *is*, so it needs no announcement.
    pub description_md: String,
    pub repro_md: Option<String>,
    pub impact_md: Option<String>,
    pub remediation_md: Option<String>,
}

/// The headings that mean a section, and which column they land in.
///
/// Aliases are recognised but not emitted: `## Fix` parses, and comes back as
/// `## Remediation`. Only the canonical spelling round-trips unchanged, which
/// is what keeps a second edit from re-splitting the document differently.
const SECTIONS: &[(Section, &[&str])] = &[
    (Section::Description, &["description"]),
    (
        Section::Repro,
        &["reproduction", "repro", "steps to reproduce"],
    ),
    (Section::Impact, &["impact"]),
    (Section::Remediation, &["remediation", "fix", "mitigation"]),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Section {
    Description,
    Repro,
    Impact,
    Remediation,
}

/// The heading a section is written back out under.
fn heading(section: Section) -> &'static str {
    match section {
        Section::Description => "Description",
        Section::Repro => "Reproduction",
        Section::Impact => "Impact",
        Section::Remediation => "Remediation",
    }
}

/// Which section a line opens, if any.
///
/// Exactly two hashes: `### Impact` is a subheading *inside* a section, and
/// stealing it would rearrange a document the author had already organised.
fn section_of(line: &str) -> Option<Section> {
    let rest = line.trim().strip_prefix("##")?;
    if rest.starts_with('#') {
        return None;
    }
    let name = rest.trim().to_ascii_lowercase();
    SECTIONS
        .iter()
        .find(|(_, aliases)| aliases.contains(&name.as_str()))
        .map(|(section, _)| *section)
}

impl WriteUp {
    /// Split a markdown document back into the four columns.
    ///
    /// Text before any recognised heading is the description, so a write-up
    /// that is just a paragraph stays just a paragraph. An unrecognised `##`
    /// heading is left as literal text in whichever section it falls in — the
    /// parser only claims headings it knows, so nothing an author writes can be
    /// silently dropped.
    pub fn parse(text: &str) -> Self {
        let mut out = WriteUp::default();
        let mut current = Section::Description;
        let mut buffer: Vec<&str> = Vec::new();

        // Sections are flushed when the *next* heading arrives, and once at the
        // end, so a heading's body is whatever follows it up to the next one.
        let mut flush = |section: Section, buffer: &mut Vec<&str>| {
            let body = buffer.join("\n").trim().to_string();
            buffer.clear();
            let slot = match section {
                Section::Description => {
                    // Two description blocks — a bare paragraph plus an
                    // explicit `## Description` — are one description, joined
                    // rather than one overwriting the other.
                    if !body.is_empty() {
                        if out.description_md.is_empty() {
                            out.description_md = body;
                        } else {
                            out.description_md.push_str("\n\n");
                            out.description_md.push_str(&body);
                        }
                    }
                    return;
                }
                Section::Repro => &mut out.repro_md,
                Section::Impact => &mut out.impact_md,
                Section::Remediation => &mut out.remediation_md,
            };
            // An emptied section is a cleared column, not an untouched one:
            // deleting everything under `## Impact` has to mean the impact is
            // gone, or a section could never be removed.
            let body = (!body.is_empty()).then_some(body);
            match (slot.as_mut(), body) {
                (Some(existing), Some(body)) => {
                    existing.push_str("\n\n");
                    existing.push_str(&body);
                }
                (None, body) => *slot = body,
                (Some(_), None) => {}
            }
        };

        for line in text.lines() {
            match section_of(line) {
                Some(next) => {
                    flush(current, &mut buffer);
                    current = next;
                }
                None => buffer.push(line),
            }
        }
        flush(current, &mut buffer);
        out
    }

    /// Render the four columns as one markdown document.
    ///
    /// Empty sections are left out entirely rather than written as a bare
    /// heading, so an untouched finding opens as an empty page instead of a
    /// form to fill in. Adding the heading back is how you add the section.
    pub fn render(&self) -> String {
        let mut out = self.description_md.trim().to_string();
        let sections = [
            (Section::Repro, &self.repro_md),
            (Section::Impact, &self.impact_md),
            (Section::Remediation, &self.remediation_md),
        ];
        for (section, body) in sections {
            let Some(body) = body.as_deref().map(str::trim).filter(|b| !b.is_empty()) else {
                continue;
            };
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str("## ");
            out.push_str(heading(section));
            out.push('\n');
            out.push_str(body);
        }
        out
    }
}

impl Finding {
    /// This finding's prose as one markdown document, ready to be edited.
    pub fn write_up(&self) -> String {
        WriteUp {
            description_md: self.description_md.clone(),
            repro_md: self.repro_md.clone(),
            impact_md: self.impact_md.clone(),
            remediation_md: self.remediation_md.clone(),
        }
        .render()
    }
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
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14,?15)",
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
            f.origin,
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
/// Change a finding's triage state.
///
/// Severity and status only: they are what move during triage, and the prose
/// fields belong in an editor rather than behind a keystroke. `None` leaves a
/// column alone.
pub fn set_triage(
    conn: &Connection,
    id: i64,
    severity: Option<&str>,
    status: Option<&str>,
    now: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE finding
            SET severity = COALESCE(?2, severity),
                status = COALESCE(?3, status),
                updated_at = ?4
          WHERE id = ?1",
        rusqlite::params![id, severity, status, now],
    )
}

/// Replace a finding's whole write-up.
///
/// All four columns are written unconditionally, with no `COALESCE`: the
/// document the operator saved *is* the prose, so a section they deleted has to
/// come back out as NULL. Anything that wants to change one column without
/// touching the rest should read, edit, and write the whole `WriteUp`.
pub fn set_write_up(conn: &Connection, id: i64, w: &WriteUp, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE finding
            SET description_md = ?2,
                repro_md = ?3,
                impact_md = ?4,
                remediation_md = ?5,
                updated_at = ?6
          WHERE id = ?1",
        params![
            id,
            w.description_md,
            w.repro_md,
            w.impact_md,
            w.remediation_md,
            now,
        ],
    )
}

/// A partial edit to a finding: every field that can be revised after filing.
///
/// Two layers of `Option` on the nullable columns, because they have to say
/// three things and not two. `None` is "leave this column alone"; `Some(None)`
/// is "clear it"; `Some(Some(v))` is "set it to v". Collapsing the first two —
/// the usual `COALESCE` shortcut — would mean a CVSS vector or an impact
/// paragraph could be written but never taken back.
///
/// Evidence links are not here: adding and removing them is a different shape
/// from setting a column, and a caller that passed a partial list would silently
/// unlink flows it never mentioned.
#[derive(Clone, Debug, Default)]
pub struct FindingEdit {
    pub title: Option<String>,
    /// Validated by the caller, like `NewFinding::severity`.
    pub severity: Option<String>,
    pub status: Option<String>,
    /// Not nullable in the schema: an empty description is `Some(String::new())`.
    pub description_md: Option<String>,
    pub repro_md: Option<Option<String>>,
    pub impact_md: Option<Option<String>>,
    pub remediation_md: Option<Option<String>>,
    pub cvss_vector: Option<Option<String>>,
    pub cvss_score: Option<Option<f64>>,
    pub cvss_version: Option<Option<String>>,
    pub cwe: Option<Option<String>>,
}

impl FindingEdit {
    /// Whether this edit would change anything at all.
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.severity.is_none()
            && self.status.is_none()
            && self.description_md.is_none()
            && self.repro_md.is_none()
            && self.impact_md.is_none()
            && self.remediation_md.is_none()
            && self.cvss_vector.is_none()
            && self.cvss_score.is_none()
            && self.cvss_version.is_none()
            && self.cwe.is_none()
    }
}

/// Apply a partial edit, returning rows changed (0 for an unknown id).
///
/// Read-modify-write rather than a `COALESCE` update, because "clear this
/// column" cannot be expressed as a parameter that also means "leave it". The
/// pair runs in one transaction so a concurrent edit cannot land between the
/// read and the write.
pub fn update(conn: &Connection, id: i64, edit: &FindingEdit, now: i64) -> rusqlite::Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let Some(current) = get(&tx, id)? else {
        return Ok(0);
    };

    // `unwrap_or` for the flat fields, and the outer `Option` for the nullable
    // ones: unwrapping one layer leaves exactly the value to store.
    let rows = tx.execute(
        "UPDATE finding
            SET title = ?2,
                severity = ?3,
                status = ?4,
                description_md = ?5,
                repro_md = ?6,
                impact_md = ?7,
                remediation_md = ?8,
                cvss_vector = ?9,
                cvss_score = ?10,
                cvss_version = ?11,
                cwe = ?12,
                updated_at = ?13
          WHERE id = ?1",
        params![
            id,
            edit.title.clone().unwrap_or(current.title),
            edit.severity.clone().unwrap_or(current.severity),
            edit.status.clone().unwrap_or(current.status),
            edit.description_md
                .clone()
                .unwrap_or(current.description_md),
            edit.repro_md.clone().unwrap_or(current.repro_md),
            edit.impact_md.clone().unwrap_or(current.impact_md),
            edit.remediation_md
                .clone()
                .unwrap_or(current.remediation_md),
            edit.cvss_vector.clone().unwrap_or(current.cvss_vector),
            edit.cvss_score.unwrap_or(current.cvss_score),
            edit.cvss_version.clone().unwrap_or(current.cvss_version),
            edit.cwe.clone().unwrap_or(current.cwe),
            now,
        ],
    )?;
    tx.commit()?;
    Ok(rows)
}

/// Retitle a finding, leaving everything else alone.
pub fn set_title(conn: &Connection, id: i64, title: &str, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE finding SET title = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, title, now],
    )
}

/// Delete a finding and its evidence links.
pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM finding_evidence WHERE finding_id = ?1", [id])?;
    conn.execute("DELETE FROM finding WHERE id = ?1", [id])
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_up(text: &str) -> WriteUp {
        WriteUp::parse(text)
    }

    /// The document is the source of truth, so what the columns render must
    /// parse back into the same columns. Without this the second edit of a
    /// finding would quietly reshape the first.
    #[test]
    fn a_write_up_round_trips_through_its_document() {
        let original = WriteUp {
            description_md: "Session token is in the URL.".into(),
            repro_md: Some("1. Log in\n2. Click the outbound link".into()),
            impact_md: Some("Full account takeover.".into()),
            remediation_md: Some("Move the token to a cookie.".into()),
        };
        let rendered = original.render();
        assert_eq!(WriteUp::parse(&rendered), original);
        assert_eq!(WriteUp::parse(&rendered).render(), rendered);
    }

    /// The common shape: someone types a paragraph and stops. It is a
    /// description, not an unparseable document.
    #[test]
    fn text_before_any_heading_is_the_description() {
        let w = write_up("just a paragraph\nand another line");
        assert_eq!(w.description_md, "just a paragraph\nand another line");
        assert_eq!(w.repro_md, None);
    }

    /// Deleting a section has to mean deleting it. A `COALESCE`-style update
    /// would leave the old impact behind and the operator would never know.
    #[test]
    fn an_emptied_section_clears_its_column() {
        let w = write_up("desc\n\n## Impact\n\n## Remediation\npatch it");
        assert_eq!(w.impact_md, None, "a heading with no body is no section");
        assert_eq!(w.remediation_md.as_deref(), Some("patch it"));
    }

    /// Aliases are a convenience for typing, not a second storage format: they
    /// land in the right column and come back out canonically spelled.
    #[test]
    fn heading_aliases_are_recognised_and_normalised() {
        let w = write_up("d\n\n## repro\nsteps\n\n## Fix\npatch");
        assert_eq!(w.repro_md.as_deref(), Some("steps"));
        assert_eq!(w.remediation_md.as_deref(), Some("patch"));
        assert!(w.render().contains("## Reproduction"));
        assert!(w.render().contains("## Remediation"));
    }

    /// A heading the parser does not know stays where the author put it. The
    /// alternative — dropping it, or treating it as a section boundary — loses
    /// text somebody wrote.
    #[test]
    fn unknown_headings_stay_inside_their_section() {
        let w = write_up("## Impact\nbad\n\n## Notes for the client\nsee appendix");
        assert_eq!(
            w.impact_md.as_deref(),
            Some("bad\n\n## Notes for the client\nsee appendix")
        );
        assert_eq!(w.description_md, "");
    }

    /// `###` is a subheading of the section it sits in, not a new section.
    #[test]
    fn deeper_headings_are_not_section_boundaries() {
        let w = write_up("## Reproduction\n### Impact of step 2\nstill repro");
        assert_eq!(
            w.repro_md.as_deref(),
            Some("### Impact of step 2\nstill repro")
        );
        assert_eq!(w.impact_md, None);
    }

    /// An explicit `## Description` is allowed, and does not fight with the
    /// untitled paragraph above it.
    #[test]
    fn an_explicit_description_heading_joins_the_untitled_text() {
        let w = write_up("first\n\n## Description\nsecond\n\n## Impact\nbad");
        assert_eq!(w.description_md, "first\n\nsecond");
        assert_eq!(w.impact_md.as_deref(), Some("bad"));
    }

    /// An untouched finding should open as a blank page, not as a form of
    /// empty headings.
    #[test]
    fn an_empty_write_up_renders_to_nothing() {
        assert_eq!(WriteUp::default().render(), "");
        assert_eq!(WriteUp::parse(""), WriteUp::default());
    }
}
